// Offline: synthetic transactions with real signatures, signed Nostr events, an in-memory chain. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as L from "@bitauth/libauth";
import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from "nostr-tools";
import {
  buildCommitment, signP2pkh, dataOutputBytecode, readCommitment, buildClaim, buildUnbind, verifyBinding, findByAddress, TAG, NIP39_WORDING,
  listWall, onWall,
} from "../lib/index.mjs";

const T0 = 1_700_000_000; // block time of every synthetic header
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

function bchKey() {
  let priv;
  do { priv = rand(32); } while (!L.secp256k1.validatePrivateKey(priv));
  const pub = L.secp256k1.derivePublicKeyCompressed(priv);
  const payload = L.hash160(pub);
  const enc = L.encodeCashAddress({ prefix: "bitcoincash", type: "p2pkh", payload });
  return { priv, pub, payload, lock: L.encodeLockingBytecodeP2pkh(payload), address: typeof enc === "string" ? enc : enc.address };
}

function nostrKey(sk = generateSecretKey()) {
  const pk = getPublicKey(sk);
  return { sk, pk, npub: nip19.npubEncode(pk) };
}

function memoryChain({ tip = 900_000 } = {}) {
  const txs = new Map(), history = new Map();
  return {
    txs,
    add(tx) { const raw = L.encodeTransaction(tx); const txid = L.hashTransaction(raw); txs.set(txid, raw); return txid; },
    touch(address, txid, height) { if (!history.has(address)) history.set(address, []); history.get(address).push({ tx_hash: txid, height }); },
    getTx: async (id) => { if (!txs.has(id)) throw new Error("not found"); return txs.get(id); },
    getHistory: async (address) => history.get(address) ?? [],
    getTipHeight: async () => tip,
    getHeader: async () => { const h = new Uint8Array(80); new DataView(h.buffer).setUint32(68, T0, true); return h; },
  };
}

const nostrOf = (...claims) => ({ fetchClaim: async (pk) => ({ claim: claims.find((c) => c.pubkey === pk) ?? null }) });

function fund(chain, key, sats = 10_000n) {
  const txid = chain.add({
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: rand(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.of(0x51) }],
    outputs: [{ lockingBytecode: key.lock, valueSatoshis: sats }],
  });
  return { txid, vout: 0, satoshis: sats };
}

/** A commitment from key to id, mined at height, plus id's signed claim. mutate runs before signing. */
function bind(chain, { key = bchKey(), id = nostrKey(), sighash = 0x41, mutate = (t) => t, height = 899_990 } = {}) {
  const { transaction, sourceOutputs } = buildCommitment({ address: key.address, npub: id.npub, coins: [fund(chain, key)] });
  const signed = signP2pkh(mutate(transaction), sourceOutputs, key.priv, sighash);
  const txid = chain.add(signed);
  chain.touch(key.address, txid, height);
  return { key, id, txid, signed, claim: finalizeEvent(buildClaim(null, key.address, txid), id.sk) };
}

const check = (chain, b, npub = b.id.npub, claims = [b.claim]) => verifyBinding(npub, { nostr: nostrOf(...claims), chain, now: T0 + 3 * 86400 });
const extraData = (npub) => (t) => ({ ...t, outputs: [...t.outputs, { lockingBytecode: dataOutputBytecode(npub), valueSatoshis: 0n }] });

test("a mined binding verifies, with its confirmations and age", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const r = await check(chain, b);
  assert.equal(r.status, "verified");
  assert.equal(r.confirmations, 11);
  assert.equal(r.address, b.key.address);
  assert.equal(r.txid, b.txid);
  assert.equal(r.boundSince, T0);
  assert.deepEqual(r.warnings, []);
});

test("a commitment still in the mempool is pending and marked new", async () => {
  const chain = memoryChain();
  const r = await check(chain, bind(chain, { height: 0 }));
  assert.equal(r.status, "pending");
  assert.deepEqual(r.warnings, ["new"]);
});

for (const [name, sighash] of [["NONE", 0x42], ["SINGLE", 0x43]]) {
  test(`a signature with sighash ${name} is refused: it doesn't cover every output`, async () => {
    const chain = memoryChain();
    const r = await check(chain, bind(chain, { sighash }));
    assert.equal(r.status, "invalid");
    assert.match(r.reason, new RegExp(`sighash 0x${sighash.toString(16)}`));
  });
}

test("two Countersign data outputs are refused", async () => {
  const chain = memoryChain();
  const r = await check(chain, bind(chain, { mutate: extraData(nostrKey().npub) }));
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /more than one/);
});

test("a transaction without a Countersign data output is refused", async () => {
  const chain = memoryChain();
  const other = L.flattenBinArray([Uint8Array.of(0x6a), L.encodeDataPush(L.utf8ToBin("XYZ\0")), L.encodeDataPush(L.utf8ToBin("hello"))]);
  const r = await check(chain, bind(chain, { mutate: (t) => ({ ...t, outputs: [{ lockingBytecode: other, valueSatoshis: 0n }, t.outputs[1]] }) }));
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /no Countersign data output/);
});

test("a claim that points at someone else's commitment is refused", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const thief = nostrKey();
  const claim = finalizeEvent(buildClaim(null, b.key.address, b.txid), thief.sk);
  const r = await check(chain, b, thief.npub, [claim]);
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /another Nostr key/);
});

test("a server that changes the transaction is caught by its hash", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const forged = L.encodeTransaction({ ...b.signed, locktime: 1 });
  chain.txs.set(b.txid, forged);
  const r = await check(chain, b);
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /doesn't hash to its id/);
});

test("a server that changes a parent transaction is caught by its hash", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const parentId = L.binToHex(b.signed.inputs[0].outpointTransactionHash);
  const parent = L.decodeTransaction(chain.txs.get(parentId));
  chain.txs.set(parentId, L.encodeTransaction({ ...parent, outputs: [{ ...parent.outputs[0], valueSatoshis: 99_999n }] }));
  const r = await check(chain, b);
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /doesn't hash to its id/);
});

test("the same private key for BCH and Nostr is refused", async () => {
  const chain = memoryChain();
  const key = bchKey();
  const r = await check(chain, bind(chain, { key, id: nostrKey(key.priv) }));
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /same key/);
});

test("a claim naming an address that didn't sign the commitment is refused", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const other = bchKey();
  const claim = finalizeEvent(buildClaim(null, other.address, b.txid), b.id.sk);
  const r = await check(chain, b, b.id.npub, [claim]);
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /no input is signed by this address/);
});

test("a broken signature is refused by the BCH virtual machine", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const unlock = b.signed.inputs[0].unlockingBytecode.slice();
  unlock[10] ^= 0xff; // inside the Schnorr signature, not its sighash byte
  const txid = chain.add({ ...b.signed, inputs: [{ ...b.signed.inputs[0], unlockingBytecode: unlock }] });
  chain.touch(b.key.address, txid, 899_991);
  const claim = finalizeEvent(buildClaim(null, b.key.address, txid), b.id.sk);
  const r = await check(chain, b, b.id.npub, [claim]);
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /virtual machine rejects/);
});

test("anyone can send a tagged transaction TO the address, but it can't supersede the binding", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const stranger = bchKey();
  const coin = fund(chain, stranger);
  const tx = {
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: L.hexToBin(coin.txid), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() }],
    outputs: [
      { lockingBytecode: dataOutputBytecode(nostrKey().npub), valueSatoshis: 0n },
      { lockingBytecode: b.key.lock, valueSatoshis: 546n },
      { lockingBytecode: stranger.lock, valueSatoshis: 9_000n },
    ],
  };
  const txid = chain.add(signP2pkh(tx, [{ lockingBytecode: stranger.lock, valueSatoshis: coin.satoshis }], stranger.priv));
  chain.touch(b.key.address, txid, 899_995);
  const r = await check(chain, b);
  assert.equal(r.status, "verified");
});

test("a later commitment signed by the same address supersedes the binding", async () => {
  const chain = memoryChain();
  const first = bind(chain);
  const second = bind(chain, { key: first.key, height: 899_995 });
  const r = await check(chain, first);
  assert.equal(r.status, "superseded");
  assert.deepEqual(r.supersededBy, { npub: second.id.npub, txid: second.txid });
  assert.equal((await check(chain, second)).status, "verified");
});

test("the newest commitment from the address decides: N1, then N2, then N1 again leaves N1 current, whichever commitment its claim names", async () => {
  const chain = memoryChain();
  const first = bind(chain, { height: 899_990 }); // N1
  const second = bind(chain, { key: first.key, height: 899_992 }); // N2
  const again = bind(chain, { key: first.key, id: first.id, height: 899_994 }); // N1 again, the newest
  const nostr = (...claims) => ({ fetchClaim: async (pk) => ({ claim: claims.find((c) => c.pubkey === pk) ?? null }) });
  const r1 = await verifyBinding(first.id.npub, { nostr: nostr(first.claim), chain, now: T0 + 3 * 86400 }); // its claim still names the first
  assert.equal(r1.status, "verified");
  assert.equal(r1.txid, first.txid);
  assert.equal((await verifyBinding(first.id.npub, { nostr: nostr(again.claim), chain, now: T0 + 3 * 86400 })).status, "verified");
  const r2 = await check(chain, second);
  assert.equal(r2.status, "superseded");
  assert.deepEqual(r2.supersededBy, { npub: first.id.npub, txid: again.txid });
});

/** A stranger pays the address 546 sat n times, listed in its history from `height` on. No key of the address needed. */
function strangerPays(chain, key, n, height) {
  const stranger = bchKey();
  for (let i = 0; i < n; i++) {
    const coin = fund(chain, stranger);
    const tx = {
      version: 2, locktime: 0,
      inputs: [{ outpointTransactionHash: L.hexToBin(coin.txid), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() }],
      outputs: [{ lockingBytecode: key.lock, valueSatoshis: 546n }, { lockingBytecode: stranger.lock, valueSatoshis: 9_000n }],
    };
    chain.touch(key.address, chain.add(signP2pkh(tx, [{ lockingBytecode: stranger.lock, valueSatoshis: coin.satoshis }], stranger.priv)), height + i);
  }
}

test("padding the history with payments can't hide a rotation: past 300 later transactions the binding is unchecked, never payable", async () => {
  const chain = memoryChain();
  const first = bind(chain, { height: 899_000 });
  strangerPays(chain, first.key, 40, 899_001); // before the owner rotates (the old window read 30)
  const second = bind(chain, { key: first.key, height: 899_100 });
  assert.equal((await check(chain, first)).status, "superseded");
  strangerPays(chain, first.key, 300, 899_101); // and after: the rotation is now 301st from the newest
  const r = await check(chain, first);
  assert.equal(r.status, "unchecked");
  assert.match(r.reason, /more than 300 transactions follow the commitment, so a newer binding can't be ruled out/);
  assert.equal((await check(chain, second)).status, "verified"); // exactly 300 after it: all read
  strangerPays(chain, first.key, 1, 899_401);
  assert.equal((await check(chain, second)).status, "unchecked");
});

test("a history that is unavailable, leaves out the commitment, or lists what no server returns makes the binding unchecked", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  assert.match((await check({ ...chain, getHistory: async () => { throw new Error("timeout"); } }, b)).reason, /address history is unavailable/);
  assert.match((await check({ ...chain, getHistory: async () => [] }, b)).reason, /don't list the commitment/);
  const second = bind(chain, { key: b.key, height: 899_995 });
  chain.txs.delete(L.binToHex(second.signed.inputs[0].outpointTransactionHash)); // the rotation's parent: gone
  assert.match((await check(chain, b)).reason, /later commitment's parents couldn't be read/);
  chain.touch(b.key.address, "ab".repeat(32), 899_996); // listed, never served
  const r = await check(chain, b);
  assert.equal(r.status, "unchecked");
  assert.match(r.reason, /later transaction in the address history couldn't be read/);
});

test("the history is put in height order: a server that reverses it can't swap the old and the new name", async () => {
  const chain = memoryChain();
  const first = bind(chain);
  const second = bind(chain, { key: first.key, height: 899_995 });
  const reversed = { ...chain, getHistory: async (a) => [...(await chain.getHistory(a))].reverse() };
  assert.equal((await check(reversed, first)).status, "superseded");
  assert.equal((await check(reversed, second)).status, "verified");
});

test("servers that disagree about the history leave the binding unchecked; no usable tip or header leaves its age unknown", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const split = { ...chain, getHistory: async () => { throw Object.assign(new Error("the servers disagree"), { disputed: true }); } };
  assert.match((await check(split, b)).reason, /^the servers disagree about the address history, so a newer binding can't be ruled out$/);
  for (const broken of [{ getTipHeight: async () => 10 }, { getHeader: async () => { throw new Error("timeout"); } }]) {
    const r = await check({ ...chain, ...broken }, b);
    assert.equal(r.status, "verified"); // in a block, as the history says, but shown as new
    assert.equal(r.confirmations, null);
    assert.equal(r.boundSince, null);
    assert.ok(r.warnings.includes("new"));
  }
});

test("a claim whose signature doesn't verify is refused", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const r = await check(chain, b, b.id.npub, [{ ...b.claim, content: "edited after signing" }]);
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /signature/);
});

test("the claim merges: other identities kept, one BCH address, a newer timestamp", () => {
  const now = T0;
  const current = { created_at: now + 100, content: "", tags: [["i", "github:someone", "gistid"], ["i", "bitcoincash:qold", "a".repeat(64)], ["t", "countersign"]] };
  const next = buildClaim(current, "bitcoincash:qnew", "b".repeat(64), { now });
  assert.equal(next.kind, 10011);
  assert.equal(next.created_at, now + 101);
  assert.deepEqual(next.tags, [["i", "github:someone", "gistid"], ["i", "bitcoincash:qnew", "b".repeat(64)], ["t", "countersign"]]);
});

test("unbinding keeps the other identities and drops the BCH address and the wall tag; the name then has no address", async () => {
  const now = T0;
  const current = { created_at: now + 100, content: "", tags: [["i", "github:someone", "gistid"], ["i", "bitcoincash:qold", "a".repeat(64)], ["t", "countersign"]] };
  const next = buildUnbind(current, { now });
  assert.equal(next.kind, 10011);
  assert.equal(next.created_at, now + 101);
  assert.deepEqual(next.tags, [["i", "github:someone", "gistid"]]);
  assert.deepEqual(current.tags.length, 3, "the current claim is left as it was");

  const chain = memoryChain();
  const b = bind(chain);
  assert.equal((await check(chain, b)).status, "verified");
  const after = finalizeEvent(buildUnbind(b.claim, { now: b.claim.created_at }), b.id.sk);
  const r = await check(chain, b, b.id.npub, [after]);
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /names no BCH address/);
  assert.equal(onWall(after), false);
});

test("the data output fits the 223-byte limit and reads back", () => {
  const { npub, pk } = nostrKey();
  const bytecode = dataOutputBytecode(npub);
  assert.ok(bytecode.length <= 223, `${bytecode.length} bytes`);
  assert.deepEqual(bytecode.slice(1, 6), L.flattenBinArray([Uint8Array.of(0x04), TAG]));
  assert.deepEqual(readCommitment({ outputs: [{ lockingBytecode: bytecode, valueSatoshis: 0n }] }), { npub, pubkey: pk });
});

test("malformed data outputs are refused", () => {
  const { npub } = nostrKey();
  const out = (...pushes) => ({ outputs: [{ lockingBytecode: L.flattenBinArray([Uint8Array.of(0x6a), ...pushes.map((p) => L.encodeDataPush(p))]), valueSatoshis: 0n }] });
  assert.match(readCommitment(out(TAG, L.utf8ToBin(NIP39_WORDING + npub), Uint8Array.of(1))).error, /malformed/);
  assert.match(readCommitment(out(TAG, L.utf8ToBin("Hi, I am " + npub))).error, /NIP-39 wording/);
  assert.match(readCommitment(out(TAG, L.utf8ToBin(NIP39_WORDING + "npub1notakey"))).error, /no valid npub/);
});

test("the builder never spends a coin that carries tokens", () => {
  const key = bchKey();
  const { npub } = nostrKey();
  const plain = { tx_hash: "11".repeat(32), tx_pos: 0, value: 5_000 };
  const token = { tx_hash: "22".repeat(32), tx_pos: 1, value: 1_000_000, token_data: { category: "33".repeat(32), amount: "100" } };
  const { transaction } = buildCommitment({ address: key.address, npub, coins: [token, plain] });
  assert.deepEqual(transaction.inputs.map((i) => L.binToHex(i.outpointTransactionHash)), [plain.tx_hash]);
  assert.throws(() => buildCommitment({ address: key.address, npub, coins: [token] }), /not enough coins/);
});

const discoverer = (claims, { relaysIndex = true } = {}) => ({
  ...nostrOf(...claims),
  claimsFor: async (address) => (relaysIndex ? claims.filter((c) => c.tags.some((t) => t[0] === "i" && t[1] === address)) : []),
});

test("discovery by address: found through the relays and through the chain alone", async () => {
  const chain = memoryChain();
  const b = bind(chain);
  const both = await findByAddress(b.key.address, { nostr: discoverer([b.claim]), chain, now: T0 + 3 * 86400 });
  assert.equal(both.status, "verified");
  assert.equal(both.npub, b.id.npub);
  assert.deepEqual(both.via.sort(), ["chain", "relays"]);
  const chainOnly = await findByAddress(b.key.address, { nostr: discoverer([b.claim], { relaysIndex: false }), chain, now: T0 + 3 * 86400 });
  assert.equal(chainOnly.npub, b.id.npub);
  assert.deepEqual(chainOnly.via, ["chain"]);
  assert.equal(await findByAddress(bchKey().address, { nostr: discoverer([]), chain }), null);
});

test("discovery by address: a rebound address gives its newest name, a stranger's tagged transaction gives none", async () => {
  const chain = memoryChain();
  const first = bind(chain, { height: 899_990 });
  const second = bind(chain, { key: first.key, height: 899_995 });
  const stranger = bchKey(), strangerId = nostrKey();
  const coin = fund(chain, stranger);
  const tx = {
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: L.hexToBin(coin.txid), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() }],
    outputs: [
      { lockingBytecode: dataOutputBytecode(strangerId.npub), valueSatoshis: 0n },
      { lockingBytecode: first.key.lock, valueSatoshis: 546n },
      { lockingBytecode: stranger.lock, valueSatoshis: 9_000n },
    ],
  };
  const txid = chain.add(signP2pkh(tx, [{ lockingBytecode: stranger.lock, valueSatoshis: coin.satoshis }], stranger.priv));
  chain.touch(first.key.address, txid, 899_998);
  const strangerClaim = finalizeEvent(buildClaim(null, first.key.address, txid), strangerId.sk);
  const r = await findByAddress(first.key.address, { nostr: discoverer([first.claim, second.claim, strangerClaim]), chain, now: T0 + 3 * 86400 });
  assert.equal(r.status, "verified");
  assert.equal(r.npub, second.id.npub);
});

test("discovery by address: a stranger's tagged payment to an unbound address names no one, through either road", async () => {
  const chain = memoryChain();
  const victim = bchKey(), stranger = bchKey(), strangerId = nostrKey();
  const coin = fund(chain, stranger);
  const tx = {
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: L.hexToBin(coin.txid), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() }],
    outputs: [
      { lockingBytecode: dataOutputBytecode(strangerId.npub), valueSatoshis: 0n },
      { lockingBytecode: victim.lock, valueSatoshis: 546n },
      { lockingBytecode: stranger.lock, valueSatoshis: 9_000n },
    ],
  };
  const txid = chain.add(signP2pkh(tx, [{ lockingBytecode: stranger.lock, valueSatoshis: coin.satoshis }], stranger.priv));
  chain.touch(victim.address, txid, 899_995);
  const strangerClaim = finalizeEvent(buildClaim(null, victim.address, txid), strangerId.sk);
  for (const claims of [[], [strangerClaim]]) { // the chain road alone, then both roads
    assert.equal(await findByAddress(victim.address, { nostr: discoverer(claims), chain, now: T0 + 3 * 86400 }), null);
  }
});


test("the wall lists a name only while its newest claim keeps the tag and its binding verifies", async () => {
  const chain = memoryChain();
  const listed = bind(chain); // bound through the page: listed by default
  const hidden = bind(chain); // chose not to be listed
  const unlisted = finalizeEvent(buildClaim(null, hidden.key.address, hidden.txid, { wall: false }), hidden.id.sk);
  const left = bind(chain); // listed once, then left the wall
  const leftNow = finalizeEvent(buildClaim(left.claim, left.key.address, left.txid, { wall: false }), left.id.sk);
  const stranger = bind(chain); // a tagged claim pointing at someone else's commitment
  const forged = finalizeEvent(buildClaim(null, stranger.key.address, listed.txid), nostrKey().sk);
  const nostr = {
    wallClaims: async () => [listed.claim, unlisted, left.claim, forged].filter(onWall),
    fetchClaim: async (pk) => ({ claim: [listed.claim, unlisted, leftNow, forged].find((c) => c.pubkey === pk) ?? null }),
  };
  assert.equal(onWall(unlisted), false);
  const seen = [];
  const rows = await listWall({ nostr, chain, now: T0 + 3 * 86400, onRow: (r) => seen.push(r.npub) });
  assert.deepEqual(seen, [listed.id.npub]);
  assert.deepEqual(rows.map((r) => r.npub), [listed.id.npub]);
  assert.equal(rows[0].status, "verified");
  assert.equal(rows[0].address, listed.key.address);
});

test("junk tagged claims can't empty the wall: it keeps looking, and claims dated in the future are ignored", async () => {
  const chain = memoryChain();
  const real = bind(chain);
  const junk = (n, at) => Array.from({ length: n }, (_, i) => finalizeEvent(buildClaim(null, bchKey().address, "ab".repeat(32), { now: at + i }), nostrKey().sk));
  const all = [real.claim, ...junk(40, real.claim.created_at + 1), ...junk(5, real.claim.created_at + 100_000)]; // newer, and far ahead
  const nostr = { wallClaims: async () => all, fetchClaim: async (pk) => ({ claim: all.find((c) => c.pubkey === pk) ?? null }) };
  assert.deepEqual((await listWall({ nostr, chain, now: T0 + 3 * 86400 })).map((r) => r.npub), [real.id.npub]);
  const more = [bind(chain), bind(chain)];
  all.push(...more.map((b) => b.claim));
  assert.equal((await listWall({ nostr, chain, now: T0 + 3 * 86400, limit: 2 })).length, 2); // stops once the wall is full
});
