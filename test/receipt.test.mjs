// Offline tests for payment receipts (spec §8.3): signed notes, synthetic payments with real signatures, an in-memory chain.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as L from "@bitauth/libauth";
import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from "nostr-tools";
import {
  buildCommitment, buildClaim, buildPayment, signP2pkh, verifyBinding, receiptTemplate, readReceipt, verifyReceipt, listReceipts,
  txIdentity, explorerUrl, RECEIPT_TAG, TX_KIND,
} from "../lib/index.mjs";

const T0 = 1_700_000_000; // block time of every synthetic header
const NOW = T0 + 3 * 86400;
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

function bchKey() {
  let priv;
  do { priv = rand(32); } while (!L.secp256k1.validatePrivateKey(priv));
  const pub = L.secp256k1.derivePublicKeyCompressed(priv);
  const enc = L.encodeCashAddress({ prefix: "bitcoincash", type: "p2pkh", payload: L.hash160(pub) });
  return { priv, pub, lock: L.encodeLockingBytecodeP2pkh(L.hash160(pub)), address: typeof enc === "string" ? enc : enc.address };
}

function nostrKey(sk = generateSecretKey()) {
  const pk = getPublicKey(sk);
  return { sk, pk, npub: nip19.npubEncode(pk) };
}

function memoryChain({ tip = 900_000 } = {}) {
  const txs = new Map(), history = new Map();
  return {
    add(tx) { const raw = L.encodeTransaction(tx); const txid = L.hashTransaction(raw); txs.set(txid, raw); return txid; },
    touch(address, txid, height) { if (!history.has(address)) history.set(address, []); history.get(address).push({ tx_hash: txid, height }); },
    getTx: async (id) => { if (!txs.has(id)) throw new Error("not found"); return txs.get(id); },
    getHistory: async (address) => history.get(address) ?? [],
    getTipHeight: async () => tip,
    getHeader: async () => { const h = new Uint8Array(80); new DataView(h.buffer).setUint32(68, T0, true); return h; },
  };
}

/** A coin from nowhere (its parent's own input is made up, as no verifier fetches grandparents). */
function fund(chain, key, sats = 10_000n) {
  const txid = chain.add({
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: rand(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.of(0x51) }],
    outputs: [{ lockingBytecode: key.lock, valueSatoshis: sats }],
  });
  return { txid, vout: 0, satoshis: sats, lockingBytecode: key.lock, path: ["receive", 0] };
}

/** A mined binding; its commitment's change (output 1) stays at the bound address as a coin to pay with. */
function bind(chain) {
  const key = bchKey(), id = nostrKey();
  const { transaction, sourceOutputs } = buildCommitment({ address: key.address, npub: id.npub, coins: [fund(chain, key)] });
  const signed = signP2pkh(transaction, sourceOutputs, key.priv);
  const txid = chain.add(signed);
  chain.touch(key.address, txid, 899_990);
  const coin = { txid, vout: 1, satoshis: signed.outputs[1].valueSatoshis, lockingBytecode: key.lock, path: ["receive", 0] };
  return { key, id, txid, coin, claim: finalizeEvent(buildClaim(null, key.address, txid), id.sk) };
}

/** from pays `to` from these coins; the transaction lands in both address histories at `height` (0 = mempool). */
function pay(chain, from, coins, to, sats, { height = 899_995, sighash = 0x41 } = {}) {
  const p = buildPayment({ coins, to, satoshis: sats, changeLockingBytecode: from.lock });
  const txid = chain.add(signP2pkh(p.transaction, p.sourceOutputs, from.priv, sighash));
  chain.touch(to, txid, height);
  chain.touch(from.address, txid, height);
  return txid;
}

const receipt = (id, payee, txid, sats, extra = {}) => finalizeEvent({ ...receiptTemplate({ payee: payee.id.npub, txid, sats, now: NOW }), ...extra }, id.sk);

/** Relays as a list of notes and claims: mentions() filters like a relay would, by `p` and `t` tags. */
const relaysOf = (notes, claims) => ({
  mentions: async (pk, tag) => notes.filter((n) => n.tags.some((t) => t[0] === "p" && t[1] === pk) && n.tags.some((t) => t[0] === "t" && t[1] === tag)),
  fetchClaim: async (pk) => ({ claim: claims.find((c) => c.pubkey === pk) ?? null }),
});
const bindingOf = (chain, claims) => (pk) => verifyBinding(nip19.npubEncode(pk), { nostr: relaysOf([], claims), chain, now: NOW });
const target = (b) => ({ pubkey: b.id.pk, address: b.key.address });

test("a receipt tags the payee, the transaction (NIP-73) and the hashtag, and reads back", () => {
  const payee = { id: nostrKey() };
  const txid = "ab".repeat(32);
  const t = receiptTemplate({ payee: payee.id.npub, txid, sats: 10_000n, link: "https://example.org/#/x", now: NOW });
  assert.equal(t.kind, 1);
  assert.deepEqual(t.tags, [["p", payee.id.pk], ["i", `bitcoincash:tx:${txid}`, explorerUrl(txid)], ["k", "bitcoincash:tx"], ["t", "countersign"]]);
  assert.equal(txIdentity(txid), `${TX_KIND}:${txid}`);
  assert.equal(t.content, `Paid nostr:${payee.id.npub} 0.0001 BCH on chain with Countersign.\n${explorerUrl(txid)}\nPay them too: https://example.org/#/x`);
  const r = readReceipt(finalizeEvent(t, nostrKey().sk));
  assert.equal(r.txid, txid);
  assert.deepEqual(r.payees, [payee.id.pk]);
  assert.throws(() => receiptTemplate({ payee: payee.id.npub, txid: "xyz", sats: 1n }), /not a transaction id/);
  assert.throws(() => receiptTemplate({ payee: "npub1nope", txid, sats: 1n }));
});

test("a payment signed by the payer's own bound address is proven; from another address it is only a claim", async () => {
  const chain = memoryChain();
  const payee = bind(chain), payer = bind(chain);
  const claims = [payee.claim, payer.claim];
  const fromBound = pay(chain, payer.key, [payer.coin], payee.key.address, 2_000n);
  const v = await verifyReceipt(receipt(payer.id, payee, fromBound, 2_000n), { payee: target(payee), chain, payerBinding: bindingOf(chain, claims) });
  assert.equal(v.proof, "bound");
  assert.equal(v.sats, 2_000n);
  assert.equal(v.npub, payer.id.npub);
  assert.equal(v.address, payer.key.address);

  const other = bchKey();
  const fromOther = pay(chain, other, [fund(chain, other)], payee.key.address, 3_000n);
  const c = await verifyReceipt(receipt(payer.id, payee, fromOther, 3_000n), { payee: target(payee), chain, payerBinding: bindingOf(chain, claims) });
  assert.equal(c.proof, "claim");
  assert.equal(c.sats, 3_000n);
});

test("the amount comes from the chain, never from the note", async () => {
  const chain = memoryChain();
  const payee = bind(chain), payer = bind(chain);
  const txid = pay(chain, payer.key, [payer.coin], payee.key.address, 1_000n);
  const boast = receipt(payer.id, payee, txid, 1_000n, { content: "Paid 5 BCH!" });
  const v = await verifyReceipt(boast, { payee: target(payee), chain, payerBinding: bindingOf(chain, [payer.claim]) });
  assert.equal(v.sats, 1_000n);
});

test("a bound address that signs without covering every output proves nothing", async () => {
  const chain = memoryChain();
  const payee = bind(chain), payer = bind(chain);
  const txid = pay(chain, payer.key, [payer.coin], payee.key.address, 2_000n, { sighash: 0x42 }); // NONE|FORKID: outputs not signed
  const v = await verifyReceipt(receipt(payer.id, payee, txid, 2_000n), { payee: target(payee), chain, payerBinding: bindingOf(chain, [payer.claim]) });
  assert.equal(v.proof, "claim");
});

test("refused: no payment to the payee, the payee's own change, the wrong payee, the payee itself, edits, odd forms", async () => {
  const chain = memoryChain();
  const payee = bind(chain), payer = bind(chain), elsewhere = bind(chain);
  const opts = { payee: target(payee), chain, payerBinding: bindingOf(chain, [payer.claim]) };
  const elsewhereTx = pay(chain, payer.key, [payer.coin], elsewhere.key.address, 2_000n);
  assert.match((await verifyReceipt(receipt(payer.id, payee, elsewhereTx, 2_000n), opts)).error, /pays nothing to the payee/);
  // The payee's commitment sends its change back to the payee's own address: not a payment.
  assert.match((await verifyReceipt(receipt(payer.id, payee, payee.txid, 9_000n), opts)).error, /payee's own transaction/);

  const stranger = bchKey();
  const txid = pay(chain, stranger, [fund(chain, stranger)], payee.key.address, 1_000n);
  const good = receipt(payer.id, payee, txid, 1_000n);
  assert.equal((await verifyReceipt(good, opts)).proof, "claim");
  assert.match((await verifyReceipt(receipt(payer.id, elsewhere, txid, 1_000n), opts)).error, /doesn't tag this payee/);
  assert.match((await verifyReceipt(receipt(payee.id, payee, txid, 1_000n), opts)).error, /from the payee itself/);
  // nostr-tools marks signed objects as verified and a spread copies the mark: the check runs on a fresh copy.
  const swapped = { ...good, tags: good.tags.map((t) => (t[0] === "i" ? ["i", txIdentity(elsewhereTx)] : t)) };
  assert.match((await verifyReceipt(swapped, opts)).error, /signature doesn't verify/);
  const two = receipt(payer.id, payee, txid, 1_000n, { tags: [...good.tags, ["i", txIdentity(elsewhereTx)]] });
  assert.match((await verifyReceipt(two, opts)).error, /more than one transaction/);
  const none = receipt(payer.id, payee, txid, 1_000n, { tags: good.tags.filter((t) => t[0] !== "i") });
  assert.match((await verifyReceipt(none, opts)).error, /names no BCH transaction/);
  const untagged = receipt(payer.id, payee, txid, 1_000n, { tags: good.tags.filter((t) => t[0] !== "t") });
  assert.match((await verifyReceipt(untagged, opts)).error, /not a Countersign receipt/);
  const otherKind = receipt(payer.id, payee, txid, 1_000n, { kind: 1111 });
  assert.match((await verifyReceipt(otherKind, opts)).error, /not a note/);
  assert.match((await verifyReceipt(receipt(payer.id, payee, "cd".repeat(32), 1_000n), opts)).error, /not found|no server/);
  assert.match((await verifyReceipt(good, { ...opts, heights: new Map() })).error, /isn't in the payee's address history/);
});

test("the list: one row per payment, newest first, a proven payer over earlier claims, nothing outside the history", async () => {
  const chain = memoryChain();
  const payee = bind(chain), payer = bind(chain), copycat = nostrKey();
  const stranger = bchKey();
  const older = pay(chain, stranger, [fund(chain, stranger)], payee.key.address, 1_000n, { height: 899_991 });
  const proven = pay(chain, payer.key, [payer.coin], payee.key.address, 2_000n, { height: 899_993 });
  const fresh = pay(chain, stranger, [fund(chain, stranger)], payee.key.address, 3_000n, { height: 0 });
  const unseen = bchKey();
  const offList = pay(chain, unseen, [fund(chain, unseen)], bchKey().address, 4_000n); // pays someone else entirely
  const at = (n, extra = {}) => ({ created_at: NOW + n, ...extra });
  const notes = [
    receipt(copycat, payee, proven, 2_000n, at(-60)), // claims it first
    receipt(payer.id, payee, proven, 2_000n, at(0)), // the payer, proven by the bound address
    receipt(payer.id, payee, older, 1_000n, at(5)), // a claim on a stranger's payment
    receipt(copycat, payee, older, 1_000n, at(9)), // a later claim on the same one
    receipt(copycat, payee, fresh, 3_000n, at(20)),
    receipt(copycat, payee, offList, 4_000n, at(30)),
  ];
  const seen = [];
  const rows = await listReceipts({
    payee: target(payee), nostr: relaysOf(notes, [payee.claim, payer.claim]), chain, now: NOW, onRow: (r) => seen.push(r.txid),
  });
  assert.deepEqual(rows.map((r) => [r.txid, r.npub, r.proof, r.sats]), [
    [fresh, copycat.npub, "claim", 3_000n],
    [proven, payer.id.npub, "bound", 2_000n],
    [older, payer.id.npub, "claim", 1_000n],
  ]);
  assert.deepEqual(rows.map((r) => r.height), [0, 899_993, 899_991]);
  assert.deepEqual(seen.sort(), [fresh, proven, older].sort());
  assert.deepEqual(await listReceipts({ payee: target(payee), nostr: relaysOf([], []), chain }), []);
});
