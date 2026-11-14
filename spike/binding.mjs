// Nostr half of the identity proof, offline (throwaway, nothing published):
// the BCH key signs a tx whose OP_RETURN carries the Nostr pubkey; the Nostr key signs an event
// carrying the BCH address + that txid. A verifier checks both directions, then a challenge-response
// login with the Nostr key. Negative cases must all fail.
import * as L from "@bitauth/libauth";
import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from "nostr-tools/pure";
import * as nip19 from "nostr-tools/nip19";

const ok = (x, what) => { if (typeof x === "string") throw new Error(`${what}: ${x}`); return x; };
const cat = (...a) => L.flattenBinArray(a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x))));
const utf8 = (s) => new TextEncoder().encode(s);
const hex = L.binToHex;
// NIP-39: the tx carries the standard verification text; the event is kind 10011 with an `i` tag
const proofText = (npubHex) => `Verifying that I control the following Nostr public key: ${nip19.npubEncode(npubHex)}`;
const opReturn = (npubHex) => cat([0x6a], L.encodeDataPush(utf8(proofText(npubHex))));
const bare = (addr) => addr.split(":").pop();

// ── BCH side: a key, its address, a signed commitment tx (fake input: offline) ──
function bchCommit(bchPriv, nostrPubHex) {
  const pub = ok(L.secp256k1.derivePublicKeyCompressed(bchPriv), "pub");
  const lock = L.encodeLockingBytecodeP2pkh(L.hash160(pub));
  const fake = L.generateRandomBytes(32);
  const sourceOutputs = [{ lockingBytecode: lock, valueSatoshis: 10_000n }];
  const tx = {
    version: 2, locktime: 0,
    inputs: [{ outpointIndex: 0, outpointTransactionHash: fake, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() }],
    outputs: [
      { lockingBytecode: opReturn(nostrPubHex), valueSatoshis: 0n },
      { lockingBytecode: lock, valueSatoshis: 9_700n },
    ],
  };
  const pre = L.generateSigningSerializationBch({ inputIndex: 0, sourceOutputs, transaction: tx }, { coveredBytecode: lock, signingSerializationType: Uint8Array.of(0x41) });
  const sig = ok(L.secp256k1.signMessageHashSchnorr(bchPriv, L.sha256.hash(L.sha256.hash(pre))), "sign");
  tx.inputs[0].unlockingBytecode = cat(L.encodeDataPush(cat(sig, [0x41])), L.encodeDataPush(pub));
  const txHex = hex(L.encodeTransaction(tx));
  const h = L.hashTransaction(L.hexToBin(txHex));
  const address = ok(L.encodeCashAddress({ prefix: "bitcoincash", type: "p2pkh", payload: L.hash160(pub) }), "addr");
  return { txHex, txid: typeof h === "string" ? h : hex(h), sourceOutputs, address: typeof address === "string" ? address : address.address };
}

// ── Nostr side: the binding event (NIP-39 identity claim, kind 10011) ──
const bindingEvent = (nsec, address, txid) => finalizeEvent({
  kind: 10011, created_at: Math.floor(Date.now() / 1000), content: "",
  tags: [["i", `bch:${bare(address)}`, txid]],
}, nsec);

// ── verifier: both directions, no secret needed ──
// nostr-tools caches « verified » on the event object (a symbol that object spread copies along):
// verify a fresh copy parsed from JSON, never the object you were handed
const fresh = (e) => JSON.parse(JSON.stringify(e));

function verifyBinding(event, txHex, sourceOutputs) {
  event = fresh(event);
  if (!verifyEvent(event)) return "nostr signature invalid";
  const claim = event.tags.find((t) => t[0] === "i" && t[1]?.startsWith("bch:"));
  const address = claim && `bitcoincash:${claim[1].slice(4)}`, txid = claim?.[2];
  if (!address || !txid) return "binding tags missing";
  const h = L.hashTransaction(L.hexToBin(txHex));
  if ((typeof h === "string" ? h : hex(h)) !== txid) return "tx does not match the claimed txid";
  const tx = L.decodeTransaction(L.hexToBin(txHex));
  if (typeof tx === "string") return `bad tx: ${tx}`;
  const want = hex(opReturn(event.pubkey));
  if (!tx.outputs.some((o) => hex(o.lockingBytecode) === want)) return "tx does not commit to this Nostr key";
  const dec = L.decodeCashAddress(address);
  if (typeof dec === "string") return `bad address: ${dec}`;
  const lock = hex(L.encodeLockingBytecodeP2pkh(dec.payload));
  if (!sourceOutputs.some((s) => hex(s.lockingBytecode) === lock)) return "no input spends from the claimed address";
  const vm = L.createVirtualMachineBch().verify({ sourceOutputs, transaction: tx }); // on chain: confirmation does this
  if (vm !== true) return `tx signatures invalid: ${vm}`;
  return true;
}

// ── challenge-response login with the Nostr key (NIP-42 style) ──
const used = new Set();
const challenge = () => hex(L.generateRandomBytes(16));
const answer = (nsec, nonce, domain) => finalizeEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000), content: "", tags: [["challenge", nonce], ["domain", domain]] }, nsec);
function login(ev, nonce, domain, bindings) {
  ev = fresh(ev);
  if (!verifyEvent(ev) || ev.kind !== 22242) return "bad signature or kind";
  const tag = (k) => ev.tags.find((t) => t[0] === k)?.[1];
  if (tag("challenge") !== nonce || used.has(nonce)) return "wrong or replayed challenge";
  if (tag("domain") !== domain) return "wrong domain";
  if (Math.abs(Date.now() / 1000 - ev.created_at) > 60) return "stale";
  used.add(nonce);
  const b = bindings.get(ev.pubkey);
  return b ? `logged in as ${b}` : "no binding for this key";
}

// ── run ──
let pass = 0, fail = 0;
const expect = (label, got, want) => {
  const good = want === true ? got === true : typeof got === "string" && got.includes(want);
  good ? pass++ : fail++;
  console.log(`${good ? "ok  " : "FAIL"} ${label.padEnd(44)} ${got === true ? "true" : got}`);
};
const nsec = generateSecretKey(), npubHex = getPublicKey(nsec);
const bchPriv = L.generateRandomBytes(32);
const c = bchCommit(bchPriv, npubHex);
const ev = bindingEvent(nsec, c.address, c.txid);
console.log(`npub ${nip19.npubEncode(npubHex).slice(0, 20)}… ↔ ${c.address.slice(0, 26)}… · tx ${c.txHex.length / 2} B · event ${JSON.stringify(ev).length} B`);

expect("valid binding", verifyBinding(ev, c.txHex, c.sourceOutputs), true);
const other = generateSecretKey();
expect("event signed by another Nostr key", verifyBinding(bindingEvent(other, c.address, c.txid), c.txHex, c.sourceOutputs), "does not commit");
expect("address tag swapped for someone else's", verifyBinding(bindingEvent(nsec, bchCommit(L.generateRandomBytes(32), npubHex).address, c.txid), c.txHex, c.sourceOutputs), "claimed address");
const c2 = bchCommit(bchPriv, getPublicKey(other));
expect("tx commits to a different npub", verifyBinding(bindingEvent(nsec, c.address, c2.txid), c2.txHex, c2.sourceOutputs), "does not commit");
expect("txid tag does not match the tx", verifyBinding(bindingEvent(nsec, c.address, c2.txid), c.txHex, c.sourceOutputs), "claimed txid");
const forged = { ...ev, tags: [["i", `bch:${bare(bchCommit(L.generateRandomBytes(32), npubHex).address)}`, c.txid]] }; // spread copies the « verified » flag too
expect("event edited after signing", verifyBinding(forged, c.txHex, c.sourceOutputs), "nostr signature invalid");

const bindings = new Map([[npubHex, c.address]]);
const n1 = challenge();
expect("login with the bound key", login(answer(nsec, n1, "demo.app"), n1, "demo.app", bindings), "logged in as bitcoincash:");
expect("same answer replayed", login(answer(nsec, n1, "demo.app"), n1, "demo.app", bindings), "replayed");
const n2 = challenge();
expect("answer made for another site", login(answer(nsec, n2, "evil.app"), n2, "demo.app", bindings), "wrong domain");
const n3 = challenge();
expect("unbound key", login(answer(other, n3, "demo.app"), n3, "demo.app", bindings), "no binding");
console.log(`--- ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
