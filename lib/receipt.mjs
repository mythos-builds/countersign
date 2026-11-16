// Payment receipts (spec §8.3): after paying a name, the payer may post a public note that points at the payment by its
// transaction id (NIP-73). Anyone can post such a note about anyone's payment, so the chain decides what a note is worth:
// the transaction must pay the payee's bound address, and the payer is proven only when their own bound address signed it.
import * as L from "@bitauth/libauth";
import { nip19 } from "nostr-tools";
import { npubToHex, decodeP2pkhAddress } from "./commitment.mjs";
import { verifiedCopy } from "./nostr.mjs";
import { formatBch, paidTo } from "./pay.mjs";
import { verifyBinding, getVerifiedTx, addressSigned } from "./verify.mjs";

export const RECEIPT_KIND = 1; // a plain note: every client shows it, and the payee is notified through its `p` tag
export const RECEIPT_TAG = "countersign"; // the hashtag the wall's claims carry too (§7); the kinds keep them apart
export const TX_KIND = "bitcoincash:tx"; // NIP-73 names no blockchain for BCH: the word of its URI scheme and addresses
export const txIdentity = (txid) => `${TX_KIND}:${txid}`;
export const explorerUrl = (txid) => `https://blockchair.com/bitcoin-cash/transaction/${txid}`;
const TX_IDENTITY = /^bitcoincash:tx:([0-9a-f]{64})$/;

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The note a payer signs after paying: payee = their npub, sats = what the transaction paid them,
 * link = where others can pay them too (optional). Tags: `p` payee, `i` + `k` the transaction (NIP-73), `t` countersign.
 */
export function receiptTemplate({ payee, txid, sats, link, now = Math.floor(Date.now() / 1000) }) {
  const pubkey = npubToHex(payee);
  if (!/^[0-9a-f]{64}$/.test(txid ?? "")) throw new Error("not a transaction id");
  const lines = [`Paid nostr:${payee} ${formatBch(sats)} BCH on chain with Countersign.`, explorerUrl(txid)];
  if (link) lines.push(`Pay them too: ${link}`);
  return {
    kind: RECEIPT_KIND,
    created_at: now,
    tags: [["p", pubkey], ["i", txIdentity(txid), explorerUrl(txid)], ["k", TX_KIND], ["t", RECEIPT_TAG]],
    content: lines.join("\n"),
  };
}

/** A receipt's own form, signature checked on a fresh copy: → { event, txid, payees } or { error }. Nothing fetched. */
export function readReceipt(note) {
  const event = verifiedCopy(note);
  if (!event) return { error: "the note's signature doesn't verify" };
  if (event.kind !== RECEIPT_KIND) return { error: `a kind ${event.kind} event, not a note` };
  if (!event.tags.some((t) => t[0] === "t" && t[1] === RECEIPT_TAG)) return { error: "not a Countersign receipt" };
  const txids = [...new Set(event.tags.filter((t) => t[0] === "i").map((t) => TX_IDENTITY.exec(t[1] ?? "")?.[1]).filter(Boolean))];
  if (txids.length !== 1) return { error: txids.length ? "the note names more than one transaction" : "the note names no BCH transaction" };
  const payees = event.tags.filter((t) => t[0] === "p" && /^[0-9a-f]{64}$/.test(t[1] ?? "")).map((t) => t[1]);
  return { event, txid: txids[0], payees };
}

/** Does an input carry a public key of this address? A P2PKH unlock is <signature> <public key>; nothing is fetched. */
const keyOf = (tx, payload) =>
  tx.inputs.some((input) => {
    const ins = L.decodeAuthenticationInstructions(input.unlockingBytecode);
    return ins.length === 2 && !ins.some((i) => i.malformed || !i.data) && eq(L.hash160(ins[1].data), payload);
  });

/**
 * What one receipt is worth. payee = { pubkey, address } from the payee's verified binding; chain = fulcrumChain();
 * payerBinding(pubkey) → verifyBinding's result for the note's author (listReceipts shares one per author);
 * heights = Map(txid → height) of the payee's address history, when the caller has it.
 * → { txid, sats, pubkey, npub, proof, eventId, created_at, height } or { error }.
 * proof: "bound" = the author's own bound address signed the payment over every output; "claim" = the author says so.
 */
export async function verifyReceipt(note, { payee, chain, payerBinding, heights }) {
  const r = readReceipt(note);
  if (r.error) return r;
  const { event, txid } = r;
  if (!r.payees.includes(payee.pubkey)) return { error: "the note doesn't tag this payee" };
  if (event.pubkey === payee.pubkey) return { error: "a note from the payee itself" };
  if (heights && !heights.has(txid)) return { error: "the transaction isn't in the payee's address history" };
  let tx;
  try { tx = await getVerifiedTx(chain, txid); } catch (e) { return { error: e.message }; }
  // The payee's own spend can send change back to its address: that is no payment.
  if (keyOf(tx, decodeP2pkhAddress(payee.address).payload)) return { error: "the payee's own transaction (it spends from the payee's address)" };
  const sats = paidTo(tx, payee.address);
  if (sats <= 0n) return { error: "the transaction pays nothing to the payee's address" };
  const found = { txid, sats, pubkey: event.pubkey, npub: nip19.npubEncode(event.pubkey), eventId: event.id, created_at: event.created_at, height: heights?.get(txid) ?? null };
  const b = await Promise.resolve(payerBinding?.(event.pubkey)).catch(() => null);
  if (b && (b.status === "verified" || b.status === "pending")) {
    const { payload } = decodeP2pkhAddress(b.address);
    if (keyOf(tx, payload)) {
      const signed = await addressSigned(chain, tx, payload).catch((e) => ({ error: e.message }));
      if (!signed.error) return { ...found, proof: "bound", address: b.address };
    }
  }
  return { ...found, proof: "claim" };
}

/**
 * Receipts for payments to a bound name, newest payment first (mempool, then by block height). One row per transaction:
 * a proven payer wins over a claim, and between claims the earliest note. Every note naming the transaction is checked (one
 * binding check per author, one fetch per transaction): dated notes are the author's word, so none can push a proven one out.
 * payee = { pubkey, address } from its verified binding,
 * nostr = relayReader() (mentions, fetchClaim), chain = fulcrumChain(). onRow(row, rank) fires as each row passes.
 */
export async function listReceipts({ payee, nostr, chain, limit = 20, parallel = 4, now, onRow }) {
  const [notes, history] = await Promise.all([nostr.mentions(payee.pubkey, RECEIPT_TAG, { limit: 200 }), chain.getHistory(payee.address)]);
  const heights = new Map(history.map((h) => [h.tx_hash, h.height]));
  const txs = new Map(); // one fetch per transaction, however many notes name it
  const reader = { ...chain, getTx: (id) => { if (!txs.has(id)) txs.set(id, chain.getTx(id)); return txs.get(id); } };
  const byTx = new Map();
  for (const note of notes) {
    const r = readReceipt(note);
    if (r.error || !heights.has(r.txid) || !r.payees.includes(payee.pubkey)) continue;
    if (!byTx.has(r.txid)) byTx.set(r.txid, []);
    byTx.get(r.txid).push(r.event);
  }
  const rank = (txid) => (heights.get(txid) > 0 ? heights.get(txid) : Infinity); // unconfirmed (0, or −1 with an unconfirmed parent) first
  const txids = [...byTx.keys()].sort((a, b) => (rank(a) === rank(b) ? 0 : rank(a) < rank(b) ? 1 : -1)).slice(0, limit);
  const bindings = new Map(); // one binding check per author
  const payerBinding = (pubkey) => {
    if (!bindings.has(pubkey)) bindings.set(pubkey, verifyBinding(nip19.npubEncode(pubkey), { nostr, chain: reader, ...(now ? { now } : {}) }));
    return bindings.get(pubkey);
  };
  const rows = new Array(txids.length);
  let next = 0;
  async function worker() {
    while (next < txids.length) {
      const i = next++;
      const notes = byTx.get(txids[i]).sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : 1));
      let best = null;
      for (const note of notes) {
        const v = await verifyReceipt(note, { payee, chain: reader, payerBinding, heights }).catch((e) => ({ error: e.message }));
        if (v.error) continue;
        if (v.proof === "bound") { best = v; break; }
        best ??= v;
      }
      if (best) { rows[i] = best; onRow?.(best, i); }
    }
  }
  await Promise.all(Array.from({ length: Math.min(parallel, txids.length) }, worker));
  return rows.filter(Boolean);
}
