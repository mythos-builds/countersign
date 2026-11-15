// verifyBinding (spec §5): trusts nothing it is handed. Relays and Fulcrum servers are readers that can
// hide data, never forge it: event signatures, transaction hashes and the BCH virtual machine decide.
import * as L from "@bitauth/libauth";
import { npubToHex, decodeP2pkhAddress, readCommitment, findSigningInput, sameAddress, MAX_INPUTS } from "./commitment.mjs";
import { claimedAddresses, verifiedCopy, CLAIM_KIND } from "./nostr.mjs";
import { headerTime } from "./fulcrum.mjs";

const NEW_FOR = 24 * 3600;
const MAX_LATER = 30; // later transactions checked for a superseding commitment

/** A transaction by id from the chain reader, re-hashed against its id, decoded. */
export async function getVerifiedTx(chain, txid) {
  const raw = await chain.getTx(txid);
  if (L.hashTransaction(raw) !== txid) throw new Error(`transaction ${txid.slice(0, 12)}… doesn't hash to its id`);
  const tx = L.decodeTransaction(raw);
  if (typeof tx === "string") throw new Error(`transaction ${txid.slice(0, 12)}… doesn't decode: ${tx}`);
  return tx;
}

/**
 * The input this address signed over every output, in a transaction the BCH virtual machine accepts with its parents'
 * outputs, each parent fetched and re-hashed (spec §5.5–5.6). → { index, publicKey } or { error }.
 */
export async function addressSigned(chain, tx, payload) {
  if (tx.inputs.length > MAX_INPUTS) return { error: `more than ${MAX_INPUTS} inputs` };
  const parents = new Map();
  const sourceOutputs = [];
  for (const input of tx.inputs) {
    const id = L.binToHex(input.outpointTransactionHash);
    if (!parents.has(id)) parents.set(id, await getVerifiedTx(chain, id));
    const out = parents.get(id).outputs[input.outpointIndex];
    if (!out) return { error: `an input spends an output that doesn't exist in ${id.slice(0, 12)}…` };
    sourceOutputs.push(out);
  }
  const signer = findSigningInput(tx, sourceOutputs, payload);
  if (signer.error) return signer;
  const vm = L.createVirtualMachineBch(false); // consensus rules: a mined transaction is valid even if non-standard
  const ok = vm.verify({ sourceOutputs, transaction: tx });
  return ok === true ? signer : { error: `the BCH virtual machine rejects the transaction: ${ok}` };
}

/** The BCH half alone: a transaction, signed by this address over every output, that names a Nostr key (spec §5.3–5.7). */
export async function verifyCommitment(chain, txid, address) {
  try {
    const { payload } = decodeP2pkhAddress(address);
    const tx = await getVerifiedTx(chain, txid);
    if (tx.inputs.length > MAX_INPUTS) return { error: `more than ${MAX_INPUTS} inputs` };
    const named = readCommitment(tx);
    if (named.error) return named;
    const signer = await addressSigned(chain, tx, payload);
    if (signer.error) return signer;
    if (L.binToHex(signer.publicKey.slice(1, 33)) === named.pubkey) return { error: "the BCH key and the Nostr key are the same key" };
    return { npub: named.npub, pubkey: named.pubkey };
  } catch (e) {
    return { error: e.message };
  }
}

/**
 * Is this npub bound to a BCH address right now? → { status, npub, address, txid, confirmations, boundSince, warnings, reason?, supersededBy? }
 * status: verified (≥ 1 confirmation) · pending (mempool, payable, shown as new) · superseded · invalid.
 * nostr = { fetchClaim(pubkeyHex) → { claim } }, chain = { getTx, getHistory, getTipHeight, getHeader } (see relayReader, fulcrumChain).
 */
export async function verifyBinding(npub, { nostr, chain, address: wanted, now = Math.floor(Date.now() / 1000) }) {
  const out = (status, extra = {}) => ({ status, npub, warnings: [], ...extra });
  let pubkey;
  try { pubkey = npubToHex(npub); } catch { return out("invalid", { reason: "not an npub" }); }

  const fetched = (await nostr.fetchClaim(pubkey))?.claim;
  if (!fetched) return out("invalid", { reason: "no identity claim (kind 10011) found on the relays" });
  const claim = verifiedCopy(fetched);
  if (!claim || claim.pubkey !== pubkey || claim.kind !== CLAIM_KIND) return out("invalid", { reason: "the claim's signature doesn't verify" });

  const entries = claimedAddresses(claim).filter((e) => !wanted || sameAddress(e.address, wanted));
  if (!entries.length) return out("invalid", { reason: wanted ? "the claim doesn't name this address" : "the newest claim names no BCH address" });
  const { address, txid } = entries[0];
  const warnings = entries.length > 1 ? ["several BCH addresses in the claim: the first one is used"] : [];

  const c = await verifyCommitment(chain, txid, address);
  if (c.error) return out("invalid", { address, txid, reason: c.error, warnings });
  if (c.pubkey !== pubkey) return out("invalid", { address, txid, reason: "the transaction names another Nostr key", warnings });

  // Both halves are valid from here on: what's left (age, confirmations, a newer binding) comes from the address history.
  let history = [], at = -1, confirmations = 0, boundSince = null;
  try {
    history = await chain.getHistory(address);
    at = history.findIndex((h) => h.tx_hash === txid);
    const height = at >= 0 && history[at].height > 0 ? history[at].height : 0;
    if (height) {
      confirmations = (await chain.getTipHeight()) - height + 1;
      boundSince = headerTime(await chain.getHeader(height));
    }
  } catch {
    warnings.push("address history unavailable: confirmations and newer bindings not checked");
  }
  if (at < 0 && history.length) warnings.push("the server doesn't list the commitment in the address history");
  if (!boundSince || now - boundSince < NEW_FOR) warnings.push("new");

  // Superseded = a later transaction, signed by this same address, naming another npub. Anyone can send a
  // transaction TO the address, so only one that passes the full commitment check counts.
  const later = at >= 0 ? history.slice(at + 1) : [];
  if (later.length > MAX_LATER) warnings.push(`only the first ${MAX_LATER} later transactions were checked for a newer binding`);
  for (const h of later.slice(0, MAX_LATER)) {
    const tx = await getVerifiedTx(chain, h.tx_hash).catch(() => null);
    const named = tx && readCommitment(tx);
    if (!named || named.error || named.pubkey === pubkey) continue;
    const newer = await verifyCommitment(chain, h.tx_hash, address);
    if (!newer.error) return out("superseded", { address, txid, confirmations, boundSince, supersededBy: { npub: newer.npub, txid: h.tx_hash }, warnings });
  }
  return out(confirmations >= 1 ? "verified" : "pending", { address, txid, confirmations, boundSince, warnings });
}
