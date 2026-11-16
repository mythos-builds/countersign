// Discovery by address (spec §7): which Nostr name is bound to this BCH address? Two independent roads find
// candidates, the relays (claims tagging the address) and the chain alone (commitments in the address history);
// every candidate is then verified in full, so neither road is trusted.
import * as L from "@bitauth/libauth";
import { nip19 } from "nostr-tools";
import { decodeP2pkhAddress, readCommitment } from "./commitment.mjs";
import { verifyBinding } from "./verify.mjs";

/**
 * → the current binding of this address in verifyBinding's shape plus `via` (["relays", "chain"]), or null if none holds.
 * nostr = relayReader(), chain = fulcrumChain(). maxHistory bounds the chain road on busy addresses.
 */
export async function findByAddress(address, { nostr, chain, maxHistory = 50, now }) {
  decodeP2pkhAddress(address); // throws on anything but a P2PKH cash address
  const candidates = new Map(); // pubkey hex → Set of roads
  const add = (pubkey, road) => { if (!candidates.has(pubkey)) candidates.set(pubkey, new Set()); candidates.get(pubkey).add(road); };

  for (const claim of await nostr.claimsFor(address).catch(() => [])) add(claim.pubkey, "relays");
  const history = await chain.getHistory(address).catch(() => []);
  for (const { tx_hash: txid } of history.slice(-maxHistory)) {
    const tx = await chain.getTx(txid).then((raw) => L.decodeTransaction(raw)).catch(() => null);
    const named = tx && typeof tx !== "string" ? readCommitment(tx) : null;
    if (named && !named.error) add(named.pubkey, "chain");
  }

  const results = await Promise.all([...candidates].map(async ([pubkey, roads]) => ({
    ...(await verifyBinding(nip19.npubEncode(pubkey), { nostr, chain, address, ...(now ? { now } : {}) })),
    via: [...roads],
  })));
  // A rebound address leaves its older names « superseded »; of the live ones, the newest commitment wins. An `invalid`
  // candidate is no binding at all: anyone can name any key in a payment to the address, or in a claim, so it gets no say.
  const at = (r) => history.findIndex((h) => h.tx_hash === r.txid);
  const live = results.filter((r) => r.status === "verified" || r.status === "pending").sort((a, b) => at(b) - at(a));
  return live[0] ?? results.find((r) => r.status === "unchecked") ?? results.find((r) => r.status === "superseded") ?? null;
}
