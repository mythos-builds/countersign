// The Nostr half of a binding (spec §4): the person's NIP-39 identity list, kind 10011,
// with ["i", "bitcoincash:<address>", "<commitment txid>"].
import { SimplePool, verifyEvent } from "nostr-tools";

export const DEFAULT_RELAYS = ["wss://relay.primal.net", "wss://relay.snort.social", "wss://offchain.pub", "wss://relay.damus.io", "wss://nos.lol"];
export const CLAIM_KIND = 10011;
const BCH_IDENTITY = /^(bitcoincash|bchtest):[02-9ac-hj-np-z]+$/;

/** Signature check on a fresh copy: nostr-tools marks event objects as verified, and a marked object skips the check. */
export function verifiedCopy(event) {
  let copy;
  try { copy = JSON.parse(JSON.stringify(event)); } catch { return null; }
  return verifyEvent(copy) ? copy : null;
}

/** Newest replaceable event wins; on a tie, the lowest id (NIP-01). */
export const newest = (events) =>
  events.reduce((best, e) => (!best || e.created_at > best.created_at || (e.created_at === best.created_at && e.id < best.id) ? e : best), null);

/** [{ address, txid }] for each BCH identity a claim names. */
export const claimedAddresses = (event) =>
  event.tags
    .filter((t) => t[0] === "i" && BCH_IDENTITY.test(t[1] ?? "") && /^[0-9a-f]{64}$/.test(t[2] ?? ""))
    .map((t) => ({ address: t[1], txid: t[2] }));

/** The claim to sign, merged into the person's current one: other identities kept, one BCH address (spec §4). */
export function buildClaim(current, address, txid, { wall = true, now = Math.floor(Date.now() / 1000) } = {}) {
  const kept = (current?.tags ?? []).filter(
    (t) => !(t[0] === "i" && /^(bitcoincash|bchtest):/.test(t[1] ?? "")) && !(t[0] === "t" && t[1] === "countersign"),
  );
  return {
    kind: CLAIM_KIND,
    created_at: Math.max(now, (current?.created_at ?? 0) + 1),
    tags: [...kept, ["i", address, txid], ...(wall ? [["t", "countersign"]] : [])],
    content: current?.content ?? "",
  };
}

/** Reads claims from the author's own write relays (kind 10002) plus defaults. */
export function relayReader({ relays = DEFAULT_RELAYS, maxWait = 6000 } = {}) {
  const pool = new SimplePool();
  const used = new Set(relays);
  const query = async (urls, filter) => {
    urls.forEach((u) => used.add(u));
    return (await pool.querySync(urls, filter, { maxWait })).map(verifiedCopy).filter(Boolean);
  };
  const writeRelays = async (pubkey) => {
    const list = newest((await query(relays, { kinds: [10002], authors: [pubkey] })).filter((e) => e.pubkey === pubkey && e.kind === 10002));
    return (list?.tags ?? []).filter((t) => t[0] === "r" && /^wss:\/\//.test(t[1] ?? "") && t[2] !== "read").map((t) => t[1]);
  };
  return {
    writeRelays,
    async fetchClaim(pubkey) {
      const outbox = await writeRelays(pubkey).catch(() => []);
      const urls = [...new Set([...outbox.slice(0, 5), ...relays])];
      const claims = (await query(urls, { kinds: [CLAIM_KIND], authors: [pubkey] })).filter((e) => e.pubkey === pubkey && e.kind === CLAIM_KIND);
      return { claim: newest(claims), relays: urls };
    },
    async publish(event, urls = relays) {
      urls.forEach((u) => used.add(u));
      return Promise.allSettled(pool.publish(urls, event));
    },
    close: () => pool.close([...used]),
  };
}
