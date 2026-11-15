// The Nostr half of a binding (spec §4): the person's NIP-39 identity list, kind 10011,
// with ["i", "bitcoincash:<address>", "<commitment txid>"].
import { SimplePool, verifyEvent } from "nostr-tools";

export const DEFAULT_RELAYS = ["wss://relay.primal.net", "wss://relay.snort.social", "wss://offchain.pub", "wss://relay.damus.io", "wss://nos.lol"];
export const CLAIM_KIND = 10011;
/** A claim carrying ["t", WALL_TAG] asks to be listed on the wall (spec §7). */
export const WALL_TAG = "countersign";
export const onWall = (event) => (event?.tags ?? []).some((t) => t[0] === "t" && t[1] === WALL_TAG);
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

/** The person's current claim without its BCH addresses and wall tag, dated so it replaces the current one. */
const unbound = (current, now) => ({
  kind: CLAIM_KIND,
  created_at: Math.max(now, (current?.created_at ?? 0) + 1),
  tags: (current?.tags ?? []).filter((t) => !(t[0] === "i" && /^(bitcoincash|bchtest):/.test(t[1] ?? "")) && !(t[0] === "t" && t[1] === WALL_TAG)),
  content: current?.content ?? "",
});

/** The claim to sign, merged into the person's current one: other identities kept, one BCH address (spec §4). */
export function buildClaim(current, address, txid, { wall = true, now = Math.floor(Date.now() / 1000) } = {}) {
  const claim = unbound(current, now);
  claim.tags.push(["i", address, txid], ...(wall ? [["t", WALL_TAG]] : []));
  return claim;
}

/** The claim that unbinds (spec §6): other identities kept, no BCH address, off the wall. The commitment stays on chain but no longer counts. */
export const buildUnbind = (current, { now = Math.floor(Date.now() / 1000) } = {}) => unbound(current, now);

/** Reads claims from the author's own write relays (kind 10002) plus defaults. */
export function relayReader({ relays = DEFAULT_RELAYS, maxWait = 6000 } = {}) {
  const pool = new SimplePool();
  const used = new Set(relays);
  const query = async (urls, filter) => {
    urls.forEach((u) => used.add(u));
    return (await pool.querySync(urls, filter, { maxWait })).map(verifiedCopy).filter(Boolean);
  };
  const lists = new Map(); // pubkey → its newest relay list (kind 10002), asked once per reader
  const relayList = (pubkey) => {
    if (!lists.has(pubkey)) {
      const asked = query(relays, { kinds: [10002], authors: [pubkey] })
        .then((events) => newest(events.filter((e) => e.pubkey === pubkey && e.kind === 10002))?.tags ?? []);
      asked.catch(() => lists.delete(pubkey)); // a failed ask is asked again next time
      lists.set(pubkey, asked);
    }
    return lists.get(pubkey);
  };
  // NIP-65: an `r` tag marked "read" is an inbox only, one marked "write" an outbox only, an unmarked one both.
  const listed = async (pubkey, other) => (await relayList(pubkey)).filter((t) => t[0] === "r" && /^wss:\/\//.test(t[1] ?? "") && t[2] !== other).map((t) => t[1]);
  const writeRelays = (pubkey) => listed(pubkey, "read");
  const readRelays = (pubkey) => listed(pubkey, "write");
  const readFrom = async (pubkey, hints) => {
    const outbox = await writeRelays(pubkey).catch(() => []);
    return [...new Set([...outbox.slice(0, 5), ...hints.slice(0, 3), ...relays])];
  };
  return {
    writeRelays,
    /** Where this key reads its mentions (NIP-65 inbox): notes that tag it go there too. */
    readRelays,
    /** hints = relays named by an nprofile or a NIP-05 document, asked as well. */
    async fetchClaim(pubkey, hints = []) {
      const urls = await readFrom(pubkey, hints);
      const claims = (await query(urls, { kinds: [CLAIM_KIND], authors: [pubkey] })).filter((e) => e.pubkey === pubkey && e.kind === CLAIM_KIND);
      return { claim: newest(claims), relays: urls };
    },
    /** Claims whose "i" tag names this address (relays index single-letter tags), signatures checked. */
    async claimsFor(address) {
      const events = await query(relays, { kinds: [CLAIM_KIND], "#i": [address], limit: 50 });
      return events.filter((e) => e.kind === CLAIM_KIND && claimedAddresses(e).some((c) => c.address === address));
    },
    /** Who may be on the wall: tagged claims, newest per author, signatures checked. Each still needs the full check (listWall). */
    async wallClaims({ limit = 100 } = {}) {
      const byAuthor = new Map();
      for (const e of await query(relays, { kinds: [CLAIM_KIND], "#t": [WALL_TAG], limit })) {
        if (e.kind === CLAIM_KIND && onWall(e) && claimedAddresses(e).length) byAuthor.set(e.pubkey, newest([byAuthor.get(e.pubkey), e].filter(Boolean)));
      }
      return [...byAuthor.values()];
    },
    /** Kind 1 notes that tag this key and carry this hashtag (receipts, spec §8.3), from its inbox relays too; signatures checked. */
    async mentions(pubkey, hashtag, { limit = 100 } = {}) {
      const inbox = await readRelays(pubkey).catch(() => []);
      const events = await query([...new Set([...inbox.slice(0, 5), ...relays])], { kinds: [1], "#p": [pubkey], "#t": [hashtag], limit });
      return [...new Map(events.filter((e) => e.kind === 1).map((e) => [e.id, e])).values()];
    },
    /** The newest kind 0, reduced to plain strings: { name, picture (https only), about, nip05 } or null. */
    async fetchProfile(pubkey, hints = []) {
      const urls = await readFrom(pubkey, hints);
      const event = newest((await query(urls, { kinds: [0], authors: [pubkey] })).filter((e) => e.pubkey === pubkey && e.kind === 0));
      let meta;
      try { meta = JSON.parse(event?.content ?? "null"); } catch { return null; }
      if (!meta || typeof meta !== "object") return null;
      const str = (v, max) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : undefined);
      const picture = str(meta.picture, 500);
      return {
        name: str(meta.display_name, 60) ?? str(meta.name, 60),
        picture: picture && /^https:\/\/[^\s"'<>]+$/.test(picture) ? picture : undefined,
        about: str(meta.about, 280),
        nip05: str(meta.nip05, 100),
      };
    },
    async publish(event, urls = relays) {
      urls.forEach((u) => used.add(u));
      return Promise.allSettled(pool.publish(urls, event));
    },
    close: () => pool.close([...used]),
  };
}
