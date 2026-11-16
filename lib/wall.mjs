// The wall (spec §7): names bound through Countersign that chose to be listed. Relays only suggest who is there:
// each name's newest claim must still carry the wall tag, then its binding goes through the full check (§5).
import { nip19 } from "nostr-tools";
import { onWall } from "./nostr.mjs";
import { verifyBinding } from "./verify.mjs";

const MAX_CANDIDATES = 200; // tagged claims checked to fill the wall: anyone can tag junk claims, so the wall keeps looking
const AHEAD = 600; // seconds: a claim dated further ahead of this clock is ignored (created_at is its author's word)

/**
 * → [{ ...verifyBinding's result, pubkey }] for the names that are verified or pending, newest claim first.
 * nostr = relayReader() (wallClaims, fetchClaim), chain = fulcrumChain(). Candidates are checked newest first until `limit`
 * names pass (MAX_CANDIDATES at most), `parallel` at a time;
 * onRow(row, rank) fires as each name passes, so a page can show them one by one.
 */
export async function listWall({ nostr, chain, limit = 30, parallel = 4, now, onRow }) {
  const ahead = Math.floor(Date.now() / 1000) + AHEAD;
  const candidates = (await nostr.wallClaims({ limit: MAX_CANDIDATES }))
    .filter((c) => c.created_at <= ahead)
    .sort((a, b) => b.created_at - a.created_at)
    .slice(0, MAX_CANDIDATES);
  const rows = new Array(candidates.length);
  let next = 0, shown = 0;
  async function worker() {
    while (next < candidates.length && shown < limit) {
      const i = next++;
      const { pubkey } = candidates[i];
      try {
        const claim = (await nostr.fetchClaim(pubkey))?.claim; // the newest one, read from the name's own relays as well
        if (!onWall(claim)) continue; // gone, or left the wall since
        const r = await verifyBinding(nip19.npubEncode(pubkey), { nostr: { fetchClaim: async () => ({ claim }) }, chain, ...(now ? { now } : {}) });
        if ((r.status === "verified" || r.status === "pending") && shown < limit) { shown++; rows[i] = { ...r, pubkey }; onRow?.(rows[i], i); }
      } catch { /* a name that can't be checked isn't shown */ }
    }
  }
  await Promise.all(Array.from({ length: Math.min(parallel, candidates.length) }, worker));
  return rows.filter(Boolean);
}
