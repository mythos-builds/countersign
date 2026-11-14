// What a person pastes → a Nostr public key: npub, nprofile, 64-hex, a nostr: link, a profile URL, or name@domain (NIP-05).
import { nip19 } from "nostr-tools";

const BECH32 = /(npub1[02-9ac-hj-np-z]{58}|nprofile1[02-9ac-hj-np-z]+)/;
const NIP05 = /^(?:([a-z0-9._-]+)@)?((?:[a-z0-9-]+\.)+[a-z]{2,})$/i;
const HEX_KEY = /^[0-9a-f]{64}$/;

const wssOnly = (urls) => (Array.isArray(urls) ? urls.filter((u) => typeof u === "string" && /^wss:\/\/[^\s]+$/.test(u)).slice(0, 5) : []);

/** → { pubkey, npub, relays (hints, maybe empty), via }. Throws an Error whose message can be shown as is. */
export async function resolveName(input, { fetchImpl = globalThis.fetch, timeoutMs = 6000 } = {}) {
  const text = String(input ?? "").trim();
  const bech = BECH32.exec(text)?.[1];
  if (bech) {
    let d;
    try { d = nip19.decode(bech); } catch { throw new Error("That key has a typo: its checksum doesn't match."); }
    if (d.type === "npub") return { pubkey: d.data, npub: bech, relays: [], via: "npub" };
    return { pubkey: d.data.pubkey, npub: nip19.npubEncode(d.data.pubkey), relays: wssOnly(d.data.relays), via: "nprofile" };
  }
  if (HEX_KEY.test(text.toLowerCase())) {
    const pubkey = text.toLowerCase();
    return { pubkey, npub: nip19.npubEncode(pubkey), relays: [], via: "hex" };
  }
  const m = NIP05.exec(text.replace(/^nostr:/i, ""));
  if (!m) throw new Error("Paste an npub, a name@domain or a Nostr profile link.");
  const name = (m[1] ?? "_").toLowerCase();
  const domain = m[2].toLowerCase();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let doc;
  try {
    // NIP-05: no redirects; the document must answer for this exact name.
    const res = await fetchImpl(`https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(name)}`, { redirect: "error", signal: ctl.signal });
    if (!res.ok) throw new Error(`${domain} answered ${res.status}`);
    doc = await res.json();
  } catch (e) {
    throw new Error(`Couldn't look up ${name === "_" ? domain : `${name}@${domain}`}: ${e.name === "AbortError" ? "no answer in time" : e.message}.`);
  } finally {
    clearTimeout(timer);
  }
  const pubkey = String(doc?.names?.[name] ?? "").toLowerCase();
  if (!HEX_KEY.test(pubkey)) throw new Error(`${domain} doesn't list the name « ${name} ».`);
  return { pubkey, npub: nip19.npubEncode(pubkey), relays: wssOnly(doc?.relays?.[pubkey]), via: `${name}@${domain}` };
}
