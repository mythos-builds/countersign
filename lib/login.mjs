// Login (spec §9): NIP-98 HTTP auth over a single-use challenge. The app hands out a URL carrying a fresh nonce,
// the person's Nostr key signs a kind 27235 event naming that exact URL and method, the app checks it and spends
// the nonce. Which BCH address the key is bound to is then verifyBinding's answer: no identity provider is asked.
import { nip19 } from "nostr-tools";
import { verifiedCopy } from "./nostr.mjs";

export const LOGIN_KIND = 27235;
const SKEW = 60; // seconds either side of the app's clock (NIP-98)
const TTL = 120; // a challenge not answered by then is dropped
const MAX_OPEN = 10_000; // open challenges kept at once; past that, the oldest goes

const randomHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const toBase64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const fromBase64 = (s) => new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));

/** The event that answers a challenge (NIP-98), to be signed by the person's key: NIP-07 extension, remote signer or secret key. */
export const loginTemplate = ({ url, method }, now = Math.floor(Date.now() / 1000)) =>
  ({ kind: LOGIN_KIND, created_at: now, tags: [["u", url], ["method", method]], content: "" });

/** The Authorization header that carries a signed answer. */
export const authorizationHeader = (event) => `Nostr ${toBase64(JSON.stringify(event))}`;

/**
 * The app's side. url = the login endpoint as people reach it (e.g. https://app.example/login).
 * Open challenges live in this object's memory: one process, or share the store.
 */
export function loginGate({ url, ttl = TTL, skew = SKEW, clock = () => Math.floor(Date.now() / 1000) }) {
  const endpoint = new URL(url);
  const open = new Map(); // nonce → expires at
  return {
    /** → { url, method, expiresAt }: the person signs `url` and `method`, then sends the answer to `url`. */
    challenge() {
      const now = clock();
      for (const [nonce, expires] of open) if (expires < now) open.delete(nonce);
      if (open.size >= MAX_OPEN) open.delete(open.keys().next().value);
      const nonce = randomHex(16);
      open.set(nonce, now + ttl);
      const u = new URL(endpoint);
      u.searchParams.set("nonce", nonce);
      return { url: u.href, method: "POST", expiresAt: now + ttl };
    },
    /**
     * authorization = the request's Authorization header, requestUrl = the absolute URL it was sent to.
     * → { pubkey, npub }, the nonce spent; or { error }: a wrong answer leaves the challenge open for the right one.
     */
    check(authorization, { url: requestUrl, method = "POST" }) {
      const now = clock();
      const m = /^Nostr ([A-Za-z0-9+/]+={0,2})$/.exec(authorization ?? "");
      if (!m) return { error: "no « Authorization: Nostr … » header" };
      let event;
      try { event = JSON.parse(fromBase64(m[1])); } catch { return { error: "the header doesn't hold a JSON event" }; }
      const signed = verifiedCopy(event);
      if (!signed) return { error: "the event's signature doesn't verify" };
      if (signed.kind !== LOGIN_KIND) return { error: `not a login event (kind ${LOGIN_KIND})` };
      if (Math.abs(now - signed.created_at) > skew) return { error: `the event is dated more than ${skew} s away from the app's clock` };
      const tag = (name) => signed.tags.find((t) => t[0] === name)?.[1];
      if (tag("u") !== requestUrl) return { error: "the event names another URL" };
      if (tag("method")?.toUpperCase() !== method.toUpperCase()) return { error: "the event names another method" };
      let nonce = null;
      try {
        const u = new URL(requestUrl);
        if (u.origin === endpoint.origin && u.pathname === endpoint.pathname) nonce = u.searchParams.get("nonce");
      } catch { /* not a URL: no nonce */ }
      const expires = nonce && open.get(nonce);
      if (!expires) return { error: "this challenge was never issued here, or it was already used" };
      open.delete(nonce);
      if (expires < now) return { error: "the challenge expired" };
      return { pubkey: signed.pubkey, npub: nip19.npubEncode(signed.pubkey) };
    },
  };
}
