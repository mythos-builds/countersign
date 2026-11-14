// Offline tests for the login (spec §9): NIP-98 answers to single-use challenges.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateSecretKey, getPublicKey, finalizeEvent, nip19, nip98 } from "nostr-tools";
import { loginGate, loginTemplate, authorizationHeader, LOGIN_KIND } from "../lib/index.mjs";

const URL_ = "https://app.example/login";
let now = 1_800_000_000;
const gate = (opts = {}) => loginGate({ url: URL_, clock: () => now, ...opts });
const sk = generateSecretKey();
const answer = (challenge, extra = {}, key = sk) =>
  authorizationHeader(finalizeEvent({ ...loginTemplate(challenge, now), ...extra }, key));
const post = (challenge) => ({ url: challenge.url, method: "POST" });

test("login: a signed answer to a fresh challenge signs the key in, once", () => {
  const g = gate();
  const c = g.challenge();
  assert.match(c.url, /^https:\/\/app\.example\/login\?nonce=[0-9a-f]{32}$/);
  const header = answer(c);
  const who = g.check(header, post(c));
  assert.deepEqual(who, { pubkey: getPublicKey(sk), npub: nip19.npubEncode(getPublicKey(sk)) });
  assert.match(g.check(header, post(c)).error, /already used/); // replay
});

test("login: each challenge is its own; answers don't cross", () => {
  const g = gate();
  const [a, b] = [g.challenge(), g.challenge()];
  assert.notEqual(a.url, b.url);
  assert.match(g.check(answer(a), post(b)).error, /another URL/);
  assert.ok(g.check(answer(b), post(b)).pubkey);
  assert.ok(g.check(answer(a), post(a)).pubkey);
});

test("login: a challenge from another app, or a made-up nonce, is refused", () => {
  const g = gate();
  const other = loginGate({ url: URL_, clock: () => now }).challenge();
  assert.match(g.check(answer(other), post(other)).error, /never issued here/);
  const elsewhere = { url: "https://evil.example/login?nonce=" + "0".repeat(32), method: "POST" };
  assert.match(g.check(answer(elsewhere), post(elsewhere)).error, /never issued here/);
});

test("login: wrong method, wrong kind, stale or future time are refused, and the challenge stays open", () => {
  const g = gate();
  const c = g.challenge();
  assert.match(g.check(answer({ ...c, method: "GET" }), post(c)).error, /another method/);
  assert.match(g.check(answer(c, { kind: 1 }), post(c)).error, /not a login event/);
  assert.match(g.check(answer(c, { created_at: now - 61 }), post(c)).error, /more than 60 s/);
  assert.match(g.check(answer(c, { created_at: now + 61 }), post(c)).error, /more than 60 s/);
  assert.ok(g.check(answer(c, { created_at: now - 60 }), post(c)).pubkey); // the edge of the window still counts
});

test("login: a forged or mangled answer is refused", () => {
  const g = gate();
  const c = g.challenge();
  const signed = finalizeEvent(loginTemplate(c, now), sk);
  const thief = getPublicKey(generateSecretKey());
  assert.match(g.check(authorizationHeader({ ...signed, pubkey: thief }), post(c)).error, /signature/);
  assert.match(g.check(authorizationHeader({ ...signed, tags: [["u", c.url], ["method", "PUT"]] }), post(c)).error, /signature/);
  assert.match(g.check(undefined, post(c)).error, /header/);
  assert.match(g.check("Bearer abc", post(c)).error, /header/);
  assert.match(g.check("Nostr bm90IGpzb24=", post(c)).error, /JSON/);
  assert.ok(g.check(authorizationHeader(signed), post(c)).pubkey); // nothing above spent it
});

test("login: a challenge answered too late has expired", () => {
  const g = gate({ ttl: 120, skew: 600 });
  const c = g.challenge();
  now += 121;
  try {
    assert.match(g.check(answer(c), post(c)).error, /expired/);
  } finally {
    now -= 121;
  }
});

test("login: an answer made by nostr-tools' own NIP-98 helper is accepted (interop)", async () => {
  const g = loginGate({ url: URL_ }); // the real clock: getToken dates the event itself
  const c = g.challenge();
  const token = await nip98.getToken(c.url, "post", (e) => finalizeEvent(e, sk), true);
  assert.equal(g.check(token, post(c)).pubkey, getPublicKey(sk));
  assert.equal(LOGIN_KIND, 27235);
});
