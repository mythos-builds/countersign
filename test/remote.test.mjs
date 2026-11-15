// Offline tests for remote signers (NIP-46, spec §10): a signer and this page talk through an in-memory relay.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateSecretKey, getPublicKey, finalizeEvent } from "nostr-tools";
import { getConversationKey, encrypt, decrypt } from "nostr-tools/nip44";
import { connectLink, viaLink, viaBunker, buildClaim } from "../lib/index.mjs";

const NC = 24133;
const RELAYS = ["wss://relay.example"];

/** Every subscriber whose filter matches gets each published event, a fresh copy, on the next tick (limit 0: new events only). */
function memoryRelay() {
  const subs = new Set();
  const match = (f, e) => (!f.kinds || f.kinds.includes(e.kind)) && (!f.authors || f.authors.includes(e.pubkey))
    && (!f["#p"] || e.tags.some((t) => t[0] === "p" && f["#p"].includes(t[1])));
  return {
    subscribe(_relays, filter, { onevent, onclose, abort, maxWait } = {}) {
      const s = { filter, onevent }; let timer;
      const close = () => { if (subs.delete(s)) { clearTimeout(timer); onclose?.(["closed"]); } };
      subs.add(s);
      if (maxWait) timer = setTimeout(close, maxWait);
      abort?.addEventListener("abort", close);
      return { close: async () => { await null; close(); } }; // like SimplePool: the caller's close lands a tick later
    },
    publish(_relays, event) {
      const copy = JSON.parse(JSON.stringify(event));
      setImmediate(() => { for (const s of [...subs]) if (match(s.filter, copy)) s.onevent(copy); });
      return [Promise.resolve("ok")];
    },
  };
}

/** A signer app: holds the user's key, answers NIP-46 requests. `cheat` = "other-key" | "other-content" | "bad-secret". */
function signerApp(pool, { cheat } = {}) {
  const sk = generateSecretKey(), userSk = generateSecretKey(), pubkey = getPublicKey(sk);
  const reply = (to, body) => {
    const ck = getConversationKey(sk, to);
    pool.publish(RELAYS, finalizeEvent({ kind: NC, created_at: Math.floor(Date.now() / 1000), tags: [["p", to]], content: encrypt(JSON.stringify(body), ck) }, sk));
  };
  const seen = [];
  const sub = pool.subscribe(RELAYS, { kinds: [NC], "#p": [pubkey] }, {
    onevent(ev) {
      const { id, method, params } = JSON.parse(decrypt(ev.content, getConversationKey(sk, ev.pubkey)));
      seen.push(method);
      let result = null;
      if (method === "connect") result = "ack";
      else if (method === "get_public_key") result = getPublicKey(userSk);
      else if (method === "ping") result = "pong";
      else if (method === "switch_relays") result = "null";
      else if (method === "sign_event") {
        const t = JSON.parse(params[0]);
        if (cheat === "other-content") t.content = "something else";
        result = JSON.stringify(finalizeEvent(t, cheat === "other-key" ? generateSecretKey() : userSk));
      } else return reply(ev.pubkey, { id, error: `no ${method}` });
      reply(ev.pubkey, { id, result });
    },
  });
  return {
    userPubkey: getPublicKey(userSk), seen,
    bunkerUrl: `bunker://${pubkey}?relay=${encodeURIComponent(RELAYS[0])}&secret=s3cret`,
    /** The user scans a nostrconnect:// link: answer the page with the link's secret. */
    scan(uri) {
      const u = new URL(uri);
      reply(u.host || u.pathname.replace(/^\/+/, ""), { id: "c1", result: cheat === "bad-secret" ? "not-the-secret" : u.searchParams.get("secret") });
    },
    close: () => sub.close(),
  };
}

const template = () => ({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [["t", "countersign"]], content: "hello" });

test("bunker:// link: connect, get the user's key, sign exactly what was asked", async () => {
  const pool = memoryRelay(), app = signerApp(pool);
  const id = await viaBunker(app.bunkerUrl, { pool });
  assert.equal(id.pubkey, app.userPubkey);
  assert.equal(id.via, "remote");
  const t = template(), ev = await id.sign(t);
  assert.equal(ev.pubkey, app.userPubkey);
  assert.deepEqual([ev.kind, ev.created_at, ev.content, ev.tags], [t.kind, t.created_at, t.content, t.tags]);
  assert.deepEqual(app.seen.slice(0, 2), ["connect", "get_public_key"]);
  await id.close(); app.close();
});

test("nostrconnect:// link: the signer that answers with the link's secret becomes the identity", async () => {
  const pool = memoryRelay(), app = signerApp(pool), link = connectLink({ url: "https://example.org" });
  assert.match(link.uri, /^nostrconnect:\/\/[0-9a-f]{64}\?/);
  assert.ok(link.uri.includes("perms=") && link.uri.includes("secret="));
  const waiting = viaLink(link, { pool });
  app.scan(link.uri);
  const id = await waiting;
  assert.equal(id.pubkey, app.userPubkey);
  const claim = buildClaim(null, "bitcoincash:qqmjav83u3qthh9yenz379pn5evx23t90clwm7l3t9", "65169531cd14c7fc5dce66dcfeb87896a51547d8235416d831ad6505a1ea4f04");
  const signed = await id.sign(claim);
  assert.equal(signed.kind, 10011);
  await id.close(); app.close();
});

test("an answer without the link's secret is ignored (the wait is cancelled, not answered)", async () => {
  const pool = memoryRelay(), app = signerApp(pool, { cheat: "bad-secret" }), link = connectLink();
  const stop = new AbortController();
  const waiting = viaLink(link, { pool, signal: stop.signal });
  app.scan(link.uri);
  setTimeout(() => stop.abort(), 200);
  await assert.rejects(waiting, /closed before connection/);
  app.close();
});

test("a signer that signs with another key is refused", async () => {
  const pool = memoryRelay(), app = signerApp(pool, { cheat: "other-key" });
  const id = await viaBunker(app.bunkerUrl, { pool });
  await assert.rejects(id.sign(template()), /doesn't verify for this key/);
  await id.close(); app.close();
});

test("a signer that changes the event is refused", async () => {
  const pool = memoryRelay(), app = signerApp(pool, { cheat: "other-content" });
  const id = await viaBunker(app.bunkerUrl, { pool });
  await assert.rejects(id.sign(template()), /signed something else/);
  await id.close(); app.close();
});

test("a pasted string that isn't a bunker link is refused before any network", async () => {
  await assert.rejects(viaBunker("npub1nothing"), /isn't a bunker/);
  await assert.rejects(viaBunker(""), /isn't a bunker/);
});
