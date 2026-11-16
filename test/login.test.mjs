// Offline tests for the login (spec §9): NIP-98 answers to single-use challenges.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { generateSecretKey, getPublicKey, finalizeEvent, nip19, nip98 } from "nostr-tools";
import * as L from "@bitauth/libauth";
import { loginGate, loginTemplate, authorizationHeader, LOGIN_KIND, signP2pkh, p2pkhAddress, findAddressPath, walletProofTransaction, TAG } from "../lib/index.mjs";

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
  for (const json of ["null", "5", '"x"', "true", "[]", "{}"]) assert.match(g.check("Nostr " + btoa(json), post(c)).error, /signature/); // JSON, not an event: an answer, never a throw
  assert.ok(g.check(authorizationHeader(signed), post(c)).pubkey); // nothing above spent it
});

test("login: the example server answers bad requests and stays up", async () => {
  const origin = `http://127.0.0.1:${40_000 + Math.floor(Math.random() * 20_000)}`;
  const server = spawn(process.execPath, [fileURLToPath(new URL("../examples/login-server.mjs", import.meta.url))], { env: { ...process.env, ORIGIN: origin }, stdio: ["ignore", "pipe", "pipe"] });
  const exited = new Promise((res) => server.on("exit", (code) => res(`exited (${code})`)));
  try {
    await new Promise((res, rej) => {
      server.stdout.on("data", (d) => String(d).includes("login demo on") && res());
      exited.then(rej);
      setTimeout(() => rej(new Error("the example server didn't start in 5 s")), 5_000).unref();
    });
    const status = (path, init) => fetch(origin + path, init).then((r) => r.status);
    assert.equal(await status(`/login?nonce=${"0".repeat(32)}`, { method: "POST", headers: { authorization: "Nostr " + btoa("null") } }), 401);
    assert.equal(await status("//", { method: "POST" }), 500); // not a URL: the handler throws, the server answers
    assert.equal(await Promise.race([exited, status("/challenge")]), 200);
  } finally { server.kill(); }
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

// ── The wallet's live answer (spec §9.5) ──
const bchKey = L.sha256.hash(L.utf8ToBin("wallet proof test key"));
const bchPub = L.secp256k1.derivePublicKeyCompressed(bchKey);
const ADDRESS = p2pkhAddress(bchPub);
const NPUB = nip19.npubEncode(getPublicKey(sk));
const hexTx = (tx) => L.binToHex(L.encodeTransaction(tx));
const walletSigns = (c, key = bchKey, sighash = 0x41) => hexTx(signP2pkh(c.transaction, c.sourceOutputs, key, sighash));

test("wallet proof: the wallet behind the bound address signs the one-time code, once", () => {
  const g = gate();
  const c = g.walletChallenge({ npub: NPUB, address: ADDRESS });
  assert.match(c.text, /^Sign in to app\.example as npub1[02-9ac-hj-np-z]{58}, one-time code [0-9a-f]{32}$/);
  assert.equal(c.expiresAt, now + 300);
  const signed = walletSigns(c);
  assert.deepEqual(g.walletCheck(signed), { npub: NPUB, address: ADDRESS, publicKey: L.binToHex(bchPub) });
  assert.match(g.walletCheck(signed).error, /already used/); // replay
});

test("wallet proof: nothing moves; it spends output 0 of a parent made from the text, which spends nothing", () => {
  const c = gate().walletChallenge({ npub: NPUB, address: ADDRESS });
  const [input] = c.transaction.inputs;
  assert.equal(c.transaction.inputs.length, 1);
  assert.equal(input.outpointIndex, 0);
  assert.deepEqual(c.transaction.outputs.map((o) => o.valueSatoshis), [0n]);
  assert.equal(c.sourceOutputs[0].valueSatoshis, 0n);
  const [data] = c.transaction.outputs;
  const pushes = L.decodeAuthenticationInstructions(data.lockingBytecode.slice(1));
  assert.equal(data.lockingBytecode[0], 0x6a);
  assert.deepEqual([pushes[0].data, L.binToUtf8(pushes[1].data)], [TAG, c.text]);
  assert.ok(data.lockingBytecode.length <= 223);
  // Same text → same parent; another text → another parent. The parent's own input is the null outpoint.
  const again = walletProofTransaction({ address: ADDRESS, text: c.text });
  assert.deepEqual(again.transaction.inputs[0].outpointTransactionHash, input.outpointTransactionHash);
  assert.notDeepEqual(walletProofTransaction({ address: ADDRESS, text: c.text + "x" }).transaction.inputs[0].outpointTransactionHash, input.outpointTransactionHash);
  assert.throws(() => walletProofTransaction({ address: ADDRESS, text: "x".repeat(216) }), /too long/);
});

test("wallet proof: another key, a broken signature or a partial sighash is refused, and the challenge stays open", () => {
  const g = gate();
  const c = g.walletChallenge({ npub: NPUB, address: ADDRESS });
  const other = L.sha256.hash(L.utf8ToBin("someone else"));
  assert.match(g.walletCheck(walletSigns(c, other)).error, /no input is signed by this address/);
  // The right public key with another key's signature: the VM decides.
  const forged = signP2pkh(c.transaction, [{ ...c.sourceOutputs[0], lockingBytecode: L.encodeLockingBytecodeP2pkh(L.hash160(L.secp256k1.derivePublicKeyCompressed(other))) }], other);
  const [sig] = L.decodeAuthenticationInstructions(forged.inputs[0].unlockingBytecode);
  const swapped = { ...forged, inputs: [{ ...forged.inputs[0], unlockingBytecode: L.flattenBinArray([L.encodeDataPush(sig.data), L.encodeDataPush(bchPub)]) }] };
  assert.match(g.walletCheck(hexTx(swapped)).error, /doesn't verify/);
  assert.match(g.walletCheck(walletSigns(c, bchKey, 0x42)).error, /doesn't cover every output/); // NONE
  assert.ok(g.walletCheck(walletSigns(c)).publicKey);
});

test("wallet proof: a wallet that changes the transaction, garbage, or a proof made for another app is refused", () => {
  const g = gate();
  const c = g.walletChallenge({ npub: NPUB, address: ADDRESS });
  const edit = (f) => hexTx(signP2pkh(f(c.transaction), c.sourceOutputs, bchKey));
  assert.match(g.walletCheck(edit((t) => ({ ...t, locktime: 1 }))).error, /changed the transaction/);
  assert.match(g.walletCheck(edit((t) => ({ ...t, outputs: [...t.outputs, { lockingBytecode: L.encodeLockingBytecodeP2pkh(L.hash160(bchPub)), valueSatoshis: 0n }] }))).error, /changed the transaction/);
  assert.match(g.walletCheck("zz").error, /isn't a transaction/);
  assert.match(g.walletCheck(undefined).error, /isn't a transaction/);
  const elsewhere = loginGate({ url: "https://other.example/login", clock: () => now }).walletChallenge({ npub: NPUB, address: ADDRESS });
  assert.match(g.walletCheck(walletSigns(elsewhere)).error, /never issued here/);
  assert.ok(g.walletCheck(walletSigns(c)).publicKey);
});

test("wallet proof: an answer after five minutes has expired, and the code is spent", () => {
  const g = gate();
  const c = g.walletChallenge({ npub: NPUB, address: ADDRESS });
  const signed = walletSigns(c);
  now += 301;
  try {
    assert.match(g.walletCheck(signed).error, /expired/);
    assert.match(g.walletCheck(signed).error, /already used/);
  } finally { now -= 301; }
});

test("wallet proof: the page finds the bound address in the wallet's public keys, or says it isn't there", () => {
  const keyAt = (child, i) => L.secp256k1.derivePublicKeyCompressed(L.sha256.hash(L.utf8ToBin(`${child}/${i}`)));
  assert.deepEqual(findAddressPath(keyAt, p2pkhAddress(keyAt(1, 3n))), ["change", 3]);
  assert.deepEqual(findAddressPath(keyAt, p2pkhAddress(keyAt(0, 41n))), ["receive", 41]);
  assert.equal(findAddressPath(keyAt, ADDRESS, { max: 50 }), null);
  assert.equal(findAddressPath((child, i) => (child === 0 ? keyAt(0, i) : undefined), p2pkhAddress(keyAt(1, 3n)), { max: 50 }), null);
});
