// Offline tests for paying a name: amounts, the payment builder, the wallet scan, and name lookup.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as L from "@bitauth/libauth";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { parseBch, formatBch, paymentUri, paidTo, buildPayment, buildCommitment, scanWallet, signP2pkh, resolveName, verifiedNip05, DUST } from "../lib/index.mjs";

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

function bchKey() {
  let priv;
  do { priv = rand(32); } while (!L.secp256k1.validatePrivateKey(priv));
  const pub = L.secp256k1.derivePublicKeyCompressed(priv);
  const enc = L.encodeCashAddress({ prefix: "bitcoincash", type: "p2pkh", payload: L.hash160(pub) });
  return { priv, pub, lock: L.encodeLockingBytecodeP2pkh(L.hash160(pub)), address: typeof enc === "string" ? enc : enc.address };
}

const coin = (key, satoshis, extra = {}) => ({ txid: L.binToHex(rand(32)), vout: 0, satoshis, lockingBytecode: key.lock, path: ["receive", 0], ...extra });

test("amounts: parse and format BCH without floating point", () => {
  assert.equal(parseBch("0.0001"), 10_000n);
  assert.equal(parseBch("1"), 100_000_000n);
  assert.equal(parseBch("0,5"), 50_000_000n);
  assert.equal(parseBch(".00000546"), 546n);
  for (const bad of ["", "0", "abc", "1.123456789", "-1", "1e-4", null]) assert.equal(parseBch(bad), null, String(bad));
  assert.equal(formatBch(10_000n), "0.0001");
  assert.equal(formatBch(100_000_000n), "1");
  assert.equal(formatBch(123_456_789n), "1.23456789");
  const payee = bchKey();
  assert.equal(paymentUri(payee.address, 10_000n), `${payee.address}?amount=0.0001`);
});

test("a payment pays the payee, sends change back, and is valid once signed", () => {
  const payer = bchKey(), payee = bchKey();
  const coins = [coin(payer, 3_000n), coin(payer, 50_000n), coin(payer, 1_000n)];
  const p = buildPayment({ coins, to: payee.address, satoshis: 10_000n, changeLockingBytecode: payer.lock });
  assert.equal(p.transaction.inputs.length, 1, "the largest coin alone is enough");
  assert.deepEqual(p.inputPaths, [[0, "receive", 0]]);
  assert.equal(p.transaction.outputs[0].valueSatoshis, 10_000n);
  assert.equal(p.transaction.outputs[1].valueSatoshis, 50_000n - 10_000n - p.fee);
  const signed = signP2pkh(p.transaction, p.sourceOutputs, payer.priv);
  assert.equal(L.createVirtualMachineBch(true).verify({ sourceOutputs: p.sourceOutputs, transaction: signed }), true);
  // Fee covers the worst-case ECDSA input (108 bytes), so it is at least 1 sat/byte for a Schnorr signer too.
  assert.ok(p.fee >= BigInt(L.encodeTransaction(signed).length) + 8n);
  assert.equal(paidTo(signed, payee.address), 10_000n);
});

test("a leftover under dust goes to the fee instead of a change output", () => {
  const payer = bchKey(), payee = bchKey();
  const p = buildPayment({ coins: [coin(payer, 10_500n)], to: payee.address, satoshis: 10_000n, changeLockingBytecode: payer.lock });
  assert.equal(p.transaction.outputs.length, 1);
  assert.equal(p.fee, 500n);
  assert.equal(p.change, 0n);
});

test("coins carrying tokens are never spent, even when they would be enough", () => {
  const payer = bchKey(), payee = bchKey();
  const tokenCoin = coin(payer, 1_000_000n, { token_data: { category: "aa".repeat(32), amount: "1" } });
  assert.throws(() => buildPayment({ coins: [tokenCoin], to: payee.address, satoshis: 10_000n, changeLockingBytecode: payer.lock }), /not enough spendable coins/);
  const p = buildPayment({ coins: [tokenCoin, coin(payer, 20_000n)], to: payee.address, satoshis: 10_000n, changeLockingBytecode: payer.lock });
  assert.equal(p.sourceOutputs.length, 1);
  assert.equal(p.sourceOutputs[0].valueSatoshis, 20_000n);
});

test("payments under dust and to a non-P2PKH address are refused", () => {
  const payer = bchKey();
  assert.throws(() => buildPayment({ coins: [coin(payer, 20_000n)], to: payer.address, satoshis: DUST - 1n, changeLockingBytecode: payer.lock }), /smallest payment/);
  const p2sh = L.encodeCashAddress({ prefix: "bitcoincash", type: "p2sh", payload: rand(20) });
  assert.throws(() => buildPayment({ coins: [coin(payer, 20_000n)], to: typeof p2sh === "string" ? p2sh : p2sh.address, satoshis: 10_000n, changeLockingBytecode: payer.lock }), /only P2PKH/);
});

test("the wallet scan follows the gap limit, skips token coins and picks a fresh change address", async () => {
  const keys = new Map(); // "child/index" → key
  const keyAt = (child, index) => {
    const id = `${child}/${index}`;
    if (!keys.has(id)) keys.set(id, bchKey());
    return keys.get(id);
  };
  const used = new Map([[keyAt(0, 0).address, [{ value: 5_000, tx_hash: "11".repeat(32), tx_pos: 1 }]],
    [keyAt(0, 25).address, [{ value: 7_000, tx_hash: "22".repeat(32), tx_pos: 0 }, { value: 9_000, tx_hash: "33".repeat(32), tx_pos: 2, token_data: { amount: "5" } }]],
    [keyAt(1, 0).address, []]]); // a change address used once and emptied
  const chain = {
    getHistory: async (a) => (used.has(a) ? [{ tx_hash: "44".repeat(32), height: 1 }] : []),
    listCoins: async (a) => used.get(a) ?? [],
  };
  const { coins, change } = await scanWallet(chain, (child, i) => keyAt(child, Number(i)).pub);
  assert.deepEqual(coins.map((c) => [c.satoshis, c.path]), [[5_000n, ["receive", 0]], [7_000n, ["receive", 25]]]);
  assert.equal(change.address, keyAt(1, 1).address);
  assert.deepEqual(change.path, ["change", 1]);
});

test("names: npub, nprofile, hex, nostr: links and profile URLs", async () => {
  const pk = getPublicKey(generateSecretKey());
  const npub = nip19.npubEncode(pk);
  for (const input of [npub, `nostr:${npub}`, `https://primal.net/p/${npub}`, ` ${npub} `, pk]) {
    const r = await resolveName(input);
    assert.equal(r.pubkey, pk, input);
    assert.equal(r.npub, npub);
  }
  const nprofile = nip19.nprofileEncode({ pubkey: pk, relays: ["wss://relay.example.com", "http://not-a-relay"] });
  assert.deepEqual((await resolveName(nprofile)).relays, ["wss://relay.example.com"]);
  await assert.rejects(resolveName(npub.slice(0, -1) + (npub.endsWith("q") ? "p" : "q")), /checksum/);
  await assert.rejects(resolveName("hello there"), (e) => e.code === "unrecognized" && /Paste an npub/.test(e.message));
  // A domain that is down or refuses browsers: fetch only says « Failed to fetch », the message says it in words.
  const refused = async () => { throw new TypeError("Failed to fetch"); };
  await assert.rejects(resolveName("bob@example.com", { fetchImpl: refused }), /Couldn't look up bob@example\.com: no answer \(no Nostr names there/);
  const notJson = async () => ({ ok: true, json: async () => JSON.parse("<html>") });
  await assert.rejects(resolveName("bob@example.com", { fetchImpl: notJson }), /isn't a list of Nostr names/);
});

test("names: NIP-05 lookups use the exact name, no redirects, and check the key", async () => {
  const pk = getPublicKey(generateSecretKey());
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push([url, opts.redirect]);
    return { ok: true, json: async () => ({ names: { alice: pk, _: pk, bad: "zz" }, relays: { [pk]: ["wss://r.example.com"] } }) };
  };
  const r = await resolveName("Alice@Example.com", { fetchImpl });
  assert.equal(r.pubkey, pk);
  assert.deepEqual(r.relays, ["wss://r.example.com"]);
  assert.deepEqual(calls[0], ["https://example.com/.well-known/nostr.json?name=alice", "error"]);
  assert.equal((await resolveName("example.com", { fetchImpl })).pubkey, pk);
  await assert.rejects(resolveName("bob@example.com", { fetchImpl }), /doesn't list the name/);
  await assert.rejects(resolveName("bad@example.com", { fetchImpl }), /doesn't list the name/);
  await assert.rejects(resolveName("x@down.example", { fetchImpl: async () => ({ ok: false, status: 404 }) }), /answered 404/);
});

test("names: the shipped .well-known/nostr.json makes « countersign.cash » Countersign's own name", async () => {
  const doc = JSON.parse(await readFile(new URL("../app/public/.well-known/nostr.json", import.meta.url), "utf8"));
  const r = await resolveName("countersign.cash", { fetchImpl: async () => ({ ok: true, json: async () => doc }) });
  assert.equal(r.npub, "npub1v2zlnx5g0m847j4k34d30az2dykjwrlazp68fqwe3c0nekaqltkqd23d95");
  assert.equal(r.via, "_@countersign.cash");
  assert.ok(r.relays.length > 0);
});

test("names: a profile's NIP-05 is shown only when its domain lists that very key", async () => {
  const pk = getPublicKey(generateSecretKey()), other = getPublicKey(generateSecretKey());
  const fetchImpl = async () => ({ ok: true, json: async () => ({ names: { _: pk, bob: other } }) });
  assert.equal(await verifiedNip05("_@Example.com", pk, { fetchImpl }), "example.com");
  assert.equal(await verifiedNip05("bob@example.com", other, { fetchImpl }), "bob@example.com");
  assert.equal(await verifiedNip05("bob@example.com", pk, { fetchImpl }), null);   // the domain lists another key under that name
  assert.equal(await verifiedNip05("carol@example.com", pk, { fetchImpl }), null); // not listed
  assert.equal(await verifiedNip05(nip19.npubEncode(pk), pk, { fetchImpl }), null); // a key is not a name
  assert.equal(await verifiedNip05("not a name", pk, { fetchImpl }), null);
  assert.equal(await verifiedNip05(undefined, pk, { fetchImpl }), null);
  assert.equal(await verifiedNip05("_@down.example", pk, { fetchImpl: async () => { throw new TypeError("Failed to fetch"); } }), null);
});

test("a commitment from a wallet: fee sized for an ECDSA signer, WizardConnect paths and outpoints", () => {
  const key = bchKey();
  const npub = nip19.npubEncode(getPublicKey(generateSecretKey()));
  const c = buildCommitment({ address: key.address, npub, coins: [coin(key, 9_773n, { path: ["change", 0] })] });
  assert.deepEqual(c.inputPaths, [[0, "change", 0]]);
  assert.equal(L.binToHex(c.sourceOutputs[0].outpointTransactionHash), L.binToHex(c.transaction.inputs[0].outpointTransactionHash));
  const signed = signP2pkh(c.transaction, c.sourceOutputs, key.priv);
  assert.equal(L.createVirtualMachineBch(true).verify({ sourceOutputs: c.sourceOutputs, transaction: signed }), true);
  assert.ok(c.fee >= BigInt(L.encodeTransaction(signed).length) + 8n, "covers 8 more bytes than a Schnorr signature");
  assert.equal(buildCommitment({ address: key.address, npub, coins: [{ tx_hash: "11".repeat(32), tx_pos: 0, value: 5_000 }] }).inputPaths, null);
});
