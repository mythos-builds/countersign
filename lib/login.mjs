// Login (spec §9): NIP-98 HTTP auth over a single-use challenge. The app hands out a URL carrying a fresh nonce,
// the person's Nostr key signs a kind 27235 event naming that exact URL and method, the app checks it and spends
// the nonce. Which BCH address the key is bound to is then verifyBinding's answer: no identity provider is asked.
// Optionally the wallet behind that address answers too, live: it signs a one-time code that can never be broadcast.
import * as L from "@bitauth/libauth";
import { nip19 } from "nostr-tools";
import { verifiedCopy } from "./nostr.mjs";
import { TAG, decodeP2pkhAddress, findSigningInput, npubToHex } from "./commitment.mjs";

export const LOGIN_KIND = 27235;
const SKEW = 60; // seconds either side of the app's clock (NIP-98)
const TTL = 120; // a challenge not answered by then is dropped
const WALLET_TTL = 300; // connecting a wallet and approving in it takes longer than a Nostr signature
const MAX_DATA_OUTPUT = 223; // bytes: the largest standard data output, a wallet may refuse a bigger one
const PROOF_TAG = L.sha256.hash(L.utf8ToBin("Countersign/wallet-proof")); // tagged hash, as in BIP-340 and BIP-322
const MAX_OPEN = 10_000; // open challenges kept at once; past that, the oldest goes

const randomHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const toBase64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const fromBase64 = (s) => new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));

/** The event that answers a challenge (NIP-98), to be signed by the person's key: NIP-07 extension, remote signer or secret key. */
export const loginTemplate = ({ url, method }, now = Math.floor(Date.now() / 1000)) =>
  ({ kind: LOGIN_KIND, created_at: now, tags: [["u", url], ["method", method]], content: "" });

/** The Authorization header that carries a signed answer. */
export const authorizationHeader = (event) => `Nostr ${toBase64(JSON.stringify(event))}`;

/** The words the wallet signs at login: the site, the Nostr key that just signed in, a one-time code. */
export const walletProofText = ({ host, npub, nonce }) => `Sign in to ${host} as ${npub}, one-time code ${nonce}`;

/**
 * What the wallet signs at login, BIP-322's construction on BCH (spec §9.5). A made-up parent transaction, whose one
 * input spends nothing and carries the text's hash, pays 0 sat to the address; the wallet signs a spend of that
 * output whose only output is the text, tagged. The parent can never be mined (a null outpoint outside a valid
 * coinbase), so no network accepts the spend: it moves nothing and costs no fee.
 * → { transaction, sourceOutputs }, unsigned, in WizardConnect's shape: the wallet signs input 0 with the address's key.
 */
export function walletProofTransaction({ address, text }) {
  const { lockingBytecode } = decodeP2pkhAddress(address);
  const data = L.flattenBinArray([Uint8Array.of(0x6a), L.encodeDataPush(TAG), L.encodeDataPush(L.utf8ToBin(text))]);
  if (data.length > MAX_DATA_OUTPUT) throw new Error("the text is too long for a standard data output");
  const hash = L.sha256.hash(L.flattenBinArray([PROOF_TAG, PROOF_TAG, L.utf8ToBin(text)]));
  const parent = {
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0xffffffff, sequenceNumber: 0, unlockingBytecode: L.flattenBinArray([Uint8Array.of(0x00), L.encodeDataPush(hash)]) }],
    outputs: [{ lockingBytecode, valueSatoshis: 0n }],
  };
  const input = { outpointTransactionHash: L.hashTransactionUiOrder(L.encodeTransaction(parent)), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() };
  return {
    transaction: { version: 2, locktime: 0, inputs: [input], outputs: [{ lockingBytecode: data, valueSatoshis: 0n }] },
    sourceOutputs: [{ ...input, lockingBytecode, valueSatoshis: 0n }],
  };
}

/**
 * The app's side. url = the login endpoint as people reach it (e.g. https://app.example/login).
 * Open challenges live in this object's memory: one process, or share the store.
 */
export function loginGate({ url, ttl = TTL, walletTtl = WALLET_TTL, skew = SKEW, clock = () => Math.floor(Date.now() / 1000) }) {
  const endpoint = new URL(url);
  const open = new Map(); // nonce → expires at
  const proofs = new Map(); // made-up parent's id → { npub, address, text, expires }
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
    /**
     * After a sign-in, ask the wallet behind the bound address to answer too (spec §9.5). npub = who signed in,
     * address = verifyBinding's answer for it. → { npub, address, text, transaction, sourceOutputs, expiresAt }:
     * the person's wallet signs `transaction` without broadcasting it, and the signed hex comes back to walletCheck.
     */
    walletChallenge({ npub, address }) {
      npubToHex(npub);
      const now = clock();
      for (const [id, p] of proofs) if (p.expires < now) proofs.delete(id);
      if (proofs.size >= MAX_OPEN) proofs.delete(proofs.keys().next().value);
      const text = walletProofText({ host: endpoint.host, npub, nonce: randomHex(16) });
      const built = walletProofTransaction({ address, text });
      proofs.set(L.binToHex(built.transaction.inputs[0].outpointTransactionHash), { npub, address, text, expires: now + walletTtl });
      return { npub, address, text, ...built, expiresAt: now + walletTtl };
    },
    /**
     * signed = the wallet's signed transaction, hex. → { npub, address, publicKey }, the challenge spent; or { error }:
     * as with check(), a wrong answer leaves the challenge open for the right one.
     */
    walletCheck(signed) {
      const now = clock();
      const tx = typeof signed === "string" && /^(?:[0-9a-f]{2})+$/i.test(signed) ? L.decodeTransaction(L.hexToBin(signed)) : "not hex";
      if (typeof tx === "string") return { error: "the answer isn't a transaction" };
      if (tx.inputs.length !== 1) return { error: "a wallet's answer has exactly one input" };
      const id = L.binToHex(tx.inputs[0].outpointTransactionHash);
      const asked = proofs.get(id);
      if (!asked) return { error: "this challenge was never issued here, or it was already used" };
      // Rebuilt from what was asked, never taken from the answer: the wallet may add its signature and nothing else.
      const expected = walletProofTransaction(asked);
      const unsigned = { ...tx, inputs: [{ ...tx.inputs[0], unlockingBytecode: Uint8Array.of() }] };
      if (L.binToHex(L.encodeTransaction(unsigned)) !== L.binToHex(L.encodeTransaction(expected.transaction))) return { error: "the wallet changed the transaction" };
      const signer = findSigningInput(tx, expected.sourceOutputs, decodeP2pkhAddress(asked.address).payload);
      if (signer.error) return signer;
      const ok = L.createVirtualMachineBch(false).verify({ sourceOutputs: expected.sourceOutputs, transaction: tx });
      if (ok !== true) return { error: `the signature doesn't verify: ${ok}` };
      proofs.delete(id);
      if (asked.expires < now) return { error: "the challenge expired" };
      return { npub: asked.npub, address: asked.address, publicKey: L.binToHex(signer.publicKey) };
    },
  };
}
