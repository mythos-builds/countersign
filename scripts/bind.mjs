// Bind a BCH address to a Nostr key from the command line: commitment transaction, then the NIP-39 claim.
// Usage: node scripts/bind.mjs --wif-file <file> --nostr-key-file <file> [--chipnet] [--dry-run]
// The WIF file holds the BCH key (bare, or JSON with a "wif" field); the Nostr key file holds the hex secret key.
// Keys are read from files, never from the command line, and never printed.
import { readFileSync } from "node:fs";
import * as L from "@bitauth/libauth";
import { finalizeEvent, getPublicKey, nip19 } from "nostr-tools";
import {
  buildCommitment, signP2pkh, buildClaim, fulcrumChain, relayReader, MAINNET_SERVERS, CHIPNET_SERVERS, DEFAULT_RELAYS,
} from "../lib/index.mjs";

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); if (i < 0 || !args[i + 1]) throw new Error(`missing ${name}`); return args[i + 1]; };
const chipnet = args.includes("--chipnet");

const wifText = readFileSync(opt("--wif-file"), "utf8").trim();
const key = L.decodePrivateKeyWif(wifText.startsWith("{") ? JSON.parse(wifText).wif : wifText);
if (typeof key === "string") throw new Error("the WIF file doesn't hold a valid key");
const pub = L.secp256k1.derivePublicKeyCompressed(key.privateKey);
const enc = L.encodeCashAddress({ prefix: chipnet ? "bchtest" : "bitcoincash", type: "p2pkh", payload: L.hash160(pub) });
const address = typeof enc === "string" ? enc : enc.address;
const sk = L.hexToBin(readFileSync(opt("--nostr-key-file"), "utf8").trim());
const pubkey = getPublicKey(sk);
const npub = nip19.npubEncode(pubkey);

const chain = await fulcrumChain(chipnet ? CHIPNET_SERVERS : MAINNET_SERVERS);
const nostr = relayReader();
let code = 0;
try {
  const { transaction, sourceOutputs, fee } = buildCommitment({ address, npub, coins: await chain.listCoins(address) });
  const signed = signP2pkh(transaction, sourceOutputs, key.privateKey);
  const ok = L.createVirtualMachineBch(true).verify({ sourceOutputs, transaction: signed }); // standard rules = what nodes relay
  if (ok !== true) throw new Error(`not broadcast, the BCH virtual machine rejects it: ${ok}`);
  const raw = L.encodeTransaction(signed);
  const txid = L.hashTransaction(raw);
  console.log(`commitment ${txid} · ${raw.length} bytes · fee ${fee} sat\n  ${address} → ${npub}`);
  if (!args.includes("--dry-run")) {
    const sent = await chain.broadcast(L.binToHex(raw));
    if (sent !== txid) throw new Error(`the server answered ${sent}, expected ${txid}`);
    console.log(`broadcast via ${chain.servers[0]}`);
    const { claim: current } = await nostr.fetchClaim(pubkey);
    const claim = finalizeEvent(buildClaim(current, address, txid), sk);
    const results = await nostr.publish(claim, DEFAULT_RELAYS);
    results.forEach((r, i) => console.log(`claim ${claim.id.slice(0, 12)}… → ${DEFAULT_RELAYS[i]}: ${r.status === "fulfilled" ? "accepted" : r.reason?.message ?? r.reason}`));
    if (!results.some((r) => r.status === "fulfilled")) code = 1;
  }
} catch (e) {
  console.error(e.message);
  code = 1;
} finally {
  chain.close();
  nostr.close();
}
process.exit(code);
