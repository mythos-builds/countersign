// WizardConnect spike, end to end on one machine: a dapp and a throwaway reference wallet talk through
// the public WizardConnect relays, the wallet hands over its xpubs, the dapp builds an
// "identity commitment" transaction (OP_RETURN + change) and asks for one signature,
// then the BCH virtual machine checks the signed transaction. Fake input: nothing is broadcast.
import { once } from "node:events";
import { initiateDappRelay, childIndexOfPathName, parseExtendedJson } from "@wizardconnect/core";
import { DappConnectionManager } from "@wizardconnect/dapp";
import { WalletConnectionManager } from "@wizardconnect/wallet";
import * as L from "@bitauth/libauth";

const t0 = Date.now();
const ms = () => `${((Date.now() - t0) / 1000).toFixed(1)}s`;
const ok = (x, what) => { if (typeof x === "string") throw new Error(`${what}: ${x}`); return x; };
const cat = (...a) => L.flattenBinArray(a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x))));
const utf8 = (s) => new TextEncoder().encode(s);
// the relay JSON.stringify()s messages: bigint/Uint8Array must travel in libauth's extended form
const wire = (o) => JSON.parse(L.stringify(o));
const withTimeout = (p, s, what) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout ${s}s: ${what}`)), s * 1000))]);

// ── throwaway HD wallet (m/44'/145'/0'/<child>/<index>) ──
const seed = L.generateRandomBytes(32);
const account = ok(L.deriveHdPath(ok(L.deriveHdPrivateNodeFromSeed(seed), "seed"), "m/44'/145'/0'"), "account");
const childNode = (child) => ok(L.deriveHdPathRelative(account, `${child}`), "child");
const privAt = (child, i) => ok(L.deriveHdPathRelative(account, `${child}/${i}`), "leaf").privateKey;
const pubOf = (priv) => ok(L.secp256k1.derivePublicKeyCompressed(priv), "pub");
const seen = {};

const adapter = {
  walletName: "Spike wallet (local, throwaway)",
  walletIcon: "",
  getRelayPrivateKey: (uri) => L.sha256.hash(cat(seed, utf8(uri))),
  getPublicKey: (path, index) => pubOf(privAt(path, index)),
  getXpub: (path) => {
    const r = ok(L.encodeHdPublicKey({ network: "testnet", node: L.deriveHdPublicNode(childNode(path)) }), "xpub");
    return typeof r === "string" ? r : r.hdPublicKey;
  },
  async signTransaction(request) {
    seen.onWire = JSON.stringify(request.transaction.sourceOutputs[0]).slice(0, 120);
    const wc = parseExtendedJson(JSON.stringify(request.transaction));
    seen.txType = typeof wc.transaction;
    seen.valueType = typeof wc.sourceOutputs[0]?.valueSatoshis;
    seen.bytecodeType = wc.sourceOutputs[0]?.lockingBytecode?.constructor?.name;
    seen.userPrompt = wc.userPrompt;
    seen.broadcast = wc.broadcast;
    const tx = typeof wc.transaction === "string" ? ok(L.decodeTransaction(L.hexToBin(wc.transaction)), "decode") : wc.transaction;
    const sourceOutputs = wc.sourceOutputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token }));
    const inputs = tx.inputs.map((i) => ({ ...i }));
    for (const [inputIndex, pathName, addrIndex] of request.inputPaths) {
      const priv = privAt(childIndexOfPathName(pathName), BigInt(addrIndex));
      const pub = pubOf(priv);
      // a real wallet must refuse to sign an input whose coin is not its own key
      const mine = L.encodeLockingBytecodeP2pkh(L.hash160(pub));
      if (L.binToHex(mine) !== L.binToHex(sourceOutputs[inputIndex].lockingBytecode)) throw new Error(`input ${inputIndex} is not ${pathName}/${addrIndex}`);
      const preimage = L.generateSigningSerializationBch(
        { inputIndex, sourceOutputs, transaction: { ...tx, inputs } },
        { coveredBytecode: sourceOutputs[inputIndex].lockingBytecode, signingSerializationType: Uint8Array.of(0x41) },
      );
      const sig = ok(L.secp256k1.signMessageHashSchnorr(priv, L.sha256.hash(L.sha256.hash(preimage))), "sign");
      inputs[inputIndex] = { ...inputs[inputIndex], unlockingBytecode: cat(L.encodeDataPush(cat(sig, [0x41])), L.encodeDataPush(pub)) };
    }
    return { signedTransaction: L.binToHex(L.encodeTransaction({ ...tx, inputs })) };
  },
};

// ── dapp side ──
const dapp = new DappConnectionManager("BLAZE spike", undefined, { session: false });
const relay = initiateDappRelay(({ client, status }) => {
  console.log(`[${ms()}] dapp relay: ${status.status}${status.error ? " " + status.error : ""}`);
  dapp.updateConnection(client, status);
});
dapp.attachRelay(relay);
console.log(`[${ms()}] URI scheme/shape: ${relay.uri.replace(/([?&](s|secret|k)=)[^&]+/g, "$1<hidden>").slice(0, 160)}`);
console.log(`[${ms()}] URI length ${relay.uri.length}, qrUri length ${relay.qrUri.length}`);

// ── wallet side ──
const wallet = new WalletConnectionManager(adapter);
wallet.on("connectionStatusChanged", (id, st) => console.log(`[${ms()}] wallet relay: ${st.status}`));
wallet.on("pendingSignRequest", async ({ connectionId, request }) => {
  console.log(`[${ms()}] wallet got sign_transaction_request seq=${request.sequence} inputs=${JSON.stringify(request.inputPaths)}`);
  try {
    const { signedTransaction } = await adapter.signTransaction(request);
    await wallet.sendSignResponse(connectionId, request.sequence, signedTransaction);
  } catch (e) {
    await wallet.sendSignError(connectionId, request.sequence, String(e.message || e));
  }
});

let code = 1;
try {
  const ready = once(dapp, "walletready");
  wallet.connect(relay.uri);
  const [msg] = await withTimeout(ready, 45, "wallet_ready");
  console.log(`[${ms()}] dapp got wallet_ready: wallet="${dapp.walletName}" protocol=${dapp.protocol} paths=${dapp.getSessionPaths().map((p) => p.name).join(",")}`);

  // the dapp derives the wallet's keys itself from the xpubs: no round trip per address
  const pkR = dapp.getPubkey(0, 0n), pkC = dapp.getPubkey(1, 0n);
  const lockR = L.encodeLockingBytecodeP2pkh(L.hash160(pkR));
  const lockC = L.encodeLockingBytecodeP2pkh(L.hash160(pkC));
  const addr = ok(L.encodeCashAddress({ prefix: "bchtest", type: "p2pkh", payload: L.hash160(pkR) }), "addr");
  console.log(`[${ms()}] receive/0 address derived by the dapp: ${typeof addr === "string" ? addr : addr.address}`);
  const derivedOk = L.binToHex(pkR) === L.binToHex(adapter.getPublicKey(0, 0n));
  console.log(`[${ms()}] dapp-derived pubkey == wallet pubkey: ${derivedOk}`);

  // identity commitment: OP_RETURN "BLZID" <32-byte Nostr pubkey stand-in>, change back to the wallet
  const fakeTxid = L.generateRandomBytes(32);
  const npub = L.generateRandomBytes(32);
  const source = { outpointIndex: 0, outpointTransactionHash: fakeTxid, sequenceNumber: 0, unlockingBytecode: Uint8Array.of(), lockingBytecode: lockR, valueSatoshis: 10_000n };
  const tx = {
    version: 2, locktime: 0,
    inputs: [{ outpointIndex: 0, outpointTransactionHash: fakeTxid, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() }],
    outputs: [
      { lockingBytecode: cat([0x6a], L.encodeDataPush(utf8("BLZID")), L.encodeDataPush(npub)), valueSatoshis: 0n },
      { lockingBytecode: lockC, valueSatoshis: 9_700n },
    ],
  };
  const res = await withTimeout(
    dapp.signTransaction({ transaction: wire({ transaction: tx, sourceOutputs: [source], broadcast: false, userPrompt: "Bind your Nostr key (spike)" }), inputPaths: [[0, "receive", 0]] }),
    45, "sign_transaction_response");
  console.log(`[${ms()}] dapp got sign_transaction_response: ${res.error ? "ERROR " + res.error : res.signedTransaction.length / 2 + " bytes"}`);
  console.log(`[${ms()}] what the wallet saw: ${JSON.stringify(seen)}`);

  const signed = ok(L.decodeTransaction(L.hexToBin(res.signedTransaction)), "decode signed");
  const verdict = L.createVirtualMachineBch().verify({ sourceOutputs: [{ lockingBytecode: lockR, valueSatoshis: 10_000n }], transaction: signed });
  console.log(`[${ms()}] BCH VM verify: ${verdict === true ? "VALID" : verdict}`);
  const h = L.hashTransaction(L.encodeTransaction(signed));
  console.log(`[${ms()}] txid would be ${typeof h === "string" ? h : L.binToHex(h)}`);

  // a coin that is not the wallet's must be refused, not signed
  const badSource = { ...source, lockingBytecode: L.encodeLockingBytecodeP2pkh(L.hash160(pkC)) };
  const bad = await withTimeout(dapp.signTransaction({ transaction: wire({ transaction: tx, sourceOutputs: [badSource] }), inputPaths: [[0, "receive", 0]] }), 45, "bad request")
    .then((r) => (r.error ? `refused: ${r.error}` : "SIGNED (bad)"), (e) => `rejected: ${e.message}`);
  console.log(`[${ms()}] mismatched-coin request -> ${bad}`);
  code = verdict === true && derivedOk && !bad.startsWith("SIGNED") ? 0 : 2;
} catch (e) {
  console.log(`[${ms()}] FAILED: ${e.stack || e}`);
} finally {
  try { await dapp.sendDisconnect("spike done"); } catch {}
  try { wallet.disconnectAll(); } catch {}
  try { relay.cleanup(); dapp.destroy(); } catch {}
  setTimeout(() => process.exit(code), 500);
}
