// Wallet half of the spike (argv[2] = wiz:// URI from the page). From e2e.mjs: a dapp and a throwaway reference wallet talk through
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


const wallet = new WalletConnectionManager(adapter);
wallet.on("connectionStatusChanged", (id, st) => console.log(`[${ms()}] wallet relay: ${st.status}`));
wallet.on("pendingSignRequest", async ({ connectionId, request }) => {
  console.log(`[${ms()}] sign request seq=${request.sequence} prompt="${request.transaction.userPrompt}"`);
  try {
    const { signedTransaction } = await adapter.signTransaction(request);
    await wallet.sendSignResponse(connectionId, request.sequence, signedTransaction);
    console.log(`[${ms()}] signed and sent (${signedTransaction.length / 2} bytes)`);
  } catch (e) {
    await wallet.sendSignError(connectionId, request.sequence, String(e.message || e));
    console.log(`[${ms()}] refused: ${e.message || e}`);
  }
});
wallet.connect(process.argv[2]);
setTimeout(() => { wallet.disconnectAll(); setTimeout(() => process.exit(0), 500); }, Number(process.argv[3] || 90) * 1000);
