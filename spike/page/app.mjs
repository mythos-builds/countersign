// Browser side of the spike: connect any WizardConnect wallet, ask for one signature.
// Fake input, broadcast: false, so nothing ever reaches the chain.
import { initiateDappRelay } from "@wizardconnect/core";
import { DappConnectionManager } from "@wizardconnect/dapp";
import * as L from "@bitauth/libauth";
import { renderSVG } from "uqr";

const $ = (id) => document.getElementById(id);
const log = (m) => { $("log").textContent += `${new Date().toISOString().slice(11, 19)} ${m}\n`; };
const wire = (o) => JSON.parse(L.stringify(o)); // the relay JSON.stringify()s: bigint/Uint8Array in libauth's extended form
const utf8 = (s) => new TextEncoder().encode(s);
const cat = (...a) => L.flattenBinArray(a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x))));
const spike = (window.spike = { status: "idle", broadcast: new URLSearchParams(location.search).has("broadcast") });
let dapp, relay, lockR, lockC;

$("connect").onclick = () => {
  $("connect").disabled = true;
  dapp = new DappConnectionManager("BLAZE spike", undefined, { session: false });
  relay = initiateDappRelay(({ client, status }) => { log(`relay ${status.status}`); dapp.updateConnection(client, status); });
  dapp.attachRelay(relay);
  spike.uri = relay.uri;
  spike.status = "waiting";
  $("qr").innerHTML = renderSVG(relay.qrUri);
  $("open").href = relay.uri;
  $("open").hidden = false;
  dapp.on("walletready", () => {
    const pkR = dapp.getPubkey(0, 0n);
    lockR = L.encodeLockingBytecodeP2pkh(L.hash160(pkR));
    lockC = L.encodeLockingBytecodeP2pkh(L.hash160(dapp.getPubkey(1, 0n)));
    const a = L.encodeCashAddress({ prefix: "bchtest", type: "p2pkh", payload: L.hash160(pkR) });
    spike.address = typeof a === "string" ? a : a.address;
    spike.wallet = dapp.walletName;
    spike.status = "connected";
    log(`wallet ready: ${dapp.walletName} · ${spike.address}`);
    $("sign").disabled = false;
  });
  dapp.on("disconnect", (reason, m) => { spike.status = "disconnected"; log(`disconnect ${reason} ${m ?? ""}`); });
};

$("sign").onclick = async () => {
  $("sign").disabled = true;
  const fakeTxid = L.generateRandomBytes(32);
  const source = { outpointIndex: 0, outpointTransactionHash: fakeTxid, sequenceNumber: 0, unlockingBytecode: Uint8Array.of(), lockingBytecode: lockR, valueSatoshis: 10_000n };
  const tx = {
    version: 2, locktime: 0,
    inputs: [{ outpointIndex: 0, outpointTransactionHash: fakeTxid, sequenceNumber: 0, unlockingBytecode: Uint8Array.of() }],
    outputs: [
      { lockingBytecode: cat([0x6a], L.encodeDataPush(utf8("BLZID")), L.encodeDataPush(L.generateRandomBytes(32))), valueSatoshis: 0n },
      { lockingBytecode: lockC, valueSatoshis: 9_700n },
    ],
  };
  spike.status = "signing";
  log("sign request sent: check your wallet");
  try {
    const res = await dapp.signTransaction({
      transaction: wire({ transaction: tx, sourceOutputs: [source], broadcast: spike.broadcast, userPrompt: spike.broadcast ? "BLAZE spike: broadcast test (fake coin, must fail)" : "BLAZE spike: test signature, never broadcast" }),
      inputPaths: [[0, "receive", 0]],
    });
    const signed = L.decodeTransaction(L.hexToBin(res.signedTransaction));
    const v = L.createVirtualMachineBch().verify({ sourceOutputs: [{ lockingBytecode: lockR, valueSatoshis: 10_000n }], transaction: signed });
    spike.verdict = v === true ? "VALID" : String(v);
  } catch (e) {
    spike.verdict = `error: ${e.message || e}`;
  }
  spike.status = "done";
  log(`signature: ${spike.verdict}`);
  $("sign").disabled = false;
};
