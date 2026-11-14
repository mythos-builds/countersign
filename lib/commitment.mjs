// The BCH half of a binding (spec §3): a transaction spent from the address, whose one tagged
// data output names the Nostr key in NIP-39's own wording.
import * as L from "@bitauth/libauth";
import { nip19 } from "nostr-tools";

export const TAG = Uint8Array.of(0x43, 0x53, 0x47, 0x00); // "CSG\0" = protocol ID 0x00475343, Lokad style
export const NIP39_WORDING = "Verifying that I control the following Nostr public key: ";
export const ALLOWED_SIGHASH = [0x41, 0x61, 0xc1, 0xe1]; // ALL|FORKID, alone or with UTXOS / ANYONECANPAY: every output is covered
export const DUST = 546n;
export const MAX_INPUTS = 20; // a verifier fetches every parent, so a commitment can't make it fetch hundreds

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export function npubToHex(npub) {
  const d = nip19.decode(npub);
  if (d.type !== "npub") throw new Error("not an npub");
  return d.data;
}

/** P2PKH only in v0. A token-aware address has the same payload, so it decodes too. */
export function decodeP2pkhAddress(address) {
  const d = L.decodeCashAddress(address);
  if (typeof d === "string") throw new Error(`bad address: ${d}`);
  if (d.type !== "p2pkh" && d.type !== "p2pkhWithTokens") throw new Error("only P2PKH addresses are supported");
  return { ...d, lockingBytecode: L.encodeLockingBytecodeP2pkh(d.payload) };
}

export const sameAddress = (a, b) => {
  try { return eq(decodeP2pkhAddress(a).payload, decodeP2pkhAddress(b).payload) && a.split(":")[0] === b.split(":")[0]; } catch { return false; }
};

export function dataOutputBytecode(npub) {
  npubToHex(npub);
  return L.flattenBinArray([Uint8Array.of(0x6a), L.encodeDataPush(TAG), L.encodeDataPush(L.utf8ToBin(NIP39_WORDING + npub))]);
}

/** The Nostr key a transaction names: exactly one tagged data output, two pushes, NIP-39 wording (spec §3.2, §5.4). */
export function readCommitment(tx) {
  const tagged = tx.outputs
    .filter((o) => o.lockingBytecode[0] === 0x6a)
    .map((o) => L.decodeAuthenticationInstructions(o.lockingBytecode.slice(1)))
    .filter((ins) => ins[0]?.data && eq(ins[0].data, TAG));
  if (tagged.length !== 1) return { error: tagged.length ? "more than one Countersign data output" : "no Countersign data output" };
  const ins = tagged[0];
  if (ins.length !== 2 || ins.some((i) => i.malformed || !i.data)) return { error: "malformed Countersign data output" };
  const text = L.binToUtf8(ins[1].data);
  if (!text.startsWith(NIP39_WORDING)) return { error: "the data output doesn't use the NIP-39 wording" };
  const npub = text.slice(NIP39_WORDING.length);
  try { return { npub, pubkey: npubToHex(npub) }; } catch { return { error: "the data output names no valid npub" }; }
}

/** The input that proves the address signed (spec §5.5). sourceOutputs must come from re-hashed parents, never from the caller. */
export function findSigningInput(tx, sourceOutputs, payload) {
  const lock = L.encodeLockingBytecodeP2pkh(payload);
  let sighashProblem;
  for (const [i, input] of tx.inputs.entries()) {
    if (!eq(sourceOutputs[i].lockingBytecode, lock)) continue;
    const ins = L.decodeAuthenticationInstructions(input.unlockingBytecode);
    if (ins.length !== 2 || ins.some((x) => x.malformed || !x.data)) continue;
    const [sig, pub] = [ins[0].data, ins[1].data];
    if (!eq(L.hash160(pub), payload)) continue;
    if (!ALLOWED_SIGHASH.includes(sig.at(-1))) {
      sighashProblem = `input ${i} is signed with sighash 0x${sig.at(-1)?.toString(16)}, which doesn't cover every output`;
      continue;
    }
    return { index: i, publicKey: pub };
  }
  return { error: sighashProblem ?? "no input is signed by this address" };
}

/**
 * An unsigned commitment from the address's own coins: the data output, then change back to the same address.
 * coins = [{ txid, vout, satoshis, token? }], all locked to the address. Returns { transaction, sourceOutputs, fee }.
 */
export function buildCommitment({ address, npub, coins, feeRate = 1 }) {
  const { lockingBytecode } = decodeP2pkhAddress(address);
  const data = dataOutputBytecode(npub);
  // Accepts Fulcrum's listunspent shape too ({ tx_hash, tx_pos, value, token_data }).
  const usable = coins
    .filter((c) => !c.token && !c.token_data)
    .map((c) => ({ txid: c.txid ?? c.tx_hash, vout: c.vout ?? c.tx_pos, satoshis: BigInt(c.satoshis ?? c.value) }))
    .sort((a, b) => (b.satoshis > a.satoshis ? 1 : b.satoshis < a.satoshis ? -1 : 0));
  const dummyUnlock = new Uint8Array(100); // <65-byte Schnorr sig> <33-byte key>, with their push bytes
  const picked = [];
  let total = 0n;
  for (const coin of usable.slice(0, MAX_INPUTS)) {
    picked.push(coin);
    total += coin.satoshis;
    const draft = {
      version: 2, locktime: 0,
      inputs: picked.map((c) => ({ outpointTransactionHash: L.hexToBin(c.txid), outpointIndex: c.vout, sequenceNumber: 0, unlockingBytecode: dummyUnlock })),
      outputs: [{ lockingBytecode: data, valueSatoshis: 0n }, { lockingBytecode, valueSatoshis: 0n }],
    };
    const fee = BigInt(Math.ceil(L.encodeTransaction(draft).length * feeRate));
    if (total - fee < DUST) continue;
    draft.outputs[1].valueSatoshis = total - fee;
    draft.inputs = draft.inputs.map((i) => ({ ...i, unlockingBytecode: Uint8Array.of() }));
    return { transaction: draft, sourceOutputs: picked.map((c) => ({ lockingBytecode, valueSatoshis: c.satoshis })), fee };
  }
  throw new Error("not enough coins without tokens at this address to pay the fee");
}

/** Sign every input locked to this key (Schnorr). Wallets do this themselves; this is for tests and scripts. */
export function signP2pkh(transaction, sourceOutputs, privateKey, sighash = 0x41) {
  const pub = L.secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof pub === "string") throw new Error(pub);
  const lock = L.encodeLockingBytecodeP2pkh(L.hash160(pub));
  const inputs = transaction.inputs.map((input, inputIndex) => {
    if (!eq(sourceOutputs[inputIndex].lockingBytecode, lock)) return input;
    const serialization = L.generateSigningSerializationBch(
      { inputIndex, sourceOutputs, transaction },
      { coveredBytecode: lock, signingSerializationType: Uint8Array.of(sighash) },
    );
    const sig = L.secp256k1.signMessageHashSchnorr(privateKey, L.hash256(serialization));
    if (typeof sig === "string") throw new Error(sig);
    return { ...input, unlockingBytecode: L.flattenBinArray([L.encodeDataPush(L.flattenBinArray([sig, Uint8Array.of(sighash)])), L.encodeDataPush(pub)]) };
  });
  return { ...transaction, inputs };
}
