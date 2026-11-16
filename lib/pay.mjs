// Paying a bound name (spec §8). The payer's wallet signs; this file finds the payer's coins through
// public keys only, builds a plain P2PKH payment, and reads payments back from the chain.
import * as L from "@bitauth/libauth";
import { decodeP2pkhAddress, DUST, WALLET_UNLOCK_BYTES } from "./commitment.mjs";
import { getVerifiedTx } from "./verify.mjs";

export const SATS_PER_BCH = 100_000_000n;
const WALLET_UNLOCK = new Uint8Array(WALLET_UNLOCK_BYTES);

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** "0.0001" → 10000n. null unless it is a positive amount with 8 decimals at most. */
export function parseBch(text) {
  const m = /^\s*(\d{0,8})(?:[.,](\d{0,8}))?\s*$/.exec(String(text ?? ""));
  if (!m || (!m[1] && !m[2])) return null;
  const sats = BigInt(m[1] || "0") * SATS_PER_BCH + BigInt((m[2] ?? "").padEnd(8, "0"));
  return sats > 0n ? sats : null;
}

/** 10000n → "0.0001" */
export function formatBch(sats) {
  const s = BigInt(sats);
  const frac = (s % SATS_PER_BCH).toString().padStart(8, "0").replace(/0+$/, "");
  return frac ? `${s / SATS_PER_BCH}.${frac}` : `${s / SATS_PER_BCH}`;
}

/** The payment link any BCH wallet opens: bitcoincash:q…?amount=0.0001 */
export const paymentUri = (address, sats) => (sats ? `${address}?amount=${formatBch(sats)}` : address);

/** Satoshis a decoded transaction pays to this address. */
export function paidTo(tx, address) {
  const lock = decodeP2pkhAddress(address).lockingBytecode;
  return tx.outputs.reduce((sum, o) => (eq(o.lockingBytecode, lock) ? sum + o.valueSatoshis : sum), 0n);
}

export function p2pkhAddress(publicKey, prefix = "bitcoincash") {
  const enc = L.encodeCashAddress({ prefix, type: "p2pkh", payload: L.hash160(publicKey) });
  return typeof enc === "string" ? enc : enc.address;
}

/**
 * The spendable coins of an HD wallet seen through its public keys (WizardConnect gives xpubs, never private keys).
 * pubkeyAt(childIndex, index) → compressed public key or undefined; childIndex 0 = receive, 1 = change.
 * Scans each chain until `gap` unused addresses in a row. The coin list is a server's word, so each coin is checked against
 * its parent transaction, fetched and re-hashed: one that carries tokens there (spending it would burn them), whose value
 * or lock differs, or whose parent no server returns, is left out.
 * → { coins: [{ txid, vout, satoshis, lockingBytecode, path: [name, index] }], change: { address, lockingBytecode, path } }
 */
export async function scanWallet(chain, pubkeyAt, { gap = 20, prefix = "bitcoincash", maxAddresses = 400 } = {}) {
  const coins = [];
  const firstUnused = {};
  for (const [name, child] of [["receive", 0], ["change", 1]]) {
    if (!pubkeyAt(child, 0n)) continue;
    let unused = 0;
    for (let start = 0; unused < gap && start < maxAddresses; start += gap) {
      const batch = await Promise.all(Array.from({ length: gap }, async (_, k) => {
        const index = start + k;
        const pub = pubkeyAt(child, BigInt(index));
        const address = p2pkhAddress(pub, prefix);
        const [history, utxos] = await Promise.all([chain.getHistory(address), chain.listCoins(address)]);
        return { index, address, used: history.length > 0, utxos, lockingBytecode: L.encodeLockingBytecodeP2pkh(L.hash160(pub)) };
      }));
      for (const b of batch) {
        unused = b.used ? 0 : unused + 1;
        if (!b.used && !firstUnused[name]) firstUnused[name] = { address: b.address, lockingBytecode: b.lockingBytecode, path: [name, b.index] };
        for (const u of b.utxos) {
          if (u.token_data) continue;
          coins.push({ txid: u.tx_hash, vout: u.tx_pos, satoshis: BigInt(u.value), lockingBytecode: b.lockingBytecode, path: [name, b.index] });
        }
      }
    }
  }
  const parents = new Map();
  const checked = [];
  for (const c of coins) {
    if (!parents.has(c.txid)) parents.set(c.txid, getVerifiedTx(chain, c.txid).catch(() => null));
    const out = (await parents.get(c.txid))?.outputs[c.vout];
    if (out && !out.token && out.valueSatoshis === c.satoshis && eq(out.lockingBytecode, c.lockingBytecode)) checked.push(c);
  }
  return { coins: checked, change: firstUnused.change ?? firstUnused.receive };
}

/**
 * Where an address sits in an HD wallet seen through its public keys: [name, index] (receive or change), or null
 * if it isn't among the first `max` of either chain. Derivation only: no server is asked.
 */
export function findAddressPath(pubkeyAt, address, { max = 2000 } = {}) {
  const want = L.binToHex(decodeP2pkhAddress(address).payload);
  const chains = [["receive", 0], ["change", 1]].filter(([, child]) => pubkeyAt(child, 0n));
  for (let index = 0; index < max; index++) {
    for (const [name, child] of chains) if (L.binToHex(L.hash160(pubkeyAt(child, BigInt(index)))) === want) return [name, index];
  }
  return null;
}

/**
 * The wallet's signed transaction held to the one built here (a payment or a commitment): the same coins spent, the same
 * outputs, and the BCH virtual machine accepts it with the built source outputs. Throws otherwise: the page sends only what it built.
 */
export function checkSigned(built, signed) {
  const out = (o) => `${o.valueSatoshis}:${L.binToHex(o.lockingBytecode)}`;
  if (signed.outputs.map(out).join() !== built.transaction.outputs.map(out).join()) throw new Error("the wallet changed the transaction's outputs, so this page won't send it");
  const spent = (i) => `${L.binToHex(i.outpointTransactionHash)}:${i.outpointIndex}`;
  if (signed.inputs.map(spent).join() !== built.transaction.inputs.map(spent).join()) throw new Error("the wallet spent other coins than the ones this page chose, so this page won't send it");
  const ok = L.createVirtualMachineBch(true).verify({ sourceOutputs: built.sourceOutputs, transaction: signed });
  if (ok !== true) throw new Error(`the signed transaction doesn't verify: ${ok}`);
}

/**
 * An unsigned payment from the payer's coins: one output to the payee, then change if it is above dust.
 * Largest coins first; a leftover under dust goes to the fee. Coins carrying tokens are refused here too.
 * → { transaction, sourceOutputs, inputPaths, fee, change } — sourceOutputs and inputPaths in WizardConnect's shape.
 */
export function buildPayment({ coins, to, satoshis, changeLockingBytecode, feeRate = 1 }) {
  const amount = BigInt(satoshis);
  if (amount < DUST) throw new Error(`the smallest payment is ${DUST} satoshis`);
  const payee = decodeP2pkhAddress(to).lockingBytecode;
  const usable = coins
    .filter((c) => !c.token && !c.token_data)
    .sort((a, b) => (b.satoshis > a.satoshis ? 1 : b.satoshis < a.satoshis ? -1 : 0));
  const picked = [];
  let total = 0n;
  const draft = (withChange) => ({
    version: 2, locktime: 0,
    inputs: picked.map((c) => ({ outpointTransactionHash: L.hexToBin(c.txid), outpointIndex: c.vout, sequenceNumber: 0, unlockingBytecode: WALLET_UNLOCK })),
    outputs: [{ lockingBytecode: payee, valueSatoshis: amount }, ...(withChange ? [{ lockingBytecode: changeLockingBytecode, valueSatoshis: 0n }] : [])],
  });
  const feeOf = (tx) => BigInt(Math.ceil(L.encodeTransaction(tx).length * feeRate));
  const finish = (tx, fee, change) => ({
    transaction: { ...tx, inputs: tx.inputs.map((i) => ({ ...i, unlockingBytecode: Uint8Array.of() })) },
    sourceOutputs: picked.map((c) => ({
      outpointTransactionHash: L.hexToBin(c.txid), outpointIndex: c.vout, sequenceNumber: 0, unlockingBytecode: Uint8Array.of(),
      lockingBytecode: c.lockingBytecode, valueSatoshis: c.satoshis,
    })),
    inputPaths: picked.map((c, i) => [i, c.path[0], c.path[1]]),
    fee,
    change,
  });
  for (const coin of usable) {
    picked.push(coin);
    total += coin.satoshis;
    if (changeLockingBytecode) {
      const tx = draft(true);
      const fee = feeOf(tx);
      if (total - amount - fee >= DUST) {
        tx.outputs[1].valueSatoshis = total - amount - fee;
        return finish(tx, fee, total - amount - fee);
      }
    }
    const tx = draft(false);
    if (total - amount >= feeOf(tx)) return finish(tx, total - amount, 0n);
  }
  throw new Error("not enough spendable coins in this wallet (coins carrying tokens are never spent)");
}
