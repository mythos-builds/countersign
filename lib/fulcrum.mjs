// Minimal Electrum (Fulcrum) JSON-RPC client over WebSocket, for browsers and Node 22+.
// Servers can hide data but never forge it: every transaction is re-hashed against its id here, and again in verify.mjs.
import * as L from "@bitauth/libauth";

export const MAINNET_SERVERS = ["wss://bch.imaginary.cash:50004", "wss://bch.loping.net:50004", "wss://blackie.c3-soft.com:50004", "wss://electroncash.dk:50004"];
export const CHIPNET_SERVERS = ["wss://chipnet.imaginary.cash:50004"];

export function connect(url, { timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const pending = new Map();
    const listeners = new Map(); // notification method → Set of callbacks
    let id = 0;
    const failAll = (err) => { for (const p of pending.values()) p.reject(err); pending.clear(); };
    const openTimer = setTimeout(() => { ws.close(); reject(new Error(`${url}: no connection after ${timeoutMs} ms`)); }, timeoutMs);
    const call = (method, ...params) => new Promise((res, rej) => {
      // send() on a closed socket drops the message without a word: fail now rather than at the timeout.
      if (ws.readyState !== WebSocket.OPEN) return rej(new Error(`${url}: connection closed`));
      const n = ++id;
      // A socket silent this long is taken for dead (a phone waking up keeps half-open ones): closing it gets it replaced.
      const t = setTimeout(() => { pending.delete(n); rej(new Error(`${url}: ${method} timed out`)); ws.close(); }, timeoutMs);
      pending.set(n, { resolve: (v) => { clearTimeout(t); res(v); }, reject: (e) => { clearTimeout(t); rej(e); } });
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: n, method, params }));
    });
    ws.onmessage = (e) => {
      let m;
      try { m = JSON.parse(e.data); } catch { return; }
      if (m.method && m.id == null) { listeners.get(m.method)?.forEach((fn) => fn(m.params)); return; }
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      m.error ? p.reject(new Error(`${url}: ${m.error.message ?? JSON.stringify(m.error)}`)) : p.resolve(m.result);
    };
    ws.onerror = () => { clearTimeout(openTimer); const err = new Error(`${url}: socket error`); failAll(err); reject(err); };
    ws.onclose = () => failAll(new Error(`${url}: connection closed`));
    ws.onopen = async () => {
      clearTimeout(openTimer);
      try {
        await call("server.version", "countersign 0.1", "1.4");
        const on = (method, fn) => {
          if (!listeners.has(method)) listeners.set(method, new Set());
          listeners.get(method).add(fn);
          return () => listeners.get(method).delete(fn);
        };
        resolve({ url, call, on, open: () => ws.readyState === WebSocket.OPEN, close: () => ws.close() });
      } catch (err) { ws.close(); reject(err); }
    };
  });
}

/**
 * A chain reader over several servers: each question goes to the next server when one fails or lies.
 * Sockets drop (a phone tab sent to the background, a server's idle timeout): the open ones carry on, and with
 * none left the reader connects to every server again.
 */
export async function fulcrumChain(servers = MAINNET_SERVERS, opts) {
  let clients = [];
  let connecting = null;
  let closed = false;
  const connectAll = async () => {
    const settled = await Promise.allSettled(servers.map((u) => connect(u, opts)));
    const fresh = settled.filter((r) => r.status === "fulfilled").map((r) => r.value);
    if (!fresh.length) throw new Error(`no Fulcrum server reachable (${settled.map((r) => r.reason?.message).join("; ")})`);
    return (clients = fresh);
  };
  const live = async () => {
    if (closed) throw new Error("this chain reader was closed");
    const open = clients.filter((c) => c.open());
    return open.length ? open : (connecting ??= connectAll().finally(() => { connecting = null; }));
  };
  await live();
  const first = async (method, ...params) => {
    let last;
    for (const c of await live()) {
      try { return await c.call(method, ...params); } catch (e) { last = e; }
    }
    throw last;
  };
  return {
    get servers() { return clients.map((c) => c.url); },
    async getTx(txid) {
      for (const c of await live()) {
        const raw = await c.call("blockchain.transaction.get", txid, false).then((hex) => L.hexToBin(hex)).catch(() => null);
        if (raw && L.hashTransaction(raw) === txid) return raw;
      }
      throw new Error(`no server returned transaction ${txid}`);
    },
    getHistory: (address) => first("blockchain.address.get_history", address),
    getTipHeight: async () => (await first("blockchain.headers.get_tip")).height,
    getHeader: async (height) => L.hexToBin(await first("blockchain.block.header", height)),
    // Coins carrying CashTokens are left out here and again by the builder: spending them without their tokens burns the tokens.
    listCoins: (address) => first("blockchain.address.listunspent", address, "exclude_tokens"),
    broadcast: (rawHex) => first("blockchain.transaction.broadcast", rawHex),
    /** Calls onChange(statusHash) each time the address gains a transaction, mempool included. Returns { status, stop }. */
    async watchAddress(address, onChange) {
      let last;
      for (const c of await live()) {
        const off = c.on("blockchain.address.subscribe", ([a, status]) => { if (a === address) onChange(status); });
        try {
          const status = await c.call("blockchain.address.subscribe", address);
          return { status, server: c.url, stop: () => { off(); c.call("blockchain.address.unsubscribe", address).catch(() => {}); } };
        } catch (e) { off(); last = e; }
      }
      throw last;
    },
    close: () => { closed = true; clients.forEach((c) => c.close()); },
  };
}

/** Block time from an 80-byte header (seconds since 1970). */
export const headerTime = (header) => new DataView(header.buffer, header.byteOffset).getUint32(68, true);
