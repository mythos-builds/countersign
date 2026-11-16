// Offline tests for the Fulcrum client: sockets that drop or go silent are replaced, never waited on for nothing;
// heights, headers and histories are cross-checked between servers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fulcrumChain, headerTime } from "../lib/index.mjs";

/** A stand-in for a Fulcrum server behind a WebSocket. The test can cut it, or make it silent while it looks open. */
class FakeSocket {
  static OPEN = 1;
  static made = [];
  static pings = 0;
  static answers = new Map(); // url → { method: result } where a server answers its own way
  readyState = 0;
  silent = false;
  constructor(url) {
    this.url = url;
    FakeSocket.made.push(this);
    queueMicrotask(() => { this.readyState = 1; this.onopen?.(); });
  }
  send(text) {
    if (this.readyState !== 1 || this.silent) return; // like a browser on a closed socket: the message is dropped
    const { id, method } = JSON.parse(text);
    if (method === "server.ping") FakeSocket.pings++;
    const result = FakeSocket.answers.get(this.url)?.[method] ?? (method === "blockchain.headers.get_tip" ? { height: 977_400, hex: "" } : ["fake", "1.4"]);
    queueMicrotask(() => this.onmessage?.({ data: JSON.stringify({ jsonrpc: "2.0", id, result }) }));
  }
  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    queueMicrotask(() => this.onclose?.());
  }
}

const servers = ["wss://a.example", "wss://b.example"];
const tick = () => new Promise((r) => setTimeout(r, 0));
async function fakeChain(t, urls = servers) {
  const real = globalThis.WebSocket;
  globalThis.WebSocket = FakeSocket;
  FakeSocket.made = [];
  FakeSocket.answers = new Map();
  const chain = await fulcrumChain(urls, { timeoutMs: 200 });
  t.after(() => { chain.close(); globalThis.WebSocket = real; });
  return chain;
}
async function quick(fn) {
  const started = Date.now();
  const value = await fn();
  assert.ok(Date.now() - started < 150, "answered at once, not after a timeout");
  return value;
}

test("every socket dropped (a phone tab sent to the background): the next question reconnects", async (t) => {
  const chain = await fakeChain(t);
  FakeSocket.made.forEach((s) => s.close());
  await tick();
  assert.equal(await quick(() => chain.getTipHeight()), 977_400);
  assert.equal(FakeSocket.made.length, 4, "one new socket per server");
  assert.deepEqual(chain.servers, servers);
});

test("one socket dropped: the other answers at once, nothing reconnects", async (t) => {
  const chain = await fakeChain(t);
  FakeSocket.made[0].close();
  await tick();
  assert.equal(await quick(() => chain.getTipHeight()), 977_400);
  assert.equal(FakeSocket.made.length, 2);
});

test("a socket that looks open but stays silent is dropped after one timeout, then left out", async (t) => {
  const chain = await fakeChain(t);
  FakeSocket.made[0].silent = true;
  assert.equal(await chain.getTipHeight(), 977_400); // waits out the silent one once, then asks the other
  assert.equal(FakeSocket.made[0].readyState, 3);
  assert.equal(await quick(() => chain.getTipHeight()), 977_400);
});

test("a closed reader stays closed", async (t) => {
  const chain = await fakeChain(t);
  chain.close();
  await assert.rejects(chain.getTipHeight(), /closed/);
});

test("quiet sockets are pinged each minute, and one that stops answering is closed by its ping", async (t) => {
  t.mock.timers.enable({ apis: ["setInterval"] }); // timeouts stay real (200 ms here)
  const chain = await fakeChain(t);
  FakeSocket.pings = 0;
  t.mock.timers.tick(60_000);
  assert.equal(FakeSocket.pings, 2, "one ping per server");
  FakeSocket.made[0].silent = true; // the server went away without closing the socket
  t.mock.timers.tick(60_000);
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(FakeSocket.made[0].readyState, 3, "closed by the ping that got no answer");
  assert.equal(FakeSocket.made[1].readyState, 1);
  assert.equal(await quick(() => chain.getTipHeight()), 977_400);
});

const headerAt = (time) => { const h = new Uint8Array(80); new DataView(h.buffer).setUint32(68, time, true); return Buffer.from(h).toString("hex"); };

test("tip and header are asked of every server: one can't add confirmations or make a binding look old", async (t) => {
  const chain = await fakeChain(t);
  FakeSocket.answers.set(servers[0], { "blockchain.block.header": headerAt(1_763_000_000) });
  FakeSocket.answers.set(servers[1], { "blockchain.headers.get_tip": { height: 10_000_000, hex: "" }, "blockchain.block.header": headerAt(1_420_070_400) });
  assert.equal(await chain.getTipHeight(), 977_400); // the lower median
  assert.equal(headerTime(await chain.getHeader(977_000)), 1_763_000_000); // the newest offered
});

test("a history counts when most servers give it; a split is « disputed »; the mempool's order doesn't matter", async (t) => {
  const urls = [...servers, "wss://c.example"];
  const chain = await fakeChain(t, urls);
  const mined = [{ tx_hash: "aa".repeat(32), height: 900_000 }, { tx_hash: "bb".repeat(32), height: 900_010 }];
  const mempool = [{ tx_hash: "cc".repeat(32), height: 0 }, { tx_hash: "dd".repeat(32), height: -1 }];
  const answer = (list) => ({ "blockchain.address.get_history": list });
  FakeSocket.answers.set(urls[0], answer([...mined, ...mempool]));
  FakeSocket.answers.set(urls[1], answer([...mined].reverse())); // reordered, mempool hidden
  FakeSocket.answers.set(urls[2], answer([...mined, ...[...mempool].reverse()]));
  assert.deepEqual(await chain.getHistory("bitcoincash:q", { agreed: true }), [...mined, ...mempool]);
  assert.deepEqual(await chain.getHistory("bitcoincash:q"), [...mined, ...mempool]); // without { agreed }: the first answer, as before
  FakeSocket.made[2].close(); // two servers left, and they disagree
  await tick();
  await assert.rejects(chain.getHistory("bitcoincash:q", { agreed: true }), (e) => e.disputed === true && /disagree/.test(e.message));
});
