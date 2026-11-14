// Offline tests for the Fulcrum client: sockets that drop or go silent are replaced, never waited on for nothing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fulcrumChain } from "../lib/index.mjs";

/** A stand-in for a Fulcrum server behind a WebSocket. The test can cut it, or make it silent while it looks open. */
class FakeSocket {
  static OPEN = 1;
  static made = [];
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
    const result = method === "blockchain.headers.get_tip" ? { height: 977_400, hex: "" } : ["fake", "1.4"];
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
async function fakeChain(t) {
  const real = globalThis.WebSocket;
  globalThis.WebSocket = FakeSocket;
  FakeSocket.made = [];
  const chain = await fulcrumChain(servers, { timeoutMs: 200 });
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
