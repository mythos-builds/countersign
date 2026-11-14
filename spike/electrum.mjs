// Can a page read a wallet's coins and the chain tip from a public Fulcrum server, with no library?
// Raw Electrum JSON-RPC over WebSocket (the browser has the same WebSocket). Read-only.
const servers = (process.argv[2] || "wss://bch.imaginary.cash:50004,wss://electroncash.de:60004,wss://chipnet.imaginary.cash:50004").split(",");
const addr = { main: "bitcoincash:qpuln33gefagw4d45fz57a03hqlkkrkv6uex636f3y", chip: "bchtest:qpuln33gefagw4d45fz57a03hqlkkrkv6ua57kc7kc" };

function rpc(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const pending = new Map(); let id = 0;
    const timer = setTimeout(() => { ws.close(); reject(new Error("timeout")); }, 12000);
    const call = (method, ...params) => new Promise((res, rej) => {
      pending.set(++id, { res, rej });
      ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    });
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      const p = pending.get(m.id); if (!p) return;
      pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result);
    };
    ws.onerror = () => { clearTimeout(timer); reject(new Error("socket error")); };
    ws.onopen = () => resolve({ call, close: () => { clearTimeout(timer); ws.close(); } });
  });
}

for (const url of servers) {
  const t = Date.now();
  try {
    const c = await rpc(url);
    const version = await c.call("server.version", "BLAZE spike", "1.4");
    const tip = await c.call("blockchain.headers.get_tip");
    const a = url.includes("chipnet") ? addr.chip : addr.main;
    const utxos = await c.call("blockchain.address.listunspent", a);
    const bal = await c.call("blockchain.address.get_balance", a);
    c.close();
    console.log(`ok   ${url}  ${Date.now() - t} ms  ${version.join(" ")}  tip ${tip.height}  utxos ${utxos.length}  balance ${bal.confirmed}+${bal.unconfirmed}`);
  } catch (e) {
    console.log(`FAIL ${url}  ${Date.now() - t} ms  ${e.message}`);
  }
}
process.exit(0);
