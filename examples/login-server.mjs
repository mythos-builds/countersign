// A tiny app that signs people in with their Nostr key and shows the BCH address bound to it (spec §9).
// It asks no identity provider: relays and Bitcoin Cash servers are only readers, every check runs here.
// Run: node examples/login-server.mjs   then   node examples/login-client.mjs   (ORIGIN = the URL people reach it at)
import http from "node:http";
import { loginGate, verifyBinding, relayReader, fulcrumChain } from "../lib/index.mjs";

const ORIGIN = process.env.ORIGIN ?? "http://localhost:8787";
const gate = loginGate({ url: `${ORIGIN}/login` });
const nostr = relayReader();
let chainP;
const chain = () => (chainP ??= fulcrumChain().catch((e) => { chainP = null; throw e; }));
const send = (res, code, body) => res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(body, null, 2));

http.createServer(async (req, res) => {
  const url = new URL(req.url, ORIGIN);
  if (req.method === "GET" && url.pathname === "/challenge") return send(res, 200, gate.challenge());
  if (req.method === "POST" && url.pathname === "/login") {
    const who = gate.check(req.headers.authorization, { url: url.href, method: "POST" });
    if (who.error) return send(res, 401, who);
    // Signed in. Which BCH address does this key answer for? Both halves of the binding are checked from scratch.
    const bch = await chain().then((c) => verifyBinding(who.npub, { nostr, chain: c })).catch((e) => ({ status: "unknown", reason: e.message }));
    return send(res, 200, { signedInAs: who.npub, bch }); // a real app would open its session here
  }
  send(res, 404, { error: "GET /challenge, then POST to the URL it gives with « Authorization: Nostr <signed event> »" });
}).listen(Number(new URL(ORIGIN).port || 80), () => console.log(`login demo on ${ORIGIN}`));
