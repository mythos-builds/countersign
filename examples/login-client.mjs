// Signs in to examples/login-server.mjs, then replays the same answer to show it is refused.
// Usage: node examples/login-client.mjs [<server>] [<file holding a hex Nostr secret key>]   (no file = a throwaway key)
import { readFileSync } from "node:fs";
import { generateSecretKey, finalizeEvent } from "nostr-tools";
import { loginTemplate, authorizationHeader } from "../lib/index.mjs";

const [server = "http://localhost:8787", keyFile] = process.argv.slice(2);
const sk = keyFile ? Uint8Array.from(Buffer.from(readFileSync(keyFile, "utf8").trim(), "hex")) : generateSecretKey();

const challenge = await (await fetch(`${server}/challenge`)).json();
console.log("challenge:", challenge);
const authorization = authorizationHeader(finalizeEvent(loginTemplate(challenge), sk));
for (const attempt of ["login", "replay"]) {
  const res = await fetch(challenge.url, { method: challenge.method, headers: { authorization } });
  console.log(`${attempt}: ${res.status}`, await res.json());
}
