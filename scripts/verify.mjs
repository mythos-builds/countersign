// Verify a binding from scratch: fresh relay and server connections, nothing cached.
// Usage: node scripts/verify.mjs <npub> [<address>] [--chipnet]   (exit 0 = verified or pending)
import { verifyBinding, fulcrumChain, relayReader, MAINNET_SERVERS, CHIPNET_SERVERS } from "../lib/index.mjs";

const [npub, address] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const chain = await fulcrumChain(process.argv.includes("--chipnet") ? CHIPNET_SERVERS : MAINNET_SERVERS);
const nostr = relayReader();
let result;
try {
  result = await verifyBinding(npub, { nostr, chain, address });
  console.log(JSON.stringify({ ...result, servers: chain.servers }, null, 2));
} finally {
  chain.close();
  nostr.close();
}
process.exit(["verified", "pending"].includes(result?.status) ? 0 : 1);
