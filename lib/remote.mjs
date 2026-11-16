// Remote signers (NIP-46, « Nostr Connect »): the Nostr key stays in a signer app (Amber, nsec.app, a bunker) and this
// page only ever receives signed events. Each one is re-verified here, and must be exactly the event we asked for (spec §10).
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { BunkerSigner, parseBunkerInput, createNostrConnectURI } from "nostr-tools/nip46";
import { verifiedCopy } from "./nostr.mjs";

/** Relays the connection link names: one run by a signer (nsec.app) and two large public ones. */
export const CONNECT_RELAYS = ["wss://relay.nsec.app", "wss://nos.lol", "wss://relay.primal.net"];
/** What we ask the signer for: the public key, then only the kinds Countersign signs (NIP-39 claim, receipt note, NIP-98 login). */
export const CONNECT_PERMS = ["get_public_key", "sign_event:10011", "sign_event:1", "sign_event:27235"];

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** A nostrconnect:// link for a signer app to scan or open (the client starts the connection). Keep the result private:
 *  `clientSk` is this page's throwaway session key, and the link's secret proves the answer comes from whoever got the link. */
export function connectLink({ name = "Countersign", url, relays = CONNECT_RELAYS, perms = CONNECT_PERMS } = {}) {
  const clientSk = generateSecretKey();
  const secret = hex(crypto.getRandomValues(new Uint8Array(16)));
  const uri = createNostrConnectURI({ clientPubkey: getPublicKey(clientSk), relays, secret, name, ...(url ? { url } : {}), perms });
  return { clientSk, uri };
}

/** Wait until a signer answers `link` → an identity (see `remoteIdentity`). `signal` cancels the wait. */
export async function viaLink(link, { signal, onauth, pool, timeout = 90_000 } = {}) {
  const signer = await BunkerSigner.fromURI(link.clientSk, link.uri, { onauth, pool, timeout }, signal ?? 600_000);
  return remoteIdentity(signer);
}

/** Connect to a pasted bunker:// link (or a bunker's NIP-05 name) → an identity (see `remoteIdentity`). */
export async function viaBunker(input, { onauth, pool, timeout = 90_000 } = {}) {
  const bp = await parseBunkerInput(String(input ?? "").trim());
  if (!bp) throw new Error("that isn't a bunker:// link");
  const signer = BunkerSigner.fromBunker(generateSecretKey(), bp, { onauth, pool, timeout });
  try {
    await signer.connect();
    return await remoteIdentity(signer);
  } catch (e) {
    await signer.close().catch(() => {});
    throw e;
  }
}

/** Same kind, tags, content and time as asked: a signer may only add its key, the id and the signature. */
export function sameEvent(event, template) {
  return event.kind === template.kind && event.created_at === template.created_at && event.content === template.content
    && JSON.stringify(event.tags) === JSON.stringify(template.tags);
}

/** An identity like the app's others ({ pubkey, npub, sign }) backed by a connected signer. `sign` resolves only with an event
 *  that verifies (on a fresh copy) for this key and is exactly the template; anything else is refused. */
export async function remoteIdentity(signer) {
  const pubkey = await signer.getPublicKey();
  if (!/^[0-9a-f]{64}$/.test(pubkey ?? "")) {
    await signer.close().catch(() => {});
    throw new Error("the signer gave no key");
  }
  return {
    pubkey,
    npub: nip19.npubEncode(pubkey),
    via: "remote",
    async sign(template) {
      const event = verifiedCopy(await signer.signEvent(template));
      if (!event || event.pubkey !== pubkey) throw new Error("the signer's answer doesn't verify for this key");
      if (!sameEvent(event, template)) throw new Error("the signer signed something else than what was asked");
      return event;
    },
    close: () => signer.close(),
  };
}
