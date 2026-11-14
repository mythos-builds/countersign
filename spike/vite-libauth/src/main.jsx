// Throwaway test (ideation week, declared in /spike): libauth + nostr-tools inside a Vite/React browser bundle.
import { createRoot } from 'react-dom/client';
import * as L from '@bitauth/libauth';
import { generateSecretKey, getPublicKey, nip19, finalizeEvent, verifyEvent } from 'nostr-tools';

function run() {
  const priv = L.hexToBin('11'.repeat(32));
  const pub = L.secp256k1.derivePublicKeyCompressed(priv);
  const enc = L.encodeCashAddress({ prefix: 'bitcoincash', type: 'p2pkh', payload: L.hash160(pub) });
  const addr = typeof enc === 'string' ? enc : enc.address;
  const digest = L.sha256.hash(new TextEncoder().encode('countersign'));
  const sig = L.secp256k1.signMessageHashSchnorr(priv, digest);
  const sigOk = L.secp256k1.verifySignatureSchnorr(sig, pub, digest);
  const sk = generateSecretKey();
  const npub = nip19.npubEncode(getPublicKey(sk));
  const ev = finalizeEvent({ kind: 10011, created_at: 1794528000, tags: [['i', addr, 'txid-placeholder']], content: '' }, sk);
  const evOk = verifyEvent(JSON.parse(JSON.stringify(ev)));
  return { addr, npub: npub.slice(0, 16) + '…', sigOk, evOk };
}

let out;
try { out = run(); } catch (e) { out = { error: String(e) }; }
window.__RESULT__ = out;
createRoot(document.getElementById('root')).render(<pre id="out">{JSON.stringify(out, null, 1)}</pre>);
