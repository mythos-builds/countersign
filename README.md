# Countersign

Pay a Nostr name in Bitcoin Cash, without asking anyone for an address. Countersign lets anyone check, with no server in the middle, that one person controls both a BCH address and a Nostr key.

Built for [BCH BLAZE 2026](https://dorahacks.io/hackathon/bchblaze2026) by one human and an AI agent.

**Live**
- The site: https://mythos-builds.github.io/countersign/
- Bind your Nostr name to your BCH wallet: https://mythos-builds.github.io/countersign/#/bind
- Pay a bound name (Countersign's own), and see its recent payments: https://mythos-builds.github.io/countersign/#/npub1v2zlnx5g0m847j4k34d30az2dykjwrlazp68fqwe3c0nekaqltkqd23d95
- A separate demo app that signs people in with their key: https://mythos-builds.github.io/countersign/demo-login/
- The project as it stood when hacking began: https://mythos-builds.github.io/countersign/start-2026-11-14/
- The deck (on the BCH BLAZE "Widget Factory" template): https://mythos-builds.github.io/countersign/deck/countersign-deck.pdf

The site is static files. Every check runs in your browser; relays and public Bitcoin Cash servers are only read from.

## The bounty's five requirements, and where to see each

| # | Requirement | Where to see it |
|---|---|---|
| 1 | Create or connect both identities, keys stay with the user | [#/bind](https://mythos-builds.github.io/countersign/#/bind), steps 1 and 2: your Nostr extension (NIP-07), a signer app over Nostr Connect (NIP-46: Amber, nsec.app, any bunker; the key never leaves it), or a new key made in the browser, whose secret you keep; then your own BCH wallet over WizardConnect, which shares public keys only. No account, no custodian. |
| 2 | Cryptographic binding | #/bind, steps 3 and 4: the BCH wallet signs a transaction that names the Nostr key, the Nostr key signs a claim that names the address and that transaction. Two different keys, each signing a statement about the other. |
| 3 | Discovery without a central database | The search box on the [site](https://mythos-builds.github.io/countersign/): an npub, nprofile, `nostr:` link or `name@domain` (NIP-05), or a BCH address, found through Nostr relays or from the chain alone. |
| 4 | Independent verification and challenge-response login | Every lookup runs the full check below in your browser. [demo-login/](https://mythos-builds.github.io/countersign/demo-login/) is another app that signs you in with a NIP-98 challenge, then checks your binding; [examples/login-server.mjs](examples/login-server.mjs) does the same as a real Node server. The demo app can then ask your wallet to answer too: it signs a one-time code in a transaction that can never be broadcast. |
| 5 | Working demo, source, setup, architecture and crypto docs | This README, [spec/SPEC.md](spec/SPEC.md), the source in `lib/` and `app/`, 43 tests. |

Stretch goals touched: **payments by name** (the pay page, two rails), **BCH-backed commitments** (why a transaction, below), **key rotation** (a newer commitment from the same address supersedes the older one), **interoperability** (a library and a spec built on NIP-39, NIP-98, NIP-05 and NIP-07).

## How it works

A binding is two signed statements that point at each other.

```
  Nostr key ──signs──▶ CLAIM, a Nostr event (kind 10011, NIP-39)
                       ["i", "bitcoincash:qq…", "<txid>"] ─────────────┐
                                                                       ▼
  BCH key ────signs──▶ COMMITMENT, a BCH transaction <txid>
                       spent from qq…, with one data output:
                       "CSG\0" "Verifying that I control the following
                                Nostr public key: npub1…" ─▶ names the Nostr key
```

- **The BCH half** is a small transaction spent from the address. Its one data output carries a 4-byte protocol tag (`CSG\0`) and NIP-39's own sentence naming the npub. No payment to anyone: the fee is a few hundred satoshis and the rest goes back to the same address.
- **The Nostr half** is the person's NIP-39 identity list (kind 10011) with an `i` tag holding the address and the commitment's txid. It is merged into the list, so the person's other identities stay.
- **Neither key leaves its wallet**, and the two keys must differ: the verifier refuses a binding where the BCH key and the Nostr key are the same key.

Where things live: the claim on Nostr relays, the commitment on the Bitcoin Cash chain. Public Fulcrum servers (the Electrum protocol) are read-only windows on the chain. The checks run with [libauth](https://github.com/bitauth/libauth) (the BCH virtual machine) and [nostr-tools](https://github.com/nbd-wtf/nostr-tools). Nothing of ours sits in between.

### Why a transaction, not a signed message

1. WizardConnect has no message signing, so a transaction is the one proof every BCH wallet can make today.
2. The chain dates it: a binding cannot be backdated. Pages show "bound since …" and flag a binding under 24 hours old, which is the defence if a Nostr key is stolen.
3. It can be found from the address alone, without any relay.
4. "The latest commitment wins" gives key rotation with no extra machinery.

## The cryptographic check, step by step

`verifyBinding(npub)` trusts nothing it is handed ([lib/verify.mjs](lib/verify.mjs), spec §5):

1. **The claim.** Read the person's relay list (kind 10002), then fetch their newest kind 10011 from those relays and five defaults. Check its Schnorr signature on a fresh copy of the event; its author must be the npub.
2. **The address.** Take the `bitcoincash:` identity from the claim, decode it, require P2PKH.
3. **The transaction.** Fetch the txid from public Fulcrum servers and hash the bytes: the hash must equal the txid, so a server cannot hand over a forged transaction.
4. **What it names.** Exactly one data output with the `CSG\0` tag, in NIP-39's wording; the npub in it must be the claim's author.
5. **Who signed it.** Fetch every parent transaction and hash each one too. One input must spend a coin locked to the claimed address, with an unlock of `<signature> <public key>` where `hash160(public key)` equals the address, and a sighash byte that covers every output (`0x41`, `0x61`, `0xC1` or `0xE1`), so the signature cannot be reused with another data output.
6. **The signatures themselves.** Run the BCH virtual machine (libauth, consensus rules) on the whole transaction with the real parent outputs. Any failure means invalid.
7. **No key reuse.** The BCH public key's x-coordinate must differ from the Nostr key.
8. **Age.** From the address history: at least one confirmation means `verified`; mempool only means `pending` (payable, shown as new). "Bound since" is the block's time.
9. **Is it still current?** A later transaction from the same address that passes this same check and names another npub makes the binding `superseded`. Anyone can send coins *to* an address, so only a transaction signed *by* it counts.

Relays and servers can hide data, never forge it: signatures, hashes and the virtual machine decide. The tests in [test/offline.test.mjs](test/offline.test.mjs) try the attacks: someone else's transaction naming you, a transaction sent to the address, sighash NONE and SINGLE, two data outputs, a forged transaction or parent, the same key on both sides, a claim signed by the wrong key, a broken signature.

## Discovery

- **By name:** the site takes an npub, an nprofile (its relay hints are used), a `nostr:` link, 64-hex or `name@domain` (NIP-05, no redirects followed).
- **By address:** two independent roads, the relays (a `#i` filter on kind 10011, which relays index) and the chain alone (the commitments in the address history name their npub). Every candidate goes through the full check; the newest live commitment wins.
- **The wall** ([#/wall](https://mythos-builds.github.io/countersign/#/wall)): names bound here that chose to be listed (the claim carries `["t", "countersign"]`; the bind page asks, ticked by default, and either way the binding itself is public). Relays only suggest who is there: each name's newest claim must still carry the tag, then its binding goes through the full check, and names appear one by one as they pass (`listWall`).

## Sign-in to another app (challenge-response)

The demo app and `examples/login-server.mjs` use the library's `loginGate`, which follows NIP-98:

1. The app hands out a challenge: its login URL with a fresh single-use nonce in it.
2. The person's Nostr key (extension, remote signer or secret key) signs a kind 27235 event naming that exact URL and the method.
3. The app checks the signature, the kind, the time (±60 s), the URL and the method, and that the nonce was issued here and not used before. Then it spends the nonce: a replay is refused. A wrong answer leaves the challenge open for the right one.
4. The app runs `verifyBinding` on the signed-in key: "signed in as …, pays to …". No identity provider is asked.
5. Optional, the wallet too (in the demo app): `walletChallenge({ npub, address })` asks the wallet behind the bound address to sign a one-time code, with `broadcast: false`. The transaction it signs spends a coin that can never exist (BIP-322's construction, on BCH), so no network accepts it: it moves nothing and costs no fee. `walletCheck(signedHex)` rebuilds what was asked and compares it byte for byte, checks the signature covers every output, runs the BCH virtual machine, and spends the code. Tested end to end with the reference wallet; a real BCH server refuses the signed transaction (« Missing inputs »).

The core of [examples/login-server.mjs](examples/login-server.mjs):

```js
import { loginGate, verifyBinding, relayReader, fulcrumChain } from "./lib/index.mjs"; // not on npm yet

const gate = loginGate({ url: "https://app.example/login" });
// GET /challenge  →  gate.challenge()  →  { url, method, expiresAt }
// POST <that url> with "Authorization: Nostr <base64 event>":
const who = gate.check(req.headers.authorization, { url: requestUrl, method: "POST" });
if (who.error) return reply(401, who);
const bch = await verifyBinding(who.npub, { nostr: relayReader(), chain: await fulcrumChain() });
```

For a real deployment: tie each nonce to the browser session that asked for it, rate-limit `challenge()`, and keep in mind that open challenges live in memory (one process; at most 10 000 open, the oldest goes first).

## Paying a name

`#/<name>` resolves the name, runs the full check, then offers two rails:

- **Wallet app (WizardConnect):** the wallet shares public keys only; the page finds its coins, builds the payment, the wallet shows it and signs. The page checks the wallet signed exactly the outputs it built before sending.
- **Any wallet (QR):** a `bitcoincash:` payment link; the page sees the payment arrive by itself through a Fulcrum address subscription.

A phone often drops the page's connections while you approve in the wallet app: the page reconnects and looks again as soon as it is shown.

An npub that has not bound cannot be paid, by design: deriving a BCH address from a Nostr key would be the key reuse the bounty forbids.

Coins carrying CashTokens are never spent, by the payment or by the commitment: spending them in a transaction that doesn't carry the tokens on would burn them.

### Receipts on Nostr

After « Paid ✓ », the payer can post a receipt: a public note from their Nostr name (a browser extension, a signer app, or the name made on the bind page) that tags the payee, so the payee is notified in any Nostr client, and points at the transaction with NIP-73's id, `bitcoincash:tx:<txid>`. The pay page lists a name's **Recent payments** from these notes, and checks each one on chain first: the transaction must pay the name's bound address, and the amount shown is the chain's, not the note's.

Anyone can post a note about anyone's payment, so the page says who paid only as far as the chain proves it: **« from their bound address »** when the payer's own bound address signed the payment, otherwise **« says it was them »**. One row per payment; a proven payer beats an earlier claim. Tested on mainnet on November 14: the reference wallet paid Countersign's name 0.00001 BCH through the page (tx `c5814de6…3d05`), the demo name posted the receipt, and the page and a cold check from Node both list it as « from their bound address ».

## Setup

Node 22 or newer (the Fulcrum client uses the built-in WebSocket).

```sh
git clone https://github.com/mythos-builds/countersign
cd countersign
npm ci
npm test              # 43 tests, offline
npm run dev           # the site and the demo app on a local server
npm run build         # static build into dist/ (any static host works)
```

From the command line:

```sh
node scripts/verify.mjs <npub> [<address>] [--chipnet]   # the full check; exit 0 = verified or pending
node examples/login-server.mjs                     # a login server on localhost:8787
node examples/login-client.mjs                     # signs in with a throwaway key, then replays: 401
node scripts/bind.mjs --wif-file <f> --nostr-key-file <f> [--chipnet] [--dry-run]
```

`bind.mjs` reads keys from files, never from the command line, and never prints them.

## Library

`lib/index.mjs`, the same code the site runs:

| Export | What it does |
|---|---|
| `verifyBinding(npub, { nostr, chain, address? })` | The full check → `{ status, npub, address, txid, confirmations, boundSince, warnings, reason?, supersededBy? }` |
| `verifyCommitment(chain, txid, address)` | The BCH half alone → `{ npub, pubkey }` or `{ error }` |
| `findByAddress(address, { nostr, chain })` | The current binding of an address, with `via: ["relays", "chain"]` |
| `resolveName(text)` | npub, nprofile, hex, `nostr:` link or `name@domain` → `{ pubkey, npub, relays }` |
| `relayReader({ relays? })` | Reads claims (`fetchClaim`, `claimsFor`), receipts (`mentions`), profiles and relay lists (`writeRelays`, `readRelays`); publishes events |
| `fulcrumChain(servers?)` | Read-only chain access: transactions (hash-checked), history, headers, coins, broadcast, address watch |
| `buildCommitment({ address, npub, coins })` | The unsigned commitment from the address's own coins, for a wallet to sign |
| `buildClaim(current, address, txid)` | The kind 10011 event to sign, merged into the current one |
| `loginGate({ url })` | `challenge()` and `check(authorization, { url, method })`; the wallet step: `walletChallenge({ npub, address })` and `walletCheck(signedHex)` |
| `findAddressPath(pubkeyAt, address)` | Where an address sits in a wallet seen through its public keys (receive or change, and its index) |
| `loginTemplate(challenge)`, `authorizationHeader(event)` | The client's side of a login |
| `buildPayment`, `scanWallet`, `paidTo`, `paymentUri` | Payments by name |
| `receiptTemplate({ payee, txid, sats })`, `listReceipts({ payee, nostr, chain })`, `verifyReceipt(note, …)` | Receipts on Nostr: the note to sign, and the checked list of a name's payments (`proof: "bound"` or `"claim"`) |

## Layout

- `lib/`: the library (binding, verification, discovery, login, payments, receipts, Fulcrum client).
- `app/`: the site (`#/<name>` pays and lists receipts, `#/bind` binds, `#/wall` lists names) and `app/demo-login/`, a separate app that imports only the library and nostr-tools.
- `examples/`: the login server and client in Node.
- `scripts/`: bind and verify from the command line.
- `test/`: offline tests, attacks included.
- `spec/SPEC.md`: the binding spec.
- `spike/`: the ideation-week code, kept as it was.

## Limits, said plainly

- P2PKH addresses only for now; P2SH and multisig are not covered.
- Binding in the browser needs a wallet that speaks WizardConnect. Paytaca paid through the page and bound a name on mainnet (November 14). Cashonize and our own reference wallet also sign the current request format (November 14: a test signature on a made-up coin, never broadcast). On an iPhone, Paytaca opens no `wiz://` link, so the page offers the connection link to paste in Paytaca (Apps → WizardConnect → Paste URL); tested end to end on November 14 (an iPhone alone, Safari and Paytaca, a real payment through the page).
- Wallets show the data output as raw bytes, so the page says in words what the wallet is asked to sign.
- Relays or servers that are down or hiding data can make a bound name look unbound. They cannot make a false binding pass.
- The demo app runs its "server" in the page, labelled as such, so both sides can be watched. The Node example is a real server.

## How this was built

By one human and an AI agent. The tag `start-2026-11-14` marks the project as it stood when hacking began: everything in it (`spike/`, and `spec/SPEC.md` v0) was written during the ideation week, November 11 and 12, before the kick-off. Its live demo is linked above. Everything since is in the git history, from November 14 on.

## License

MIT
