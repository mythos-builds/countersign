# Countersign binding — draft spec v0

*Ideation-week draft, written 2026-11-12 (before the 11-14 kick-off). Moves into the repo's `/spec` on D1 and is declared there as pre-existing design work.*

## 1. Purpose
Let anyone check, with no server of ours, that **one person controls both a Bitcoin Cash address and a Nostr key**, so that a Nostr name can be paid in BCH on chain, with no custodian and no Lightning. Neither key ever leaves its wallet; no key is reused across the two systems.

## 2. Terms
- **npub**: a Nostr public key (NIP-19 form). **Address**: a BCH CashAddress, P2PKH only in v0.
- **Commitment**: a BCH transaction spent from the address that names the npub (the BCH half).
- **Claim**: the person's NIP-39 identity list, kind 10011, carrying the address and the commitment's txid (the Nostr half).
- **Binding**: a claim + a commitment that point at each other and both verify.

## 3. The BCH half: commitment transaction
1. At least one input spends a P2PKH output locked to the claimed address. Its signature's sighash byte is one of `0x41, 0x61, 0xC1, 0xE1` (every variant that covers all outputs); anything else is refused, so a signature cannot be re-used with another data output.
2. Exactly one OP_RETURN output: `OP_RETURN <tag: 4 bytes> <sentence>`, where *sentence* is the UTF-8 text of NIP-39's own wording: `Verifying that I control the following Nostr public key: npub1…` (about 128 bytes in total, under the 223-byte relay limit). **Tag proposal: script bytes `43 53 47 00` (« CSG\0 ») = protocol ID `0x00475343`** under the Lokad guideline (pushed as `0x04` + 4 bytes, little-endian, like SLP's « SLP\0 » = `0x00504c53`); in the allowed range (0x10 … 0x0FFFFFFF) and **not in the registry** (`bitcoincashorg/bitcoincash.org` `etc/protocols.csv`, 31 claimed IDs, read 2026-11-12). Claiming it there is a courtesy PR (name, authors, spec URL, optional address) — after the event, under the project identity.
3. Change goes back to the same address (recommended). The transaction is otherwise ordinary (about 330 bytes, a fraction of a cent).
4. Coins carrying CashTokens are never spent by the builder (see §10).

## 4. The Nostr half: claim event
- Kind **10011** (NIP-39, replaceable), tag `["i", "bitcoincash:<cashaddr>", "<txid>"]`. The `platform:identity` value reads exactly like the address a wallet shows (`bchtest:` on chipnet). Addresses are compared by decoded hash, never as text.
- The builder **merges** into the person's existing kind 10011 and keeps every other `i` tag.
- Optional `["t", "countersign"]` puts the person on the public wall.

## 5. Verification: `verifyBinding(npub[, address])`
Trusts nothing it is handed.
1. Read the author's relay list (kind 10002), then fetch the newest kind 10011 by the author from those relays + three defaults; newest `created_at` wins. Verify its signature **on a fresh copy parsed from JSON** (nostr-tools caches « verified » on event objects).
2. Take the `i` tag(s) with platform `bitcoincash` (or `bchtest`); decode; require P2PKH.
3. Fetch the transaction by txid from two Fulcrum servers or more; re-hash it; the hash must equal the txid.
4. Require exactly one OP_RETURN with the tag; parse the npub from the sentence; it must equal the event's author.
5. Find an input whose unlock is `<sig> <pubkey>` with `hash160(pubkey)` = the address payload and an allowed sighash byte.
6. Fetch every parent transaction by id, re-hash each, rebuild the source outputs; run the BCH virtual machine (libauth) on the whole transaction. Any failure = invalid.
7. Refuse key reuse: the BCH public key's x-coordinate must differ from the Nostr public key.
8. Confirmations from Fulcrum → `verified` (≥ 1) or `pending` (mempool only, both halves valid).
9. Supersession: a later commitment from the same address naming another npub, or a newer claim without the tag → `superseded`.
Result: `{status, npub, address, txid, boundSince, warnings}`; `warnings` includes `new` when the commitment is under 24 h old.

## 6. Statuses
`verified` · `pending` (payable, shown as new) · `superseded` · `invalid: <reason>`.

## 7. Discovery (no indexer of ours)
- **By npub**: the person's kind 10011.
- **By address**: relay filter `{"kinds":[10011], "#i":["bitcoincash:q…"]}` (single-letter tag, indexed by relays).
- **From the chain alone**: the address history (Fulcrum `blockchain.address.get_history`) → commitment → the npub in its data output.
- Names: `name@domain` resolved through NIP-05, then as above. Every result is re-verified in the browser before it is shown.

## 8. Paying a name
- **WizardConnect rail**: the page builds the payment from the payer's own coins (found from the wallet's xpubs), the wallet signs and broadcasts (`broadcast: true`, said in words on the page).
- **Plain rail**: a `bitcoincash:` payment link / QR for any wallet; « paid » detected live through a Fulcrum address subscription.
- Paying an npub that has not bound is not possible by design (deriving an address from a Nostr key = the key reuse the bounty forbids).

## 9. Login (challenge-response, another app)
NIP-98: the server issues a single-use nonce; the client signs a kind 27235 event with `u` = the URL carrying the nonce and a `method` tag; the server accepts it within 60 s, once, then runs `verifyBinding(npub)` → « signed in as …, pays to … ». A 30-line Node server example ships with the library.

## 10. Security
- Never spend a coin carrying tokens (Fulcrum `exclude_tokens`, then re-check each coin has no `token_data`): tokens left out of the outputs are burned.
- The wallet shows the data output as raw hex, so the signing prompt says in words what is signed.
- Relays and Fulcrum servers can hide data, never forge it (signature checks, re-hashing, the VM).
- A stolen Nostr key can re-point the claim, but not forge a commitment; « bound since » and the `new` warning are the user's defence. A tricked wallet can only attach its own address.

## 11. Open (none blocks D1)
Final word on the tag on D1 (proposal in §3) · Paytaca's view on the on-chain proof type · P2SH and token-aware addresses (v1) · rotation screen (the « latest commitment wins » rule already covers it).
