# BLAZE pre-flight — done early, 2026-11-12 evening (AI agent)

## Throwaway tests (declared in `/spike`)
1. **A wallet returns a signed transaction with `broadcast: false`** — already PASSED on 11-11 18:10 with Cashonize (VM: VALID, nothing broadcast); `broadcast: true` signs and sends (18:12). Paytaca = Gate G2 with him on Sat.
2. **Vite builds libauth for the browser** — PASSED 2026-11-12 ~20:34: `spike/vite-libauth/` (vite 8.3.5 with Rolldown, @vitejs/plugin-react 6.1.2, react 19.3.1, @bitauth/libauth 3.0.0, nostr-tools 2.25.4; versions ≥ 2 weeks old; `npm i --ignore-scripts`). `build.target: 'es2022'` (libauth's WASM top-level await). In headless Chromium: cashaddr derived (same as Node), Schnorr sign + verify OK, kind 10011 event signed + verified on a JSON copy, no page error. Bundle 671 kB (272 kB gzip) → code-split in polish (D5).

## Deck outline (Widget Factory template: title · story · benefits · BCH usage · vision · thanks)
1. **Title** — Countersign · « Your Nostr name is now a BCH address. »
2. **Story** — Nostr people get tipped over Lightning, through custodians or channels. Paying someone in BCH still means asking for an address. Countersign makes the name enough.
3. **Benefits** — users: paste a name, pay in seconds, no address exchange · wallet makers: « send to a Nostr name » with one library call · apps: sign-in that also tells you where to pay the user.
4. **BCH usage** — every binding is a real mainnet transaction (dated, public, cents) · payments over WizardConnect · verification runs the BCH virtual machine in the browser; no server, no custody.
5. **Vision** — wallets adopt the library · tips and creator payouts by name · shops check out to a name · v1: token-aware addresses, rotation screen, receipts posted on Nostr.
6. **Thanks** — the judges, Paytaca, BCH BLAZE; the honesty line (one human + an AI agent, built 11-14 → 11-21; the spike is dated in `/spike`).

## Screens in words (390 px first)
- **Pay page `/#/<name>`** — top: the name, avatar and « pays to bitcoincash:q… (bound since …) » with a green check, or an amber « new binding » note. Middle: amount in BCH with a dollar hint. Two buttons: « Pay with WizardConnect » (QR on desktop, tap-to-open link on a phone) and « Other wallet » (payment QR). After paying: « Paid ✓ » with the txid and a link to the explorer. Empty / loading / « this name has no BCH binding yet » states.
- **Bind wizard** — step 1 connect the wallet (one reassuring line: the wallet shares its public keys, never its secrets) · step 2 connect Nostr (browser extension, or a local demo identity you can export) · step 3 « sign the commitment » (says in words: a tiny transaction from your address that names your npub, about 0.0000033 BCH) · step 4 publish to your relays · step 5 « here is your pay link » + copy button.
- **Wall** — names that bound with `#countersign`, each re-verified in the browser before it shows.
- **Login demo `/demo-login`** — « Sign in with Nostr » → « signed in as … · pays to … » + the 30-line server snippet.
