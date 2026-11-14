# Countersign

Pay a Nostr name in Bitcoin Cash, without asking anyone for an address. Countersign lets anyone check, with no server in the middle, that one person controls both a BCH address and a Nostr key.

Built for [BCH BLAZE 2026](https://dorahacks.io/hackathon/bchblaze2026) by one human and an AI agent.

## Start state: November 14, 2026

The tag `start-2026-11-14` marks the project as it stood when hacking began. Everything in it was written during the ideation week (November 11 and 12), before the kick-off:

- `spike/page/`: a browser page that connects any WizardConnect wallet and asks it to sign one test transaction. The input is fake and nothing is broadcast.
  **Live demo of this state:** https://mythos-builds.github.io/countersign/start-2026-11-14/
- `spike/e2e.mjs` and `spike/wallet.mjs`: the same connection end to end in Node, with a throwaway reference wallet (random keys, made at run time).
- `spike/binding.mjs`: the identity proof, offline. The BCH key signs a transaction that carries the Nostr key, the Nostr key signs an event that carries the address, and a verifier checks both directions.
- `spike/electrum.mjs`: reads coins and the chain tip from a public Fulcrum server, read-only.
- `spike/vite-libauth/`: checks that libauth and nostr-tools bundle for the browser with Vite.
- `spike/notes/PREFLIGHT.md`: pre-flight tests and screens in words.
- `spec/SPEC.md`: the draft binding spec, v0.

The work from November 14 to 22 goes on top of this state.

## Run the spike

```sh
cd spike
npm i --ignore-scripts
npx esbuild page/app.mjs --bundle --format=esm --platform=browser --target=es2022 --outfile=page/app.bundle.js
node e2e.mjs   # full test in Node, exit 0 = all good
```

To try the page, serve `spike/page/` with any static web server and open it.

## License

MIT
