// Members' corner: a demo app that signs people in with Countersign (spec §9). It uses the library, nostr-tools and
// WizardConnect only, nothing from the Countersign site. Its server part runs in this page, labelled, so both sides
// can be watched.
import { generateSecretKey, finalizeEvent } from "nostr-tools";
import { renderSVG } from "uqr";
import { initiateDappRelay } from "@wizardconnect/core";
import { DappConnectionManager } from "@wizardconnect/dapp";
import { sourceOutputToRelay, transactionToHex } from "@wizardconnect/core/hdwalletv1-serialize";
import { loginGate, loginTemplate, authorizationHeader, verifyBinding, relayReader, fulcrumChain, findAddressPath } from "../../lib/index.mjs";

const SITE = new URL("../", location.href).href; // the Countersign site: bind and pay links
const BIND_KEY = "countersign-demo-identity"; // an identity made on the site's Bind page (same origin)
const view = document.getElementById("view");

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v != null && v !== false) el.setAttribute(k, v === true ? "" : v);
  }
  el.append(...kids.flat().filter((k) => k != null && k !== false));
  return el;
}
const shortKey = (s) => `${s.slice(0, 14)}…${s.slice(-6)}`;
const fromHex = (s) => Uint8Array.from(s.match(/../g), (b) => parseInt(b, 16));
const eventJson = (e) => `{\n${Object.entries(e).map(([k, v]) => `  "${k}": ${JSON.stringify(v)}`).join(",\n")}\n}`; // one line per field
const spinner = () => h("div", { class: "spinner", role: "status", "aria-label": "Working" });
function copyButton(text, label) {
  const b = h("button", {
    type: "button", class: "link",
    onclick: async () => {
      try { await navigator.clipboard.writeText(text); b.textContent = "Copied"; } catch { b.textContent = "Copy failed"; }
      setTimeout(() => { b.textContent = label; }, 1500);
    },
  }, label);
  return b;
}
const txLink = (txid) => h("a", { href: `https://blockchair.com/bitcoin-cash/transaction/${txid}`, target: "_blank", rel: "noopener" }, `transaction ${txid.slice(0, 8)}…`);

// ── The app's server part. A real app runs this on its own machine: examples/login-server.mjs. ──
const nostr = relayReader();
let chainP;
const chain = () => (chainP ??= fulcrumChain().catch((e) => { chainP = null; throw e; }));
const gate = loginGate({ url: new URL("login", location.href).href });
const server = {
  challenge: () => gate.challenge(),
  /** POST <url> with « Authorization: Nostr … » → who signed, and the BCH address bound to that key. */
  async login(authorization, url) {
    const who = gate.check(authorization, { url, method: "POST" });
    if (who.error) return who;
    const [bch, profile] = await Promise.all([
      chain().then((c) => verifyBinding(who.npub, { nostr, chain: c })).catch((e) => ({ status: "unknown", reason: e.message })),
      nostr.fetchProfile(who.pubkey).catch(() => null),
    ]);
    // The bound address's wallet may answer too: a one-time code it signs without sending (spec §9 step 5).
    let walletChallenge = null;
    if (bch.status === "verified" || bch.status === "pending") {
      try { walletChallenge = gate.walletChallenge({ npub: who.npub, address: bch.address }); } catch { /* no wallet step */ }
    }
    return { ...who, bch, profile, walletChallenge };
  },
  /** POST <url>/wallet with the wallet's signed transaction (hex) → who, and the address whose key signed. */
  walletLogin: (signedHex) => gate.walletCheck(signedHex),
};

// ── The person's side: whatever holds their Nostr key signs. The secret key never reaches the app's part. ──
function signers() {
  const list = [];
  if (window.nostr?.signEvent) list.push({ label: "Sign in with my Nostr extension", sign: (t) => window.nostr.signEvent(t) });
  let hex = null;
  try { hex = localStorage.getItem(BIND_KEY); } catch { /* storage blocked */ }
  if (hex && /^[0-9a-f]{64}$/.test(hex)) {
    const sk = fromHex(hex);
    list.push({ label: "Sign in with the identity I made on Countersign", sign: async (t) => finalizeEvent(t, sk) });
  }
  list.push({ label: "Try it with a new throwaway key", sign: async (t) => finalizeEvent(t, generateSecretKey()) });
  return list;
}

let started = false;
let walletSession = null; // stops the open WizardConnect session, if any
function showStart() {
  started = false;
  walletSession?.();
  view.replaceChildren(
    h("section", { class: "hero" },
      h("h1", {}, "Members sign in with their own key."),
      h("p", { class: "lede" }, "No password and no account with us. Your Nostr key answers a one-time challenge, then the app learns which Bitcoin Cash address you bound to that key, from Nostr relays and the BCH chain."),
    ),
    h("div", { class: "actions" }, signers().map((s, i) => h("button", { class: i === 0 ? "primary" : "", onclick: () => signIn(s) }, s.label))),
    h("p", { class: "quiet" }, "No Nostr identity yet? ", h("a", { href: `${SITE}#/bind` }, "Make one and bind a wallet on Countersign"), ", then come back here."),
  );
}

async function signIn(signer) {
  started = true;
  const top = h("div", {}, h("div", { class: "card center" }, spinner(), h("span", { class: "quiet" }, "Signing in…")));
  const talk = h("ol", { class: "talk" });
  view.replaceChildren(top, h("h2", { class: "label" }, "What the two sides said"), talk);
  const say = (side, title, ...body) => {
    const li = h("li", { class: side }, h("span", { class: "who" }, side === "app" ? "The app" : "You"), h("strong", {}, title), ...body);
    talk.append(li);
    return li;
  };
  const restart = () => top.replaceChildren(h("button", { class: "primary", onclick: showStart }, "Start over"));

  const c = server.challenge();
  say("app", "Here is a one-time challenge.", h("p", {}, "Sign this exact request within two minutes:"), h("code", {}, `POST ${c.url}`));
  let signed;
  try {
    signed = await signer.sign(loginTemplate(c));
  } catch (e) {
    say("you", "I didn't sign.", h("p", { class: "bad" }, e?.message ?? String(e)));
    return restart();
  }
  const authorization = authorizationHeader(signed);
  say("you", "Here is my answer, signed by my Nostr key.", h("p", {}, "A NIP-98 event (kind 27235) naming that URL and method. My secret key stays with me."), h("pre", {}, eventJson(signed)));

  const reply = say("app", "Checking…", spinner());
  const r = await server.login(authorization, c.url);
  if (r.error) {
    reply.replaceChildren(h("span", { class: "who" }, "The app"), h("strong", {}, "Refused."), h("p", { class: "bad" }, r.error));
    return restart();
  }
  reply.replaceChildren(
    h("span", { class: "who" }, "The app"),
    h("strong", {}, "Signed in."),
    h("ul", { class: "checks" }, ["the signature is this key's", "a login event, kind 27235", "dated within 60 s of my clock", "it names this URL and POST", "a challenge I issued, now spent"].map((t) => h("li", {}, t))),
    bindingNote(r.bch),
  );
  top.replaceChildren(welcome(r));
  if (r.walletChallenge) top.append(walletCard(r.walletChallenge, say));

  const replay = say("you", "What if someone replays that same answer?", h("p", {}, h("button", {
    onclick: async (ev) => {
      ev.currentTarget.disabled = true;
      const again = await server.login(authorization, c.url);
      replay.append(h("p", { class: again.error ? "good" : "bad" }, again.error ? `The app refuses it: ${again.error}.` : "The app let it in. That is a bug."));
    },
  }, "Send the same answer again")));
}

// ── The wallet's answer (spec §9 step 5): the key behind the bound address signs the app's one-time code. ──
/** A WizardConnect session drawn in `el`: QR and phone link, then onReady(dapp) once the wallet shares its public keys. → stop() */
function connectWallet(el, onReady, again) {
  const dapp = new DappConnectionManager("Members' corner", undefined, { session: false });
  const relay = initiateDappRelay(({ client, status }) => dapp.updateConnection(client, status));
  dapp.attachRelay(relay);
  let ready = false, stopped = false;
  const qr = h("div", { class: "qr" });
  qr.innerHTML = renderSVG(relay.qrUri);
  const waiting = h("p", { class: "quiet" }, "Waiting for your wallet…");
  el.replaceChildren(qr, h("p", {}, "Scan this with your wallet app (Paytaca, Cashonize)."),
    h("p", {}, "On this phone? ", copyButton(relay.uri, "Copy the connection link"), " and paste it in your wallet (Paytaca: Apps → WizardConnect → Paste URL), or ", h("a", { href: relay.uri }, "open it directly"), "."),
    waiting);
  // WizardConnect gives up silently when a key exchange stalls (« Key exchange timed out » in the console): offer a fresh code.
  const stall = setTimeout(() => { if (!ready && !stopped) waiting.append(" Stuck? ", h("button", { type: "button", class: "link", onclick: again }, "Get a fresh code")); }, 45_000);
  dapp.on("walletready", () => { if (!ready) { ready = true; onReady(dapp); } });
  dapp.on("disconnect", () => { if (!stopped) el.replaceChildren(h("p", {}, "The wallet disconnected."), h("button", { onclick: again }, "Connect again")); });
  return () => {
    if (stopped) return;
    stopped = true;
    clearTimeout(stall);
    // Let the goodbye (and any message still on its way to a slower relay) leave before the sockets close.
    const bye = Promise.resolve().then(() => dapp.sendDisconnect("done")).catch(() => {});
    Promise.race([bye, new Promise((r) => setTimeout(r, 1500))]).finally(() => { relay.cleanup(); dapp.destroy(); });
  };
}

/** The wallet signs input 0 and keeps it (broadcast: false). → the signed transaction, hex. */
async function walletSigns(dapp, c, path) {
  const { inputs, outputs, version, locktime } = c.transaction;
  const res = await dapp.signTransaction({
    transaction: {
      transaction: transactionToHex(inputs, outputs, version, locktime),
      sourceOutputs: c.sourceOutputs.map(sourceOutputToRelay),
      broadcast: false,
      userPrompt: `Sign in to ${location.host}: this proves you hold this address. Nothing is sent, it spends a coin that can never exist.`,
    },
    inputPaths: [[0, path[0], path[1]]],
  });
  if (res.error) throw new Error(res.error);
  return res.signedTransaction;
}

function walletCard(c, say) {
  const body = h("div", { class: "step" });
  const retry = (label = "Try again") => h("button", { onclick: connect }, label);
  function connect() {
    walletSession?.();
    const stop = (walletSession = connectWallet(body, async (dapp) => {
      const path = findAddressPath((child, i) => dapp.getPubkey(child, i), c.address);
      if (!path) {
        stop();
        return body.replaceChildren(h("p", { class: "bad" }, "This wallet doesn't hold that address."), h("p", { class: "quiet" }, "I looked at its first 2 000 receive and change addresses. Connect the wallet you bound this key with."), retry("Connect another wallet"));
      }
      body.replaceChildren(h("div", { class: "center" }, spinner(), h("span", {}, `Found it in your wallet (${path[0]} ${path[1]}). Approve the signature there…`)));
      let signed;
      try {
        signed = await walletSigns(dapp, c, path);
      } catch (e) {
        say("you", "My wallet didn't sign.", h("p", { class: "bad" }, e?.message ?? String(e)));
        return body.replaceChildren(retry());
      } finally { stop(); }
      say("you", "Here is my wallet's answer.", h("p", {}, "The key behind my address signed this text:"), h("code", {}, c.text), h("p", {}, "My wallet kept the transaction; it was never sent."), h("pre", {}, signed));
      const r = server.walletLogin(signed);
      if (r.error) {
        say("app", "Refused.", h("p", { class: "bad" }, r.error));
        return body.replaceChildren(retry());
      }
      say("app", "Your wallet answered too.", h("ul", { class: "checks" }, ["one input, spending a coin made from my challenge, which can never exist", "its only output is the one-time code", "signed by the key behind your bound address, over every output", "the BCH virtual machine accepts the signature", "a code I issued, now spent"].map((t) => h("li", {}, t))));
      body.replaceChildren(h("p", { class: "status verified" }, "✓ Both keys answered: your Nostr key and the wallet behind this address."));
      const tries = say("you", "What if someone replays it, or tries to send it as a payment?");
      tries.append(h("div", { class: "actions" },
        h("button", { onclick: (ev) => {
          ev.currentTarget.disabled = true;
          const again = server.walletLogin(signed);
          tries.append(h("p", { class: again.error ? "good" : "bad" }, again.error ? `The app refuses it: ${again.error}.` : "The app let it in. That is a bug."));
        } }, "Send it to the app again"),
        h("button", { onclick: async (ev) => {
          ev.currentTarget.disabled = true;
          const out = h("p", {}, spinner());
          tries.append(out);
          try {
            const txid = await (await chain()).broadcast(signed);
            out.replaceChildren(h("span", { class: "bad" }, `A server took it (${txid}). That is a bug.`));
          } catch (e) {
            out.replaceChildren(h("span", { class: "good" }, `A Bitcoin Cash server refuses it: ${String(e?.message ?? e).trim().replace(/[.\s]+$/, "")}.`));
          }
        } }, "Try to broadcast it")));
    }, connect));
  }
  body.append(h("button", { class: "primary", onclick: connect }, "Connect my wallet"));
  return h("section", { class: "card" },
    h("p", { class: "kicker" }, "Optional"),
    h("h2", {}, "Prove the wallet too"),
    h("p", {}, "Your Nostr key answered. Your wallet can answer as well: it signs a one-time code with the key behind ", h("span", { class: "mono" }, c.address), "."),
    h("p", { class: "quiet" }, "Nothing is sent. The transaction it signs spends a coin that can never exist, so no network accepts it: it moves no money and costs no fee."),
    body);
}

function bindingNote(bch) {
  if (bch.status === "verified" || bch.status === "pending") {
    return h("p", {}, "Then I checked your Bitcoin Cash binding myself: your signed Nostr claim names ", h("span", { class: "mono" }, bch.address),
      ", and ", txLink(bch.txid), ", signed by that address, names your Nostr key. ", bch.status === "verified" ? "It is in a block." : "It waits for its first block.");
  }
  return h("p", {}, "Then I looked for a Bitcoin Cash binding: ", bch.reason ?? bch.status, ".");
}

function welcome({ npub, bch, profile }) {
  const bound = bch.status === "verified" || bch.status === "pending";
  const plural = bch.confirmations === 1 ? "" : "s";
  return h("section", { class: "card welcome" },
    h("p", { class: "kicker" }, "Signed in"),
    h("h1", {}, `Welcome, ${profile?.name ?? shortKey(npub)}.`),
    h("p", { class: "mono quiet" }, npub),
    bound
      ? [
          h("p", {}, "Your Bitcoin Cash address, bound to this key:"),
          h("code", {}, bch.address),
          h("p", { class: `status ${bch.status}` }, bch.status === "verified" ? `Verified · ${bch.confirmations} confirmation${plural}` : "Pending · the binding waits for its first block"),
          h("p", {}, "Other members can pay you without asking for an address: ", h("a", { href: `${SITE}#/${npub}` }, "your pay page"), "."),
        ]
      : h("p", {}, bch.status === "unknown"
          ? `Your key is fine, but no Bitcoin Cash server answered (${bch.reason}).`
          : bch.status === "superseded"
            ? "The address this key named was later bound to another Nostr key by its owner."
            : /no identity claim/.test(bch.reason ?? "")
              ? ["No Bitcoin Cash address is bound to this key yet. ", h("a", { href: `${SITE}#/bind` }, "Bind one on Countersign"), " (one small transaction from your wallet), then sign in again."]
              : `This key's binding doesn't check out: ${bch.reason}.`),
    h("button", { onclick: showStart }, "Sign out"),
  );
}

showStart();
setTimeout(() => { if (!started && window.nostr?.signEvent) showStart(); }, 800); // extensions can inject window.nostr late
