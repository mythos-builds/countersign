// Members' corner: a demo app that signs people in with Countersign (spec §9). It uses the library and nostr-tools
// only, nothing from the Countersign site. Its server part runs in this page, labelled, so both sides can be watched.
import { generateSecretKey, finalizeEvent } from "nostr-tools";
import { loginGate, loginTemplate, authorizationHeader, verifyBinding, relayReader, fulcrumChain } from "../../lib/index.mjs";

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
    return { ...who, bch, profile };
  },
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
function showStart() {
  started = false;
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

  const replay = say("you", "What if someone replays that same answer?", h("p", {}, h("button", {
    onclick: async (ev) => {
      ev.currentTarget.disabled = true;
      const again = await server.login(authorization, c.url);
      replay.append(h("p", { class: again.error ? "good" : "bad" }, again.error ? `The app refuses it: ${again.error}.` : "The app let it in. That is a bug."));
    },
  }, "Send the same answer again")));
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
