// The site (spec §7, §8): #/<name> pays a bound name and lists its receipts, #/bind binds yours, #/wall lists the names bound here.
// Every check runs in this browser.
import * as L from "@bitauth/libauth";
import { renderSVG } from "uqr";
import { initiateDappRelay } from "@wizardconnect/core";
import { DappConnectionManager } from "@wizardconnect/dapp";
import { sourceOutputToRelay, transactionToHex } from "@wizardconnect/core/hdwalletv1-serialize";
import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from "nostr-tools";
import {
  resolveName, relayReader, fulcrumChain, verifyBinding, verifiedCopy, parseBch, formatBch, paymentUri, paidTo, scanWallet,
  buildPayment, buildCommitment, buildClaim, findByAddress, decodeP2pkhAddress, npubToHex, listWall, DEFAULT_RELAYS, DUST,
  receiptTemplate, listReceipts, explorerUrl, connectLink, viaLink, viaBunker,
} from "../lib/index.mjs";

const PROJECT = "npub1v2zlnx5g0m847j4k34d30az2dykjwrlazp68fqwe3c0nekaqltkqd23d95";
const DEFAULT_AMOUNT = "0.0001";
const DEMO_KEY = "countersign-demo-identity";
const view = document.getElementById("view");

/** Tiny DOM builder: strings become text nodes, never HTML. */
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  el.append(...kids.flat().filter((k) => k != null && k !== false));
  return el;
}
const fill = (el, ...kids) => el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));

const shortKey = (s) => `${s.slice(0, 12)}…${s.slice(-6)}`;
const sentence = (s) => (s ? s[0].toUpperCase() + s.slice(1) + (/[.!?]$/.test(s) ? "" : ".") : "");
const spinner = () => h("div", { class: "spinner", role: "status", "aria-label": "Working" });
const initial = (name) => h("div", { class: "avatar", "aria-hidden": "true" }, [...name][0]?.toUpperCase() ?? "?");
const txLink = (txid, label = `transaction ${txid.slice(0, 8)}…`) => h("a", { href: explorerUrl(txid), target: "_blank", rel: "noopener" }, label);
function ago(seconds) {
  const m = Math.max(1, Math.round(seconds / 60));
  return m < 60 ? `${m} min ago` : m < 2880 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} days ago`;
}

function copyButton(text, label = "Copy") {
  const b = h("button", {
    type: "button", class: "link",
    onclick: async () => {
      try { await navigator.clipboard.writeText(text); b.textContent = "Copied"; } catch { b.textContent = "Copy failed"; }
      setTimeout(() => { b.textContent = label; }, 1500);
    },
  }, label);
  return b;
}

let chainP = null;
const chain = () => (chainP ??= fulcrumChain().catch((e) => { chainP = null; throw e; }));
let cleanups = [];
let nav = 0;

function route() {
  cleanups.splice(0).forEach((fn) => { try { fn(); } catch { /* already gone */ } });
  const me = ++nav;
  let raw = location.hash.replace(/^#\/?/, "");
  try { raw = decodeURIComponent(raw); } catch { /* keep it as typed */ }
  raw = raw.trim();
  if (raw === "bind") showBind();
  else if (raw === "wall") showWall(me);
  else if (raw) showName(raw, me);
  else showHome();
  window.scrollTo(0, 0);
}
// The BLAZE banner is static markup; its copy button gets the same behaviour as the others.
for (const b of document.querySelectorAll("[data-copy]")) b.replaceWith(copyButton(b.dataset.copy));
window.addEventListener("hashchange", route);
route();

function go(name) {
  const hash = `#/${encodeURIComponent(name).replace(/%40/g, "@")}`;
  if (location.hash === hash) route(); else location.hash = hash;
}

function showHome(error, value = "") {
  const input = h("input", {
    type: "text", value, placeholder: "npub1…, name@domain, a profile link or a BCH address", autocomplete: "off", autocapitalize: "off",
    spellcheck: "false", "aria-label": "A Nostr name",
  });
  fill(view, h("section", { class: "hero" },
    h("h1", {}, "Pay any Nostr name in Bitcoin Cash."),
    h("p", { class: "lede" }, "On chain, from your own wallet. No custodian and no account: the name's owner signed with both keys, and your browser checks both signatures."),
    h("form", { class: "find", onsubmit: (e) => { e.preventDefault(); if (input.value.trim()) go(input.value.trim()); } },
      input, h("button", { type: "submit", class: "primary" }, "Find")),
    error ? h("p", { class: "error", role: "alert" }, error) : null,
    h("p", { class: "try" }, "Try it with ", h("a", { href: `#/${PROJECT}` }, "Countersign's own name"), "."),
    h("p", { class: "try" }, "Have a Nostr name? ", h("a", { href: "#/bind" }, "Bind it to your Bitcoin Cash address"), " in two signatures."),
    h("p", { class: "try" }, "Who's here already? ", h("a", { href: "#/wall" }, "See the wall"), ".")));
  if (!matchMedia("(pointer: coarse)").matches) input.focus();
}

// ── Paying a name ────────────────────────────────────────────────────────────

/** A pasted BCH address in its plain P2PKH form (token-aware « z » addresses too), or null. */
function asAddress(raw) {
  const text = raw.replace(/\?.*$/, "").toLowerCase();
  for (const t of text.includes(":") ? [text] : [text, `bitcoincash:${text}`]) {
    try {
      const { prefix, payload } = decodeP2pkhAddress(t);
      const enc = L.encodeCashAddress({ prefix, type: "p2pkh", payload });
      return typeof enc === "string" ? enc : enc.address;
    } catch { /* not an address */ }
  }
  return null;
}

/** Shaped like a cash address but not one we can use: why, in words. */
function addressProblem(raw) {
  const text = raw.replace(/\?.*$/, "").toLowerCase();
  if (!/^((bitcoincash|bchtest):)?[qpzr][02-9ac-hj-np-z]{41}$/.test(text)) return null;
  const d = L.decodeCashAddress(text.includes(":") ? text : `bitcoincash:${text}`);
  return typeof d === "string" ? "That address has a typo: its checksum doesn't match." : "Only plain (P2PKH) addresses can carry a name for now; this one is a script address.";
}

async function showName(raw, me) {
  const address = asAddress(raw);
  fill(view, h("section", { class: "card loading" }, spinner(),
    h("div", {}, h("b", {}, address ? "Looking up this address…" : "Checking this name…"),
      h("p", { class: "muted", style: "margin:0" }, address
        ? "Names that claim it on Nostr relays, commitments in its history on the Bitcoin Cash chain."
        : "Its claim on Nostr relays, its commitment on the Bitcoin Cash chain."))));
  let who = null;
  if (!address) {
    const problem = addressProblem(raw);
    if (problem) { if (me === nav) showHome(problem, raw); return; }
    try { who = await resolveName(raw); } catch (e) {
      if (me === nav) showHome(e.code === "unrecognized" ? "Paste an npub, a name@domain, a Nostr profile link or a BCH address." : e.message, raw);
      return;
    }
  }
  const nostr = relayReader();
  let result, profile, servers = [];
  try {
    const c = await chain();
    servers = c.servers;
    if (address) {
      // Discovery by address: claims tagging it on relays, commitments in its history; each one verified in full.
      result = await findByAddress(address, { nostr, chain: c });
      if (!result) { if (me === nav) showHome(`No Nostr name is bound to ${address} yet.`, raw); return; }
      who = { pubkey: npubToHex(result.npub), npub: result.npub, relays: [], via: `the address, found through the ${result.via.join(" and the ")}` };
      profile = await nostr.fetchProfile(who.pubkey).catch(() => null);
    } else {
      [result, profile] = await Promise.all([
        verifyBinding(who.npub, { nostr: { fetchClaim: (pk) => nostr.fetchClaim(pk, who.relays) }, chain: c }),
        nostr.fetchProfile(who.pubkey, who.relays).catch(() => null),
      ]);
    }
  } catch (e) {
    if (!who) { if (me === nav) showHome(`Couldn't look up this address: ${e.message}`, raw); return; }
    result = { status: "error", reason: e.message, warnings: [] };
  } finally {
    nostr.close();
  }
  if (me !== nav) return;
  const name = profile?.name ?? shortKey(who.npub);
  const avatar = profile?.picture
    ? h("img", { class: "avatar", src: profile.picture, alt: "", referrerpolicy: "no-referrer", onerror: (e) => e.target.replaceWith(initial(name)) })
    : initial(name);
  const payable = result.status === "verified" || result.status === "pending";
  const recent = payable ? receiptsCard(result, who, me) : null;
  fill(view,
    h("section", { class: "card" },
      h("div", { class: "who" }, avatar,
        h("div", { style: "min-width:0" }, h("h2", {}, name), h("p", { class: "npub" }, shortKey(who.npub), " ", copyButton(who.npub, "Copy npub")))),
      statusBox(result),
      payable ? h("p", { class: "addr" }, h("span", { class: "muted" }, "Pays to "), h("code", {}, result.address), " ", copyButton(result.address)) : null),
    payable ? payCard(result, name, who, recent) : null,
    recent?.el,
    howChecked(who, result, servers));
  recent?.load();
}

function statusBox(r) {
  const isNew = r.warnings?.includes("new");
  const since = r.boundSince ? `Bound since ${new Date(r.boundSince * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })} (${ago(Date.now() / 1000 - r.boundSince)})` : "";
  const careful = " If you know this person, check it with them before sending much.";
  switch (r.status) {
    case "verified":
      return h("div", { class: `status ${isNew ? "warn" : "ok"}` }, h("b", {}, isNew ? "Verified, and new" : "Verified"),
        `${since}, ${r.confirmations} confirmation${r.confirmations === 1 ? "" : "s"}.`, isNew ? " Less than a day old." + careful : "");
    case "pending":
      return h("div", { class: "status warn" }, h("b", {}, "New: waiting for its first block"),
        "Both signatures check out and the commitment is in the mempool." + careful);
    case "superseded":
      return h("div", { class: "status bad" }, h("b", {}, "Replaced"), "This address was later bound to another Nostr name, so this binding no longer counts.");
    case "error":
      return h("div", { class: "status bad" }, h("b", {}, "Couldn't check this name right now"), sentence(r.reason));
    default:
      return h("div", { class: "status bad" }, h("b", {}, "No Bitcoin Cash address for this name"), sentence(r.reason),
        h("p", { style: "margin:0.5rem 0 0" }, "Is it yours? ", h("a", { href: "#/bind" }, "Bind it"), "."));
  }
}

function howChecked(who, r, servers) {
  const items = [
    [`Name: ${who.via === "npub" ? "an npub" : who.via} → `, h("code", {}, who.npub)],
    r.txid && "Claim: the name's newest NIP-39 identity list (kind 10011) from Nostr relays, its signature checked in this browser.",
    r.txid && ["Commitment: ", txLink(r.txid, `transaction ${r.txid.slice(0, 10)}…`),
      " and each of its parents, fetched and re-hashed; signed by the address over every output; run through the BCH virtual machine here; its data output names this npub."],
    r.status === "verified" && `${r.confirmations} confirmation${r.confirmations === 1 ? "" : "s"}; first block at ${new Date(r.boundSince * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC.`,
    r.status === "pending" && "Not in a block yet.",
    ...(r.warnings ?? []).filter((w) => w !== "new").map(sentence),
    servers.length && `Chain servers: ${servers.map((u) => new URL(u).hostname).join(", ")}.`,
    "No server of ours took part: there is none.",
  ];
  return h("details", {}, h("summary", {}, "How this name was checked"), h("ul", {}, ...items.filter(Boolean).map((x) => h("li", {}, x))));
}

function payCard(r, name, who, recent) {
  let sats = parseBch(DEFAULT_AMOUNT);
  const amount = () => (sats && sats >= DUST ? sats : null);
  const hint = h("p", { class: "error", style: "margin:0 0 0.8rem", hidden: true });
  const onAmount = new Set();
  const setAmount = (text) => {
    sats = parseBch(text);
    hint.hidden = !!amount();
    hint.textContent = sats ? `The smallest payment is ${formatBch(DUST)} BCH.` : "Enter an amount in BCH.";
    onAmount.forEach((fn) => fn());
  };
  const input = h("input", { type: "text", inputmode: "decimal", value: DEFAULT_AMOUNT, "aria-label": "Amount in BCH", oninput: () => setAmount(input.value) });
  const chips = ["0.0001", "0.001", "0.01"].map((v) => h("button", { type: "button", class: "chip", onclick: () => { input.value = v; setAmount(v); } }, v));

  const paidBox = h("div", { class: "paid", hidden: true });
  const shown = new Set();
  const markPaid = ({ txid, sats: got }) => {
    if (shown.has(txid)) return;
    shown.add(txid);
    const want = amount();
    paidBox.hidden = false;
    paidBox.prepend(h("div", {},
      h("div", { class: "big" }, want && got >= want ? "Paid ✓" : `Received ${formatBch(got)} BCH`),
      h("p", {}, `${formatBch(got)} BCH reached ${name} · `, txLink(txid)),
      receiptOffer({ txid, sats: got }, who, name, () => recent?.load())));
  };

  const rails = {};
  const railBox = h("div");
  const tabs = [["wallet", "Wallet app"], ["qr", "Any wallet (QR)"]];
  const tabEls = tabs.map(([id, label]) => h("button", { type: "button", role: "tab", onclick: () => show(id) }, label));
  function show(id) {
    tabEls.forEach((t, i) => t.setAttribute("aria-selected", String(tabs[i][0] === id)));
    if (!rails[id]) {
      rails[id] = id === "wallet" ? walletRail(r, name, amount, markPaid) : qrRail(r, amount);
      if (rails[id].update) onAmount.add(rails[id].update);
      if (rails[id].stop) cleanups.push(rails[id].stop);
    }
    fill(railBox, rails[id].el);
  }
  show("wallet");

  watchPayments(r.address, markPaid).then((stop) => cleanups.push(stop)).catch(() => {});
  return h("section", { class: "card" },
    h("h2", {}, `Pay ${name}`),
    h("div", { class: "amount" }, input, h("span", { class: "muted" }, "BCH")), h("div", { class: "chips" }, ...chips), hint,
    paidBox,
    h("div", { class: "tabs", role: "tablist" }, ...tabEls), railBox);
}

/** Calls onPayment({ txid, sats }) for each new transaction paying the address: a Fulcrum subscription, plus a slow poll as a net. */
async function watchPayments(address, onPayment) {
  const c = await chain();
  const seen = new Set();
  let ready = false;
  const check = async () => {
    if (!ready) return;
    for (const { tx_hash: txid } of await c.getHistory(address)) {
      if (seen.has(txid)) continue;
      seen.add(txid); // before any await: overlapping checks (subscription, poll, page shown again) report a payment once
      const tx = await c.getTx(txid).then(L.decodeTransaction, (e) => { seen.delete(txid); throw e; }); // getTx re-hashes against the id
      const sats = typeof tx === "string" ? 0n : paidTo(tx, address);
      if (sats > 0n) onPayment({ txid, sats });
    }
  };
  const sub = await c.watchAddress(address, () => check().catch(() => {})).catch(() => null);
  (await c.getHistory(address)).forEach((x) => seen.add(x.tx_hash));
  ready = true;
  const poll = setInterval(() => check().catch(() => {}), 20_000);
  // Back from paying in the wallet app: look at once (the subscription may have died with the tab in the background).
  const onShow = () => { if (document.visibilityState === "visible") check().catch(() => {}); };
  document.addEventListener("visibilitychange", onShow);
  return () => { clearInterval(poll); sub?.stop(); document.removeEventListener("visibilitychange", onShow); };
}

function qrRail(r, amount) {
  const qr = h("div", { class: "qr" });
  const open = h("a", { class: "button primary" }, "Open in my wallet");
  const update = () => {
    const uri = paymentUri(r.address, amount());
    qr.innerHTML = renderSVG(uri); // SVG drawn from our own checked address and amount
    open.href = uri;
  };
  update();
  return {
    el: h("div", { class: "rail" }, qr, open,
      h("p", { class: "muted" }, "Any Bitcoin Cash wallet can scan this. This page sees the payment arrive by itself."),
      copyButton(r.address, "Copy the address")),
    update,
  };
}

// ── Receipts ─────────────────────────────────────────────────────────────────

/** The Nostr names this browser can sign with: an extension (NIP-07), a signer app (NIP-46), the identity made on the bind page. */
function signers() {
  const ways = [];
  if (window.nostr) ways.push({
    label: "Post it with my Nostr extension",
    get: async () => {
      const pubkey = await window.nostr.getPublicKey();
      if (!/^[0-9a-f]{64}$/.test(pubkey ?? "")) throw new Error("the extension gave no key");
      return { pubkey, sign: (t) => window.nostr.signEvent(t) };
    },
  });
  ways.push(remote
    ? { label: `Post it as ${shortKey(remote.npub)} (your signer app)`, get: async () => remote }
    : { label: "Post it with a signer app", get: (el) => remoteSigner(el) });
  const sk = loadDemoKey();
  if (sk) ways.push({ label: `Post it as ${shortKey(nip19.npubEncode(getPublicKey(sk)))} (made here)`, get: async () => localIdentity(sk) });
  return ways;
}

// ── Remote signers (NIP-46) ──────────────────────────────────────────────────

let remote = null; // the signer app connected in this tab, reused until the tab closes

/** Connect a signer app (Amber, nsec.app, a bunker) by its QR or link, or by a pasted bunker:// link, inside `el`.
 *  Resolves with an identity whose signatures are re-verified (lib/remote.mjs); rejects with « cancelled » on Cancel. */
function remoteSigner(el) {
  if (remote) return Promise.resolve(remote);
  return new Promise((resolve, reject) => {
    const stop = new AbortController();
    const link = connectLink({ url: location.protocol === "https:" ? `${location.origin}${location.pathname}` : undefined });
    const status = h("p", { class: "muted" }, "Waiting for your signer app…");
    const onauth = (url) => /^https:\/\//.test(url) && fill(status, "Your signer asks you to approve this page first: ",
      h("a", { href: url, target: "_blank", rel: "noopener" }, "open its page"), ", then come back here.");
    const qr = h("div", { class: "qr" });
    qr.innerHTML = renderSVG(link.uri); // SVG drawn from the link we just made
    const input = h("input", { type: "text", placeholder: "or paste a bunker:// link", "aria-label": "bunker link", autocomplete: "off", spellcheck: "false" });
    const done = (id) => { stop.abort(); remote = id; resolve(id); };
    const failed = (e) => fill(status, h("span", { class: "error" }, `Not connected: ${e.message || e}`));
    fill(el,
      h("p", {}, "Scan this with your signer app (Amber, nsec.app…), or open the link on this phone. Your key stays in the app: this page only receives what it signs, and checks every signature."),
      h("div", { class: "row center" }, qr),
      h("div", { class: "row center" }, h("a", { class: "button", href: link.uri }, "Open in a signer app"), copyButton(link.uri, "Copy the link")),
      h("div", { class: "row" }, input, h("button", { type: "button", onclick: paste }, "Connect")),
      status,
      h("button", { type: "button", class: "link", onclick: () => { stop.abort(); reject(new Error("cancelled")); } }, "Cancel"));
    viaLink(link, { signal: stop.signal, onauth }).then(done, (e) => { if (!stop.signal.aborted) failed(e); });
    async function paste() {
      fill(status, "Connecting to the bunker…");
      try { done(await viaBunker(input.value, { onauth })); } catch (e) { failed(e); }
    }
  });
}

/** After a payment: an optional public note from the payer's Nostr name that points at the transaction (spec §8.3). */
function receiptOffer({ txid, sats }, payee, name, onPosted) {
  const ways = signers();
  if (!ways.length) return null;
  const el = h("div", { class: "offer" });
  const start = () => fill(el,
    h("p", {}, `Post a receipt? A public note from your Nostr name that points at this payment: ${name} is notified, and it shows under Recent payments.`),
    h("div", { class: "row center" }, ...ways.map((w) => h("button", { type: "button", onclick: () => post(w) }, w.label))));
  async function post(way) {
    fill(el, spinner(), h("p", {}, "Signing and publishing the note…"));
    const reader = relayReader();
    try {
      const id = await way.get(el);
      if (id.via === "remote") fill(el, spinner(), h("p", {}, "Approve the note in your signer app…"));
      if (id.pubkey === payee.pubkey) throw new Error(`that is ${name}'s own Nostr name, and a payee's own receipts aren't listed`);
      const link = location.protocol === "https:" ? `${location.origin}${location.pathname}#/${payee.npub}` : undefined; // never a local address in a public note
      const event = verifiedCopy(await id.sign(receiptTemplate({ payee: payee.npub, txid, sats, link })));
      if (!event || event.pubkey !== id.pubkey) throw new Error("the signed note doesn't verify for this key");
      // NIP-65: the payer's outbox, the payee's inbox, and the defaults every reader here asks.
      const [outbox, inbox] = await Promise.all([reader.writeRelays(id.pubkey).catch(() => []), reader.readRelays(payee.pubkey).catch(() => [])]);
      const targets = [...new Set([...outbox.slice(0, 5), ...inbox.slice(0, 5), ...DEFAULT_RELAYS])];
      const results = await reader.publish(event, targets);
      const accepted = targets.filter((_, i) => results[i].status === "fulfilled");
      if (!accepted.length) throw new Error("no relay accepted it");
      const nevent = nip19.neventEncode({ id: event.id, author: event.pubkey, relays: accepted.slice(0, 2) });
      fill(el, h("p", {}, `Receipt posted on ${accepted.length} of ${targets.length} relays · `,
        h("a", { href: `https://njump.me/${nevent}`, target: "_blank", rel: "noopener" }, "see the note")));
      onPosted?.();
    } catch (e) {
      if (e.message === "cancelled") return start();
      fill(el, h("p", { class: "error" }, `Not posted: ${e.message || e}`), h("button", { type: "button", onclick: start }, "Back"));
    } finally {
      reader.close();
    }
  }
  start();
  return el;
}

/** Recent payments: receipts on Nostr for this name, each checked on chain in this browser. → { el, load } */
function receiptsCard(r, who, me) {
  const list = h("ul", { class: "receipts", hidden: true });
  const note = h("div", { class: "muted small" });
  const el = h("section", { class: "card" }, h("h2", {}, "Recent payments"), list, note);
  const entry = (row, p) => {
    const name = p?.name ?? shortKey(row.npub);
    const avatar = p?.picture
      ? h("img", { class: "avatar", src: p.picture, alt: "", referrerpolicy: "no-referrer", onerror: (e) => e.target.replaceWith(initial(name)) })
      : initial(name);
    return h("li", { class: "who" }, avatar,
      h("div", { class: "grow" },
        h("p", { class: "line" }, h("a", { href: `#/${row.npub}` }, h("b", {}, name)), ` paid ${formatBch(row.sats)} BCH`),
        h("p", { class: "meta" },
          row.proof === "bound" ? h("span", { class: "proof" }, "✓ from their bound address") : "says it was them",
          ` · ${row.height > 0 ? ago(Math.max(0, Date.now() / 1000 - row.created_at)) : "not in a block yet"} · `, txLink(row.txid, "transaction"))));
  };
  let run = 0;
  async function load() {
    const mine = ++run;
    const live = () => mine === run && me === nav;
    fill(note, h("div", { class: "loading" }, spinner(), "Looking for receipts on Nostr, then checking each payment on chain…"));
    const nostr = relayReader();
    const shown = [], pending = [];
    try {
      const add = async (row, rank) => {
        const profile = await nostr.fetchProfile(row.pubkey).catch(() => null);
        if (!live()) return;
        shown[rank] = entry(row, profile);
        list.hidden = false;
        fill(list, shown.filter(Boolean));
      };
      await listReceipts({ payee: { pubkey: who.pubkey, address: r.address }, nostr, chain: await chain(), onRow: (row, rank) => pending.push(add(row, rank)) });
      await Promise.all(pending);
    } catch (e) {
      if (live()) fill(note, h("p", { class: "error" }, `Couldn't read the receipts: ${e.message}`), h("button", { type: "button", onclick: load }, "Try again"));
      return;
    } finally {
      nostr.close();
    }
    if (!live()) return;
    fill(note, shown.some(Boolean)
      ? "Receipts are public Nostr notes that point at a payment; each one here pays this name on chain. Anyone can post one about any payment, so a payer is proven only when their own bound address signed it."
      : "No public receipts yet. After paying, you can post one from your Nostr name.");
  }
  return { el, load };
}

// ── WizardConnect ────────────────────────────────────────────────────────────

/** A WizardConnect session drawn in `el`: QR and phone link, then onReady(dapp) once the wallet has shared its public keys. */
function connectWallet(el, onReady) {
  let dapp, relay, readyOnce, stall;
  function stop() {
    clearTimeout(stall);
    const [d, r] = [dapp, relay];
    dapp = relay = null;
    if (!d) return;
    // Let the goodbye (and any message still on its way to a slower relay) leave before the sockets close.
    const bye = Promise.resolve().then(() => d.sendDisconnect("page closed")).catch(() => {});
    Promise.race([bye, new Promise((res) => setTimeout(res, 1500))]).finally(() => { r.cleanup(); d.destroy(); });
  }
  function start() {
    stop();
    readyOnce = false;
    // Each relay reports to its own session: a closing one must never reach the next (or a null one).
    const session = new DappConnectionManager("Countersign", undefined, { session: false });
    relay = initiateDappRelay(({ client, status }) => session.updateConnection(client, status));
    session.attachRelay(relay);
    dapp = session;
    const qr = h("div", { class: "qr" });
    qr.innerHTML = renderSVG(relay.qrUri);
    const waiting = h("p", { class: "muted" }, "Waiting for your wallet…");
    fill(el, qr, h("p", {}, "Scan this with your wallet app."),
      // iOS knows no wiz:// scheme (Paytaca registers none: 2026-11-14), so a phone gets the link to paste.
      h("p", {}, "On this phone? ", copyButton(relay.uri, "Copy the connection link"), " and paste it in your wallet (Paytaca: Apps → WizardConnect → Paste URL), or ", h("a", { href: relay.uri }, "open it directly"), "."),
      waiting);
    const d = dapp;
    // WizardConnect gives up silently when a key exchange stalls (« Key exchange timed out » in the console): offer a fresh code.
    stall = setTimeout(() => { if (!readyOnce && dapp === d) waiting.append(" Stuck? ", h("button", { type: "button", class: "link", onclick: start }, "Get a fresh code")); }, 45_000);
    d.on("walletready", () => { if (!readyOnce) { readyOnce = true; onReady(d); } });
    d.on("disconnect", () => { if (dapp === d) fill(el, h("p", {}, "The wallet disconnected."), h("button", { type: "button", class: "primary", onclick: start }, "Connect again")); });
  }
  start();
  cleanups.push(stop);
  return { stop };
}

/** The wallet signs and broadcasts; the page checks it signed exactly what was built, and hands it to the network too. → txid */
async function signAndSend(dapp, built, userPrompt) {
  // The protocol's own relay format (hdwalletv1-serialize): the transaction as hex, source outputs with hex fields.
  // Paytaca reads only this; libauth's extended JSON reached it as zero bytes (2026-11-14).
  const { inputs, outputs, version, locktime } = built.transaction;
  const res = await dapp.signTransaction({
    transaction: {
      transaction: transactionToHex(inputs, outputs, version, locktime),
      sourceOutputs: built.sourceOutputs.map(sourceOutputToRelay),
      broadcast: true,
      userPrompt,
    },
    inputPaths: built.inputPaths,
  });
  if (res.error) throw new Error(res.error);
  const raw = L.hexToBin(res.signedTransaction);
  const signed = L.decodeTransaction(raw);
  if (typeof signed === "string") throw new Error(`the wallet sent back something that isn't a transaction (${signed})`);
  const out = (o) => `${o.valueSatoshis}:${L.binToHex(o.lockingBytecode)}`;
  if (signed.outputs.map(out).join() !== built.transaction.outputs.map(out).join()) throw new Error("the wallet changed the transaction's outputs, so this page won't send it");
  const ok = L.createVirtualMachineBch(true).verify({ sourceOutputs: built.sourceOutputs, transaction: signed });
  if (ok !== true) throw new Error(`the signed transaction doesn't verify: ${ok}`);
  // The wallet broadcasts it too (broadcast: true); a second copy is harmless and covers a wallet that didn't.
  await (await chain()).broadcast(res.signedTransaction).catch((e) => {
    if (!/already|known|exists|in.?mempool/i.test(e.message)) throw e;
  });
  return L.hashTransaction(raw);
}

/** WizardConnect rail: the wallet shares public keys only; the page builds the payment from its coins, the wallet signs. */
function walletRail(r, name, amount, markPaid) {
  const el = h("div", { class: "rail" });
  let session, dapp, scan, update = () => {};

  async function ready(d) {
    dapp = d;
    fill(el, spinner(), h("p", {}, `Connected to ${dapp.walletName ?? "your wallet"}. Looking for coins it can spend…`));
    try {
      scan = await scanWallet(await chain(), (child, i) => dapp.getPubkey(child, i));
    } catch (e) {
      return fill(el, h("p", { class: "error" }, `Couldn't read the wallet's coins: ${e.message}`), h("button", { type: "button", onclick: () => ready(dapp) }, "Try again"));
    }
    payButton();
  }

  function payButton() {
    const total = scan.coins.reduce((s, c) => s + c.satoshis, 0n);
    const btn = h("button", { type: "button", class: "pay", onclick: pay });
    update = () => {
      const a = amount();
      btn.textContent = a ? `Pay ${formatBch(a)} BCH` : "Enter an amount";
      btn.disabled = !a || total === 0n;
    };
    update();
    fill(el, h("p", {}, `${dapp.walletName ?? "Wallet"} connected · ${formatBch(total)} BCH it can spend.`), btn,
      total === 0n ? h("p", { class: "muted" }, "No coins without tokens in this wallet yet. Coins carrying tokens are never spent here.") : null);
  }

  async function pay() {
    const a = amount();
    if (!a) return;
    update = () => {};
    let p;
    try {
      p = buildPayment({ coins: scan.coins, to: r.address, satoshis: a, changeLockingBytecode: scan.change.lockingBytecode });
    } catch (e) {
      return fill(el, h("p", { class: "error" }, sentence(e.message)), h("button", { type: "button", onclick: payButton }, "Back"));
    }
    fill(el, spinner(), h("p", {}, h("b", {}, "Approve the payment in your wallet.")),
      h("p", { class: "muted" }, `${formatBch(a)} BCH to ${name}, network fee ${p.fee} satoshis.`));
    try {
      const txid = await signAndSend(dapp, p, `Pay ${formatBch(a)} BCH to ${name} (Countersign)`);
      markPaid({ txid, sats: a });
      fill(el, h("p", {}, "Sent from your wallet."), h("button", { type: "button", onclick: () => ready(dapp) }, "Pay again"));
    } catch (e) {
      fill(el, h("p", { class: "error" }, `Not sent: ${e.message || e}`), h("button", { type: "button", onclick: payButton }, "Try again"));
    }
  }

  fill(el, h("p", {}, "Connect Paytaca, Cashonize or any wallet that speaks WizardConnect. Your wallet shows you the payment and asks you to approve it; your keys never leave it."),
    h("button", { type: "button", class: "primary", onclick: () => { session = connectWallet(el, ready); } }, "Connect a wallet"));
  return { el, update: () => update(), stop: () => session?.stop() };
}

// ── Binding a name ───────────────────────────────────────────────────────────

function loadDemoKey() {
  try { const hex = localStorage.getItem(DEMO_KEY); return hex && /^[0-9a-f]{64}$/.test(hex) ? L.hexToBin(hex) : null; } catch { return null; }
}
function saveDemoKey(sk) { try { localStorage.setItem(DEMO_KEY, L.binToHex(sk)); } catch { /* private window: the nsec shown is the only copy */ } }
function forgetDemoKey() { try { localStorage.removeItem(DEMO_KEY); } catch { /* nothing kept */ } }

const localIdentity = (sk, name) => {
  const pubkey = getPublicKey(sk);
  return { pubkey, npub: nip19.npubEncode(pubkey), sk, name, sign: async (t) => finalizeEvent(t, sk) };
};

function showBind() {
  const step = (title) => {
    const body = h("div", { class: "step-body" });
    const el = h("li", { class: "step" }, h("h3", {}, title), body);
    return { el, body, set: (...kids) => fill(body, ...kids), state: (s) => { el.className = `step ${s}`; } };
  };
  const s1 = step("Your Nostr name"), s2 = step("Your Bitcoin Cash wallet"), s3 = step("Sign the commitment"), s4 = step("Publish the claim");
  let listMe = true; // the claim's wall tag (spec §7)
  [s2, s3, s4].forEach((s) => s.set(h("p", { class: "muted" }, "After the step above.")));
  s1.state("active");
  fill(view,
    h("section", { class: "hero small" },
      h("h1", {}, "Bind your Nostr name to a Bitcoin Cash address."),
      h("p", { class: "lede" }, "Two signatures, one from each key, and neither key leaves where it lives. After that, anyone can pay your Nostr name.")),
    h("section", { class: "card" }, h("ol", { class: "steps" }, s1.el, s2.el, s3.el, s4.el)));

  let id, dapp, built, address, txid;

  // 1 · the Nostr identity: a browser extension (NIP-07), or a new one made here.
  const nameInput = h("input", { type: "text", placeholder: "Your name (optional)", maxlength: "60", "aria-label": "Name people will see" });
  const stored = loadDemoKey();
  s1.set(
    h("p", {}, "The name people will pay."),
    window.nostr ? h("button", { type: "button", class: "primary", onclick: useExtension }, "Use my Nostr extension") : null,
    h("button", { type: "button", onclick: useRemote }, remote ? `Use my signer app (${shortKey(remote.npub)})` : "Use a signer app (Amber, nsec.app…)"),
    stored ? h("button", { type: "button", onclick: () => chosen(localIdentity(stored)) }, `Use the identity made here before (${shortKey(nip19.npubEncode(getPublicKey(stored)))})`) : null,
    h("div", { class: "row" }, nameInput, h("button", { type: "button", onclick: createIdentity }, "Create a new one here")),
    window.nostr ? null : h("p", { class: "muted" }, "No Nostr extension in this browser (nos2x, Alby…). A signer app works, and so does a new identity: you'll get its secret key to keep."));

  async function useExtension() {
    try {
      const pubkey = await window.nostr.getPublicKey();
      if (!/^[0-9a-f]{64}$/.test(pubkey ?? "")) throw new Error("it returned no key");
      chosen({ pubkey, npub: nip19.npubEncode(pubkey), sign: (t) => window.nostr.signEvent(t) });
    } catch (e) {
      s1.body.append(h("p", { class: "error" }, `The extension didn't give a key: ${e.message ?? e}`));
    }
  }
  async function useRemote() {
    const panel = h("div", { class: "offer" });
    s1.body.append(panel);
    try {
      chosen(await remoteSigner(panel));
    } catch (e) {
      panel.remove();
      if (e.message !== "cancelled") s1.body.append(h("p", { class: "error" }, `The signer app didn't connect: ${e.message ?? e}`));
    }
  }
  function createIdentity() {
    const sk = generateSecretKey();
    saveDemoKey(sk);
    chosen(localIdentity(sk, nameInput.value.trim() || undefined));
  }
  function chosen(identity) {
    id = identity;
    s1.state("done");
    s1.set(h("p", {}, h("code", {}, id.npub)),
      id.sk ? h("div", { class: "status warn" }, h("b", {}, "Save your secret key now"),
        "It is the only way to use this name in other Nostr apps. This browser keeps a copy until you forget it.",
        h("p", { style: "margin:0.5rem 0 0" }, copyButton(nip19.nsecEncode(id.sk), "Copy the secret key (nsec)"), " · ",
          h("button", { type: "button", class: "link", onclick: () => { forgetDemoKey(); route(); } }, "Forget it and start over"))) : null);
    s2.state("active");
    s2.set(h("p", {}, "The wallet whose address people will pay. It shares public keys only."),
      h("button", { type: "button", class: "primary", onclick: () => connectWallet(s2.body, walletReady) }, "Connect a wallet"));
  }

  // 2 · the wallet: the bound address = the address of the coins the commitment spends.
  async function walletReady(d) {
    dapp = d;
    s2.set(spinner(), h("p", {}, `Connected to ${dapp.walletName ?? "your wallet"}. Looking at its addresses…`));
    let scan;
    try { scan = await scanWallet(await chain(), (child, i) => dapp.getPubkey(child, i)); } catch (e) {
      return s2.set(h("p", { class: "error" }, `Couldn't read the wallet: ${e.message}`), h("button", { type: "button", onclick: () => walletReady(dapp) }, "Try again"));
    }
    const byAddress = new Map();
    for (const c of scan.coins) {
      const k = L.binToHex(c.lockingBytecode);
      if (!byAddress.has(k)) byAddress.set(k, { coins: [], total: 0n });
      byAddress.get(k).coins.push(c);
      byAddress.get(k).total += c.satoshis;
    }
    const best = [...byAddress.values()].sort((a, b) => (b.total > a.total ? 1 : b.total < a.total ? -1 : 0))[0];
    try {
      if (!best) throw new Error("no coins");
      const enc = L.lockingBytecodeToCashAddress({ bytecode: best.coins[0].lockingBytecode, prefix: "bitcoincash" });
      address = typeof enc === "string" ? enc : enc.address;
      built = buildCommitment({ address, npub: id.npub, coins: best.coins });
    } catch {
      return s2.set(h("p", {}, "This wallet has no coins to pay the network fee from (coins carrying tokens are never spent here). Send it a few cents, 0.0001 BCH is plenty, then look again."),
        h("button", { type: "button", onclick: () => walletReady(dapp) }, "Look again"));
    }
    s2.state("done");
    s2.set(h("p", {}, `${dapp.walletName ?? "Wallet"} · this address will be bound:`), h("code", {}, address));
    s3.state("active");
    s3.set(h("p", {}, "A small transaction from that address, with one note on chain: « Verifying that I control the following Nostr public key: ", h("code", {}, shortKey(id.npub)), " ». No payment to anyone: ",
      `the network fee is ${built.fee} satoshis and the rest comes back to the same address.`),
    h("label", { class: "check" }, h("input", { type: "checkbox", checked: listMe, onchange: (e) => { listMe = e.target.checked; } }),
      h("span", {}, "List my name on the public ", h("a", { href: "#/wall", target: "_blank" }, "wall"), ". Either way the binding itself is public: anyone can find it by name or by address.")),
    h("button", { type: "button", class: "pay", onclick: sign }, "Sign in my wallet"));
  }

  // 3 · the BCH half: the wallet signs the commitment.
  async function sign() {
    s3.set(spinner(), h("p", {}, h("b", {}, "Approve it in your wallet.")), h("p", { class: "muted" }, "It shows the note as raw bytes; the wording above is what they say."));
    try {
      txid = await signAndSend(dapp, built, `Countersign: bind this address to the Nostr name ${id.npub}. A note on chain, no payment (fee ${built.fee} sat).`);
    } catch (e) {
      return s3.set(h("p", { class: "error" }, `Not sent: ${e.message || e}`), h("button", { type: "button", class: "pay", onclick: sign }, "Try again"));
    }
    s3.state("done");
    s3.set(h("p", {}, "Commitment sent: ", txLink(txid), "."));
    s4.state("active");
    publish();
  }

  // 4 · the Nostr half: the claim, merged into the name's own identity list, sent to its relays and three defaults.
  async function publish() {
    s4.set(spinner(), h("p", {}, id.sk ? "Signing and publishing the claim…" : id.via === "remote" ? "Approve the claim in your signer app…" : "Approve the claim in your Nostr extension…"));
    const reader = relayReader();
    try {
      const [{ claim: current }, outbox] = await Promise.all([reader.fetchClaim(id.pubkey), reader.writeRelays(id.pubkey).catch(() => [])]);
      const event = verifiedCopy(await id.sign(buildClaim(current, address, txid, { wall: listMe })));
      if (!event || event.pubkey !== id.pubkey) throw new Error("the signed claim doesn't verify for this key");
      const targets = [...new Set([...outbox.slice(0, 5), ...DEFAULT_RELAYS])];
      const extra = [];
      if (id.sk && !outbox.length) {
        // A name made here gets a relay list (so readers know where to look) and, if given, a profile name.
        const now = Math.floor(Date.now() / 1000);
        extra.push(finalizeEvent({ kind: 10002, created_at: now, tags: DEFAULT_RELAYS.map((u) => ["r", u]), content: "" }, id.sk));
        if (id.name) extra.push(finalizeEvent({ kind: 0, created_at: now, tags: [], content: JSON.stringify({ name: id.name }) }, id.sk));
      }
      await Promise.all(extra.map((e) => reader.publish(e, targets)));
      const results = await reader.publish(event, targets);
      const accepted = targets.filter((_, i) => results[i].status === "fulfilled");
      if (!accepted.length) throw new Error("no relay accepted it");
      s4.state("done");
      const link = `${location.origin}${location.pathname}#/${id.npub}`;
      s4.set(h("p", {}, `Claim published on ${accepted.length} of ${targets.length} relays: ${accepted.map((u) => new URL(u).hostname).join(", ")}.`),
        h("div", { class: "status ok" }, h("b", {}, "Your pay link"), h("code", {}, link),
          h("p", { style: "margin:0.5rem 0 0" }, copyButton(link, "Copy the link"), " · ", h("a", { href: `#/${id.npub}` }, "Open it"))),
        h("p", { class: "muted" }, "It shows « new » until the commitment is in a block, usually within minutes."),
        listMe ? h("p", {}, h("a", { href: "#/wall" }, "See your name on the wall")) : null);
    } catch (e) {
      s4.set(h("p", { class: "error" }, `Not published: ${e.message || e}`), h("button", { type: "button", class: "pay", onclick: publish }, "Try again"));
    } finally {
      reader.close();
    }
  }
}

// ── The wall ─────────────────────────────────────────────────────────────────

/** Names bound here that chose to be listed. Relays only suggest who is there; this browser checks each one first. */
async function showWall(me) {
  const list = h("ul", { class: "wall card", hidden: true });
  const note = h("div", { class: "card loading" }, spinner(), h("b", {}, "Checking each name…"));
  fill(view, h("section", { class: "hero small" }, h("h1", {}, "The wall"),
    h("p", { class: "lede" }, "Nostr names bound to a Bitcoin Cash address with Countersign, newest first. Relays only suggest who is here: your browser checks both signatures of every name before it shows it.")),
  list, note, h("p", { class: "try" }, "Your name here? ", h("a", { href: "#/bind" }, "Bind it"), " in two signatures."));
  const entry = (r, p) => {
    const name = p?.name ?? shortKey(r.npub);
    const avatar = p?.picture
      ? h("img", { class: "avatar", src: p.picture, alt: "", referrerpolicy: "no-referrer", onerror: (e) => e.target.replaceWith(initial(name)) })
      : initial(name);
    return h("li", { class: "who" }, avatar,
      h("div", { class: "grow" }, h("b", {}, name), r.warnings.includes("new") ? h("span", { class: "badge" }, "new") : null,
        h("p", { class: "npub" }, shortKey(r.address.replace(/^bitcoincash:/, "")))),
      h("a", { class: "button", href: `#/${r.npub}` }, "Pay"));
  };
  // Each name appears as soon as it passes, in its place (newest first).
  const nostr = relayReader();
  const shown = [], pending = [];
  const add = async (r, rank) => {
    const profile = await nostr.fetchProfile(r.pubkey).catch(() => null);
    if (me !== nav) return;
    shown[rank] = entry(r, profile);
    list.hidden = false;
    fill(list, shown.filter(Boolean));
  };
  try {
    await listWall({ nostr, chain: await chain(), onRow: (r, rank) => pending.push(add(r, rank)) });
    await Promise.all(pending);
  } catch (e) {
    if (me === nav) fill(note, h("p", { class: "error", role: "alert" }, `Couldn't read the wall: ${e.message}`), h("button", { type: "button", onclick: route }, "Try again"));
    return;
  } finally {
    nostr.close();
  }
  if (me !== nav) return;
  if (shown.some(Boolean)) note.remove(); else fill(note, "No one is on the wall yet.");
}
