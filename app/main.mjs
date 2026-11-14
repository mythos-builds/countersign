// The site (spec §7, §8): #/<name> pays a bound name, #/bind binds yours. Every check runs in this browser.
import * as L from "@bitauth/libauth";
import { renderSVG } from "uqr";
import { initiateDappRelay } from "@wizardconnect/core";
import { DappConnectionManager } from "@wizardconnect/dapp";
import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from "nostr-tools";
import {
  resolveName, relayReader, fulcrumChain, verifyBinding, verifiedCopy, parseBch, formatBch, paymentUri, paidTo, scanWallet,
  buildPayment, buildCommitment, buildClaim, DEFAULT_RELAYS, DUST,
} from "../lib/index.mjs";

const PROJECT = "npub1v2zlnx5g0m847j4k34d30az2dykjwrlazp68fqwe3c0nekaqltkqd23d95";
const DEFAULT_AMOUNT = "0.0001";
const DEMO_KEY = "countersign-demo-identity";
const explorer = (txid) => `https://blockchair.com/bitcoin-cash/transaction/${txid}`;
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
const wire = (o) => JSON.parse(L.stringify(o)); // the relay JSON.stringify()s: bigint and Uint8Array in libauth's extended form
const spinner = () => h("div", { class: "spinner", role: "status", "aria-label": "Working" });
const initial = (name) => h("div", { class: "avatar", "aria-hidden": "true" }, [...name][0]?.toUpperCase() ?? "?");
const txLink = (txid, label = `transaction ${txid.slice(0, 8)}…`) => h("a", { href: explorer(txid), target: "_blank", rel: "noopener" }, label);
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
  else if (raw) showName(raw, me);
  else showHome();
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", route);
route();

function go(name) {
  const hash = `#/${encodeURIComponent(name).replace(/%40/g, "@")}`;
  if (location.hash === hash) route(); else location.hash = hash;
}

function showHome(error, value = "") {
  const input = h("input", {
    type: "text", value, placeholder: "npub1…, name@domain or a profile link", autocomplete: "off", autocapitalize: "off",
    spellcheck: "false", "aria-label": "A Nostr name",
  });
  fill(view, h("section", { class: "hero" },
    h("h1", {}, "Pay any Nostr name in Bitcoin Cash."),
    h("p", { class: "lede" }, "On chain, from your own wallet. No custodian and no account: the name's owner signed with both keys, and your browser checks both signatures."),
    h("form", { class: "find", onsubmit: (e) => { e.preventDefault(); if (input.value.trim()) go(input.value.trim()); } },
      input, h("button", { type: "submit", class: "primary" }, "Find")),
    error ? h("p", { class: "error", role: "alert" }, error) : null,
    h("p", { class: "try" }, "Try it with ", h("a", { href: `#/${PROJECT}` }, "Countersign's own name"), "."),
    h("p", { class: "try" }, "Have a Nostr name? ", h("a", { href: "#/bind" }, "Bind it to your Bitcoin Cash address"), " in two signatures.")));
  if (!matchMedia("(pointer: coarse)").matches) input.focus();
}

// ── Paying a name ────────────────────────────────────────────────────────────

async function showName(raw, me) {
  fill(view, h("section", { class: "card loading" }, spinner(),
    h("div", {}, h("b", {}, "Checking this name…"),
      h("p", { class: "muted", style: "margin:0" }, "Its claim on Nostr relays, its commitment on the Bitcoin Cash chain."))));
  let who;
  try { who = await resolveName(raw); } catch (e) { if (me === nav) showHome(e.message, raw); return; }
  const nostr = relayReader();
  let result, profile, servers = [];
  try {
    const c = await chain();
    servers = c.servers;
    [result, profile] = await Promise.all([
      verifyBinding(who.npub, { nostr: { fetchClaim: (pk) => nostr.fetchClaim(pk, who.relays) }, chain: c }),
      nostr.fetchProfile(who.pubkey, who.relays).catch(() => null),
    ]);
  } catch (e) {
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
  fill(view,
    h("section", { class: "card" },
      h("div", { class: "who" }, avatar,
        h("div", { style: "min-width:0" }, h("h2", {}, name), h("p", { class: "npub" }, shortKey(who.npub), " ", copyButton(who.npub, "Copy npub")))),
      statusBox(result),
      payable ? h("p", { class: "addr" }, h("span", { class: "muted" }, "Pays to "), h("code", {}, result.address), " ", copyButton(result.address)) : null),
    payable ? payCard(result, name) : null,
    howChecked(who, result, servers));
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

function payCard(r, name) {
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
      h("p", {}, `${formatBch(got)} BCH reached ${name} · `, txLink(txid))));
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
      const tx = L.decodeTransaction(await c.getTx(txid)); // getTx re-hashes against the id
      seen.add(txid);
      const sats = typeof tx === "string" ? 0n : paidTo(tx, address);
      if (sats > 0n) onPayment({ txid, sats });
    }
  };
  const sub = await c.watchAddress(address, () => check().catch(() => {})).catch(() => null);
  (await c.getHistory(address)).forEach((x) => seen.add(x.tx_hash));
  ready = true;
  const poll = setInterval(() => check().catch(() => {}), 20_000);
  return () => { clearInterval(poll); sub?.stop(); };
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

// ── WizardConnect ────────────────────────────────────────────────────────────

/** A WizardConnect session drawn in `el`: QR and phone link, then onReady(dapp) once the wallet has shared its public keys. */
function connectWallet(el, onReady) {
  let dapp, relay, readyOnce;
  function stop() {
    try { dapp?.sendDisconnect("page closed").catch(() => {}); } catch { /* not connected */ }
    relay?.cleanup();
    dapp?.destroy();
    dapp = relay = null;
  }
  function start() {
    stop();
    readyOnce = false;
    dapp = new DappConnectionManager("Countersign", undefined, { session: false });
    relay = initiateDappRelay(({ client, status }) => dapp.updateConnection(client, status));
    dapp.attachRelay(relay);
    const qr = h("div", { class: "qr" });
    qr.innerHTML = renderSVG(relay.qrUri);
    fill(el, qr, h("p", {}, "Scan this with your wallet app."),
      h("a", { class: "button", href: relay.uri }, "Or open the wallet on this phone"),
      h("p", { class: "muted" }, "Waiting for your wallet…"));
    const d = dapp;
    d.on("walletready", () => { if (!readyOnce) { readyOnce = true; onReady(d); } });
    d.on("disconnect", () => fill(el, h("p", {}, "The wallet disconnected."), h("button", { type: "button", class: "primary", onclick: start }, "Connect again")));
  }
  start();
  cleanups.push(stop);
  return { stop };
}

/** The wallet signs and broadcasts; the page checks it signed exactly what was built, and hands it to the network too. → txid */
async function signAndSend(dapp, built, userPrompt) {
  const res = await dapp.signTransaction({
    transaction: wire({ transaction: built.transaction, sourceOutputs: built.sourceOutputs, broadcast: true, userPrompt }),
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
    stored ? h("button", { type: "button", onclick: () => chosen(localIdentity(stored)) }, `Use the identity made here before (${shortKey(nip19.npubEncode(getPublicKey(stored)))})`) : null,
    h("div", { class: "row" }, nameInput, h("button", { type: "button", onclick: createIdentity }, "Create a new one here")),
    window.nostr ? null : h("p", { class: "muted" }, "No Nostr extension in this browser (nos2x, Alby…). A new identity works too: you'll get its secret key to keep."));

  async function useExtension() {
    try {
      const pubkey = await window.nostr.getPublicKey();
      if (!/^[0-9a-f]{64}$/.test(pubkey ?? "")) throw new Error("it returned no key");
      chosen({ pubkey, npub: nip19.npubEncode(pubkey), sign: (t) => window.nostr.signEvent(t) });
    } catch (e) {
      s1.body.append(h("p", { class: "error" }, `The extension didn't give a key: ${e.message ?? e}`));
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
    s4.set(spinner(), h("p", {}, id.sk ? "Signing and publishing the claim…" : "Approve the claim in your Nostr extension…"));
    const reader = relayReader();
    try {
      const [{ claim: current }, outbox] = await Promise.all([reader.fetchClaim(id.pubkey), reader.writeRelays(id.pubkey).catch(() => [])]);
      const event = verifiedCopy(await id.sign(buildClaim(current, address, txid)));
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
        h("p", { class: "muted" }, "It shows « new » until the commitment is in a block, usually within minutes."));
    } catch (e) {
      s4.set(h("p", { class: "error" }, `Not published: ${e.message || e}`), h("button", { type: "button", class: "pay", onclick: publish }, "Try again"));
    } finally {
      reader.close();
    }
  }
}
