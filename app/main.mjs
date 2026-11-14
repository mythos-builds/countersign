// The pay page (spec §8): #/<name> → the name's binding, verified in this browser → pay it from any BCH wallet.
import * as L from "@bitauth/libauth";
import { renderSVG } from "uqr";
import { initiateDappRelay } from "@wizardconnect/core";
import { DappConnectionManager } from "@wizardconnect/dapp";
import {
  resolveName, relayReader, fulcrumChain, verifyBinding, parseBch, formatBch, paymentUri, paidTo, scanWallet, buildPayment, DUST,
} from "../lib/index.mjs";

const PROJECT = "npub1v2zlnx5g0m847j4k34d30az2dykjwrlazp68fqwe3c0nekaqltkqd23d95";
const DEFAULT_AMOUNT = "0.0001";
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

const shortKey = (s) => `${s.slice(0, 12)}…${s.slice(-6)}`;
const sentence = (s) => (s ? s[0].toUpperCase() + s.slice(1) + (/[.!?]$/.test(s) ? "" : ".") : "");
const wire = (o) => JSON.parse(L.stringify(o)); // the relay JSON.stringify()s: bigint and Uint8Array in libauth's extended form
const spinner = () => h("div", { class: "spinner", role: "status", "aria-label": "Working" });
const initial = (name) => h("div", { class: "avatar", "aria-hidden": "true" }, [...name][0]?.toUpperCase() ?? "?");
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
  if (raw.trim()) showName(raw.trim(), me);
  else showHome();
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
  view.replaceChildren(h("section", { class: "hero" },
    h("h1", {}, "Pay any Nostr name in Bitcoin Cash."),
    h("p", { class: "lede" }, "On chain, from your own wallet. No custodian and no account: the name's owner signed with both keys, and your browser checks both signatures."),
    h("form", { class: "find", onsubmit: (e) => { e.preventDefault(); if (input.value.trim()) go(input.value.trim()); } },
      input, h("button", { type: "submit", class: "primary" }, "Find")),
    error ? h("p", { class: "error", role: "alert" }, error) : null,
    h("p", { class: "try" }, "Try it with ", h("a", { href: `#/${PROJECT}` }, "Countersign's own name"), ".")));
  if (!matchMedia("(pointer: coarse)").matches) input.focus();
}

async function showName(raw, me) {
  view.replaceChildren(h("section", { class: "card loading" }, spinner(),
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
  view.replaceChildren(
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
      return h("div", { class: "status bad" }, h("b", {}, "No Bitcoin Cash address for this name"), sentence(r.reason));
  }
}

function howChecked(who, r, servers) {
  const items = [
    [`Name: ${who.via === "npub" ? "an npub" : who.via} → `, h("code", {}, who.npub)],
    r.txid && "Claim: the name's newest NIP-39 identity list (kind 10011) from Nostr relays, its signature checked in this browser.",
    r.txid && ["Commitment: transaction ", h("a", { href: explorer(r.txid), target: "_blank", rel: "noopener" }, `${r.txid.slice(0, 10)}…`),
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
      h("p", {}, `${formatBch(got)} BCH reached ${name} · `, h("a", { href: explorer(txid), target: "_blank", rel: "noopener" }, `transaction ${txid.slice(0, 8)}…`))));
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
    railBox.replaceChildren(rails[id].el);
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

/** WizardConnect: the wallet shares public keys only; the page builds the payment from its coins, the wallet signs and broadcasts. */
function walletRail(r, name, amount, markPaid) {
  const el = h("div", { class: "rail" });
  const say = (...kids) => el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
  let dapp, relay, scan, update = () => {};
  const again = (label = "Try again") => h("button", { type: "button", onclick: payButton }, label);

  function connect() {
    dapp?.destroy();
    relay?.cleanup();
    dapp = new DappConnectionManager("Countersign", undefined, { session: false });
    relay = initiateDappRelay(({ client, status }) => dapp.updateConnection(client, status));
    dapp.attachRelay(relay);
    const qr = h("div", { class: "qr" });
    qr.innerHTML = renderSVG(relay.qrUri);
    say(qr, h("p", {}, "Scan this with your wallet app."),
      h("a", { class: "button", href: relay.uri }, "Or open the wallet on this phone"),
      h("p", { class: "muted" }, "Waiting for your wallet…"));
    dapp.on("walletready", ready);
    dapp.on("disconnect", () => {
      scan = null;
      say(h("p", {}, "The wallet disconnected."), h("button", { type: "button", class: "primary", onclick: connect }, "Connect again"));
    });
  }

  async function ready() {
    if (scan) return;
    scan = "scanning";
    say(spinner(), h("p", {}, `Connected to ${dapp.walletName ?? "your wallet"}. Looking for coins it can spend…`));
    try {
      scan = await scanWallet(await chain(), (child, i) => dapp.getPubkey(child, i));
    } catch (e) {
      scan = null;
      return say(h("p", { class: "error" }, `Couldn't read the wallet's coins: ${e.message}`), h("button", { type: "button", onclick: ready }, "Try again"));
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
    say(h("p", {}, `${dapp.walletName ?? "Wallet"} connected · ${formatBch(total)} BCH it can spend.`), btn,
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
      return say(h("p", { class: "error" }, sentence(e.message)), again());
    }
    say(spinner(), h("p", {}, h("b", {}, "Approve the payment in your wallet.")),
      h("p", { class: "muted" }, `${formatBch(a)} BCH to ${name}, network fee ${p.fee} satoshis.`));
    try {
      const res = await dapp.signTransaction({
        transaction: wire({ transaction: p.transaction, sourceOutputs: p.sourceOutputs, broadcast: true, userPrompt: `Pay ${formatBch(a)} BCH to ${name} (Countersign)` }),
        inputPaths: p.inputPaths,
      });
      if (res.error) throw new Error(res.error);
      const raw = L.hexToBin(res.signedTransaction);
      const signed = L.decodeTransaction(raw);
      if (typeof signed === "string") throw new Error(`the wallet sent back something that isn't a transaction (${signed})`);
      const same = signed.outputs.length === p.transaction.outputs.length && signed.outputs.every((o, i) =>
        o.valueSatoshis === p.transaction.outputs[i].valueSatoshis && L.binToHex(o.lockingBytecode) === L.binToHex(p.transaction.outputs[i].lockingBytecode));
      if (!same) throw new Error("the wallet changed the payment's outputs, so this page won't send it");
      const ok = L.createVirtualMachineBch(true).verify({ sourceOutputs: p.sourceOutputs, transaction: signed });
      if (ok !== true) throw new Error(`the signed payment doesn't verify: ${ok}`);
      say(spinner(), h("p", {}, "Signed. Handing it to the network…"));
      // The wallet broadcasts it too (broadcast: true); a second copy is harmless and covers a wallet that didn't.
      await (await chain()).broadcast(res.signedTransaction).catch((e) => {
        if (!/already|known|exists|in.?mempool|missing ?inputs/i.test(e.message)) throw e;
      });
      markPaid({ txid: L.hashTransaction(raw), sats: a });
      scan = null;
      say(h("p", {}, "Sent from your wallet."), h("button", { type: "button", onclick: ready }, "Pay again"));
    } catch (e) {
      say(h("p", { class: "error" }, `Not sent: ${e.message || e}`), again());
    }
  }

  say(h("p", {}, "Connect Paytaca, Cashonize or any wallet that speaks WizardConnect. Your wallet shows you the payment and asks you to approve it; your keys never leave it."),
    h("button", { type: "button", class: "primary", onclick: connect }, "Connect a wallet"));
  return {
    el,
    update: () => update(),
    stop: () => { dapp?.sendDisconnect("page closed").catch(() => {}); relay?.cleanup(); dapp?.destroy(); },
  };
}
