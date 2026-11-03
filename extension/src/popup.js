// The extension's popup: sign in, unlock, logins for the open site,
// search, generator, save offers and settings. The master password is used
// only here, to derive keys; it is never stored or sent.
import { generate, entropy, loadOptions, saveOptions } from "./pz/generator.js";
import { api, settings, saveSettings, loadTexts, t, normServer, deviceName, sameServer, consoleOrigin } from "./ext.js";
import { bg, signIn, secondFactor, unlock } from "./client.js";
import { readQR, authenticatorKeys } from "./pz/qr.js";
import { parse as totpParse } from "./pz/totp.js";
const app = document.getElementById("app");
let tab = ["site", "all", "gen"].includes(location.hash.slice(1)) ? location.hash.slice(1) : "site";

// ---- helpers

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

const PATHS = {
  lock: ["M6 11h12a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2Z", "M8 11V7a4 4 0 0 1 8 0v4"],
  menu: ["M4 6h16M4 12h16M4 18h16"],
  copy: ["M11 9h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2Z", "M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"],
  user: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z"],
  key: ["M8 19a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z", "m10.8 12.2 9.2-9.2M17 6l3 3M14 9l2 2"],
  globe: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"],
  refresh: ["M21 12a9 9 0 1 1-3-6.7L21 8", "M21 3v5h-5"],
  terminal: ["M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z", "m7 9 3 3-3 3M13 15h4"],
  qr: ["M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z", "M14 14h2v2h-2zM18 14h2M14 18v2M18 18h2v2h-2"],
  clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 7v5l3 2"],
  alert: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 8v5M12 16.5v.01"],
};

function icon(name) {
  const NS = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(NS, "svg");
  for (const [k, v] of Object.entries({ class: "ic", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) s.setAttribute(k, v);
  for (const d of PATHS[name] || []) { const p = document.createElementNS(NS, "path"); p.setAttribute("d", d); s.append(p); }
  return s;
}

function toast(msg) {
  const n = el("div", { class: "toast", role: "status", text: msg });
  document.body.append(n);
  setTimeout(() => n.remove(), 2500);
}

function errBox() { return el("div", { class: "err", role: "alert", hidden: true }); }
function showErr(box, e) { box.textContent = e && e.message ? e.message : String(e || ""); box.hidden = !box.textContent; }

function nextFrame() { return new Promise((r) => setTimeout(r, 30)); }

// ---- screens

async function start() {
  await loadTexts();
  const st = await bg("status");
  const lockBtn = document.getElementById("b-lock");
  const menuBtn = document.getElementById("b-menu");
  lockBtn.replaceChildren(icon("lock"));
  lockBtn.title = t("Lock");
  lockBtn.setAttribute("aria-label", t("Lock"));
  menuBtn.replaceChildren(icon("menu"));
  menuBtn.title = t("Settings");
  menuBtn.setAttribute("aria-label", t("Settings"));
  lockBtn.onclick = async () => { await bg("lock"); start(); };
  menuBtn.onclick = () => showMenu(st);
  lockBtn.hidden = !st.unlocked;
  menuBtn.hidden = !st.signedIn;
  if (!st.signedIn) return showSignIn(st);
  if (!st.unlocked) return showUnlock(st);
  if (passkeyRequest) return showPasskey(passkeyRequest);
  // the window that opened for "Open with" of a MaxZit console closes after
  // the unlock; the connection opens by itself
  if (openRequest) { window.close(); return; }
  return showMain(st);
}

const openRequest = new URLSearchParams(location.search).get("unlock") === "open";
const passkeyRequest = new URLSearchParams(location.search).get("passkey") || "";

// showPasskey: a website asks for a passkey; the user decides here (the
// page cannot see or press these buttons).
async function showPasskey(id) {
  const err = errBox();
  let info;
  try { info = await bg("passkeyPending", { id }); } catch (e) { app.replaceChildren(el("div", { class: "err", text: e.message })); return; }
  if (info.locked) return start();
  const decide = async (choice, itemId) => {
    try { await bg("passkeyDecide", { id, choice, itemId }); window.close(); } catch (e) { showErr(err, e); }
  };
  const other = el("button", { type: "button", class: "ghost", onclick: () => decide("other") }, t("Use another device or the browser"));
  const head = [el("h1", { text: info.op === "create" ? t("Save a passkey") : t("Sign in with a passkey") }),
    el("p", { class: "small" }, el("b", { text: info.rpName }), " ", el("span", { class: "muted", text: info.origin }))];
  if (info.op === "create") {
    app.replaceChildren(el("div", { class: "menu" }, ...head, err,
      el("p", { class: "small", text: t("PassZit keeps the passkey for %s in your vault, encrypted, and signs in with it in all your browsers.", info.userName || info.rpId) }),
      el("button", { type: "button", class: "primary", onclick: () => decide("save") }, icon("key"), t("Save in PassZit")), other));
    return;
  }
  app.replaceChildren(el("div", { class: "menu" }, ...head, err,
    ...info.list.map((p) => el("button", { type: "button", class: "primary", onclick: () => decide("use", p.id) }, icon("key"), t("Sign in as %s", p.user || p.name))),
    other));
}

function showSignIn(st) {
  const err = errBox();
  const server = el("input", { type: "url", value: st.server || "", placeholder: "https://vault.example.com", required: true, autocomplete: "off" });
  const email = el("input", { type: "email", value: st.email || "", required: true, autocomplete: "username" });
  const pw = el("input", { type: "password", required: true, autocomplete: "current-password" });
  const go = el("button", { class: "secondary", type: "submit" }, t("Sign in and unlock"));
  // connect through the web vault: it is signed in already (or signs in
  // once there) and hands this extension its own device token
  const connect = el("button", { class: "primary", type: "button", onclick: async () => {
    showErr(err, "");
    const origin = normServer(server.value);
    if (!origin) { showErr(err, t("Enter the address of your PassZit server, e.g. https://vault.example.com.")); return; }
    let granted = false;
    try { granted = await api.permissions.request({ origins: sameServer(origin).map((o) => o + "/*") }); } catch (e) { granted = false; }
    if (!granted) { showErr(err, t("Without this permission the extension cannot reach your server.")); return; }
    await saveSettings({ server: origin, token: "" });
    await bg("settingsChanged");
    await api.tabs.create({ url: origin + "/vault?connect=extension" });
    window.close();
  } }, t("Connect with the web vault"));
  const byPassword = el("details", { class: "bypw" }, el("summary", { text: t("Sign in with e-mail and master password instead") }),
    el("label", {}, t("E-mail address"), email), el("label", {}, t("Master password"), pw), go);
  const form = el("form", {}, el("h1", { text: t("Sign in to PassZit") }), err,
    el("label", {}, t("Server address"), server), connect,
    el("p", { class: "small muted", text: t("Opens the web vault of your server: if you are signed in there, one click connects this extension, without the password again.") }),
    byPassword,
    el("p", { class: "small muted", style: "margin-top:10px" }, t("The browser asks once to allow PassZit to talk to your server.")));
  email.required = false; pw.required = false;
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showErr(err, "");
    if (!byPassword.open) { connect.click(); return; }
    const origin = normServer(server.value);
    if (!origin) { showErr(err, t("Enter the address of your PassZit server, e.g. https://vault.example.com.")); return; }
    if (!email.value.trim() || !pw.value) { showErr(err, t("Enter your e-mail address and master password.")); return; }
    // The permission request must be the first thing in the click.
    let granted = false;
    try { granted = await api.permissions.request({ origins: sameServer(origin).map((o) => o + "/*") }); } catch (e) { granted = false; }
    if (!granted) { showErr(err, t("Without this permission the extension cannot reach your server.")); return; }
    go.disabled = true;
    go.textContent = t("Deriving the keys from the master password…");
    await nextFrame();
    try {
      const res = await signIn(origin, email.value.trim(), pw.value, deviceName());
      pw.value = "";
      if (res.next === "2fa") return showCode(origin, res.pending, res.wrap);
      start();
    } catch (e) {
      showErr(err, e);
      go.disabled = false;
      go.textContent = t("Sign in and unlock");
    }
  });
  app.replaceChildren(form);
  server.focus();
}

function showCode(origin, pending, wrap) {
  const err = errBox();
  const code = el("input", { inputmode: "numeric", autocomplete: "one-time-code", required: true });
  const go = el("button", { class: "primary", type: "submit" }, t("Continue"));
  const form = el("form", {}, el("h1", { text: t("Two-factor sign-in") }), err,
    el("label", {}, t("Code from the authenticator app"), code), el("p", { class: "small muted", text: t("Lost your phone? Enter one of your recovery codes instead.") }), go);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    go.disabled = true;
    try {
      await secondFactor(origin, pending, wrap, code.value.trim());
      start();
    } catch (e) {
      showErr(err, e);
      go.disabled = false;
    }
  });
  app.replaceChildren(form);
  code.focus();
}

function showUnlock(st) {
  const err = errBox();
  const pw = el("input", { type: "password", required: true, autocomplete: "current-password" });
  const go = el("button", { class: "primary", type: "submit" }, icon("lock"), t("Unlock"));
  const form = el("form", {}, el("h1", { text: t("The vault is locked") }),
    openRequest ? el("p", { class: "small", text: t("A MaxZit console wants to open a connection with a saved login. Unlock PassZit and it opens.") }) : "",
    el("p", { class: "small muted", text: t("Enter your master password to unlock %s.", st.email) }), err,
    el("label", {}, t("Master password"), pw), go,
    // the web vault can unlock with Windows Hello; one unlock opens this too
    el("button", { type: "button", class: "ghost", onclick: () => { openVault(); window.close(); } }, icon("external"), t("Unlock in the web vault (Windows Hello)")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showErr(err, "");
    go.disabled = true;
    await nextFrame();
    try {
      await unlock(pw.value);
      pw.value = "";
      start();
    } catch (e) {
      if (e.status === 401) { await saveSettings({ token: "" }); start(); return; }
      showErr(err, e);
      go.disabled = false;
      pw.select();
    }
  });
  app.replaceChildren(form);
  pw.focus();
}

async function showMain() {
  const tabs = el("div", { class: "tabs" },
    [["site", t("This site")], ["all", t("Search")], ["gen", t("Generator")]].map(([k, label]) => el("button", { type: "button", class: tab === k ? "on" : "", onclick: () => { tab = k; showMain(); } }, label)));
  const body = el("div");
  app.replaceChildren(tabs, body);
  if (tab === "gen") return body.append(generator());
  if (tab === "all") return body.append(searchPane());
  const p = await bg("page");
  if (p.locked) return start();
  for (const o of p.pending) body.append(offer(o));
  if (p.console && !p.console.active) body.append(consoleOffer(p.console.origin));
  body.append(el("div", { class: "site" }, icon("globe"), p.host || t("No website")));
  if (p.host && !p.secure) body.append(el("div", { class: "warn" }, t("This page is not encrypted (HTTP). Logins saved for HTTPS are not offered here.")));
  body.append(itemList(p.matches, true, t("No saved login for this website."), p.helper));
  if (p.host) body.append(el("button", { type: "button", class: "ghost qrscan", onclick: () => scanPage(p) }, icon("qr"), t("Read an authenticator QR code on this page")));
  if (p.device) {
    body.append(el("div", { class: "site" }, icon("globe"), t("Device %s", p.device)),
      itemList(p.deviceMatches, false, t("No saved login for this device."), p.helper));
  }
  body.append(el("div", { class: "foot" },
    el("a", { href: "#", onclick: (e) => { e.preventDefault(); openVault(); } }, t("Open the web vault")),
    el("button", { type: "button", class: "iconbtn", title: t("Reload"), "aria-label": t("Reload"), onclick: async () => { await bg("sync"); showMain(); } }, icon("refresh"))));
}

// consoleOffer: this tab is a MaxZit console (WatchZit) — one click lets its
// "Open with" use PassZit's logins. The address is shown, and the browser
// asks for its own permission; only this exact console is added.
function consoleOffer(origin) {
  const err = errBox();
  const box = el("div", { class: "offer console-offer" },
    el("b", { text: t("MaxZit console") }),
    el("p", { class: "small", text: t("Let \"Open with\" on the devices of this console use your PassZit logins?") }),
    el("code", { class: "cmd", text: origin }), err);
  const allow = el("button", { type: "button", class: "primary", onclick: async () => {
    showErr(err, "");
    // the background remembers it first (Firefox closes this popup for the
    // prompt); the permission is asked right away, still in the click
    bg("consolePending", { origin }).catch(() => {});
    let ok = false;
    try { ok = await api.permissions.request({ origins: [origin + "/*"] }); } catch (e) { ok = false; }
    if (!ok) { showErr(err, t("The browser did not allow PassZit on that console.")); return; }
    try {
      await bg("consoleAdd", { origin });
      box.replaceChildren(el("b", { text: t("MaxZit console") }), el("p", { class: "small", text: t("Done. \"Open with\" on this console now uses your PassZit logins.") }));
    } catch (e) { showErr(err, e); }
  } }, t("Allow on this console"));
  box.append(allow);
  return box;
}

const TOOLS = { rdp: "RDP", ssh: "SSH", winscp: "WinSCP", winbox: "WinBox", vnc: "VNC", telnet: "Telnet" };

function itemList(items, canFill, emptyText, helper) {
  if (!items.length) return el("p", { class: "empty", text: emptyText });
  return el("ul", { class: "list" }, ...items.map((m) => el("li", { class: "row" },
    el("span", { class: "av" }, (m.name || "?")[0].toUpperCase()),
    el("span", { class: "who" }, el("b", { text: m.name || m.site }), el("small", { text: m.username || m.site })),
    el("span", { class: "acts" },
      m.connect && helper ? el("button", { type: "button", class: "iconbtn", title: t("Connect with %s", TOOLS[m.connect.tool] || m.connect.tool),
        "aria-label": t("Connect with %s", TOOLS[m.connect.tool] || m.connect.tool), onclick: () => doConnect(m) }, icon("terminal")) : null,
      m.username ? el("button", { type: "button", class: "iconbtn", title: t("Copy the user name"), "aria-label": t("Copy the user name"), onclick: () => copySecret(m.id, "username") }, icon("user")) : null,
      m.hasPassword ? el("button", { type: "button", class: "iconbtn", title: t("Copy the password"), "aria-label": t("Copy the password"), onclick: () => copySecret(m.id, "password") }, icon("key")) : null,
      m.hasTotp ? el("button", { type: "button", class: "iconbtn", title: t("Copy the one-time code"), "aria-label": t("Copy the one-time code"), onclick: () => copySecret(m.id, "totp") }, icon("clock")) : null,
      canFill ? el("button", { type: "button", class: "fill", onclick: () => doFill(m) }, t("Fill")) : null))));
}

async function doConnect(m) {
  const tool = TOOLS[m.connect.tool] || m.connect.tool;
  const q = m.connect.tool === "winbox"
    ? t("Open %s with WinBox? WinBox takes the password only on its command line: other programs of your Windows user can see it while WinBox runs.", m.connect.host)
    : t("Open %s with %s?", m.connect.host, tool);
  if (!window.confirm(q)) return;
  try {
    const r = await bg("connect", { id: m.id });
    if (r.copy) {
      await navigator.clipboard.writeText(r.value);
      toast(r.copy === "password" ? t("The password is on the clipboard for the login prompt (cleared in %d seconds).", Math.max(r.clip, 30)) : t("The key's passphrase is on the clipboard (cleared in %d seconds).", Math.max(r.clip, 30)));
    } else {
      window.close();
    }
  } catch (e) { toast(e.message); }
}

async function doFill(m) {
  try {
    const filled = await bg("fill", { id: m.id });
    // The one-time code went into the page, or there is none.
    if (filled.code || !m.hasTotp) return window.close();
    // The sign-in usually asks for the one-time code next.
    const r = await bg("secret", { id: m.id, field: "totp" });
    await navigator.clipboard.writeText(r.value);
    toast(t("Filled. The one-time code is on the clipboard (cleared in %d seconds).", Math.max(r.clip, 30)));
    setTimeout(() => window.close(), 1500);
  } catch (e) { toast(e.message); }
}

// scanPage reads an authenticator QR code on the visible page (the browser
// gives the extension a picture of the tab only after a click on PassZit)
// and saves the key in a login of the site or in a new one.
async function scanPage(p) {
  let keys;
  try {
    const shot = await api.tabs.captureVisibleTab({ format: "png" });
    keys = authenticatorKeys(await readQR(await (await fetch(shot)).blob()));
  } catch (e) { return toast(t("The page could not be read.")); }
  if (!keys.length) return toast(t("No authenticator QR code was found on this page."));
  const uri = keys[0];
  let cfg = null;
  try { cfg = totpParse(uri); } catch (e) { return toast(t("Invalid authenticator key")); }
  const err = errBox();
  const save = async (m) => {
    if (m && m.hasTotp && !window.confirm(t("%s already has an authenticator key. Replace it?", m.name || m.site))) return;
    try {
      await bg("addTotp", { uri, id: m ? m.id : "" });
      toast(t("The authenticator key was saved."));
      showMain();
    } catch (e) { showErr(err, e); }
  };
  const who = [cfg.issuer, cfg.label].filter(Boolean).join(" · ");
  app.replaceChildren(el("div", { class: "pane" },
    el("b", { text: t("Authenticator key found") }),
    who ? el("div", { class: "small muted", text: who }) : null,
    keys.length > 1 ? el("div", { class: "small muted", text: t("The page has %d authenticator codes; the first one is used.", keys.length) }) : null,
    el("p", { class: "small", text: t("Save it in a login of this site:") }),
    el("ul", { class: "list" }, ...p.matches.map((m) => el("li", { class: "row" },
      el("span", { class: "av" }, (m.name || "?")[0].toUpperCase()),
      el("span", { class: "who" }, el("b", { text: m.name || m.site }), el("small", { text: m.username || m.site })),
      el("span", { class: "acts" }, el("button", { type: "button", class: "fill", onclick: () => save(m) }, t("Save")))))),
    err,
    el("div", { class: "btns" },
      el("button", { type: "button", class: "primary", onclick: () => save(null) }, t("New login")),
      el("button", { type: "button", class: "secondary", onclick: () => showMain() }, t("Cancel")))));
}

async function copySecret(id, field) {
  try {
    const r = await bg("secret", { id, field });
    await navigator.clipboard.writeText(r.value);
    toast(field === "password" || field === "totp" ? t("Copied. The clipboard is cleared in %d seconds.", Math.max(r.clip, 30)) : t("Copied."));
  } catch (e) { toast(e.message); }
}

function offer(o) {
  const btns = el("div", { class: "btns" },
    el("button", { type: "button", class: "primary", onclick: async () => { await bg("pending", { index: o.i, action: o.update ? "update" : "save" }); toast(t("Saved.")); showMain(); } }, o.update ? t("Update") : t("Save")),
    el("button", { type: "button", class: "secondary", onclick: async () => { await bg("pending", { index: o.i, action: "dismiss" }); showMain(); } }, t("Not now")));
  return el("div", { class: "offer" }, el("b", { text: o.update ? t("Update the password for %s?", o.host) : t("Save the login for %s?", o.host) }),
    el("div", { class: "small muted", text: o.username || t("(no user name)") }), btns);
}

function searchPane() {
  const box = el("div");
  const q = el("input", { type: "search", placeholder: t("Search the vault"), "aria-label": t("Search the vault") });
  const list = el("div");
  const run = async () => {
    const r = await bg("search", { q: q.value });
    if (r.locked) return start();
    list.replaceChildren(itemList(r.items, false, t("Nothing found.")));
  };
  q.addEventListener("input", run);
  box.append(q, el("div", { style: "height:8px" }), list);
  setTimeout(() => q.focus(), 0);
  run();
  return box;
}

function generator() {
  const o = loadOptions();
  const out = el("output");
  const info = el("small", { class: "muted" });
  let value = "";
  const regen = () => { value = generate(o); out.textContent = value; info.textContent = "~" + entropy(o) + " " + t("bits"); saveOptions(o); };
  const check = (k, label) => { const c = el("input", { type: "checkbox", onchange: () => { o[k] = c.checked; regen(); } }); c.checked = !!o[k]; return el("label", { class: "check" }, c, label); };
  const len = el("input", { type: "range", min: 8, max: 64, value: o.length, oninput: () => { o.length = +len.value; lenLabel.textContent = len.value; regen(); } });
  const lenLabel = el("b", { text: String(o.length) });
  const words = el("input", { type: "range", min: 3, max: 12, value: o.words, oninput: () => { o.words = +words.value; wLabel.textContent = words.value; regen(); } });
  const wLabel = el("b", { text: String(o.words) });
  const pwOpts = el("div", { class: "opts" }, el("label", {}, el("span", {}, t("Length"), " ", lenLabel), len),
    el("div", { class: "checks" }, check("upper", "A–Z"), check("digits", "0–9"), check("symbols", "!@#$")));
  const phOpts = el("div", { class: "opts" }, el("label", {}, el("span", {}, t("Words"), " ", wLabel), words),
    el("div", { class: "checks" }, check("capitalize", t("Capital letters")), check("number", t("Add a digit"))));
  const kinds = el("div", { class: "tabs" });
  const setKind = (k) => { o.kind = k; for (const b of kinds.children) b.classList.toggle("on", b.dataset.k === k); pwOpts.hidden = k !== "password"; phOpts.hidden = k !== "passphrase"; regen(); };
  for (const [k, label] of [["password", t("Password")], ["passphrase", t("Passphrase")]]) {
    const b = el("button", { type: "button", onclick: () => setKind(k) }, label);
    b.dataset.k = k;
    kinds.append(b);
  }
  const box = el("div", { class: "gen" }, kinds, out, info, pwOpts, phOpts,
    el("div", { class: "btnrow" }, el("button", { type: "button", class: "secondary", onclick: regen }, icon("refresh"), t("New")),
      el("button", { type: "button", class: "secondary", onclick: async () => { await navigator.clipboard.writeText(value); toast(t("Copied.")); } }, icon("copy"), t("Copy"))));
  setKind(o.kind === "passphrase" ? "passphrase" : "password");
  return box;
}

async function openVault() {
  const s = await settings();
  if (s.server) api.tabs.create({ url: s.server + "/vault" });
}

async function showMenu(st) {
  const s = await settings();
  const err = errBox();
  const save = el("input", { type: "checkbox" });
  save.checked = s.offerSave;
  save.addEventListener("change", async () => {
    showErr(err, "");
    if (save.checked) {
      let ok = false;
      try { ok = await api.permissions.request({ origins: ["https://*/*", "http://*/*"] }); } catch (e) { ok = false; }
      if (!ok) { save.checked = false; showErr(err, t("Offering to save needs access to the sites you sign in to. The browser did not allow it.")); return; }
    }
    await saveSettings({ offerSave: save.checked });
    await bg("settingsChanged");
  });
  // the number of logins of a website on the icon
  const count = el("input", { type: "checkbox" });
  count.checked = s.siteBadge;
  count.addEventListener("change", async () => {
    showErr(err, "");
    if (count.checked) {
      let ok = false;
      try { ok = await api.permissions.request({ origins: ["https://*/*", "http://*/*"] }); } catch (e) { ok = false; }
      if (!ok) { count.checked = false; showErr(err, t("For this the browser must let PassZit see the address of your tabs. It did not allow it.")); return; }
    }
    await saveSettings({ siteBadge: count.checked });
    await bg("settingsChanged");
  });
  // remote connections through the MaxZit Launcher (or passzit-helper);
  // the launcher accepts this extension only after pairing
  const helperState = el("p", { class: "small muted" });
  const firefox = typeof browser !== "undefined" && api.runtime.getURL("").startsWith("moz-extension:");
  // The MaxZit Launcher (shared with WatchZit) registers this extension
  // after the user allows it in the launcher's own window.
  const pairURL = "maxzit-launcher://pair?app=passzit&browser=" + (firefox ? "firefox" : "chromium") + "&id=" + encodeURIComponent(firefox ? "passzit@maxzit.com" : api.runtime.id);
  const pairBtn = el("button", { type: "button", class: "secondary", onclick: async () => {
    await api.tabs.create({ url: pairURL });
    window.close();
  } }, t("Pair with the MaxZit Launcher"));
  const checkHelper = async () => {
    const r = await bg("helperPing").catch(() => ({ ok: false }));
    if (r && r.ok) { helperState.replaceChildren(t("The MaxZit Launcher answers (%s).", r.version || "?")); return; }
    // not installed or not paired: download it from the Launcher page of the
    // server (the same program WatchZit offers), then pair this browser
    const page = el("button", { type: "button", class: "secondary", onclick: async () => {
      const cur = await settings();
      if (cur.server) await api.tabs.create({ url: cur.server + "/launcher" });
      window.close();
    } }, t("Download the MaxZit Launcher"));
    helperState.replaceChildren(t("Install the MaxZit Launcher on this computer and pair it with this browser."), page, pairBtn);
  };
  // passkeys of websites in the vault (needs all sites, like offering to save)
  const pkBox = el("input", { type: "checkbox" });
  pkBox.checked = !!s.passkeys;
  pkBox.addEventListener("change", async () => {
    showErr(err, "");
    if (pkBox.checked) {
      let ok = false;
      try { ok = await api.permissions.request({ origins: ["https://*/*", "http://*/*"] }); } catch (e) { ok = false; }
      if (!ok) { pkBox.checked = false; showErr(err, t("For passkeys the extension must answer on the websites you sign in to. The browser did not allow it.")); return; }
    }
    await saveSettings({ passkeys: pkBox.checked });
    await bg("settingsChanged");
  });
  // MaxZit consoles (WatchZit) whose "Open with" uses the logins of the vault
  const consoles = el("div", { class: "consoles" });
  const showConsoles = async () => {
    const cur = (await settings()).consoles;
    consoles.replaceChildren(...cur.map((o) => el("div", { class: "row console" }, el("code", { text: o }),
      el("button", { type: "button", class: "ghost", title: t("Remove"), "aria-label": t("Remove"), onclick: async () => {
        await saveSettings({ consoles: (await settings()).consoles.filter((x) => x !== o) });
        await bg("settingsChanged");
        showConsoles();
      } }, "×"))));
  };
  const consoleIn = el("input", { type: "url", placeholder: "https://watchzit.example.com:8443", "aria-label": t("Address of a MaxZit console") });
  const consoleAdd = el("button", { type: "button", class: "secondary", onclick: async () => {
    showErr(err, "");
    const origin = consoleOrigin(consoleIn.value);
    if (!origin) { showErr(err, t("Enter the address of the console, e.g. https://watchzit.example.com:8443.")); return; }
    // asked right away: the browser allows the question only on the click
    let ok = false;
    try { ok = await api.permissions.request({ origins: [origin + "/*"] }); } catch (e) { ok = false; }
    if (!ok) { showErr(err, t("The browser did not allow PassZit on that console.")); return; }
    const cur = (await settings()).consoles;
    if (!cur.includes(origin)) await saveSettings({ consoles: cur.concat(origin).slice(0, 20) });
    await bg("settingsChanged");
    consoleIn.value = "";
    showConsoles();
  } }, t("Add"));
  app.replaceChildren(el("div", { class: "menu" },
    el("h1", { text: t("Settings") }), err,
    el("p", { class: "small" }, el("b", { text: s.email }), el("br"), el("span", { class: "muted", text: s.server })),
    el("label", { class: "check" }, save, t("Offer to save new and changed logins")),
    el("p", { class: "small muted", text: t("For this the extension needs to see the sign-in forms of the sites you visit. Passwords never leave your browser unencrypted.") }),
    el("label", { class: "check" }, count, t("Show on the PassZit icon how many logins a website has")),
    el("label", { class: "check" }, pkBox, t("Use PassZit for passkeys")),
    el("p", { class: "small muted", text: t("Websites that offer a passkey can save it in PassZit and sign in with it; you confirm each time in a PassZit window. Without PassZit the browser's own passkeys answer.") }),
    el("p", { class: "small" }, el("b", { text: t("Connections (RDP, SSH, WinSCP, WinBox, VNC, Telnet)") })),
    helperState,
    el("p", { class: "small" }, el("b", { text: t("MaxZit consoles (WatchZit)") })),
    el("p", { class: "small muted", text: t("On these consoles \"Open with\" on a device opens the connection with the login saved for it, while PassZit is unlocked.") }),
    consoles, el("div", { class: "addconsole" }, consoleIn, consoleAdd),
    el("button", { type: "button", class: "secondary", onclick: openVault }, t("Open the web vault")),
    el("button", { type: "button", class: "ghost", onclick: async () => { await bg("logout"); start(); } }, t("Sign out of this browser")),
    el("button", { type: "button", class: "ghost", onclick: () => start() }, t("Back"))));
  checkHelper();
  showConsoles();
  if (!st.signedIn) start();
}

start().catch((e) => { app.replaceChildren(el("div", { class: "err", text: e.message })); });
