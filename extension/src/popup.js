// The extension's popup: sign in, unlock, logins for the open site,
// search, generator, save offers and settings. The master password is used
// only here, to derive keys; it is never stored or sent.
import { generate, entropy, loadOptions, saveOptions } from "./pz/generator.js";
import { api, settings, saveSettings, loadTexts, t, normServer, deviceName } from "./ext.js";
import { bg, signIn, secondFactor, unlock } from "./client.js";
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
  return showMain(st);
}

function showSignIn(st) {
  const err = errBox();
  const server = el("input", { type: "url", value: st.server || "", placeholder: "https://vault.example.com", required: true, autocomplete: "off" });
  const email = el("input", { type: "email", value: st.email || "", required: true, autocomplete: "username" });
  const pw = el("input", { type: "password", required: true, autocomplete: "current-password" });
  const go = el("button", { class: "primary", type: "submit" }, t("Sign in and unlock"));
  const form = el("form", {}, el("h1", { text: t("Sign in to PassZit") }), err,
    el("label", {}, t("Server address"), server), el("label", {}, t("E-mail address"), email), el("label", {}, t("Master password"), pw), go,
    el("p", { class: "small muted", style: "margin-top:10px" }, t("The browser asks once to allow PassZit to talk to your server.")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showErr(err, "");
    const origin = normServer(server.value);
    if (!origin) { showErr(err, t("Enter the address of your PassZit server, e.g. https://vault.example.com.")); return; }
    // The permission request must be the first thing in the click.
    let granted = false;
    try { granted = await api.permissions.request({ origins: [origin + "/*"] }); } catch (e) { granted = false; }
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
  (st.server ? pw : server).focus();
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
    el("p", { class: "small muted", text: t("Enter your master password to unlock %s.", st.email) }), err,
    el("label", {}, t("Master password"), pw), go);
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
  body.append(el("div", { class: "site" }, icon("globe"), p.host || t("No website")));
  if (p.host && !p.secure) body.append(el("div", { class: "warn" }, t("This page is not encrypted (HTTP). Logins saved for HTTPS are not offered here.")));
  body.append(itemList(p.matches, true, t("No saved login for this website.")));
  body.append(el("div", { class: "foot" },
    el("a", { href: "#", onclick: (e) => { e.preventDefault(); openVault(); } }, t("Open the web vault")),
    el("button", { type: "button", class: "iconbtn", title: t("Reload"), "aria-label": t("Reload"), onclick: async () => { await bg("sync"); showMain(); } }, icon("refresh"))));
}

function itemList(items, canFill, emptyText) {
  if (!items.length) return el("p", { class: "empty", text: emptyText });
  return el("ul", { class: "list" }, ...items.map((m) => el("li", { class: "row" },
    el("span", { class: "av" }, (m.name || "?")[0].toUpperCase()),
    el("span", { class: "who" }, el("b", { text: m.name || m.site }), el("small", { text: m.username || m.site })),
    el("span", { class: "acts" },
      m.username ? el("button", { type: "button", class: "iconbtn", title: t("Copy the user name"), "aria-label": t("Copy the user name"), onclick: () => copySecret(m.id, "username") }, icon("user")) : null,
      m.hasPassword ? el("button", { type: "button", class: "iconbtn", title: t("Copy the password"), "aria-label": t("Copy the password"), onclick: () => copySecret(m.id, "password") }, icon("key")) : null,
      canFill ? el("button", { type: "button", class: "fill", onclick: () => doFill(m.id) }, t("Fill")) : null))));
}

async function doFill(id) {
  try {
    await bg("fill", { id });
    window.close();
  } catch (e) { toast(e.message); }
}

async function copySecret(id, field) {
  try {
    const r = await bg("secret", { id, field });
    await navigator.clipboard.writeText(r.value);
    toast(field === "password" ? t("Copied. The clipboard is cleared in %d seconds.", Math.max(r.clip, 30)) : t("Copied."));
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
  app.replaceChildren(el("div", { class: "menu" },
    el("h1", { text: t("Settings") }), err,
    el("p", { class: "small" }, el("b", { text: s.email }), el("br"), el("span", { class: "muted", text: s.server })),
    el("label", { class: "check" }, save, t("Offer to save new and changed logins")),
    el("p", { class: "small muted", text: t("For this the extension needs to see the sign-in forms of the sites you visit. Passwords never leave your browser unencrypted.") }),
    el("button", { type: "button", class: "secondary", onclick: openVault }, t("Open the web vault")),
    el("button", { type: "button", class: "ghost", onclick: async () => { await bg("logout"); start(); } }, t("Sign out of this browser")),
    el("button", { type: "button", class: "ghost", onclick: () => start() }, t("Back"))));
  if (!st.signedIn) start();
}

start().catch((e) => { app.replaceChildren(el("div", { class: "err", text: e.message })); });
