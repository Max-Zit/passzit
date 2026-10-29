// PassZit extension background: keeps the unlocked keys (in memory and in
// storage.session, which the browser never writes to disk and empties when
// it closes), syncs the encrypted vault, finds logins for the open site and
// fills them into the page when the user asks.
import * as pz from "./pz/crypto.js";
import { api, settings, saveSettings, call, loadTexts, t } from "./ext.js";
import { match, parse } from "./domain.js";

const S = {
  keys: null,        // { accountKey, privateKey, publicKey } as Uint8Array
  vaultKeys: new Map(),
  items: new Map(),  // id → { id, vault_id, revision, deleted_at, data }
  revision: 0,
  lockMinutes: 15,
  clipSeconds: 30,
  pending: [],       // save offers: { url, site, username, password, update: id|"" }
  loaded: false,
};

// ---- persistence across service-worker restarts

async function persist() {
  if (!S.keys) { await api.storage.session.remove("pz"); return; }
  const items = [...S.items.values()].map((i) => ({ id: i.id, vault_id: i.vault_id, revision: i.revision, deleted_at: i.deleted_at, raw: i.raw }));
  await api.storage.session.set({ pz: {
    keys: { a: pz.b64u(S.keys.accountKey), p: pz.b64u(S.keys.privateKey), u: pz.b64u(S.keys.publicKey) },
    vaults: [...S.vaultKeys.entries()].map(([id, k]) => [id, pz.b64u(k)]),
    items, revision: S.revision, lock: S.lockMinutes, clip: S.clipSeconds, pending: S.pending,
  } });
}

async function restore() {
  if (S.loaded) return;
  S.loaded = true;
  await loadTexts();
  const { pz: st } = await api.storage.session.get("pz");
  if (!st) return;
  S.keys = { accountKey: pz.unb64u(st.keys.a), privateKey: pz.unb64u(st.keys.p), publicKey: pz.unb64u(st.keys.u) };
  S.vaultKeys = new Map(st.vaults.map(([id, k]) => [id, pz.unb64u(k)]));
  S.revision = st.revision;
  S.lockMinutes = st.lock;
  S.clipSeconds = st.clip;
  S.pending = st.pending || [];
  S.items.clear();
  for (const it of st.items) S.items.set(it.id, await decryptItem(it));
}

// The browser may offer storage.session to content scripts; keep it to
// the extension's own pages.
if (api.storage.session.setAccessLevel) {
  api.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});
}

// ---- vault data

async function server() {
  const s = await settings();
  if (!s.server || !s.token) throw new Error(t("You are signed out."));
  return s;
}

async function sync(full) {
  const s = await server();
  const since = full ? 0 : S.revision;
  const d = await call(s.server, s.token, "GET", "/api/sync" + (since ? "?since=" + since : ""));
  // A full sync follows vaults gained, lost or with a new key: open all again.
  if (d.full) { S.items.clear(); S.vaultKeys.clear(); }
  for (const v of d.vaults) {
    if (S.vaultKeys.has(v.id)) continue;
    try {
      const k = v.kind === "personal"
        ? await pz.open(S.keys.accountKey, v.wrapped_key, pz.AAD.vaultKey(v.id))
        : await pz.openSealed(S.keys.privateKey, S.keys.publicKey, v.wrapped_key, pz.AAD.vaultKey(v.id));
      S.vaultKeys.set(v.id, k);
    } catch (e) { /* not ours to open */ }
  }
  for (const id of d.removed) S.items.delete(id);
  for (const it of d.items) S.items.set(it.id, await decryptItem({ id: it.id, vault_id: it.vault_id, revision: it.revision, deleted_at: it.deleted_at, raw: it.data }));
  S.revision = Math.max(S.revision, d.revision);
  await persist();
}

async function decryptItem(it) {
  const k = S.vaultKeys.get(it.vault_id);
  let data = null;
  if (k) {
    try { data = await pz.openJSON(k, it.raw, pz.AAD.item(it.vault_id, it.id)); } catch (e) { /* damaged */ }
  }
  return Object.assign({}, it, { data });
}

async function maybeSync() {
  try {
    const s = await server();
    const { revision } = await call(s.server, s.token, "GET", "/api/revision");
    if (revision > S.revision) await sync(false);
  } catch (e) {
    if (e.status === 401) await signedOut();
  }
}

function personalVault() {
  for (const it of S.items.values()) if (S.vaultKeys.has(it.vault_id)) return it.vault_id;
  return S.vaultKeys.keys().next().value || "";
}

async function saveItem(item, data) {
  const s = await server();
  const vaultID = item.vault_id || S.personal || personalVault();
  const key = S.vaultKeys.get(vaultID);
  if (!key) throw new Error(t("This vault cannot be opened."));
  const id = item.id || pz.uuid();
  const raw = await pz.sealJSON(key, data, pz.AAD.item(vaultID, id));
  const res = await call(s.server, s.token, "PUT", "/api/items/" + id, { vault_id: vaultID, data: raw, revision: item.revision || 0 });
  S.items.set(id, { id, vault_id: vaultID, revision: res.revision, deleted_at: null, raw, data });
  S.revision = Math.max(S.revision, res.revision);
  await persist();
}

// ---- locking

function armLock() {
  api.alarms.create("pz-lock", { delayInMinutes: Math.max(1, S.lockMinutes) });
}

async function lock() {
  S.keys = null;
  S.vaultKeys.clear();
  S.items.clear();
  S.revision = 0;
  await api.alarms.clear("pz-lock");
  await api.alarms.clear("pz-sync");
  await persist();
  await badge();
}

async function signedOut() {
  await lock();
  await saveSettings({ token: "" });
}

// ---- matching

function summary(it, how) {
  const d = it.data;
  return { id: it.id, name: d.name || "", username: d.login && d.login.username || "", type: d.type, match: how || "",
    site: (parse((d.login && d.login.urls || [])[0]) || {}).hostname || "", hasPassword: !!(d.login && d.login.password), favorite: !!d.favorite };
}

function matchesFor(url) {
  const out = [];
  for (const it of S.items.values()) {
    const d = it.data;
    if (!d || it.deleted_at || d.type !== "login" || !d.login) continue;
    let best = "";
    for (const u of d.login.urls || []) {
      const m = match(u, url);
      if (m === "host") { best = "host"; break; }
      if (m === "site") best = "site";
    }
    if (best) out.push(summary(it, best));
  }
  return out.sort((a, b) => (a.match === b.match ? 0 : a.match === "host" ? -1 : 1) || a.name.localeCompare(b.name));
}

function search(q) {
  const f = (q || "").toLowerCase().trim();
  const out = [];
  for (const it of S.items.values()) {
    const d = it.data;
    if (!d || it.deleted_at) continue;
    const hay = [d.name, d.login && d.login.username, ...(d.login && d.login.urls || [])].join("\n").toLowerCase();
    if (!f || hay.includes(f)) out.push(summary(it));
  }
  return out.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" })).slice(0, 200);
}

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// tabURL is the address of a tab's page. Firefox gives tabs.get no URL
// without the "tabs" permission; then the page itself tells it (the same
// script access the filling needs).
async function tabURL(tab) {
  if (!tab) return "";
  if (tab.url) return tab.url;
  // Right after a page loads, Firefox may not run scripts in it yet: retry briefly.
  for (let i = 0; i < 5; i++) {
    try {
      const [r] = await api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: () => location.href });
      if (r && typeof r.result === "string" && r.result) return r.result;
    } catch (e) { /* not yet */ }
    await new Promise((res) => setTimeout(res, 200));
  }
  return "";
}

// ---- filling: a function that runs in the page's isolated world. It
// checks that the page is still the one the login was chosen for, fills
// only visible, editable fields, and reports what it did.

function pzFill(expectedOrigin, username, password) {
  if (location.origin !== expectedOrigin) return { ok: false, reason: "origin" };
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return r.width > 1 && r.height > 1 && cs.visibility !== "hidden" && cs.display !== "none" && parseFloat(cs.opacity || "1") > 0.1;
  };
  const textual = (i) => ["text", "email", "tel", "url", ""].includes((i.getAttribute("type") || "").toLowerCase());
  const inputs = [...document.querySelectorAll("input")].filter((i) => !i.disabled && !i.readOnly && visible(i));
  const pw = inputs.filter((i) => i.type === "password");
  const looksUser = (i) => i.type === "email" || /username|email/.test(i.autocomplete || "") ||
    /user|login|mail|account|benutzer|korisn/i.test((i.name || "") + " " + (i.id || "") + " " + (i.placeholder || "") + " " + (i.getAttribute("aria-label") || ""));
  const setValue = (el, v) => {
    el.focus();
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    desc.set.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const target = pw.find((p) => !/new|confirm|repeat/i.test((p.autocomplete || "") + (p.name || "") + (p.id || ""))) || pw[0];
  let user = null;
  if (target) {
    const scope = target.form ? inputs.filter((i) => i.form === target.form) : inputs;
    const before = scope.filter((i) => i !== target && textual(i) && (target.compareDocumentPosition(i) & Node.DOCUMENT_POSITION_PRECEDING));
    user = before.slice().reverse().find(looksUser) || before[before.length - 1] || null;
  } else {
    user = inputs.find((i) => textual(i) && looksUser(i)) || null; // a page that asks for the user name first
  }
  if (user && username) setValue(user, username);
  if (target && password) setValue(target, password);
  return { ok: !!(user || target), user: !!user, pass: !!target };
}

async function fill(id, tabId) {
  const it = S.items.get(id);
  if (!it || !it.data || !it.data.login) throw new Error(t("Not found."));
  const tab = tabId ? await api.tabs.get(tabId) : await activeTab();
  const url = await tabURL(tab);
  const page = parse(url);
  if (!page) throw new Error(t("This page cannot be filled."));
  const fits = (it.data.login.urls || []).some((u) => match(u, url));
  if (!fits) throw new Error(t("This login does not belong to this website."));
  const [res] = await api.scripting.executeScript({
    target: { tabId: tab.id, frameIds: [0] },
    func: pzFill,
    args: [page.origin, it.data.login.username || "", it.data.login.password || ""],
  });
  armLock();
  const r = res && res.result;
  if (!r || !r.ok) throw new Error(r && r.reason === "origin" ? t("The page changed. Try again.") : t("No sign-in fields were found on this page."));
  // Uses of items in shared vaults are logged for their managers (the
  // server ignores personal items).
  server().then((s) => call(s.server, s.token, "POST", "/api/items/" + id + "/access", { action: "fill" })).catch(() => {});
  return r;
}

// ---- clipboard clearing (an offscreen document on Chromium, the
// background page itself on Firefox)

async function clearClipboard() {
  if (api.offscreen) {
    try {
      const has = await api.offscreen.hasDocument();
      if (!has) await api.offscreen.createDocument({ url: "offscreen.html", reasons: ["CLIPBOARD"], justification: "Clear a copied password" });
      await api.runtime.sendMessage({ type: "offscreen-clear" });
      await api.offscreen.closeDocument();
    } catch (e) { /* nothing to do */ }
  } else if (typeof document !== "undefined") {
    const h = (e) => { e.clipboardData.setData("text/plain", ""); e.preventDefault(); };
    document.addEventListener("copy", h);
    document.execCommand("copy");
    document.removeEventListener("copy", h);
  }
}

// ---- save offers (only with the optional permission for all sites)

const CAPTURE = "pz-capture";

async function syncCapture() {
  const s = await settings();
  const has = await api.permissions.contains({ origins: ["https://*/*", "http://*/*"] });
  const regs = await api.scripting.getRegisteredContentScripts({ ids: [CAPTURE] }).catch(() => []);
  if (s.offerSave && has && !regs.length) {
    await api.scripting.registerContentScripts([{ id: CAPTURE, js: ["capture.js"], matches: ["https://*/*", "http://*/*"], runAt: "document_idle", allFrames: false }]);
  } else if ((!s.offerSave || !has) && regs.length) {
    await api.scripting.unregisterContentScripts({ ids: [CAPTURE] });
  }
}

async function capture(msg, sender) {
  if (!sender.tab || sender.frameId !== 0 || !msg.password || msg.password.length > 1000) return;
  const pageURL = sender.url || sender.tab.url || "";
  const page = parse(pageURL);
  if (!page) return;
  const username = String(msg.username || "").slice(0, 500);
  let update = "";
  if (S.keys) {
    for (const m of matchesFor(pageURL)) {
      const it = S.items.get(m.id);
      if ((it.data.login.username || "") === username) {
        if (it.data.login.password === msg.password) return; // already saved
        update = it.id;
      }
    }
  }
  S.pending = S.pending.filter((p) => !(p.site === page.site && p.username === username)).slice(-4);
  S.pending.push({ url: page.origin, site: page.site, host: page.hostname, username, password: msg.password, update, at: Date.now() });
  if (S.keys) await persist();
  await badge();
}

async function badge() {
  const n = S.pending.length;
  await api.action.setBadgeText({ text: n ? String(n) : "" });
  await api.action.setBadgeBackgroundColor({ color: "#4f46e5" });
}

async function savePending(index, action) {
  const p = S.pending[index];
  if (!p) return;
  S.pending.splice(index, 1);
  if (action === "save" || action === "update") {
    const now = new Date().toISOString();
    if (p.update && S.items.get(p.update)) {
      const it = S.items.get(p.update);
      const d = JSON.parse(JSON.stringify(it.data));
      d.history = (d.history || []).concat([{ password: d.login.password, changed: now }]).slice(-10);
      d.login.password = p.password;
      d.passwordChanged = now;
      await saveItem(it, d);
    } else {
      await saveItem({}, { type: "login", name: p.host, folder: "", favorite: false, notes: "", fields: [], history: [], passwordChanged: now,
        login: { username: p.username, password: p.password, urls: [p.url] } });
    }
  }
  await persist();
  await badge();
}

// ---- messages from the popup and the capture script

const handlers = {
  async status() {
    const s = await settings();
    return { server: s.server, email: s.email, signedIn: !!s.token, unlocked: !!S.keys, pending: S.pending.length, offerSave: s.offerSave };
  },
  async unlocked(msg) {
    S.keys = { accountKey: pz.unb64u(msg.keys.a), privateKey: pz.unb64u(msg.keys.p), publicKey: pz.unb64u(msg.keys.u) };
    S.lockMinutes = msg.lock || 15;
    S.clipSeconds = msg.clip || 30;
    S.vaultKeys.clear();
    S.revision = 0;
    await sync(true);
    armLock();
    api.alarms.create("pz-sync", { periodInMinutes: 5 });
    await badge();
    return { ok: true };
  },
  async lock() { await lock(); return { ok: true }; },
  async logout() {
    try {
      const s = await server();
      await call(s.server, s.token, "POST", "/api/ext/logout");
    } catch (e) { /* signed out anyway */ }
    await signedOut();
    return { ok: true };
  },
  async page() {
    if (!S.keys) return { locked: true };
    armLock();
    await maybeSync();
    const url = await tabURL(await activeTab());
    const p = parse(url);
    return { url, host: p ? p.hostname : "", secure: p ? p.protocol === "https:" : false, matches: p ? matchesFor(url) : [], pending: S.pending.map((x, i) => ({ i, host: x.host, username: x.username, update: !!x.update })) };
  },
  async search(msg) { if (!S.keys) return { locked: true }; armLock(); return { items: search(msg.q) }; },
  async fill(msg) { return await fill(msg.id, msg.tabId); },
  async secret(msg) {
    const it = S.items.get(msg.id);
    if (!S.keys || !it || !it.data) throw new Error(t("Not found."));
    armLock();
    const d = it.data;
    const v = msg.field === "username" ? (d.login && d.login.username) : msg.field === "password" ? (d.login && d.login.password) : "";
    if (msg.field === "password") api.alarms.create("pz-clip", { delayInMinutes: Math.max(S.clipSeconds, 30) / 60 });
    return { value: v || "", clip: S.clipSeconds };
  },
  async pending(msg) { await savePending(msg.index, msg.action); return { ok: true }; },
  async capture(msg, sender) { await capture(msg, sender); return { ok: true }; },
  async settingsChanged() { await syncCapture(); return { ok: true }; },
  async sync() { await sync(true); return { ok: true, count: S.items.size }; },
};

api.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!msg || msg.type === "offscreen-clear") return false;
  // Content scripts may only report captured logins.
  const fromPage = !!sender.tab && sender.id === api.runtime.id && sender.url && !sender.url.startsWith(api.runtime.getURL(""));
  if (sender.id !== api.runtime.id || (fromPage && msg.type !== "capture")) return false;
  const h = handlers[msg.type];
  if (!h) return false;
  restore().then(() => h(msg, sender)).then((r) => reply({ ok: true, data: r }), (e) => reply({ ok: false, error: e.message || String(e), status: e.status || 0 }));
  return true;
});

api.alarms.onAlarm.addListener(async (a) => {
  await restore();
  if (a.name === "pz-lock") await lock();
  else if (a.name === "pz-clip") await clearClipboard();
  else if (a.name === "pz-sync" && S.keys) await maybeSync();
});

api.commands.onCommand.addListener(async (cmd) => {
  if (cmd !== "fill-login") return;
  await restore();
  if (!S.keys) { await api.action.openPopup().catch(() => {}); return; }
  const tab = await activeTab();
  const url = await tabURL(tab);
  const m = url ? matchesFor(url) : [];
  if (m.length === 1) await fill(m[0].id, tab.id).catch(() => {});
  else await api.action.openPopup().catch(() => {});
});

api.runtime.onInstalled.addListener(() => { syncCapture().catch(() => {}); });
api.runtime.onStartup.addListener(() => { syncCapture().catch(() => {}); });
api.permissions.onRemoved.addListener(() => { syncCapture().catch(() => {}); });
