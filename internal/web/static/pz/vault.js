// The web vault. Everything is decrypted and encrypted here; the server
// gets sealed items only. Keys stay in memory (and, encrypted with a key of
// the server session, in this tab's session storage) until the vault locks.
import * as pz from "./crypto.js";
import {
  api, ApiError, t, el, icon, button, loadTexts, toast, confirmBox, copy, nextFrame,
  loadKeys, saveKeys, lockNow, clearKeys, unlockWithPassword, kdfWeaker, wireLogout,
} from "./common.js";
import { generatorPanel } from "./genui.js";

const root = document.getElementById("pz-vault");
const S = {
  keys: null,         // accountKey, privateKey, publicKey
  acct: null,         // /api/account
  vaults: new Map(),  // id → { key, rights, kind }
  items: new Map(),   // id → { id, vault_id, revision, created_at, updated_at, deleted_at, data | null }
  folders: new Map(), // id → { revision, name }
  revision: 0,
  view: "all",        // all, fav, login, note, trash, folder
  folder: "",
  q: "",
  selected: "",
  editing: null,      // a draft while the editor is open
};

const TYPES = { login: { label: "Login", icon: "key" }, note: { label: "Secure note", icon: "note" } };

// ---- start, unlock, lock

async function start() {
  await loadTexts();
  wireLogout();
  let keys = null;
  try { keys = await loadKeys(); } catch (e) { showFatal(e.message); return; }
  if (!keys) { showUnlock(); return; }
  S.keys = keys;
  await openVault();
}

function showFatal(msg) {
  root.replaceChildren(el("div", { class: "flash err", role: "alert" }, icon("alert"), el("span", { text: msg })),
    button(t("Try again"), { icon: "refresh", onclick: () => location.reload() }));
}

function showUnlock(msg) {
  stopTimers();
  const pw = el("input", { type: "password", name: "password", required: true, autocomplete: "current-password", "aria-label": t("Master password") });
  const err = el("div", { class: "flash err", role: "alert", hidden: !msg, text: msg || "" });
  const submit = button(t("Unlock"), { type: "submit", class: "primary", icon: "lock" });
  const form = el("form", { class: "stack" },
    el("label", null, t("Master password"), el("span", { class: "pwfield" }, pw,
      el("button", { type: "button", class: "iconbtn", "aria-label": t("Show the password"), onclick: () => { pw.type = pw.type === "password" ? "text" : "password"; } }, icon("eye")))),
    submit);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    err.hidden = true;
    submit.disabled = true;
    submit.classList.add("loading");
    await nextFrame();
    try {
      const acct = await api("GET", "/api/account");
      let opened;
      try {
        opened = await unlockWithPassword(acct, pw.value);
      } catch (e) {
        if (e instanceof ApiError) throw e;
        throw new Error(t("Wrong master password."));
      }
      S.keys = opened.keys;
      S.acct = acct;
      await saveKeys(S.keys);
      if (kdfWeaker(acct.kdf, acct.policy_kdf)) await upgradeKDF(acct, pw.value, opened.auth);
      pw.value = "";
      await openVault();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
      pw.select();
    } finally {
      submit.disabled = false;
      submit.classList.remove("loading");
    }
  });
  root.replaceChildren(el("section", { class: "panel unlock" },
    el("div", { class: "unlock-icon" }, icon("lock")),
    el("h1", { text: t("The vault is locked") }),
    el("p", { class: "muted", text: t("Enter your master password to unlock %s.", root.dataset.email) }),
    err, form));
  document.getElementById("pz-lock").hidden = true;
  pw.focus();
}

// upgradeKDF re-wraps the account key with the policy's stronger key
// derivation (same master password).
async function upgradeKDF(acct, password, currentAuth) {
  try {
    const keys = await pz.rewrap(password, S.keys.accountKey, acct.policy_kdf);
    await api("POST", "/api/account/kdf", Object.assign({ current_auth: currentAuth }, keys));
  } catch (e) {
    console.warn("key derivation upgrade failed", e);
  }
}

async function lock() {
  S.keys = null;
  S.vaults.clear(); S.items.clear(); S.folders.clear();
  S.editing = null;
  await lockNow();
  showUnlock();
}

let lockTimer = 0, pollTimer = 0;
const activity = () => {
  clearTimeout(lockTimer);
  const mins = +document.body.dataset.lock || 15;
  lockTimer = setTimeout(() => { if (S.keys) lock(); }, mins * 60 * 1000);
};

function startTimers() {
  for (const ev of ["mousedown", "keydown", "touchstart", "wheel"]) document.addEventListener(ev, activity, { passive: true });
  activity();
  clearInterval(pollTimer);
  pollTimer = setInterval(poll, 30000);
}

function stopTimers() {
  clearTimeout(lockTimer);
  clearInterval(pollTimer);
}

async function poll() {
  if (document.hidden || !S.keys || S.editing) return;
  try {
    const { revision } = await api("GET", "/api/revision");
    if (revision > S.revision) { await sync(S.revision); render(); }
  } catch (e) { /* next time */ }
}

// ---- data

async function openVault() {
  root.replaceChildren(el("p", { class: "busy" }, el("span", { class: "spinner" }), el("span", { text: t("Opening the vault…") })));
  try {
    if (!S.acct) S.acct = await api("GET", "/api/account");
    await sync(0);
  } catch (e) {
    showFatal(e.message);
    return;
  }
  document.body.dataset.lock = S.acct.lock_minutes;
  document.body.dataset.clip = S.acct.clipboard_seconds;
  const lb = document.getElementById("pz-lock");
  lb.hidden = false;
  lb.onclick = () => lock();
  startTimers();
  render();
}

async function sync(since) {
  const d = await api("GET", "/api/sync" + (since ? "?since=" + since : ""));
  if (d.full) { S.items.clear(); S.folders.clear(); }
  for (const v of d.vaults) {
    if (S.vaults.has(v.id)) continue;
    let key = null;
    try {
      key = v.kind === "personal"
        ? await pz.open(S.keys.accountKey, v.wrapped_key, pz.AAD.vaultKey(v.id))
        : await pz.openSealed(S.keys.privateKey, S.keys.publicKey, v.wrapped_key, pz.AAD.vaultKey(v.id));
    } catch (e) { console.warn("vault key", v.id, e); }
    S.vaults.set(v.id, { key, rights: v.rights, kind: v.kind });
  }
  for (const id of d.removed) { S.items.delete(id); S.folders.delete(id); }
  for (const f of d.folders) {
    let name = "?";
    try { name = pz.fromUtf8(await pz.open(S.keys.accountKey, f.data, pz.AAD.folder(f.id))); } catch (e) { /* damaged */ }
    S.folders.set(f.id, { revision: f.revision, name });
  }
  for (const it of d.items) S.items.set(it.id, await decryptItem(it));
  S.revision = Math.max(S.revision, d.revision);
}

async function decryptItem(it) {
  const v = S.vaults.get(it.vault_id);
  let data = null;
  if (v && v.key) {
    try { data = await pz.openJSON(v.key, it.data, pz.AAD.item(it.vault_id, it.id)); } catch (e) { /* damaged */ }
  }
  return { id: it.id, vault_id: it.vault_id, revision: it.revision, created_at: it.created_at, updated_at: it.updated_at, deleted_at: it.deleted_at || null, data };
}

function personalVault() {
  for (const [id, v] of S.vaults) if (v.kind === "personal") return id;
  return "";
}

async function saveItem(item, data) {
  const vaultID = item.vault_id || personalVault();
  const v = S.vaults.get(vaultID);
  if (!v || !v.key) throw new Error(t("This vault cannot be opened."));
  const id = item.id || pz.uuid();
  const sealed = await pz.sealJSON(v.key, data, pz.AAD.item(vaultID, id));
  const res = await api("PUT", "/api/items/" + id, { vault_id: vaultID, data: sealed, revision: item.revision || 0 });
  const now = new Date().toISOString();
  const saved = { id, vault_id: vaultID, revision: res.revision, created_at: item.created_at || now, updated_at: now, deleted_at: null, data };
  S.items.set(id, saved);
  S.revision = Math.max(S.revision, res.revision);
  return saved;
}

async function itemOp(id, op) {
  const path = "/api/items/" + id + (op === "purge" ? "" : "/" + op);
  const res = await api(op === "purge" ? "DELETE" : "POST", path);
  S.revision = Math.max(S.revision, res.revision);
  const it = S.items.get(id);
  if (op === "purge") S.items.delete(id);
  else if (it) { it.revision = res.revision; it.deleted_at = op === "trash" ? new Date().toISOString() : null; }
}

async function saveFolder(id, name, revision) {
  const fid = id || pz.uuid();
  const data = await pz.seal(S.keys.accountKey, pz.utf8(name), pz.AAD.folder(fid));
  const res = await api("PUT", "/api/folders/" + fid, { data, revision: revision || 0 });
  S.folders.set(fid, { revision: res.revision, name });
  S.revision = Math.max(S.revision, res.revision);
  return fid;
}

// ---- rendering

function itemName(it) { return it.data ? it.data.name || t("(no name)") : t("(cannot be decrypted)"); }

function visibleItems() {
  const q = S.q.trim().toLowerCase();
  const out = [];
  for (const it of S.items.values()) {
    const d = it.data;
    const trashed = !!it.deleted_at;
    if (S.view === "trash" ? !trashed : trashed) continue;
    if (d) {
      if (S.view === "fav" && !d.favorite) continue;
      if ((S.view === "login" || S.view === "note") && d.type !== S.view) continue;
      if (S.view === "folder" && (d.folder || "") !== S.folder) continue;
      if (q) {
        const hay = [d.name, d.login && d.login.username, ...(d.login && d.login.urls || []), d.notes].join("\n").toLowerCase();
        if (!hay.includes(q)) continue;
      }
    } else if (S.view !== "all" && S.view !== "trash") continue;
    out.push(it);
  }
  return out.sort((a, b) => itemName(a).localeCompare(itemName(b), undefined, { sensitivity: "base" }));
}

function render() {
  if (!S.keys) return;
  const grid = el("div", { class: "vgrid", dataset: { pane: S.editing || S.selected ? "detail" : "list" } },
    renderFilters(), renderList(), el("section", { class: "vdetail panel", id: "vdetail" }, renderDetail()));
  root.replaceChildren(grid);
}

function count(view, folder) {
  let n = 0;
  for (const it of S.items.values()) {
    const d = it.data;
    if (view === "trash") { if (it.deleted_at) n++; continue; }
    if (it.deleted_at) continue;
    if (view === "all") n++;
    else if (!d) continue;
    else if (view === "fav" && d.favorite) n++;
    else if ((view === "login" || view === "note") && d.type === view) n++;
    else if (view === "folder" && (d.folder || "") === folder) n++;
  }
  return n;
}

function renderFilters() {
  const link = (view, label, ic, folder) => {
    const on = S.view === view && (view !== "folder" || S.folder === folder);
    return el("a", { href: "#", class: on ? "on" : "", onclick: (ev) => { ev.preventDefault(); S.view = view; S.folder = folder || ""; S.selected = ""; S.editing = null; render(); } },
      icon(ic), el("span", { text: label }), el("small", { text: String(count(view, folder)) }));
  };
  const nav = el("nav", { class: "vfilters", "aria-label": t("Filters") },
    link("all", t("All items"), "grid"), link("fav", t("Favorites"), "star"),
    el("span", { class: "navlabel", text: t("Types") }),
    link("login", t("Logins"), "key"), link("note", t("Secure notes"), "note"),
    el("span", { class: "navlabel" }, t("Folders"),
      el("button", { type: "button", class: "iconbtn sm", title: t("New folder"), "aria-label": t("New folder"), onclick: newFolder }, icon("plus"))));
  const folders = [...S.folders.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name, undefined, { sensitivity: "base" }));
  for (const [id, f] of folders) nav.append(link("folder", f.name, "folder", id));
  nav.append(el("span", { class: "navlabel" }), link("trash", t("Trash"), "trash"));
  return nav;
}

async function newFolder() {
  const name = await prompt1(t("New folder"), t("Name"), "");
  if (!name) return;
  try {
    const id = await saveFolder("", name, 0);
    S.view = "folder"; S.folder = id;
    render();
  } catch (e) { toast(e.message, true); }
}

// prompt1 asks for one line of text in a dialog.
function prompt1(title, label, value) {
  return new Promise((resolve) => {
    const inp = el("input", { value, maxlength: 100, required: true });
    const f = el("form", { method: "dialog", class: "stack" }, el("h2", { text: title }), el("label", null, label, inp),
      el("div", { class: "row end" }, button(t("Cancel"), { class: "ghost", onclick: () => { d.close(); } }), button(t("Save"), { type: "submit", class: "primary" })));
    const d = el("dialog", { class: "dlg" }, f);
    let result = null;
    f.addEventListener("submit", () => { result = inp.value.trim(); });
    d.addEventListener("close", () => { d.remove(); resolve(result); });
    document.body.append(d);
    d.showModal();
    inp.focus();
  });
}

function renderList() {
  const search = el("input", { type: "search", value: S.q, placeholder: t("Search the vault"), "aria-label": t("Search the vault"), class: "vsearch" });
  search.addEventListener("input", () => {
    S.q = search.value;
    const list = document.getElementById("vlist-items");
    if (list) list.replaceChildren(...listRows());
  });
  const head = el("div", { class: "vlist-head" }, el("div", { class: "searchfield" }, icon("search"), search));
  if (S.view !== "trash") head.append(button(t("New item"), { class: "primary", icon: "plus", onclick: () => startEdit(null) }));
  let title = { all: t("All items"), fav: t("Favorites"), login: t("Logins"), note: t("Secure notes"), trash: t("Trash") }[S.view];
  if (S.view === "folder") title = (S.folders.get(S.folder) || {}).name || "";
  const tools = el("div", { class: "vlist-title" }, el("h2", { text: title }));
  if (S.view === "folder") {
    tools.append(el("span", { class: "row" },
      button("", { class: "ghost sm", icon: "edit", aria: t("Rename the folder"), title: t("Rename the folder"), onclick: renameFolder }),
      button("", { class: "ghost sm", icon: "trash", aria: t("Delete the folder"), title: t("Delete the folder"), onclick: deleteFolder })));
  }
  if (S.view === "trash") tools.append(el("small", { class: "muted", text: t("Items in the trash are deleted after %d days.", S.acct.trash_days || 30) }));
  return el("section", { class: "vlist panel" }, head, tools, el("ul", { class: "vitems", id: "vlist-items" }, ...listRows()));
}

function listRows() {
  const items = visibleItems();
  if (!items.length) {
    return [el("li", { class: "empty" }, S.q ? t("Nothing found.") : S.view === "trash" ? t("The trash is empty.") : t("No items yet. Add your first login with New item."))];
  }
  return items.map((it) => {
    const d = it.data || {};
    const sub = d.type === "login" ? (d.login && d.login.username) || hostOf((d.login && d.login.urls || [])[0]) : t(TYPES[d.type] ? TYPES[d.type].label : "Item");
    return el("li", null, el("a", { href: "#", class: it.id === S.selected ? "on" : "", onclick: (ev) => { ev.preventDefault(); S.selected = it.id; S.editing = null; render(); } },
      el("span", { class: "vicon", dataset: { type: d.type || "" } }, d.type === "note" ? icon("note") : (itemName(it)[0] || "?").toUpperCase()),
      el("span", { class: "vname" }, el("b", { text: itemName(it) }), el("small", { text: sub || "" })),
      d.favorite ? el("span", { class: "vfav", title: t("Favorite") }, icon("star")) : null));
  });
}

function hostOf(u) {
  if (!u) return "";
  try { return new URL(/^[a-z][a-z0-9+.-]*:/i.test(u) ? u : "https://" + u).host; } catch (e) { return u; }
}

function safeHref(u) {
  if (!u) return null;
  const full = /^[a-z][a-z0-9+.-]*:/i.test(u) ? u : "https://" + u;
  try {
    const p = new URL(full);
    return p.protocol === "https:" || p.protocol === "http:" ? p.href : null;
  } catch (e) { return null; }
}

async function renameFolder() {
  const f = S.folders.get(S.folder);
  if (!f) return;
  const name = await prompt1(t("Rename the folder"), t("Name"), f.name);
  if (!name || name === f.name) return;
  try { await saveFolder(S.folder, name, f.revision); render(); } catch (e) { toast(e.message, true); }
}

async function deleteFolder() {
  const f = S.folders.get(S.folder);
  if (!f || !(await confirmBox(t("Delete the folder %s? Its items stay in the vault, without a folder.", f.name), t("Delete"), true))) return;
  try {
    const res = await api("DELETE", "/api/folders/" + S.folder);
    S.revision = Math.max(S.revision, res.revision);
    S.folders.delete(S.folder);
    S.view = "all"; S.folder = "";
    render();
  } catch (e) { toast(e.message, true); }
}

// ---- detail

function renderDetail() {
  if (S.editing) return renderEditor();
  const it = S.items.get(S.selected);
  if (!it) {
    return el("div", { class: "empty" }, icon("lock"), el("p", { text: t("Choose an item, or add a new one.") }),
      el("p", { class: "small muted", text: t("%d items · encrypted in your browser", count("all")) }));
  }
  const d = it.data;
  const back = button(t("Back"), { class: "ghost sm vback", icon: "back", onclick: () => { S.selected = ""; render(); } });
  if (!d) {
    return el("div", null, back, el("div", { class: "flash err" }, icon("alert"), el("span", { text: t("This item cannot be decrypted. It may be damaged.") })),
      itemActions(it));
  }
  const rows = [];
  if (d.type === "login" && d.login) {
    const l = d.login;
    if (l.username) rows.push(field(t("User name"), l.username, { copy: true }));
    if (l.password) rows.push(field(t("Password"), l.password, { copy: true, secret: true, mono: true }));
    for (const u of l.urls || []) rows.push(urlField(u));
  }
  for (const f of d.fields || []) rows.push(field(f.name || t("Field"), f.value, { copy: true, secret: f.hidden }));
  if (d.notes) rows.push(el("div", { class: "vfield" }, el("label", { text: t("Notes") }), el("pre", { class: "vnotes", text: d.notes })));
  const folder = d.folder && S.folders.get(d.folder);
  const meta = el("p", { class: "small muted" },
    t("Changed %s", fmtDate(it.updated_at)), " · ", t("Created %s", fmtDate(it.created_at)),
    d.passwordChanged ? " · " + t("Password changed %s", fmtDate(d.passwordChanged)) : "");
  const hist = (d.history || []).length ? el("details", { class: "vhist" }, el("summary", { text: t("Password history (%d)", d.history.length) }),
    el("ul", null, ...d.history.slice().reverse().map((h) => el("li", null, el("code", { class: "mono", text: "••••••••" }),
      el("small", { class: "muted", text: " " + fmtDate(h.changed) + " " }),
      button("", { class: "ghost sm", icon: "eye", aria: t("Show"), onclick: (ev) => { const c = ev.currentTarget.parentElement.querySelector("code"); c.textContent = c.textContent === "••••••••" ? h.password : "••••••••"; } }),
      button("", { class: "ghost sm", icon: "copy", aria: t("Copy"), onclick: () => copy(h.password, true) }))))) : null;
  return el("div", { class: "vview" }, back,
    el("div", { class: "vview-head" },
      el("span", { class: "vicon lg", dataset: { type: d.type } }, d.type === "note" ? icon("note") : (itemName(it)[0] || "?").toUpperCase()),
      el("div", null, el("h2", { text: itemName(it) }), el("small", { class: "muted" }, t(TYPES[d.type] ? TYPES[d.type].label : "Item"), folder ? " · " + folder.name : "")),
      it.deleted_at ? null : el("button", { type: "button", class: "iconbtn" + (d.favorite ? " fav-on" : ""), title: t("Favorite"), "aria-pressed": d.favorite ? "true" : "false", onclick: () => toggleFav(it) }, icon("star"))),
    it.deleted_at ? el("div", { class: "flash warn" }, icon("trash"), el("span", { text: t("In the trash since %s.", fmtDate(it.deleted_at)) })) : null,
    ...rows, hist, meta, itemActions(it));
}

function itemActions(it) {
  if (it.deleted_at) {
    return el("div", { class: "row vactions" },
      button(t("Restore"), { class: "primary", icon: "restore", onclick: () => act(it, "restore", t("Restored.")) }),
      button(t("Delete forever"), { class: "danger", icon: "trash", onclick: async () => {
        if (await confirmBox(t("Delete %s for good? This cannot be undone.", itemName(it)), t("Delete forever"), true)) act(it, "purge", t("Deleted."));
      } }));
  }
  return el("div", { class: "row vactions" },
    it.data ? button(t("Edit"), { class: "primary", icon: "edit", onclick: () => startEdit(it) }) : null,
    button(t("Move to the trash"), { class: "ghost", icon: "trash", onclick: () => act(it, "trash", t("Moved to the trash.")) }));
}

async function act(it, op, msg) {
  try {
    await itemOp(it.id, op);
    if (op === "purge" || op === "trash" || op === "restore") S.selected = "";
    toast(msg);
    render();
  } catch (e) { toast(e.message, true); }
}

async function toggleFav(it) {
  const data = Object.assign({}, it.data, { favorite: !it.data.favorite });
  try { await saveItem(it, data); render(); } catch (e) { toast(e.message, true); }
}

function fmtDate(s) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d) ? "—" : d.toLocaleString(document.documentElement.lang || undefined, { dateStyle: "medium", timeStyle: "short" });
}

function field(label, value, o) {
  const opt = o || {};
  const v = el(opt.mono || opt.secret ? "code" : "span", { class: "vvalue" + (opt.mono || opt.secret ? " mono" : ""), text: opt.secret ? "••••••••••" : value });
  const tools = el("span", { class: "vtools" });
  if (opt.secret) {
    tools.append(el("button", { type: "button", class: "iconbtn sm", title: t("Show"), "aria-label": t("Show"), onclick: (ev) => {
      const shown = v.textContent !== "••••••••••";
      v.textContent = shown ? "••••••••••" : value;
      ev.currentTarget.replaceChildren(icon(shown ? "eye" : "eyeoff"));
    } }, icon("eye")));
  }
  if (opt.copy) tools.append(el("button", { type: "button", class: "iconbtn sm", title: t("Copy"), "aria-label": t("Copy") + " " + label, onclick: () => copy(value, !!opt.secret) }, icon("copy")));
  return el("div", { class: "vfield" }, el("label", { text: label }), el("div", { class: "vline" }, v, tools));
}

function urlField(u) {
  const href = safeHref(u);
  const tools = el("span", { class: "vtools" });
  if (href) tools.append(el("a", { class: "iconbtn sm", href, target: "_blank", rel: "noopener noreferrer", title: t("Open"), "aria-label": t("Open") }, icon("external")));
  tools.append(el("button", { type: "button", class: "iconbtn sm", title: t("Copy"), "aria-label": t("Copy"), onclick: () => copy(u, false) }, icon("copy")));
  return el("div", { class: "vfield" }, el("label", { text: t("Website") }), el("div", { class: "vline" }, el("span", { class: "vvalue ellipsis", text: u }), tools));
}

// ---- editor

function startEdit(it) {
  const base = it && it.data ? JSON.parse(JSON.stringify(it.data)) : { type: "login", name: "", login: { username: "", password: "", urls: [""] }, notes: "", fields: [], favorite: false, folder: S.view === "folder" ? S.folder : "" };
  if (!base.login) base.login = { username: "", password: "", urls: [""] };
  if (!base.login.urls || !base.login.urls.length) base.login.urls = [""];
  S.editing = { item: it, data: base };
  render();
  const first = document.querySelector("#vdetail input[name=name]");
  if (first) first.focus();
}

function renderEditor() {
  const e = S.editing;
  const d = e.data;
  const isNew = !e.item;
  const type = el("select", { name: "type", onchange: () => { d.type = type.value; loginPart.hidden = d.type !== "login"; } },
    ...Object.entries(TYPES).map(([k, v]) => el("option", { value: k, selected: d.type === k }, t(v.label))));
  const name = el("input", { name: "name", value: d.name, required: true, maxlength: 200, autocomplete: "off" });
  const user = el("input", { name: "username", value: d.login.username, autocomplete: "off", autocapitalize: "none", spellcheck: "false" });
  const pass = el("input", { name: "password", type: "password", value: d.login.password, autocomplete: "new-password", class: "mono", spellcheck: "false" });
  const genBtn = el("button", { type: "button", class: "iconbtn", title: t("Generate a password"), "aria-label": t("Generate a password"), onclick: () => openGenerator((v) => { pass.value = v; pass.type = "text"; }) }, icon("dice"));
  const showBtn = el("button", { type: "button", class: "iconbtn", title: t("Show"), "aria-label": t("Show"), onclick: () => { pass.type = pass.type === "password" ? "text" : "password"; } }, icon("eye"));
  const urls = el("div", { class: "rows" });
  const addURL = (v) => {
    const inp = el("input", { value: v, placeholder: "https://example.com", autocomplete: "off", spellcheck: "false", "aria-label": t("Website") });
    urls.append(el("div", { class: "rowline" }, inp, el("button", { type: "button", class: "iconbtn", "aria-label": t("Remove"), onclick: (ev) => ev.currentTarget.parentElement.remove() }, icon("x"))));
  };
  for (const u of d.login.urls) addURL(u);
  const loginPart = el("div", { class: "stack", hidden: d.type !== "login" },
    el("label", null, t("User name"), user),
    el("label", null, t("Password"), el("span", { class: "pwfield" }, pass, showBtn, genBtn)),
    el("div", null, el("label", { text: t("Websites") }), urls,
      button(t("Add a website"), { class: "ghost sm", icon: "plus", onclick: () => addURL("") })));
  const folder = el("select", { name: "folder" }, el("option", { value: "" }, t("No folder")),
    ...[...S.folders.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name)).map(([id, f]) => el("option", { value: id, selected: d.folder === id }, f.name)));
  const notes = el("textarea", { name: "notes", rows: 5, maxlength: 20000 }, d.notes || "");
  const fields = el("div", { class: "rows" });
  const addField = (f) => {
    const n = el("input", { value: f.name, placeholder: t("Name"), maxlength: 100, "aria-label": t("Name") });
    const v = el("input", { value: f.value, placeholder: t("Value"), type: f.hidden ? "password" : "text", "aria-label": t("Value"), autocomplete: "off" });
    const h = el("input", { type: "checkbox", checked: f.hidden, onchange: () => { v.type = h.checked ? "password" : "text"; } });
    fields.append(el("div", { class: "rowline field3" }, n, v, el("label", { class: "check", title: t("Hidden") }, h, " " + t("Hidden")),
      el("button", { type: "button", class: "iconbtn", "aria-label": t("Remove"), onclick: (ev) => ev.currentTarget.parentElement.remove() }, icon("x"))));
  };
  for (const f of d.fields || []) addField(f);
  const fav = el("input", { type: "checkbox", checked: d.favorite });
  const err = el("div", { class: "flash err", role: "alert", hidden: true });
  const save = button(t("Save"), { type: "submit", class: "primary", icon: "check" });
  const form = el("form", { class: "stack veditor" },
    el("h2", { text: isNew ? t("New item") : t("Edit %s", d.name || "") }), err,
    el("div", { class: "grid2" }, el("label", null, t("Type"), type), el("label", null, t("Folder"), folder)),
    el("label", null, t("Name"), name),
    loginPart,
    el("label", null, t("Notes"), notes),
    el("div", null, el("label", { text: t("More fields") }), fields, button(t("Add a field"), { class: "ghost sm", icon: "plus", onclick: () => addField({ name: "", value: "", hidden: false }) })),
    el("label", { class: "check" }, fav, " " + t("Favorite")),
    el("div", { class: "row vactions" }, save, button(t("Cancel"), { class: "ghost", onclick: () => { S.editing = null; render(); } })));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    err.hidden = true;
    const old = e.item && e.item.data;
    const out = {
      type: type.value, name: name.value.trim(), folder: folder.value, favorite: fav.checked, notes: notes.value,
      fields: [...fields.children].map((r) => { const i = r.querySelectorAll("input"); return { name: i[0].value.trim(), value: i[1].value, hidden: i[2].checked }; }).filter((f) => f.name || f.value),
      history: old && old.history ? old.history.slice() : [],
      passwordChanged: old && old.passwordChanged || "",
    };
    if (out.type === "login") {
      out.login = { username: user.value.trim(), password: pass.value, urls: [...urls.querySelectorAll("input")].map((i) => i.value.trim()).filter(Boolean) };
      const oldPw = old && old.login ? old.login.password : "";
      if (oldPw && oldPw !== out.login.password) {
        out.history.push({ password: oldPw, changed: new Date().toISOString() });
        out.history = out.history.slice(-10);
      }
      if (oldPw !== out.login.password) out.passwordChanged = new Date().toISOString();
    }
    if (!out.name) { err.textContent = t("Enter a name."); err.hidden = false; return; }
    save.disabled = true;
    try {
      const saved = await saveItem(e.item || {}, out);
      S.editing = null;
      S.selected = saved.id;
      toast(t("Saved."));
      render();
    } catch (x) {
      err.textContent = x.message;
      err.hidden = false;
      if (x instanceof ApiError && x.code === "stale") {
        err.append(" ", button(t("Reload"), { class: "secondary sm", icon: "refresh", onclick: async () => { await sync(S.revision); S.editing = null; render(); } }));
      }
    } finally {
      save.disabled = false;
    }
  });
  return form;
}

function openGenerator(onUse) {
  const d = el("dialog", { class: "dlg wide" });
  const panel = generatorPanel((v) => { onUse(v); d.close(); });
  d.append(el("div", { class: "row spread" }, el("h2", { text: t("Password generator") }),
    el("button", { type: "button", class: "iconbtn", "aria-label": t("Close"), onclick: () => d.close() }, icon("x"))), panel);
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
}

// A vault left open in a background tab still locks; the keys of a closed
// tab are gone with its session storage.
window.addEventListener("pagehide", () => { if (!S.keys) clearKeys(); });

start();
