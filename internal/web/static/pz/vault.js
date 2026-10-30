// The web vault. Everything is decrypted and encrypted here; the server
// gets sealed items only. Keys stay in memory (and, encrypted with a key of
// the server session, in this tab's session storage) until the vault locks.
import * as pz from "./crypto.js";
import {
  api, ApiError, t, el, icon, button, loadTexts, toast, confirmBox, copy, nextFrame,
  loadKeys, saveKeys, lockNow, clearKeys, unlockWithPassword, kdfWeaker, wireLogout,
} from "./common.js";
import { generatorPanel } from "./genui.js";
import { detect, importEncrypted, exportEncrypted, exportCSV, dedupeKey } from "./transfer.js";
import { authFor, strength } from "./common.js";
import { parse as totpParse, code as totpCode } from "./totp.js";
import { readQR, authenticatorKeys } from "./qr.js";
import { generate as sshGenerate, fingerprint as sshFingerprint } from "./sshkey.js";
import { initSharing, loadKnown, completePending, createVault, openVault as openVaultDialog, rotateBanner, canEditVault, vaultLabel } from "./sharing.js";
import { initSends, openSends, itemText } from "./sends.js";

const root = document.getElementById("pz-vault");
const S = {
  keys: null,         // accountKey, privateKey, publicKey
  acct: null,         // /api/account
  vaults: new Map(),  // id → { key, rights, kind }
  items: new Map(),   // id → { id, vault_id, revision, created_at, updated_at, deleted_at, data | null }
  folders: new Map(), // id → { revision, name }
  revision: 0,
  view: "vault",      // vault, folder, trash ("all": search results, jumps)
  kind: "",           // a kind of item shown in the list (KINDS key or "fav")
  closed: new Set(),  // folder groups closed in the list
  cwd: "",            // the folder of the vault last opened in the list (new items go there)
  qAll: false,        // search all vaults
  vault: "",          // the vault shown with view "vault"
  q: "",
  selected: "",
  editing: null,      // a draft while the editor is open
};

const TYPES = {
  login: { label: "Login", icon: "key", plural: "Logins" },
  note: { label: "Secure note", icon: "note", plural: "Secure notes" },
  card: { label: "Card", icon: "card", plural: "Cards" },
  identity: { label: "Identity", icon: "user", plural: "Identities" },
  sshkey: { label: "SSH key", icon: "terminal", plural: "SSH keys" },
};

// ---- start, unlock, lock

async function start() {
  initSharing({ S, render, sync, dialog, prompt1 });
  initSends({ dialog, fmtDate });
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
    if (await completePending(false)) { await sync(S.revision); render(); }
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
  // Shared vaults: confirmed keys, then access that groups give.
  await loadKnown();
  if (await completePending(true)) { await sync(S.revision); render(); }
  // folders of earlier versions move into the vaults
  await migrateFolders();
}

async function sync(since) {
  const d = await api("GET", "/api/sync" + (since ? "?since=" + since : ""));
  if (d.full) { S.items.clear(); S.folders.clear(); }
  // The vault list is always complete: vaults gained, lost, renamed or with a new key.
  const vaults = new Map();
  for (const v of d.vaults) {
    const old = S.vaults.get(v.id);
    let key = old && old.wrapped === v.wrapped_key ? old.key : null;
    try {
      if (!key) {
        key = v.kind === "personal"
          ? await pz.open(S.keys.accountKey, v.wrapped_key, pz.AAD.vaultKey(v.id))
          : await pz.openSealed(S.keys.privateKey, S.keys.publicKey, v.wrapped_key, pz.AAD.vaultKey(v.id));
      }
    } catch (e) { console.warn("vault key", v.id, e); }
    let name = "";
    if (v.kind === "shared" && key && v.data) {
      try { name = pz.fromUtf8(await pz.open(key, v.data, pz.AAD.vaultName(v.id))); } catch (e) { name = "?"; }
    }
    vaults.set(v.id, { key, rights: v.rights, kind: v.kind, wrapped: v.wrapped_key, name, keyVersion: v.key_version, needsRotation: !!v.needs_rotation, expiresAt: v.expires_at || null });
  }
  S.vaults = vaults;
  if (S.view === "vault" && !S.vaults.has(S.vault)) S.vault = personalVault();
  for (const id of [...S.items.keys()]) if (!S.vaults.has(S.items.get(id).vault_id)) S.items.delete(id);
  for (const id of d.removed) { S.items.delete(id); S.folders.delete(id); }
  for (const f of d.folders) {
    let name = "?";
    try { name = pz.fromUtf8(await pz.open(S.keys.accountKey, f.data, pz.AAD.folder(f.id))); } catch (e) { /* damaged */ }
    S.folders.set(f.id, { revision: f.revision, name });
  }
  for (const it of d.items) S.items.set(it.id, await decryptItem(it));
  for (const [id, it] of S.items) if (!S.vaults.has(it.vault_id)) S.items.delete(id);
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

// moveItem seals an item with the key of another vault and moves it there
// (its files go with it).
async function moveItem(item, toVault, data) {
  const v = S.vaults.get(toVault);
  if (!v || !v.key) throw new Error(t("This vault cannot be opened."));
  const sealed = await pz.sealJSON(v.key, data, pz.AAD.item(toVault, item.id));
  const res = await api("POST", "/api/items/" + item.id + "/move", { vault_id: toVault, data: sealed, revision: item.revision });
  const saved = Object.assign({}, item, { vault_id: toVault, revision: res.revision, updated_at: new Date().toISOString(), data });
  S.items.set(item.id, saved);
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

// ---- folders inside a vault: items of type "folder" ({ name, parent }),
// sealed with the vault key like every item, so all members of the vault
// see them; an item names its folder in data.folder. Folders can be nested
// (a customer, then its sites).

function isFolder(it) { return !!(it && it.data && it.data.type === "folder"); }

function vaultFolders(vaultID) {
  return [...S.items.values()].filter((it) => isFolder(it) && !it.deleted_at && it.vault_id === vaultID);
}

// folderOf is the folder item an item is in (null: the top of its vault).
function folderOf(it) {
  const f = it && it.data && it.data.folder ? S.items.get(it.data.folder) : null;
  return f && isFolder(f) && !f.deleted_at && f.vault_id === it.vault_id ? f : null;
}

// folderPath is "Customer / Site" for a folder item (or "").
function folderPath(f) {
  const names = [];
  for (let i = 0; f && i < 20; i++) {
    names.unshift(f.data.name || "?");
    f = folderOf({ vault_id: f.vault_id, data: { folder: f.data.parent } });
  }
  return names.join(" / ");
}

function byName(a, b) { return itemName(a).localeCompare(itemName(b), undefined, { sensitivity: "base" }); }

// FOLDER_KINDS are what a folder stands for; each shows its own icon.
const FOLDER_KINDS = [
  { key: "folder", label: "Folder", icon: "folder" },
  { key: "customer", label: "Customer", icon: "briefcase" },
  { key: "site", label: "Site", icon: "pin" },
  { key: "branch", label: "Branch office", icon: "building" },
  { key: "department", label: "Department", icon: "users" },
  { key: "datacenter", label: "Data center", icon: "server" },
  { key: "network", label: "Network", icon: "network" },
  { key: "project", label: "Project", icon: "flag" },
];

function folderKind(f) { return FOLDER_KINDS.find((k) => k.key === (f && f.data && f.data.kind)) || FOLDER_KINDS[0]; }

// folderDialog asks for the name and the kind of a folder.
function folderDialog(title, name, kind) {
  return new Promise((resolve) => {
    const inp = el("input", { value: name, maxlength: 100, required: true });
    const kinds = el("div", { class: "fkinds", role: "radiogroup", "aria-label": t("Kind") }, ...FOLDER_KINDS.map((k) =>
      el("label", { class: "fkind" }, el("input", { type: "radio", name: "fkind", value: k.key, checked: k.key === kind }), icon(k.icon), el("span", { text: t(k.label) }))));
    const f = el("form", { method: "dialog", class: "stack" }, el("h2", { text: title }), el("label", null, t("Name"), inp),
      el("div", null, el("label", { text: t("Kind") }), kinds),
      el("div", { class: "row end" }, button(t("Cancel"), { class: "ghost", onclick: () => { d.close(); } }), button(t("Save"), { type: "submit", class: "primary" })));
    const d = el("dialog", { class: "dlg" }, f);
    let result = null;
    f.addEventListener("submit", () => { result = { name: inp.value.trim(), kind: (kinds.querySelector("input:checked") || {}).value || "folder" }; });
    d.addEventListener("close", () => { d.remove(); resolve(result && result.name ? result : null); });
    document.body.append(d);
    d.showModal();
    inp.focus();
  });
}

async function newVaultFolder(vaultID, parent) {
  // below a customer the usual next level is a site
  const up = parent ? S.items.get(parent) : null;
  const r = await folderDialog(t("New folder"), "", up && folderKind(up).key === "customer" ? "site" : "folder");
  if (!r) return;
  try {
    const f = await saveItem({ vault_id: vaultID }, { type: "folder", name: r.name, kind: r.kind, parent: parent || "" });
    S.closed.delete(f.id);
    S.cwd = f.id;
    render();
  } catch (e) { toast(e.message, true); }
}

async function editVaultFolder(f) {
  const r = await folderDialog(t("Edit the folder"), f.data.name, folderKind(f).key);
  if (!r || (r.name === f.data.name && r.kind === folderKind(f).key)) return;
  try { await saveItem(f, Object.assign({}, f.data, { name: r.name, kind: r.kind })); render(); } catch (e) { toast(e.message, true); }
}

// deleteVaultFolder moves what the folder holds one level up and puts the
// folder into the trash.
async function deleteVaultFolder(f) {
  const inside = [...S.items.values()].filter((it) => !it.deleted_at && it.vault_id === f.vault_id && it.data &&
    (isFolder(it) ? it.data.parent === f.id : it.data.folder === f.id));
  const q = inside.length
    ? t("Delete the folder %s? The %d items and folders in it move to the folder above.", f.data.name, inside.length)
    : t("Delete the folder %s?", f.data.name);
  if (!(await confirmBox(q, t("Delete"), true))) return;
  try {
    const up = f.data.parent || "";
    for (const it of inside) {
      await saveItem(it, Object.assign({}, it.data, isFolder(it) ? { parent: up } : { folder: up }));
    }
    await itemOp(f.id, "trash");
    if (S.cwd === f.id) S.cwd = up;
    render();
  } catch (e) { toast(e.message, true); }
}

// migrateFolders moves the folders of earlier versions (one list per user)
// into the vaults: a folder per vault with the same name, and the items
// into it. Items of vaults this user may not change stay where they are.
let migrating = false;
async function migrateFolders() {
  if (migrating || !S.folders.size) return;
  migrating = true;
  try {
    for (const [fid, f] of [...S.folders.entries()]) {
      const items = [...S.items.values()].filter((it) => !it.deleted_at && it.data && !isFolder(it) && it.data.folder === fid);
      const vaults = new Set(items.map((it) => it.vault_id).filter((v) => canEditVault(v)));
      if (!items.length) vaults.add(personalVault());
      let left = items.length;
      for (const v of vaults) {
        const nf = await saveItem({ vault_id: v }, { type: "folder", name: f.name, parent: "" });
        for (const it of items.filter((x) => x.vault_id === v)) {
          await saveItem(it, Object.assign({}, it.data, { folder: nf.id }));
          left--;
        }
      }
      if (!left) {
        const res = await api("DELETE", "/api/folders/" + fid);
        S.revision = Math.max(S.revision, res.revision);
        S.folders.delete(fid);
      }
    }
  } catch (e) {
    toast(e.message, true);
  } finally {
    migrating = false;
    render();
  }
}

// ---- rendering

function itemName(it) { return it.data ? it.data.name || t("(no name)") : t("(cannot be decrypted)"); }

// searching reports whether the list shows search or kind results (a flat
// list) instead of the vault's folder tree.
function searching() { return !!(S.q.trim() || S.kind); }

function visibleItems() {
  const q = S.q.trim().toLowerCase();
  const everywhere = q && S.qAll;
  const out = [];
  for (const it of S.items.values()) {
    if (isFolder(it)) continue;
    const d = it.data;
    const trashed = !!it.deleted_at;
    if (S.view === "trash" ? !trashed : trashed) continue;
    if (S.view === "vault" && !everywhere && it.vault_id !== S.vault) continue;
    if (d) {
      if (S.kind === "fav" ? !d.favorite : S.kind && kindOf(d) !== S.kind) continue;
      if (q) {
        const hay = [d.name, d.login && d.login.username, ...(d.login && d.login.urls || []), d.connect && d.connect.host, d.notes].join("\n").toLowerCase();
        if (!hay.includes(q)) continue;
      }
    }
    out.push(it);
  }
  return out.sort(byName);
}

function render() {
  if (!S.keys) return;
  const grid = el("div", { class: "vgrid", dataset: { pane: S.selected ? "detail" : "list" } },
    renderFilters(), renderList(), el("section", { class: "vdetail panel", id: "vdetail" }, renderDetail()));
  root.replaceChildren(grid);
  syncEditor();
}

// The editor (and the choice of a new item's kind) opens in a dialog over
// the vault; it is built again only when a new edit starts, so a render
// meanwhile keeps what was typed. Closing it ends the edit.
let editDlg = null;
function syncEditor() {
  if (!S.editing) {
    if (editDlg) { const d = editDlg; editDlg = null; d.close(); }
    return;
  }
  if (!editDlg) {
    const d = el("dialog", { class: "dlg wide veditdlg" });
    d.addEventListener("close", () => {
      d.remove();
      if (editDlg !== d) return;
      editDlg = null;
      if (S.editing) { S.editing = null; render(); }
    });
    document.body.append(d);
    d.showModal();
    editDlg = d;
  }
  if (editDlg.pzFor !== S.editing) {
    editDlg.pzFor = S.editing;
    editDlg.replaceChildren(S.editing.choose ? renderChooser() : renderEditor());
  }
}

function count(view, vaultID) {
  let n = 0;
  for (const it of S.items.values()) {
    if (isFolder(it)) continue;
    if (view === "trash") { if (it.deleted_at) n++; continue; }
    if (it.deleted_at) continue;
    if (view === "vault") { if (it.vault_id === vaultID) n++; continue; }
    n++;
  }
  return n;
}

function renderFilters() {
  const link = (view, label, ic, vaultID) => {
    const on = S.view === view && (view !== "vault" || S.vault === vaultID);
    return el("a", { href: "#", class: on ? "on" : "", onclick: (ev) => {
      ev.preventDefault(); S.view = view; if (vaultID) S.vault = vaultID; S.kind = ""; S.cwd = ""; S.selected = ""; S.editing = null; render();
    } }, icon(ic), el("span", { text: label }), el("small", { text: String(count(view, vaultID)) }));
  };
  const nav = el("nav", { class: "vfilters", "aria-label": t("Filters") });
  // the personal vault, then the team vaults by name (a new one appears
  // among them)
  const vaultLink = (id, v) => {
    const a = link("vault", vaultLabel(id), v.kind === "personal" ? "lock" : "users", id);
    if (v.needsRotation && v.rights === "manage") a.append(el("span", { class: "dot warn", title: t("Needs a new key") }));
    return a;
  };
  const all = [...S.vaults.entries()];
  for (const [id, v] of all.filter(([, x]) => x.kind === "personal")) nav.append(vaultLink(id, v));
  const canCreate = !S.acct.shared_admins_only || S.acct.role === "admin";
  const teams = all.filter(([, x]) => x.kind !== "personal").sort((a, b) => vaultLabel(a[0]).localeCompare(vaultLabel(b[0]), undefined, { sensitivity: "base" }));
  if (teams.length || canCreate) {
    nav.append(el("span", { class: "navlabel" }, t("Team vaults"), canCreate
      ? el("button", { type: "button", class: "iconbtn sm", title: t("New shared vault"), "aria-label": t("New shared vault"), onclick: createVault }, icon("plus")) : null));
  }
  for (const [id, v] of teams) nav.append(vaultLink(id, v));
  if (!teams.length && canCreate) nav.append(el("a", { href: "#", class: "muted", onclick: (ev) => { ev.preventDefault(); createVault(); } }, icon("plus"), el("span", { text: t("New shared vault") })));
  nav.append(el("span", { class: "navlabel brk" }), link("trash", t("Trash"), "trash"),
    el("span", { class: "navlabel", text: t("Tools") }),
    el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); openHealth(); } }, icon("shield"), el("span", { text: t("Password health") })),
    S.acct.no_sends ? null : el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); openSends(""); } }, icon("link"), el("span", { text: t("Secret links") })),
    el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); openImport(); } }, icon("upload"), el("span", { text: t("Import") })),
    S.acct.no_export ? null : el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); openExport(); } }, icon("download"), el("span", { text: t("Export") })));
  return nav;
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
  const search = el("input", { type: "search", value: S.q, placeholder: S.qAll ? t("Search all vaults") : t("Search the vault"), "aria-label": t("Search the vault"), class: "vsearch" });
  const refresh = () => {
    const list = document.getElementById("vlist-items");
    if (list) list.replaceChildren(...listRows());
  };
  search.addEventListener("input", () => { S.q = search.value; refresh(); });
  const scope = el("button", { type: "button", class: "iconbtn sm" + (S.qAll ? " on" : ""), "aria-pressed": String(!!S.qAll),
    title: t("Search all vaults"), "aria-label": t("Search all vaults"), onclick: () => {
      S.qAll = !S.qAll;
      scope.classList.toggle("on", S.qAll);
      scope.setAttribute("aria-pressed", String(S.qAll));
      search.placeholder = S.qAll ? t("Search all vaults") : t("Search the vault");
      refresh();
    } }, icon("layers"));
  const head = el("div", { class: "vlist-head" }, el("div", { class: "searchfield" }, icon("search"), search, S.view === "vault" ? scope : null));
  const editable = S.view === "vault" && canEditVault(S.vault);
  if (editable) head.append(button(t("New item"), { class: "primary", icon: "plus", onclick: () => startEdit(null) }));
  const title = S.view === "trash" ? t("Trash") : S.view === "vault" ? vaultLabel(S.vault) : t("All items");
  const tools = el("div", { class: "vlist-title" }, el("h2", { text: title }));
  const actions = el("span", { class: "row" });
  if (editable) actions.append(button("", { class: "ghost sm", icon: "folderplus", aria: t("New folder"), title: t("New folder"), onclick: () => newVaultFolder(S.vault, S.cwd) }));
  if (S.view === "vault" && (S.vaults.get(S.vault) || {}).kind === "shared") {
    const v = S.vaults.get(S.vault);
    actions.append(el("small", { class: "muted", text: rightsText(v.rights) }),
      button("", { class: "ghost sm", icon: "settings", aria: t("Members and settings"), title: t("Members and settings"), onclick: () => openVaultDialog(S.vault) }));
  }
  tools.append(actions);
  if (S.view === "trash") tools.append(el("small", { class: "muted", text: t("Items in the trash are deleted after %d days.", S.acct.trash_days || 30) }));
  const banner = S.view === "vault" ? rotateBanner(S.vault) : null;
  return el("section", { class: "vlist panel" }, head, tools, banner, S.view === "trash" ? null : kindBar(), el("ul", { class: "vitems", id: "vlist-items" }, ...listRows()));
}

// KIND_ICONS are the list icons of the kinds of items.
const KIND_ICONS = { web: "globe", cred: "idcard", rdp: "monitor", ssh: "terminal", winscp: "folderopen", winbox: "router", vnc: "screen", telnet: "terminal", sshkey: "key", note: "note", card: "card", identity: "user" };

// kindOf is the KINDS key of an item: devices by the program that opens
// them, logins by whether they belong to a website.
function kindOf(d) {
  if (!d) return "";
  if (d.type === "login") {
    if (d.connect && d.connect.tool && KIND_ICONS[d.connect.tool]) return d.connect.tool;
    return (d.login && (d.login.urls || []).some(Boolean)) ? "web" : "cred";
  }
  return d.type || "";
}

// kindBar shows what the vault holds: one chip per kind with its count; a
// chip shows only that kind.
function kindBar() {
  const counts = new Map();
  let all = 0, fav = 0;
  for (const it of S.items.values()) {
    if (it.deleted_at || !it.data || isFolder(it)) continue;
    if (S.view === "vault" && it.vault_id !== S.vault) continue;
    all++;
    if (it.data.favorite) fav++;
    const k = kindOf(it.data);
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const PLURAL = { web: t("Websites"), cred: t("Credentials"), rdp: "RDP", ssh: "SSH", winscp: "WinSCP", winbox: "WinBox", vnc: "VNC", telnet: "Telnet", sshkey: t("SSH keys"), note: t("Secure notes"), card: t("Cards"), identity: t("Identities") };
  const chip = (key, label, ic, n) => el("button", { type: "button", class: "kchip" + (S.kind === key ? " on" : ""), "aria-pressed": String(S.kind === key),
    onclick: () => { S.kind = S.kind === key && key ? "" : key; S.selected = ""; S.editing = null; render(); } },
    ic ? icon(ic) : null, el("span", { text: label }), el("small", { text: String(n) }));
  const bar = el("div", { class: "kindbar", role: "toolbar", "aria-label": t("Kinds of items") }, chip("", t("All"), "", all));
  if (fav) bar.append(chip("fav", t("Favorites"), "star", fav));
  for (const k of KINDS.map((x) => x.key)) if (counts.get(k)) bar.append(chip(k, PLURAL[k], KIND_ICONS[k], counts.get(k)));
  return bar;
}

function itemRow(it, depth, extra) {
  const d = it.data || {};
  const sub = [subtitle(d), extra].filter(Boolean).join(" · ");
  const a = el("a", { href: "#", class: it.id === S.selected ? "on" : "", onclick: (ev) => { ev.preventDefault(); S.selected = it.id; S.cwd = d.folder || ""; S.editing = null; render(); } },
    avatar(it, ""),
    el("span", { class: "vname" }, el("b", { text: itemName(it) }), el("small", { text: sub })),
    d.favorite ? el("span", { class: "vfav", title: t("Favorite") }, icon("star")) : null);
  if (depth) a.style.setProperty("--depth", String(depth));
  return el("li", null, a);
}

function listRows() {
  const items = visibleItems();
  // search, a kind or the trash: a flat list that says where each item is
  if (S.view !== "vault" || searching()) {
    if (!items.length) return [el("li", { class: "empty" }, S.q ? t("Nothing found.") : S.view === "trash" ? t("The trash is empty.") : t("Nothing found."))];
    return items.map((it) => {
      const f = folderOf(it);
      const where = [S.qAll || S.view !== "vault" ? vaultLabel(it.vault_id) : "", f ? folderPath(f) : ""].filter(Boolean).join(" / ");
      return itemRow(it, 0, where);
    });
  }
  // the vault as a tree: folders (closed ones keep their contents hidden),
  // then the items at each level
  const folders = vaultFolders(S.vault);
  if (!items.length && !folders.length) return [el("li", { class: "empty" }, t("No items yet. Add your first login with New item."))];
  const ids = new Set(folders.map((f) => f.id));
  const kids = new Map(), inside = new Map();
  for (const f of folders) {
    const p = ids.has(f.data.parent) ? f.data.parent : "";
    if (!kids.has(p)) kids.set(p, []);
    kids.get(p).push(f);
  }
  for (const it of items) {
    const p = it.data && ids.has(it.data.folder) ? it.data.folder : "";
    if (!inside.has(p)) inside.set(p, []);
    inside.get(p).push(it);
  }
  const total = (fid, seen) => {
    if (seen.has(fid)) return 0;
    seen.add(fid);
    return (inside.get(fid) || []).length + (kids.get(fid) || []).reduce((n, f) => n + total(f.id, seen), 0);
  };
  const editable = canEditVault(S.vault);
  const out = [];
  const walk = (parent, depth, seen) => {
    for (const f of (kids.get(parent) || []).sort(byName)) {
      if (seen.has(f.id)) continue;
      seen.add(f.id);
      const closed = S.closed.has(f.id);
      const btn = el("button", { type: "button", class: "vfolder" + (S.cwd === f.id ? " on" : ""), "aria-expanded": String(!closed), onclick: () => {
        if (S.cwd === f.id || closed) { if (closed) S.closed.delete(f.id); else S.closed.add(f.id); }
        S.cwd = f.id;
        render();
      } }, icon(closed ? "chevr" : "chevd"), el("span", { class: "vicon", title: t(folderKind(f).label) }, icon(folderKind(f).icon)), el("span", { class: "vfname", text: f.data.name || "?" }), el("small", { text: String(total(f.id, new Set())) }));
      if (depth) btn.style.setProperty("--depth", String(depth));
      const acts = editable ? el("span", { class: "vfacts" },
        button("", { class: "ghost sm", icon: "folderplus", aria: t("New folder in %s", f.data.name), title: t("New folder in %s", f.data.name), onclick: () => newVaultFolder(S.vault, f.id) }),
        button("", { class: "ghost sm", icon: "edit", aria: t("Edit the folder"), title: t("Edit the folder"), onclick: () => editVaultFolder(f) }),
        button("", { class: "ghost sm", icon: "trash", aria: t("Delete the folder"), title: t("Delete the folder"), onclick: () => deleteVaultFolder(f) })) : null;
      out.push(el("li", { class: "vgroup" }, btn, acts));
      if (!closed) walk(f.id, depth + 1, seen);
    }
    for (const it of inside.get(parent) || []) out.push(itemRow(it, depth, ""));
  };
  walk("", 0, new Set());
  return out;
}

// subtitle is the second line of an item in the list.
function subtitle(d) {
  if (d.type === "login") return (d.login && d.login.username) || (d.connect && d.connect.host) || hostOf((d.login && d.login.urls || [])[0]);
  if (d.type === "card" && d.card) return [d.card.brand, d.card.number ? "•••• " + d.card.number.replace(/\D/g, "").slice(-4) : ""].filter(Boolean).join(" ");
  if (d.type === "identity" && d.identity) return [d.identity.first, d.identity.last].filter(Boolean).join(" ") || d.identity.email || "";
  if (d.type === "sshkey" && d.ssh) return (d.ssh.fingerprint || "").slice(0, 24);
  return t(TYPES[d.type] ? TYPES[d.type].label : "Item");
}

function avatar(it, cls) {
  const d = it.data || {};
  const k = kindOf(d);
  return el("span", { class: "vicon" + (cls ? " " + cls : ""), dataset: { type: d.type || "", kind: k } }, icon(KIND_ICONS[k] || "key"));
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

// ---- detail

let noShow = false; // "use" rights: secrets may be copied or filled, not shown

function renderDetail() {
  const it = S.items.get(S.selected);
  noShow = !!it && useOnly(it);
  curItem = it || null;
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
    if (l.totp) rows.push(totpField(l.totp));
  }
  if (d.type === "card" && d.card) {
    const c = d.card;
    if (c.holder) rows.push(field(t("Cardholder"), c.holder, { copy: true }));
    if (c.number) rows.push(field(t("Card number"), c.number, { copy: true, secret: true, mono: true }));
    if (c.expMonth || c.expYear) rows.push(field(t("Valid until"), (c.expMonth || "??") + "/" + (c.expYear || "????"), { copy: true }));
    if (c.code) rows.push(field(t("Security code"), c.code, { copy: true, secret: true, mono: true }));
  }
  if (d.type === "identity" && d.identity) {
    const p = d.identity;
    const nameLine = [p.title, p.first, p.middle, p.last].filter(Boolean).join(" ");
    if (nameLine) rows.push(field(t("Name"), nameLine, { copy: true }));
    for (const [k, label] of [["company", t("Company")], ["email", t("E-mail address")], ["phone", t("Phone")], ["username", t("User name")]]) if (p[k]) rows.push(field(label, p[k], { copy: true }));
    const addr = [p.address1, p.address2, [p.postal, p.city].filter(Boolean).join(" "), p.state, p.country].filter(Boolean).join("\n");
    if (addr) rows.push(el("div", { class: "vfield" }, el("label", { text: t("Address") }), el("pre", { class: "vnotes", text: addr })));
  }
  if (d.type === "sshkey" && d.ssh) {
    const k = d.ssh;
    if (k.publicKey) rows.push(field(t("Public key"), k.publicKey, { copy: true, mono: true }));
    if (k.fingerprint) rows.push(field(t("Fingerprint"), k.fingerprint, { copy: true, mono: true }));
    if (k.privateKey) rows.push(field(t("Private key"), k.privateKey, { copy: true, secret: true, mono: true }));
    if (k.passphrase) rows.push(field(t("Passphrase of the key"), k.passphrase, { copy: true, secret: true }));
  }
  for (const f of d.fields || []) rows.push(field(f.name || t("Field"), f.value, { copy: true, secret: f.hidden }));
  if (d.connect && d.connect.tool) {
    const c = d.connect;
    const tool = { rdp: "RDP", ssh: "SSH", winbox: "WinBox" }[c.tool] || c.tool;
    rows.push(field(t("Remote connection"), tool + " · " + (c.user ? c.user + "@" : "") + c.host + (c.port ? ":" + c.port : ""), { copy: false }));
  }
  if (d.notes) rows.push(el("div", { class: "vfield" }, el("label", { text: t("Notes") }), noShow ? el("p", { class: "small muted", text: t("Hidden: you may use this item, not read it.") }) : el("pre", { class: "vnotes", text: d.notes })));
  const folder = folderOf(it);
  const meta = el("p", { class: "small muted" },
    t("Changed %s", fmtDate(it.updated_at)), " · ", t("Created %s", fmtDate(it.created_at)),
    d.passwordChanged ? " · " + t("Password changed %s", fmtDate(d.passwordChanged)) : "");
  const hist = !noShow && (d.history || []).length ? el("details", { class: "vhist" }, el("summary", { text: t("Password history (%d)", d.history.length) }),
    el("ul", null, ...d.history.slice().reverse().map((h) => el("li", null, el("code", { class: "mono", text: "••••••••" }),
      el("small", { class: "muted", text: " " + fmtDate(h.changed) + " " }),
      button("", { class: "ghost sm", icon: "eye", aria: t("Show"), onclick: (ev) => { const c = ev.currentTarget.parentElement.querySelector("code"); c.textContent = c.textContent === "••••••••" ? h.password : "••••••••"; } }),
      button("", { class: "ghost sm", icon: "copy", aria: t("Copy"), onclick: () => copy(h.password, true) }))))) : null;
  return el("div", { class: "vview" }, back,
    el("div", { class: "vview-head" },
      avatar(it, "lg"),
      el("div", null, el("h2", { text: itemName(it) }), el("small", { class: "muted" }, t((KINDS.find((k) => k.key === kindOf(d)) || TYPES[d.type] || { label: "Item" }).label), folder ? " · " + folderPath(folder) : "",
        (S.vaults.get(it.vault_id) || {}).kind === "shared" ? " · " + vaultLabel(it.vault_id) : "")),
      it.deleted_at || !canEditItem(it) ? null : el("button", { type: "button", class: "iconbtn" + (d.favorite ? " fav-on" : ""), title: t("Favorite"), "aria-pressed": d.favorite ? "true" : "false", onclick: () => toggleFav(it) }, icon("star"))),
    it.deleted_at ? el("div", { class: "flash warn" }, icon("trash"), el("span", { text: t("In the trash since %s.", fmtDate(it.deleted_at)) })) : null,
    ...rows, noShow ? null : attachmentsBlock(it), hist, accessLog(it), meta, itemActions(it));
}

function itemActions(it) {
  const send = !it.deleted_at && it.data && !useOnly(it) && !S.acct.no_sends
    ? button(t("Send a copy"), { class: "ghost", icon: "link", onclick: () => openSends(itemText(it.data)) }) : null;
  if (!canEditItem(it)) return send ? el("div", { class: "row vactions" }, send) : null;
  if (it.deleted_at) {
    return el("div", { class: "row vactions" },
      button(t("Restore"), { class: "primary", icon: "restore", onclick: () => act(it, "restore", t("Restored.")) }),
      button(t("Delete forever"), { class: "danger", icon: "trash", onclick: async () => {
        if (await confirmBox(t("Delete %s for good? This cannot be undone.", itemName(it)), t("Delete forever"), true)) act(it, "purge", t("Deleted."));
      } }));
  }
  return el("div", { class: "row vactions" },
    it.data ? button(t("Edit"), { class: "primary", icon: "edit", onclick: () => startEdit(it) }) : null,
    send,
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
  const item = curItem;
  if (opt.secret && !noShow) {
    tools.append(el("button", { type: "button", class: "iconbtn sm", title: t("Show"), "aria-label": t("Show"), onclick: (ev) => {
      const shown = v.textContent !== "••••••••••";
      if (!shown) reportUse(item, "show");
      v.textContent = shown ? "••••••••••" : value;
      ev.currentTarget.replaceChildren(icon(shown ? "eye" : "eyeoff"));
    } }, icon("eye")));
  }
  if (opt.copy) tools.append(el("button", { type: "button", class: "iconbtn sm", title: t("Copy"), "aria-label": t("Copy") + " " + label, onclick: () => { if (opt.secret) reportUse(item, "copy"); copy(value, !!opt.secret); } }, icon("copy")));
  return el("div", { class: "vfield" }, el("label", { text: label }), el("div", { class: "vline" }, v, tools));
}

function urlField(u) {
  const href = safeHref(u);
  const tools = el("span", { class: "vtools" });
  if (href) tools.append(el("a", { class: "iconbtn sm", href, target: "_blank", rel: "noopener noreferrer", title: t("Open"), "aria-label": t("Open") }, icon("external")));
  tools.append(el("button", { type: "button", class: "iconbtn sm", title: t("Copy"), "aria-label": t("Copy"), onclick: () => copy(u, false) }, icon("copy")));
  return el("div", { class: "vfield" }, el("label", { text: t("Website") }), el("div", { class: "vline" }, el("span", { class: "vvalue ellipsis", text: u }), tools));
}

// totpField shows the current one-time code; one timer refreshes all shown codes.
let totpTimer = 0;
function totpField(secret) {
  let cfg = null;
  try { cfg = totpParse(secret); } catch (e) { /* shown as invalid */ }
  const v = el("code", { class: "vvalue mono totp", text: cfg ? "······" : t("Invalid authenticator key") });
  const left = el("small", { class: "muted" });
  const box = el("div", { class: "vfield" }, el("label", { text: t("One-time code") }), el("div", { class: "vline" }, v, left,
    el("span", { class: "vtools" }, el("button", { type: "button", class: "iconbtn sm", title: t("Copy"), "aria-label": t("Copy"), onclick: async () => { if (cfg) copy((await totpCode(cfg)).value, false); } }, icon("copy")))));
  if (cfg) {
    box.pzTotp = async () => {
      const c = await totpCode(cfg);
      v.textContent = c.value.length === 6 ? c.value.slice(0, 3) + " " + c.value.slice(3) : c.value;
      left.textContent = c.remaining + " s";
      v.classList.toggle("ending", c.remaining <= 5);
    };
    box.pzTotp();
    if (!totpTimer) {
      totpTimer = setInterval(() => {
        const shown = [...document.querySelectorAll(".vfield")].filter((f) => f.pzTotp);
        if (!shown.length) { clearInterval(totpTimer); totpTimer = 0; return; }
        for (const f of shown) f.pzTotp();
      }, 1000);
    }
  }
  return box;
}

// ---- editor

// KINDS are the choices for a new item: the type and, for devices, the
// program that opens the connection.
const KINDS = [
  { key: "web", label: "Website login", hint: "User name and password of a website", icon: "globe", type: "login" },
  { key: "cred", label: "Credentials", hint: "User name and password without a website", icon: "idcard", type: "login" },
  { key: "rdp", label: "Remote Desktop (RDP)", hint: "Windows computers and servers", icon: "monitor", type: "login", tool: "rdp" },
  { key: "ssh", label: "SSH with a password", hint: "Linux servers, switches and routers", icon: "terminal", type: "login", tool: "ssh" },
  { key: "sshkey", label: "SSH key", hint: "A key pair for SSH sign-in", icon: "key", type: "sshkey", tool: "ssh" },
  { key: "winbox", label: "WinBox (MikroTik)", hint: "MikroTik routers and switches", icon: "router", type: "login", tool: "winbox" },
  { key: "winscp", label: "WinSCP (SFTP)", hint: "Files on servers over SFTP", icon: "folderopen", type: "login", tool: "winscp" },
  { key: "vnc", label: "VNC", hint: "Screens of computers with a VNC server", icon: "screen", type: "login", tool: "vnc" },
  { key: "telnet", label: "Telnet", hint: "Older switches and devices", icon: "terminal", type: "login", tool: "telnet" },
  { key: "note", label: "Secure note", hint: "Encrypted text", icon: "note", type: "note" },
  { key: "card", label: "Card", hint: "Payment card", icon: "card", type: "card" },
  { key: "identity", label: "Identity", hint: "Name, address and contact details", icon: "user", type: "identity" },
];

// startEdit opens the editor; a new item first asks what kind it is
// (kind: one of KINDS), except in the list of one type.
function startEdit(it, kind) {
  if (!it && !kind) {
    const k = KINDS.find((x) => x.key === S.kind);
    if (!k) { S.editing = { choose: true }; render(); return; }
    kind = k;
  }
  const base = it && it.data ? JSON.parse(JSON.stringify(it.data)) : { type: kind.type, name: "", login: { username: "", password: "", urls: [""] }, notes: "", fields: [], favorite: false, folder: !it && S.view === "vault" && S.cwd && (S.items.get(S.cwd) || {}).vault_id === S.vault ? S.cwd : "" };
  if (!it && kind.tool) base.connect = { tool: kind.tool, host: "", port: 0 };
  if (!base.login) base.login = { username: "", password: "", urls: [""] };
  if (!base.login.urls || !base.login.urls.length) base.login.urls = [""];
  S.editing = { item: it, data: base };
  render();
  const first = document.querySelector(base.connect && base.connect.tool && !it ? ".veditdlg input[name=connect_host]" : ".veditdlg input[name=name]");
  if (first) setTimeout(() => first.focus(), 0);
}

function renderChooser() {
  return el("div", { class: "stack" },
    el("h2", { text: t("New item") }),
    el("p", { class: "muted", text: t("What do you want to save?") }),
    el("div", { class: "kinds" }, ...KINDS.map((k) => el("button", { type: "button", class: "kind", onclick: () => startEdit(null, k) },
      icon(k.icon), el("span", null, el("b", { text: t(k.label) }), el("small", { text: t(k.hint) }))))),
    el("div", { class: "row vactions" }, button(t("Cancel"), { class: "ghost", onclick: () => { S.editing = null; render(); } })));
}

function renderEditor() {
  const e = S.editing;
  const d = e.data;
  const isNew = !e.item;
  const type = el("select", { name: "type", onchange: () => { d.type = type.value; showParts(); } },
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
  const totp = el("input", { name: "totp", value: d.login.totp || "", autocomplete: "off", spellcheck: "false", class: "mono", placeholder: "otpauth://totp/… " + t("or the key") });
  // A QR code (a picture, a screenshot or a pasted image) is read here in
  // the browser.
  const takeQR = async (blob) => {
    try {
      const keys = authenticatorKeys(await readQR(blob));
      if (!keys.length) return toast(t("No authenticator QR code was found in the picture."), true);
      totp.value = keys[0];
      toast(keys.length > 1 ? t("The picture has %d authenticator codes; the first one was taken.", keys.length) : t("The authenticator key was read."));
    } catch (e) { toast(t("The picture could not be read."), true); }
  };
  const qrFile = el("input", { type: "file", accept: "image/*", hidden: true, onchange: () => { if (qrFile.files[0]) takeQR(qrFile.files[0]); qrFile.value = ""; } });
  const qrBtn = el("button", { type: "button", class: "iconbtn", title: t("Read a QR code"), "aria-label": t("Read a QR code"), onclick: () => qrFile.click() }, icon("qr"));
  totp.addEventListener("paste", (ev) => {
    const f = [...(ev.clipboardData && ev.clipboardData.files || [])].find((x) => x.type.startsWith("image/"));
    if (f) { ev.preventDefault(); takeQR(f); }
  });
  const loginPart = el("div", { class: "stack", hidden: d.type !== "login" },
    el("label", null, t("User name"), user),
    el("label", null, t("Password"), el("span", { class: "pwfield" }, pass, showBtn, genBtn)),
    el("label", null, t("Authenticator key (TOTP)"), el("span", { class: "pwfield" }, totp, qrBtn, qrFile),
      el("small", { text: t("The secret key or otpauth:// address a website shows when you set up two-factor sign-in, or its QR code: choose a picture or a screenshot, or paste it here. PassZit then shows the codes.") })),
    el("div", null, el("label", { text: t("Websites") }), urls,
      button(t("Add a website"), { class: "ghost sm", icon: "plus", onclick: () => addURL("") })));
  // other item types
  const inp = (name, value, attrs) => el("input", Object.assign({ name, value: value || "", autocomplete: "off", spellcheck: "false" }, attrs || {}));
  const c = d.card || {};
  const cHolder = inp("holder", c.holder), cNumber = inp("number", c.number, { inputmode: "numeric", class: "mono" }), cCode = inp("code", c.code, { class: "mono", type: "password" });
  const cMonth = inp("expMonth", c.expMonth, { inputmode: "numeric", maxlength: 2, placeholder: "MM" }), cYear = inp("expYear", c.expYear, { inputmode: "numeric", maxlength: 4, placeholder: "YYYY" });
  const cardPart = el("div", { class: "stack" }, el("label", null, t("Cardholder"), cHolder), el("label", null, t("Card number"), cNumber),
    el("div", { class: "grid2" }, el("label", null, t("Valid until"), el("span", { class: "row" }, cMonth, "/", cYear)), el("label", null, t("Security code"), cCode)));
  const p = d.identity || {};
  const idFields = {};
  const idInput = (k, label) => { idFields[k] = inp(k, p[k]); return el("label", null, label, idFields[k]); };
  const identityPart = el("div", { class: "stack" },
    el("div", { class: "grid2" }, idInput("first", t("First name")), idInput("last", t("Last name"))),
    el("div", { class: "grid2" }, idInput("email", t("E-mail address")), idInput("phone", t("Phone"))),
    el("div", { class: "grid2" }, idInput("company", t("Company")), idInput("username", t("User name"))),
    idInput("address1", t("Address")), idInput("address2", t("Address (line 2)")),
    el("div", { class: "grid2" }, idInput("postal", t("Postal code")), idInput("city", t("City"))),
    el("div", { class: "grid2" }, idInput("state", t("State or region")), idInput("country", t("Country"))));
  const k = d.ssh || {};
  const kPriv = el("textarea", { name: "privateKey", rows: 5, class: "mono", spellcheck: "false" }, k.privateKey || "");
  const kPub = el("textarea", { name: "publicKey", rows: 2, class: "mono", spellcheck: "false" }, k.publicKey || "");
  const kPass = inp("passphrase", k.passphrase, { type: "password" });
  const kFp = el("small", { class: "muted mono", text: k.fingerprint || "" });
  kPub.addEventListener("input", async () => { kFp.textContent = await sshFingerprint(kPub.value); });
  const sshPart = el("div", { class: "stack" },
    button(t("Generate an Ed25519 key"), { class: "secondary sm", icon: "key", onclick: async () => {
      if ((kPriv.value || kPub.value) && !(await confirmBox(t("Replace the key in this item with a new one?"), t("Generate"), true))) return;
      const g = await sshGenerate(name.value.trim() || "passzit");
      kPriv.value = g.privateKey; kPub.value = g.publicKey; kFp.textContent = g.fingerprint;
    } }),
    el("label", null, t("Private key"), kPriv), el("label", null, t("Public key"), kPub, kFp), el("label", null, t("Passphrase of the key"), kPass));
  // a remote connection the extension opens with passzit-helper
  const cn = d.connect || {};
  const cTool = el("select", { name: "connect_tool", "aria-label": t("Remote connection") },
    el("option", { value: "" }, t("None")), ...[["rdp", "RDP (Remote Desktop)"], ["ssh", "SSH"], ["winscp", "WinSCP (SFTP)"], ["winbox", "WinBox (MikroTik)"], ["vnc", "VNC"], ["telnet", "Telnet"]].map(([v, l]) => el("option", { value: v, selected: cn.tool === v }, l)));
  const cHost = el("input", { name: "connect_host", value: cn.host || "", placeholder: "10.0.0.5", autocomplete: "off", spellcheck: "false", class: "mono" });
  const cPort = el("input", { name: "connect_port", type: "number", min: 1, max: 65535, value: cn.port || "", placeholder: t("default"), class: "narrow" });
  const cUser = el("input", { name: "connect_user", value: cn.user || "", autocomplete: "off", spellcheck: "false" });
  const cUserRow = el("label", null, t("User name"), cUser);
  const connectPart = el("fieldset", { class: "box" }, el("legend", { text: t("Remote connection") }),
    el("div", { class: "grid2" }, el("label", null, t("Open with"), cTool), el("label", null, t("Port"), cPort)),
    el("label", null, t("Address"), cHost), cUserRow,
    el("small", { class: "muted", text: t("The browser extension opens it with the PassZit helper on this computer. A monitoring page that names the device (WatchZit) shows its logins too.") }));
  // A device login may take its address as the name.
  if (cn.tool) { name.required = false; name.placeholder = t("Empty: the address"); }
  const parts = { login: loginPart, card: cardPart, identity: identityPart, sshkey: sshPart };
  const showParts = () => {
    for (const [key, part] of Object.entries(parts)) part.hidden = d.type !== key;
    connectPart.hidden = d.type !== "login" && d.type !== "sshkey";
    cUserRow.hidden = d.type !== "sshkey";
  };
  showParts();

  // the folders of the vault the item is saved in
  const folder = el("select", { name: "folder" });
  const fillFolders = (vaultID, selected) => {
    const list = vaultFolders(vaultID).map((f) => [f.id, folderPath(f)]).sort((a, b) => a[1].localeCompare(b[1], undefined, { sensitivity: "base" }));
    folder.replaceChildren(el("option", { value: "" }, t("No folder")), ...list.map(([id, p]) => el("option", { value: id, selected: id === selected }, p)));
  };
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
  const curVault = e.item ? e.item.vault_id : S.view === "vault" && canEditVault(S.vault) ? S.vault : personalVault();
  const editable = [...S.vaults.keys()].filter((id) => canEditVault(id));
  const vaultSel = el("select", { name: "vault", onchange: () => fillFolders(vaultSel.value, "") }, ...editable.map((id) => el("option", { value: id, selected: id === curVault }, vaultLabel(id))));
  fillFolders(curVault, d.folder);
  const err = el("div", { class: "flash err", role: "alert", hidden: true });
  const save = button(t("Save"), { type: "submit", class: "primary", icon: "check" });
  const form = el("form", { class: "stack veditor" },
    el("h2", { text: isNew ? t("New item") : t("Edit %s", d.name || "") }), err,
    el("div", { class: "grid2" }, el("label", null, t("Type"), type), el("label", null, t("Folder"), folder)),
    el("label", null, t("Name"), name),
    editable.length > 1 ? el("label", null, t("Vault"), vaultSel) : null,
    ...(cn.tool ? [connectPart, loginPart] : [loginPart, connectPart]), cardPart, identityPart, sshPart,
    el("label", null, t("Notes"), notes),
    el("div", null, el("label", { text: t("More fields") }), fields, button(t("Add a field"), { class: "ghost sm", icon: "plus", onclick: () => addField({ name: "", value: "", hidden: false }) })),
    el("label", { class: "check" }, fav, " " + t("Favorite")),
    el("div", { class: "row vactions" }, save, button(t("Cancel"), { class: "ghost", onclick: () => { S.editing = null; render(); } })));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    err.hidden = true;
    const old = e.item && e.item.data;
    // Keep what this editor does not show (for example the TOTP secret of an import).
    const out = Object.assign({}, old || {}, {
      type: type.value, name: name.value.trim(), folder: folder.value, favorite: fav.checked, notes: notes.value,
      fields: [...fields.children].map((r) => { const i = r.querySelectorAll("input"); return { name: i[0].value.trim(), value: i[1].value, hidden: i[2].checked }; }).filter((f) => f.name || f.value),
      history: old && old.history ? old.history.slice() : [],
      passwordChanged: old && old.passwordChanged || "",
    });
    if (out.type === "login") {
      out.login = Object.assign({}, old && old.login || {}, { username: user.value.trim(), password: pass.value, urls: [...urls.querySelectorAll("input")].map((i) => i.value.trim()).filter(Boolean) });
      const oldPw = old && old.login ? old.login.password : "";
      if (oldPw && oldPw !== out.login.password) {
        out.history.push({ password: oldPw, changed: new Date().toISOString() });
        out.history = out.history.slice(-10);
      }
      if (oldPw !== out.login.password) out.passwordChanged = new Date().toISOString();
      out.login.totp = totp.value.trim();
      if (out.login.totp) {
        try { totpParse(out.login.totp); } catch (x) { err.textContent = t("The authenticator key is not valid."); err.hidden = false; return; }
      }
    }
    if (out.type === "card") {
      const num = cNumber.value.replace(/\s+/g, " ").trim();
      out.card = { holder: cHolder.value.trim(), number: num, expMonth: cMonth.value.trim(), expYear: cYear.value.trim(), code: cCode.value.trim(), brand: cardBrand(num) };
    }
    if (out.type === "identity") out.identity = Object.assign({}, old && old.identity || {}, Object.fromEntries(Object.entries(idFields).map(([key, f]) => [key, f.value.trim()])));
    if (out.type === "sshkey") out.ssh = { privateKey: kPriv.value.trim() ? kPriv.value.trim() + "\n" : "", publicKey: kPub.value.trim(), passphrase: kPass.value, fingerprint: await sshFingerprint(kPub.value) };
    delete out.connect;
    if ((out.type === "login" || out.type === "sshkey") && cTool.value) {
      const host = cHost.value.trim();
      if (!/^[A-Za-z0-9][A-Za-z0-9.\-:]{0,252}$/.test(host)) { err.textContent = t("Enter the address of the connection (a name or an IP address)."); err.hidden = false; return; }
      out.connect = { tool: cTool.value, host, port: +cPort.value || 0 };
      if (out.type === "sshkey" && cUser.value.trim()) out.connect.user = cUser.value.trim();
    }
    if (!out.name && out.connect) out.name = out.connect.host;
    if (!out.name) { err.textContent = t("Enter a name."); err.hidden = false; return; }
    save.disabled = true;
    try {
      const target = vaultSel.value || curVault;
      const saved = e.item && target !== e.item.vault_id ? await moveItem(e.item, target, out) : await saveItem(e.item || { vault_id: target }, out);
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

// ---- files attached to an item: each sealed with its own key, which is
// kept inside the encrypted item

function fmtSize(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

function attachmentsBlock(it) {
  const files = it.data.attachments || [];
  const canEdit = !it.deleted_at && canEditItem(it);
  if (!files.length && !canEdit) return null;
  const input = el("input", { type: "file", hidden: true, multiple: true });
  input.addEventListener("change", async () => {
    for (const file of input.files) {
      try { await addFile(S.items.get(it.id), file); } catch (e) { toast(e.message, true); }
    }
    render();
  });
  const list = el("ul", { class: "vfiles" }, ...files.map((f) => el("li", null, icon("paperclip"),
    el("span", { class: "fname", text: f.name }), el("small", { class: "muted", text: fmtSize(f.size) }),
    button("", { class: "ghost sm", icon: "download", aria: t("Download"), title: t("Download"), onclick: () => downloadFile(f).catch((e) => toast(e.message, true)) }),
    canEdit ? button("", { class: "ghost sm", icon: "trash", aria: t("Remove"), title: t("Remove"), onclick: () => removeFile(it, f).catch((e) => toast(e.message, true)) }) : null)));
  return el("div", { class: "vfield" }, el("label", { text: t("Files") }), files.length ? list : null,
    canEdit ? el("div", null, input, button(t("Attach a file"), { class: "ghost sm", icon: "paperclip", onclick: () => input.click() })) : null);
}

async function addFile(it, file) {
  const st = await api("GET", "/api/storage");
  if (file.size + 64 > st.max_file) throw new Error(t("The file is larger than %d MB.", Math.floor(st.max_file / 1048576)));
  const key = pz.random(32);
  const id = pz.uuid();
  const sealed = await pz.sealBytes(key, new Uint8Array(await file.arrayBuffer()), pz.AAD.file(id));
  const r = await fetch("/api/items/" + it.id + "/files/" + id, { method: "PUT", body: sealed, credentials: "same-origin", headers: { "Content-Type": "application/octet-stream" } });
  if (!r.ok) {
    let m = "";
    try { m = (await r.json()).message; } catch (e) { /* no JSON */ }
    throw new Error(m || t("Something went wrong (%s).", r.status));
  }
  const data = Object.assign({}, it.data, { attachments: (it.data.attachments || []).concat([{ id, name: file.name.slice(0, 200), size: file.size, type: (file.type || "").slice(0, 100), key: pz.b64u(key) }]) });
  try {
    await saveItem(it, data);
  } catch (e) {
    await api("DELETE", "/api/files/" + id).catch(() => {});
    throw e;
  }
  toast(t("File attached."));
}

async function downloadFile(f) {
  const r = await fetch("/api/files/" + f.id, { credentials: "same-origin", cache: "no-store" });
  if (!r.ok) throw new Error(t("Something went wrong (%s).", r.status));
  const plain = await pz.openBytes(pz.unb64u(f.key), new Uint8Array(await r.arrayBuffer()), pz.AAD.file(f.id));
  const url = URL.createObjectURL(new Blob([plain], { type: f.type || "application/octet-stream" }));
  const a = el("a", { href: url, download: f.name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

async function removeFile(it, f) {
  if (!(await confirmBox(t("Remove the file %s?", f.name), t("Remove"), true))) return;
  const cur = S.items.get(it.id);
  const data = Object.assign({}, cur.data, { attachments: (cur.data.attachments || []).filter((x) => x.id !== f.id) });
  await saveItem(cur, data);
  await api("DELETE", "/api/files/" + f.id).catch(() => {});
  render();
}

// ---- password health: weak, reused and old passwords, and (when the
// administrator allows it) passwords from known data breaches

async function sha1Hex(text) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text)));
  return Array.from(h, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function openHealth() {
  const logins = [...S.items.values()].filter((i) => i.data && !i.deleted_at && i.data.type === "login" && i.data.login && i.data.login.password);
  const byPw = new Map();
  for (const i of logins) byPw.set(i.data.login.password, (byPw.get(i.data.login.password) || []).concat([i]));
  const weak = logins.filter((i) => strength(i.data.login.password).score <= 2);
  const reused = logins.filter((i) => byPw.get(i.data.login.password).length > 1);
  const yearAgo = Date.now() - 365 * 864e5;
  const old = logins.filter((i) => new Date(i.data.passwordChanged || i.created_at).getTime() < yearAgo);
  const section = (title, hint, list) => el("section", { class: "health" },
    el("h3", null, title, " ", el("span", { class: "badge " + (list.length ? "warn" : "ok"), text: String(list.length) })),
    el("p", { class: "small muted", text: hint }),
    list.length ? el("ul", { class: "vitems" }, ...list.map((i) => el("li", null, el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); d.close(); S.view = "vault"; S.vault = i.vault_id; S.kind = ""; S.selected = i.id; render(); } },
      avatar(i, ""), el("span", { class: "vname" }, el("b", { text: itemName(i) }), el("small", { text: subtitle(i.data) })))))) : null);
  const breachBox = el("div");
  const score = logins.length ? Math.round(100 * (logins.length - new Set([...weak, ...reused, ...old]).size) / logins.length) : 100;
  const d = dialog(t("Password health"),
    el("p", null, el("b", { class: "healthscore", text: score + " %" }), " ", t("of %d logins have a strong, unique and recent password.", logins.length)),
    section(t("Weak passwords"), t("Easy to guess. Replace them with generated passwords."), weak),
    section(t("Reused passwords"), t("The same password on several websites: one leak opens all of them."), reused),
    section(t("Old passwords"), t("Not changed for more than a year."), old),
    breachBox);
  if (S.acct.breach_check) {
    breachBox.append(el("section", { class: "health" }, el("h3", { text: t("Known data breaches") }),
      el("p", { class: "small muted", text: t("Checks each password against the Have I Been Pwned list. Only the first 5 characters of its SHA-1 hash leave this browser.") }),
      button(t("Check now"), { class: "secondary", icon: "shield", onclick: async (ev) => {
        const b = ev.currentTarget;
        b.disabled = true;
        b.classList.add("loading");
        try {
          const cache = new Map();
          const hit = [];
          for (const [pw, items] of byPw) {
            const h = await sha1Hex(pw);
            const prefix = h.slice(0, 5);
            if (!cache.has(prefix)) {
              const r = await fetch("/api/breach/" + prefix, { credentials: "same-origin", cache: "no-store" });
              if (!r.ok) { let m = ""; try { m = (await r.json()).message; } catch (e) { /* text */ } throw new Error(m || t("Something went wrong (%s).", r.status)); }
              const set = new Map();
              for (const line of (await r.text()).split("\n")) {
                const [suf, n] = line.trim().split(":");
                if (suf && +n > 0) set.set(suf, +n);
              }
              cache.set(prefix, set);
            }
            if (cache.get(prefix).has(h.slice(5))) hit.push(...items);
          }
          breachBox.replaceChildren(section(t("Passwords found in data breaches"), t("These passwords appeared in leaked data. Change them everywhere you use them."), hit));
        } catch (e) {
          toast(e.message, true);
          b.disabled = false;
          b.classList.remove("loading");
        }
      } })));
  }
}

// ---- import and export (all in this browser; the server gets ciphertext)

function dialog(title, ...body) {
  const d = el("dialog", { class: "dlg wide" });
  d.append(el("div", { class: "row spread" }, el("h2", { text: title }),
    el("button", { type: "button", class: "iconbtn", "aria-label": t("Close"), onclick: () => d.close() }, icon("x"))), ...body);
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function today() { return new Date().toISOString().slice(0, 10); }

function openImport() {
  const err = el("div", { class: "flash err", role: "alert", hidden: true });
  const file = el("input", { type: "file", accept: ".csv,.json,.xml,text/csv,application/json,text/xml" });
  const pwField = el("input", { type: "password", autocomplete: "off" });
  const pwRow = el("label", { hidden: true }, t("Password of the export file"), pwField);
  const summary = el("div", { class: "small" });
  const skip = el("input", { type: "checkbox", checked: true });
  const into = el("select", {}, el("option", { value: "keep" }, t("Keep the folders of the file")), el("option", { value: "new" }, t("Put everything into a new folder")));
  const go = button(t("Import"), { class: "primary", icon: "upload", disabled: true });
  let parsed = null, text = "";
  const fail = (e) => {
    const m = e && e.message;
    err.textContent = m === "bitwarden-encrypted" ? t("This Bitwarden export is encrypted. Export again as unencrypted JSON or CSV.")
      : m === "unknown" || m === "empty" ? t("This file was not recognised. PassZit reads CSV files of browsers and password managers, Bitwarden JSON, KeePass XML and its own exports.")
      : e instanceof pz.DecryptError ? t("Wrong password for this export file.") : (m || String(e));
    err.hidden = false;
  };
  const show = () => {
    const have = new Set([...S.items.values()].filter((i) => i.data && !i.deleted_at && !isFolder(i)).map((i) => dedupeKey(i.data)));
    const dup = parsed.items.filter((d) => have.has(dedupeKey(d))).length;
    const folders = new Set(parsed.items.map((d) => d.folder).filter(Boolean)).size;
    summary.replaceChildren(el("p", null, el("b", { text: parsed.format }), " · ", t("%d items", parsed.items.length), " · ", t("%d folders", folders),
      dup ? " · " + t("%d already in the vault", dup) : ""));
    go.disabled = !parsed.items.length;
  };
  file.addEventListener("change", async () => {
    err.hidden = true; go.disabled = true; summary.replaceChildren(); parsed = null; pwRow.hidden = true;
    const f = file.files[0];
    if (!f) return;
    if (f.size > 20 << 20) { fail(new Error(t("The file is too large."))); return; }
    text = await f.text();
    try {
      const r = detect(text);
      if (r.encrypted) { pwRow.hidden = false; go.disabled = false; summary.replaceChildren(el("p", { text: t("A PassZit export: enter the password it was made with.") })); parsed = r; return; }
      parsed = r;
      show();
    } catch (e) { fail(e); }
  });
  go.addEventListener("click", async () => {
    err.hidden = true;
    go.disabled = true;
    try {
      if (parsed.encrypted) {
        await nextFrame();
        const payload = await importEncrypted(parsed.encrypted, pwField.value);
        parsed = { format: "PassZit", items: (payload.items || []).map((d) => Object.assign({}, d, { folder: d.folderName || "" })) };
        pwField.value = "";
        pwRow.hidden = true;
        show();
        go.disabled = false;
        return; // the summary first, then a second click imports
      }
      const n = await runImport(parsed.items, skip.checked, into.value, (msg) => { summary.replaceChildren(el("p", { text: msg })); });
      d.close();
      toast(t("%d items imported.", n));
      render();
    } catch (e) {
      fail(e);
      go.disabled = false;
    }
  });
  const d = dialog(t("Import"),
    el("p", { class: "small muted", text: t("Chrome, Edge, Firefox, Safari, Bitwarden, KeePass, KeePassXC, 1Password, LastPass and other CSV files, or a PassZit export. The file is read in this browser; delete it afterwards — it holds your passwords unencrypted.") }),
    err, el("label", null, t("File"), file), pwRow, summary,
    el("label", { class: "check" }, skip, " " + t("Skip items that are already in the vault")),
    el("label", null, t("Folders"), into),
    el("div", { class: "row end" }, go));
}

async function runImport(items, skipDupes, into, progress) {
  const have = new Set([...S.items.values()].filter((i) => i.data && !i.deleted_at && !isFolder(i)).map((i) => dedupeKey(i.data)));
  const todo = skipDupes ? items.filter((d) => !have.has(dedupeKey(d))) : items.slice();
  // folders of the personal vault by path ("A/B" makes B inside A;
  // existing ones are reused)
  const vaultID = personalVault();
  const byPath = new Map(vaultFolders(vaultID).map((f) => [folderPath(f).toLowerCase(), f.id]));
  const folderID = async (path, under) => {
    let id = under || "", p = under ? folderPath(S.items.get(under)) : "";
    for (const part of (path || "").split("/").map((s) => s.trim()).filter(Boolean)) {
      p = p ? p + " / " + part : part;
      const k = p.toLowerCase();
      if (!byPath.has(k)) byPath.set(k, (await saveItem({ vault_id: vaultID }, { type: "folder", name: part.slice(0, 100), parent: id })).id);
      id = byPath.get(k);
    }
    return id;
  };
  const common = into === "new" ? await folderID(t("Import %s", today())) : "";
  const key = S.vaults.get(vaultID).key;
  let done = 0;
  for (let i = 0; i < todo.length; i += 200) {
    const batch = [];
    for (const d of todo.slice(i, i + 200)) {
      const data = Object.assign({}, d, { folder: await folderID(d.folder, common) });
      delete data.folderName;
      const id = pz.uuid();
      batch.push({ id, vault_id: vaultID, data: await pz.sealJSON(key, data, pz.AAD.item(vaultID, id)) });
    }
    await api("POST", "/api/items", { items: batch });
    done += batch.length;
    progress(t("Imported %d of %d…", done, todo.length));
  }
  await api("POST", "/api/account/event", { event: "import", count: done }).catch(() => {});
  await sync(S.revision);
  return done;
}

function openExport() {
  const err = el("div", { class: "flash err", role: "alert", hidden: true });
  const master = el("input", { type: "password", autocomplete: "current-password", required: true });
  const fmtEnc = el("input", { type: "radio", name: "fmt", value: "enc", checked: true });
  const fmtCSV = el("input", { type: "radio", name: "fmt", value: "csv" });
  const p1 = el("input", { type: "password", autocomplete: "new-password", minlength: 12 });
  const p2 = el("input", { type: "password", autocomplete: "new-password" });
  const encPart = el("div", { class: "stack" }, el("label", null, t("Password for the export file"), p1), el("label", null, t("Repeat the password"), p2),
    el("p", { class: "small muted", text: t("Keep this password: without it the file cannot be opened. It does not have to be your master password.") }));
  const understood = el("input", { type: "checkbox" });
  const csvPart = el("div", { hidden: true }, el("div", { class: "callout warn" }, icon("alert"), el("div", { text: t("A CSV file is not encrypted: anyone who gets it can read all your passwords. Use it only to move to another program, and delete it right after.") })),
    el("label", { class: "check" }, understood, " " + t("I understand that this file is not protected.")));
  const sync2 = () => { encPart.hidden = !fmtEnc.checked; csvPart.hidden = fmtEnc.checked; };
  fmtEnc.addEventListener("change", sync2);
  fmtCSV.addEventListener("change", sync2);
  const go = button(t("Export"), { class: "primary", icon: "download" });
  go.addEventListener("click", async () => {
    err.hidden = true;
    const fail = (m) => { err.textContent = m; err.hidden = false; };
    if (fmtEnc.checked && (p1.value.length < 12 || p1.value !== p2.value)) return fail(p1.value !== p2.value ? t("The passwords do not match.") : t("The export password must have at least %d characters.", 12));
    if (!fmtEnc.checked && !understood.checked) return fail(t("Confirm that you understand the risk of an unencrypted file."));
    go.disabled = true;
    go.classList.add("loading");
    await nextFrame();
    try {
      try {
        await api("POST", "/api/account/verify", { current_auth: await authFor(S.acct, master.value) });
      } catch (e) {
        throw new Error(t("The current master password is wrong."));
      }
      const items = [...S.items.values()].filter((i) => i.data && !i.deleted_at && !isFolder(i))
        .map((i) => Object.assign({}, i.data, { folderName: folderOf(i) ? folderPath(folderOf(i)).replace(/ \/ /g, "/") : "" }));
      if (fmtEnc.checked) {
        // The server records the export first (and refuses it when the policy forbids exports).
        await api("POST", "/api/account/event", { event: "export", count: items.length });
        const out = await exportEncrypted({ version: 1, exported_at: new Date().toISOString(), items }, p1.value, S.acct.policy_kdf || pz.DEFAULT_KDF);
        download("passzit-export-" + today() + ".json", out, "application/json");
      } else {
        await api("POST", "/api/account/event", { event: "export.plain", count: items.length });
        download("passzit-export-" + today() + ".csv", exportCSV(items), "text/csv");
      }
      master.value = p1.value = p2.value = "";
      d.close();
      toast(t("%d items exported.", items.length));
    } catch (e) {
      fail(e.message);
    } finally {
      go.disabled = false;
      go.classList.remove("loading");
    }
  });
  const d = dialog(t("Export"), err,
    el("p", { class: "small muted", text: t("The export holds your items (not the trash). It is made in this browser.") }),
    el("label", null, t("Current master password"), master),
    el("label", { class: "check" }, fmtEnc, " " + t("Encrypted PassZit file (recommended)")),
    el("label", { class: "check" }, fmtCSV, " " + t("CSV file, unencrypted")),
    encPart, csvPart, el("div", { class: "row end" }, go));
}

// A vault left open in a background tab still locks; the keys of a closed
// tab are gone with its session storage.
window.addEventListener("pagehide", () => { if (!S.keys) clearKeys(); });

start();

// cardBrand names the card network from the first digits.
function cardBrand(number) {
  const n = (number || "").replace(/\D/g, "");
  if (/^4/.test(n)) return "Visa";
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(n)) return "Mastercard";
  if (/^3[47]/.test(n)) return "American Express";
  if (/^(6011|65|64[4-9])/.test(n)) return "Discover";
  if (/^3(0[0-5]|[68])/.test(n)) return "Diners Club";
  if (/^35/.test(n)) return "JCB";
  if (/^62/.test(n)) return "UnionPay";
  if (/^(5[06-9]|6)/.test(n)) return "Maestro";
  return "";
}

// ---- rights in shared vaults

function rightsText(r) {
  return { use: t("You may use the items"), view: t("You may read the items"), edit: t("You may read and change the items"), manage: t("You manage this vault") }[r] || "";
}

function rightsOf(it) { return (S.vaults.get(it.vault_id) || {}).rights || "view"; }
function canEditItem(it) { return rightsOf(it) === "edit" || rightsOf(it) === "manage"; }
function useOnly(it) { return rightsOf(it) === "use"; }

// ---- who used an item of a shared vault (reported here, shown to managers)

let curItem = null; // the item the detail view shows

function reportUse(it, action) {
  if (!it || (S.vaults.get(it.vault_id) || {}).kind !== "shared") return;
  api("POST", "/api/items/" + it.id + "/access", { action }).catch(() => {});
}

function accessLog(it) {
  const v = S.vaults.get(it.vault_id) || {};
  if (v.kind !== "shared" || v.rights !== "manage") return null;
  const body = el("div", { class: "small" }, el("p", { class: "muted", text: t("Loading…") }));
  const d = el("details", { class: "vhist" }, el("summary", { text: t("Who used this item") }), body);
  d.addEventListener("toggle", async () => {
    if (!d.open) return;
    try {
      const list = await api("GET", "/api/items/" + it.id + "/access");
      const what = { show: t("showed the password"), copy: t("copied a secret"), fill: t("filled it in"), view: t("opened it"), connect: t("connected with it") };
      body.replaceChildren(list.length ? el("ul", null, ...list.map((a) => el("li", null, el("b", { text: a.email }), " " + (what[a.action] || a.action) + " · ", el("small", { class: "muted", text: fmtDate(a.at) + (a.ip ? " · " + a.ip : "") }))))
        : el("p", { class: "muted", text: t("Nobody has used it yet.") }));
    } catch (e) { body.replaceChildren(el("p", { class: "muted", text: e.message })); }
  });
  return d;
}
