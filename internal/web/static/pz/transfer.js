// Import and export of the web vault. Everything happens in the browser:
// files are read and written here; the server only receives the items
// already encrypted. Imports turn every format into PassZit item data
// ({ type, name, folder, login: { username, password, urls, totp }, notes,
// fields, favorite }); "folder" holds a folder name until the vault maps it.
import * as pz from "./crypto.js";

// ---- CSV (RFC 4180: quotes, doubled quotes, line breaks inside quotes)

export function parseCSV(text) {
  const s = text.replace(/^﻿/, "");
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"' && field === "") quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.length > 1 || row[0] !== "") rows.push(row);
  return rows;
}

function csvField(v) {
  const s = v === undefined || v === null ? "" : String(v);
  return /[",\r\n]/.test(s) || /^\s|\s$/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

export function toCSV(rows) { return rows.map((r) => r.map(csvField).join(",")).join("\r\n") + "\r\n"; }

// ---- item helpers

export function blankItem(type) {
  return { type: type || "login", name: "", folder: "", favorite: false, notes: "", fields: [], history: [], passwordChanged: "",
    login: { username: "", password: "", urls: [], totp: "" } };
}

function hostName(u) {
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : "https://" + u).hostname; } catch (e) { return ""; }
}

function finish(it) {
  it.name = (it.name || "").trim() || hostName(it.login.urls[0] || "") || it.login.username || "(no name)";
  it.login.urls = it.login.urls.map((u) => u.trim()).filter(Boolean);
  if (it.type !== "login") it.login = { username: "", password: "", urls: [], totp: "" };
  return it;
}

// ---- CSV of browsers and other password managers, recognised by the headers

const HEADERS = {
  name: ["name", "title", "account", "item name"],
  url: ["url", "login_uri", "login uri", "website", "web site", "uri", "urls", "login url", "hostname", "web address"],
  username: ["username", "login_username", "user name", "user", "login", "email", "e-mail", "login name"],
  password: ["password", "login_password", "pass", "passwort"],
  notes: ["note", "notes", "extra", "comments", "comment"],
  totp: ["totp", "login_totp", "otpauth", "otp", "one-time password"],
  folder: ["folder", "grouping", "group", "category", "collections"],
  favorite: ["favorite", "fav", "favourite"],
  type: ["type"],
  fields: ["fields"],
};

function columns(header) {
  const h = header.map((x) => x.trim().toLowerCase());
  const map = {};
  for (const [k, names] of Object.entries(HEADERS)) {
    const i = h.findIndex((x) => names.includes(x));
    if (i >= 0) map[k] = i;
  }
  return map;
}

export function fromCSV(text) {
  const rows = parseCSV(text);
  if (rows.length < 1) throw new Error("empty");
  const col = columns(rows[0]);
  if (col.password === undefined && col.notes === undefined) throw new Error("unknown");
  const get = (r, k) => (col[k] !== undefined ? r[col[k]] || "" : "");
  const items = [];
  for (const r of rows.slice(1)) {
    if (r.every((x) => !x)) continue;
    const t = get(r, "type").toLowerCase();
    const url = get(r, "url");
    const lastpassNote = url === "http://sn"; // LastPass marks secure notes so
    const it = blankItem(t === "note" || t === "securenote" || t === "secure note" || lastpassNote ? "note" : "login");
    it.name = get(r, "name");
    it.notes = get(r, "notes");
    it.folder = get(r, "folder").replace(/\\/g, "/");
    it.favorite = ["1", "true", "yes", "x"].includes(get(r, "favorite").toLowerCase());
    it.login.username = get(r, "username");
    it.login.password = get(r, "password");
    it.login.totp = get(r, "totp");
    it.login.urls = lastpassNote ? [] : url.split(/[\n,]+/);
    for (const line of get(r, "fields").split("\n")) {
      const m = line.match(/^([^:]+):\s?(.*)$/);
      if (m) it.fields.push({ name: m[1], value: m[2], hidden: false });
    }
    items.push(finish(it));
  }
  return { format: "CSV", items };
}

// ---- Bitwarden JSON (unencrypted export)

export function fromBitwarden(data) {
  if (data.encrypted) throw new Error("bitwarden-encrypted");
  const folders = {};
  for (const f of data.folders || []) folders[f.id] = f.name;
  const items = [];
  for (const b of data.items || []) {
    // 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key
    const type = { 1: "login", 2: "note", 3: "card", 4: "identity", 5: "sshkey" }[b.type];
    if (!type) continue;
    const it = blankItem(type);
    it.name = b.name || "";
    it.notes = b.notes || "";
    it.favorite = !!b.favorite;
    it.folder = folders[b.folderId] || "";
    if (b.login) {
      it.login.username = b.login.username || "";
      it.login.password = b.login.password || "";
      it.login.totp = b.login.totp || "";
      it.login.urls = (b.login.uris || []).map((u) => u.uri || "").filter(Boolean);
    }
    const s = (v) => (v == null ? "" : String(v));
    if (type === "card" && b.card) {
      const c = b.card;
      it.card = { holder: s(c.cardholderName), number: s(c.number), expMonth: s(c.expMonth), expYear: s(c.expYear), code: s(c.code), brand: s(c.brand) };
    }
    if (type === "identity" && b.identity) {
      const p = b.identity;
      it.identity = { first: s(p.firstName), last: s(p.lastName), email: s(p.email), phone: s(p.phone), company: s(p.company), username: s(p.username),
        address1: s(p.address1), address2: [p.address2, p.address3].filter(Boolean).join(", "), postal: s(p.postalCode), city: s(p.city), state: s(p.state), country: s(p.country) };
    }
    if (type === "sshkey" && b.sshKey) {
      const k = b.sshKey;
      it.ssh = { privateKey: s(k.privateKey), publicKey: s(k.publicKey), passphrase: "", fingerprint: s(k.keyFingerprint) };
    }
    for (const f of b.fields || []) it.fields.push({ name: f.name || "", value: f.value || "", hidden: f.type === 1 });
    items.push(finish(it));
  }
  return { format: "Bitwarden", items };
}

// ---- KeePass 2 XML (KeePass and KeePassXC "XML" export, unencrypted)

export function fromKeePassXML(text) {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.querySelector("parsererror") || !doc.querySelector("KeePassFile")) throw new Error("unknown");
  const items = [];
  const recycle = (doc.querySelector("Meta > RecycleBinUUID") || {}).textContent || "";
  const walk = (group, path, root) => {
    const uuid = (group.querySelector(":scope > UUID") || {}).textContent || "";
    if (recycle && uuid === recycle) return;
    const name = (group.querySelector(":scope > Name") || {}).textContent || "";
    const here = root ? "" : (path ? path + "/" : "") + name; // the root group is no folder
    for (const e of group.querySelectorAll(":scope > Entry")) {
      const it = blankItem("login");
      it.folder = here;
      for (const s of e.querySelectorAll(":scope > String")) {
        const k = (s.querySelector("Key") || {}).textContent || "";
        const vEl = s.querySelector("Value");
        const v = vEl ? vEl.textContent : "";
        if (k === "Title") it.name = v;
        else if (k === "UserName") it.login.username = v;
        else if (k === "Password") it.login.password = v;
        else if (k === "URL") it.login.urls = v ? [v] : [];
        else if (k === "Notes") it.notes = v;
        else if (k === "otp" || k === "TOTP Seed") it.login.totp = v;
        else if (v) it.fields.push({ name: k, value: v, hidden: !!vEl && vEl.getAttribute("ProtectInMemory") === "True" });
      }
      if (!it.login.password && !it.login.username && !it.login.urls.length && it.notes) it.type = "note";
      items.push(finish(it));
    }
    for (const g of group.querySelectorAll(":scope > Group")) walk(g, here, false);
  };
  const root = doc.querySelector("KeePassFile > Root > Group");
  if (root) walk(root, "", true);
  return { format: "KeePass", items };
}

// ---- PassZit encrypted export

export async function exportEncrypted(payload, password, kdf) {
  const salt = pz.random(16);
  const key = await pz.masterKey(password, salt, kdf);
  try {
    const data = await pz.sealJSON(key, payload, pz.AAD.export());
    return JSON.stringify({ passzit_export: 1, kdf, salt: pz.b64u(salt), data }, null, 1);
  } finally {
    pz.wipe(key);
  }
}

export async function importEncrypted(file, password) {
  if (!pz.validKDF(file.kdf)) throw new Error("unknown");
  const key = await pz.masterKey(password, pz.unb64u(file.salt), file.kdf);
  try {
    return await pz.openJSON(key, file.data, pz.AAD.export());
  } finally {
    pz.wipe(key);
  }
}

// exportCSV writes items (with folder names) as PassZit CSV.
export function exportCSV(items) {
  const rows = [["folder", "favorite", "type", "name", "url", "username", "password", "totp", "notes", "fields"]];
  for (const d of items) {
    const l = d.login || {};
    rows.push([d.folderName || "", d.favorite ? "1" : "", d.type || "login", d.name || "", (l.urls || []).join("\n"), l.username || "", l.password || "",
      l.totp || "", d.notes || "", (d.fields || []).map((f) => f.name + ": " + f.value).join("\n")]);
  }
  return toCSV(rows);
}

// detect reads any supported file. A PassZit encrypted export needs its
// password: the result then says { encrypted: file } and the caller asks.
export function detect(text) {
  const t = text.replace(/^﻿/, "").trimStart();
  if (t.startsWith("{")) {
    let data;
    try { data = JSON.parse(t); } catch (e) { throw new Error("unknown"); }
    if (data.passzit_export === 1) return { format: "PassZit", encrypted: data };
    if (Array.isArray(data.items)) return fromBitwarden(data);
    throw new Error("unknown");
  }
  if (t.startsWith("<")) return fromKeePassXML(t);
  return fromCSV(t);
}

// dedupeKey tells items apart for "skip what is already in the vault".
export function dedupeKey(d) {
  const l = d.login || {};
  return [d.type, (d.name || "").toLowerCase(), (l.username || "").toLowerCase(), hostName((l.urls || [])[0] || ""), l.password || "", d.type === "note" ? d.notes : ""].join("\u0000");
}
