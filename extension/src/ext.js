// Shared by the popup and the background of the PassZit extension:
// settings, translations and calls to the PassZit server.

export const api = globalThis.browser && globalThis.browser.runtime ? globalThis.browser : globalThis.chrome;

// ---- settings (storage.local: no secrets except the device token, which
// only reaches encrypted data; the master password is never stored)

export async function settings() {
  const s = await api.storage.local.get({ server: "", email: "", token: "", device: "", offerSave: false, siteBadge: false, consoles: [], passkeys: false });
  if (!Array.isArray(s.consoles)) s.consoles = [];
  return s;
}

// consoleSecure: MaxZit consoles only over HTTPS (a page over plain HTTP
// could be changed on the way), or plain HTTP on this computer itself.
export function consoleSecure(u) {
  return !!u.hostname && (u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)));
}

// consoleOrigin turns what the user typed for a MaxZit console (WatchZit)
// into its origin, or "" when it is no web address.
export function consoleOrigin(text) {
  let v = String(text || "").trim();
  if (!v) return "";
  if (!/^https?:\/\//i.test(v)) v = "https://" + v;
  try {
    const u = new URL(v);
    return consoleSecure(u) ? u.origin : "";
  } catch (e) { return ""; }
}

export async function saveSettings(patch) {
  await api.storage.local.set(patch);
}

// ---- translations: the catalogs of the server's console, packed by tools/extpack

let texts = {};
export const LANGS = ["de", "fr", "es", "it", "pt", "nl", "pl", "cs", "sr", "tr", "ru", "zh", "ja"];

export async function loadTexts() {
  let lang = (api.i18n && api.i18n.getUILanguage ? api.i18n.getUILanguage() : navigator.language || "en").toLowerCase().split("-")[0];
  if (["hr", "bs", "sh"].includes(lang)) lang = "sr";
  if (!LANGS.includes(lang)) return;
  try {
    const r = await fetch(api.runtime.getURL("i18n/" + lang + ".json"));
    if (r.ok) texts = await r.json();
  } catch (e) { /* English then */ }
}

export function t(key, ...args) {
  let s = texts[key] || key;
  let i = 0;
  return s.replace(/%[sd]/g, () => String(args[i++]));
}

// ---- server API with the device token

export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

// normServer checks a server address: https only, no path (http only for
// a loopback test server).
export function normServer(input) {
  let s = (input || "").trim();
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u;
  try { u = new URL(s); } catch (e) { return ""; }
  const loop = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loop)) return "";
  if (u.username || u.password || u.search || u.hash || (u.pathname && u.pathname !== "/")) return "";
  return u.origin;
}

// sameServer lists the origins of one server: on this computer localhost
// and 127.0.0.1 (same scheme and port) are the same server, and people
// open the console under either name.
export function sameServer(origin) {
  let u;
  try { u = new URL(origin); } catch (e) { return []; }
  const twin = { localhost: "127.0.0.1", "127.0.0.1": "localhost" }[u.hostname];
  if (!twin) return [u.origin];
  const v = new URL(u.origin);
  v.hostname = twin;
  return [u.origin, v.origin];
}

// hostPattern is the permission pattern for a server or console origin,
// without the port: Firefox ignores patterns that name a port (and then
// never runs the content scripts), Chromium matches every port of the host
// with it. The exact origin, port included, is checked whenever a page or
// the server is talked to.
export function hostPattern(origin) {
  const u = new URL(origin);
  return u.protocol + "//" + u.hostname + "/*";
}

// hostAllowed tells whether the browser lets PassZit reach this origin
// (also with a pattern granted before 0.9.5, which named the port).
export async function hostAllowed(origin) {
  for (const p of [hostPattern(origin), origin + "/*"]) {
    if (await api.permissions.contains({ origins: [p] }).catch(() => false)) return true;
  }
  return false;
}

export async function call(server, token, method, path, body) {
  const opt = { method, headers: {}, cache: "no-store", credentials: "omit" };
  if (token) opt.headers.Authorization = "Bearer " + token;
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  let r;
  try {
    r = await fetch(server + path, opt);
  } catch (e) {
    throw new ApiError(0, "network", t("The server cannot be reached. Check the connection and try again."));
  }
  let data = null;
  try { data = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) throw new ApiError(r.status, data && data.error || "error", data && data.message || t("Something went wrong (%s).", r.status));
  return data;
}

// deviceName names this browser for the device list of the account.
export function deviceName() {
  const ua = navigator.userAgent;
  let b = "Chrome";
  if (/Edg\//.test(ua)) b = "Edge";
  else if (/OPR\//.test(ua)) b = "Opera";
  else if (/Vivaldi/.test(ua)) b = "Vivaldi";
  else if (/Firefox\//.test(ua)) b = "Firefox";
  else if (navigator.brave) b = "Brave";
  let os = "";
  if (/Windows/.test(ua)) os = "Windows";
  else if (/Mac OS X/.test(ua)) os = "macOS";
  else if (/Android/.test(ua)) os = "Android";
  else if (/Linux/.test(ua)) os = "Linux";
  return b + (os ? " · " + os : "");
}
