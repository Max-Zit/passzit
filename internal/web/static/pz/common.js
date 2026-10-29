// Shared helpers of the web vault pages: translations, API calls, small
// DOM helpers, the clipboard and the locally kept (encrypted) keys.
import * as pz from "./crypto.js";

// ---- translations: the server sends the texts of these scripts

let texts = {};

export async function loadTexts() {
  const lang = document.body.dataset.lang || "en";
  if (lang === "en") return;
  try {
    const r = await fetch("/i18n/" + lang + ".json?v=" + (document.body.dataset.asset || ""));
    if (r.ok) texts = await r.json();
  } catch (e) { /* English then */ }
}

// t translates an English text; %s and %d take the arguments in order.
export function t(key, ...args) {
  let s = texts[key] || key;
  let i = 0;
  return s.replace(/%[sd]/g, () => String(args[i++]));
}

// ---- API

export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

export async function api(method, path, body) {
  const opt = { method, headers: {}, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  let r;
  try {
    r = await fetch(path, opt);
  } catch (e) {
    throw new ApiError(0, "network", t("The server cannot be reached. Check the connection and try again."));
  }
  let data = null;
  try { data = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) {
    if (r.status === 401 && (!data || data.error === "signed_out") && path.indexOf("/api/login") !== 0 && path.indexOf("/api/recover") !== 0) {
      clearKeys();
      location.href = "/login?next=" + encodeURIComponent(location.pathname);
    }
    throw new ApiError(r.status, data && data.error || "error", data && data.message || t("Something went wrong (%s).", r.status));
  }
  return data;
}

// ---- DOM

export function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(e.dataset, v);
      else e.setAttribute(k, v === true ? "" : v);
    }
  }
  for (const k of kids.flat()) {
    if (k === undefined || k === null || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}

const NS = "http://www.w3.org/2000/svg";
// Icon paths (24×24, stroke); several follow Feather Icons (MIT), see THIRD_PARTY_LICENSES.md.
const ICONS = {
  plus: ["M12 5v14M5 12h14"],
  search: ["M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z", "m20 20-4-4"],
  copy: ["M11 9h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2Z", "M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"],
  eye: ["M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"],
  eyeoff: ["M3 3l18 18", "M10.6 6.1A10 10 0 0 1 12 6c6.4 0 10 6 10 6a17 17 0 0 1-3.1 3.7M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7c1.6 0 3-.4 4.3-1", "M9.9 9.9a3 3 0 0 0 4.2 4.2"],
  edit: ["M4 20h4L19 9l-4-4L4 16v4Z", "m13 7 4 4"],
  trash: ["M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15"],
  star: ["m12 3 2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9L12 3Z"],
  folder: ["M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"],
  key: ["M8 19a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z", "m10.8 12.2 9.2-9.2M17 6l3 3M14 9l2 2"],
  note: ["M5 3h14v18H5z", "M9 8h6M9 12h6M9 16h4"],
  grid: ["M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"],
  link: ["M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1", "M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"],
  dice: ["M6 3h12a3 3 0 0 1 3 3v12a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V6a3 3 0 0 1 3-3Z", "M8 8h.01M16 8h.01M12 12h.01M8 16h.01M16 16h.01"],
  back: ["m15 18-6-6 6-6"],
  lock: ["M6 11h12a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2Z", "M8 11V7a4 4 0 0 1 8 0v4"],
  restore: ["M3 12a9 9 0 1 0 3-6.7L3 8", "M3 3v5h5"],
  x: ["M18 6 6 18M6 6l12 12"],
  refresh: ["M21 12a9 9 0 1 1-3-6.7L21 8", "M21 3v5h-5"],
  alert: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 8v5M12 16.5v.01"],
  check: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "m8 12 3 3 5-6"],
  external: ["M14 3h7v7M21 3l-9 9", "M19 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5"],
  user: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z"],
  download: ["M12 3v12M7 10l5 5 5-5M5 21h14"],
  upload: ["M12 21V9M7 14l5-5 5 5M5 3h14"],
  more: ["M5 12h.01M12 12h.01M19 12h.01"],
};

export function icon(name) {
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("class", "ic");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("aria-hidden", "true");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.8");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  for (const d of ICONS[name] || []) {
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    s.append(p);
  }
  return s;
}

export function button(label, opts) {
  const o = opts || {};
  const b = el("button", { type: o.type || "button", class: o.class || "secondary", title: o.title, "aria-label": o.aria, onclick: o.onclick, disabled: o.disabled });
  if (o.icon) b.append(icon(o.icon));
  if (label) b.append(el("span", { text: label }));
  return b;
}

export function showError(box, msg) {
  if (!box) { alert(msg); return; }
  box.textContent = msg;
  box.hidden = !msg;
  if (msg) box.scrollIntoView({ block: "nearest" });
}

// toast shows a short message at the bottom of the page.
export function toast(msg, bad) {
  let box = document.getElementById("pz-toasts");
  if (!box) { box = el("div", { id: "pz-toasts", class: "toasts", role: "status", "aria-live": "polite" }); document.body.append(box); }
  const n = el("div", { class: "toast" + (bad ? " bad" : "") }, icon(bad ? "alert" : "check"), el("span", { text: msg }));
  box.append(n);
  setTimeout(() => n.remove(), 3500);
}

// confirmBox asks a yes/no question in a dialog; resolves true for yes.
export function confirmBox(question, yes, danger) {
  return new Promise((resolve) => {
    const d = el("dialog", { class: "dlg" },
      el("p", { text: question }),
      el("div", { class: "row end" },
        button(t("Cancel"), { class: "ghost", onclick: () => { d.close(); resolve(false); } }),
        button(yes || t("OK"), { class: danger ? "danger" : "primary", onclick: () => { d.close(); resolve(true); } })));
    d.addEventListener("close", () => { d.remove(); resolve(false); });
    document.body.append(d);
    d.showModal();
  });
}

// busy shows a spinner in a button while work runs.
export async function busy(btn, work) {
  if (btn) { btn.disabled = true; btn.classList.add("loading"); }
  try { return await work(); } finally { if (btn) { btn.disabled = false; btn.classList.remove("loading"); } }
}

// nextFrame lets the browser paint (before Argon2id blocks for a moment).
// (A hidden tab gets no animation frames: the timeout goes on anyway.)
export function nextFrame() {
  return new Promise((r) => {
    const done = () => { clearTimeout(tm); r(); };
    const tm = setTimeout(done, 60);
    requestAnimationFrame(() => setTimeout(done, 0));
  });
}

// ---- clipboard: copied secrets are cleared again

let clipTimer = 0;

export async function copy(text, secret) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    toast(t("The browser did not allow copying."), true);
    return;
  }
  if (secret) {
    const secs = +document.body.dataset.clip || 30;
    clearTimeout(clipTimer);
    clipTimer = setTimeout(() => { navigator.clipboard.writeText("").catch(() => {}); }, secs * 1000);
    toast(t("Copied. The clipboard is cleared in %d seconds.", secs));
  } else {
    toast(t("Copied."));
  }
}

// ---- password strength (an estimate for the meter, not a promise)

export function strength(pw) {
  if (!pw) return { score: 0, bits: 0 };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  if (/[^\x00-\x7f]/.test(pw)) pool += 100;
  let bits = pw.length * Math.log2(Math.max(pool, 2));
  // repeated characters and simple sequences are worth much less
  const uniq = new Set(pw).size;
  bits *= Math.min(1, 0.35 + uniq / pw.length);
  if (/^(.)\1+$/.test(pw) || /(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf|password|passwort|lozinka|admin)/i.test(pw)) bits = Math.min(bits, 20);
  // words separated by spaces or dashes: count them as words of a large list
  const words = pw.split(/[\s\-_.]+/).filter((w) => w.length >= 3);
  if (words.length >= 3) bits = Math.max(bits, words.length * 12.9);
  const score = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { score, bits: Math.round(bits) };
}

const strengthNames = ["", "Weak", "Fair", "Good", "Strong"];

// wireStrength connects password inputs with data-strength to their meter.
export function wireStrength(root) {
  for (const inp of (root || document).querySelectorAll("input[data-strength]")) {
    const m = document.querySelector(inp.dataset.strength);
    if (!m) continue;
    const upd = () => {
      const s = strength(inp.value);
      m.dataset.score = s.score;
      m.querySelector("small").textContent = inp.value ? t(strengthNames[s.score]) + " · ~" + s.bits + " " + t("bits") : "";
    };
    inp.addEventListener("input", upd);
    upd();
  }
}

// wireReveal makes the eye buttons next to password fields show the text.
export function wireReveal(root) {
  (root || document).addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-reveal]");
    if (!b) return;
    const inp = b.parentElement.querySelector("input");
    if (inp) inp.type = inp.type === "password" ? "text" : "password";
  });
}

// ---- unlocked keys in this tab: encrypted with a key that only the
// server session holds, so they survive page changes but not a lock,
// a sign-out or the end of the session.

const KEYS = "pz.keys";

export async function saveKeys(keys) {
  const { key } = await api("GET", "/api/session/key");
  const blob = await pz.sealJSON(pz.unb64u(key), { a: pz.b64u(keys.accountKey), p: pz.b64u(keys.privateKey), u: pz.b64u(keys.publicKey) }, pz.AAD.session());
  sessionStorage.setItem(KEYS, blob);
}

export async function loadKeys() {
  const blob = sessionStorage.getItem(KEYS);
  if (!blob) return null;
  try {
    const { key } = await api("GET", "/api/session/key");
    const k = await pz.openJSON(pz.unb64u(key), blob, pz.AAD.session());
    return { accountKey: pz.unb64u(k.a), privateKey: pz.unb64u(k.p), publicKey: pz.unb64u(k.u) };
  } catch (e) {
    if (e instanceof ApiError && e.status === 0) throw e;
    sessionStorage.removeItem(KEYS);
    return null;
  }
}

export function clearKeys() {
  try { sessionStorage.removeItem(KEYS); } catch (e) { /* ignore */ }
}

// lockNow forgets the keys here and on the server.
export async function lockNow() {
  clearKeys();
  try { await api("POST", "/api/session/lock"); } catch (e) { /* signed out anyway */ }
}

// The sign-out button also forgets the keys of this tab.
export function wireLogout() {
  const f = document.getElementById("pz-logout");
  if (f) f.addEventListener("submit", () => clearKeys());
}

// unlockWithPassword derives the keys and opens the account key; it also
// returns the auth key (for checks that need the master password again).
export async function unlockWithPassword(acct, password) {
  const salt = pz.unb64u(acct.salt);
  const { auth, wrap } = await pz.keysFromPassword(password, salt, acct.kdf);
  try {
    const keys = await pz.unlockAccount(wrap, acct);
    return { keys, auth: pz.b64u(auth) };
  } finally {
    pz.wipe(wrap);
  }
}

// authFor returns the auth key of a master password (for re-checks).
export async function authFor(acct, password) {
  const { auth, wrap } = await pz.keysFromPassword(password, pz.unb64u(acct.salt), acct.kdf);
  pz.wipe(wrap);
  return pz.b64u(auth);
}

// kdfWeaker reports an account whose key derivation is below the policy.
export function kdfWeaker(have, want) {
  if (!want || !have) return false;
  if (have.alg !== want.alg) return want.alg === "argon2id";
  return have.m * have.t < want.m * want.t || (want.t > have.t && want.m >= have.m);
}
