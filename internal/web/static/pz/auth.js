// Sign-in, first-run setup, invitations and recovery. The master password
// never leaves this page: only the auth key derived from it is sent.
import * as pz from "./crypto.js";
import { api, t, el, loadTexts, showError, nextFrame, saveKeys, wireStrength, wireReveal, copy } from "./common.js";

const root = document.getElementById("pz-auth");
const errBox = document.getElementById("pz-error");
const mode = root.dataset.mode;
const minLen = +root.dataset.min || 12;
let pending = null; // keys of a new or unlocked account, until signed in fully
let pendingAuth = ""; // auth key of a new account (to store its recovery key)
let acct = null;    // unlock data after a sign-in

function step(name) {
  for (const s of root.querySelectorAll("section[data-step]")) s.hidden = s.dataset.step !== name;
  const f = root.querySelector("section[data-step=\"" + name + "\"] input:not([readonly])");
  if (f) f.focus();
}

function fail(e) {
  showError(errBox, e instanceof Error ? e.message : String(e));
}

function clearError() { showError(errBox, ""); }

async function deriving(text, work) {
  const back = root.querySelector("section[data-step]:not([hidden])");
  document.getElementById("busy-text").textContent = text || t("Deriving the keys from the master password…");
  step("busy");
  await nextFrame();
  try {
    return await work();
  } catch (e) {
    if (back) step(back.dataset.step);
    throw e;
  }
}

function checkNewPassword(f) {
  const pw = f.password.value;
  if (pw.length < minLen) throw new Error(t("The master password must have at least %d characters.", minLen));
  if (pw !== f.password2.value) throw new Error(t("The master passwords do not match."));
  return pw;
}

// ---- after the password: second factor, codes, recovery key, done

async function afterPassword(next) {
  if (next === "2fa") { step("2fa"); return; }
  if (next === "enroll") { await showEnroll(); return; }
  if (!pending && acct) { await unlockAfterLogin(); return; } // test servers without a second factor
  await finish();
}

async function showEnroll() {
  const d = await api("GET", "/api/login/enroll");
  document.getElementById("enroll-secret").textContent = d.secret.replace(/(.{4})/g, "$1 ").trim();
  const box = document.getElementById("enroll-qr");
  box.replaceChildren(qrSVG(d.qr));
  step("enroll");
}

function qrSVG(q) {
  const NS = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("class", "qr");
  s.setAttribute("viewBox", "0 0 " + q.Size + " " + q.Size);
  s.setAttribute("role", "img");
  s.setAttribute("aria-label", "QR");
  const bg = document.createElementNS(NS, "rect");
  bg.setAttribute("width", q.Size); bg.setAttribute("height", q.Size); bg.setAttribute("fill", "#fff");
  s.append(bg);
  let d = "";
  for (const c of q.Cells) d += "M" + c.X + " " + c.Y + "h1.02v1.02h-1.02z";
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", d); p.setAttribute("fill", "#000");
  s.append(p);
  return s;
}

async function finish() {
  // Signed in: unlock (new accounts already have their keys) and go on.
  if (!pending) throw new Error(t("Something went wrong (%s).", "keys"));
  await saveKeys(pending);
  const isNew = mode === "setup" || mode === "invite";
  if (isNew) { showRecoveryKey(); return; }
  go();
}

function go() {
  pending = null;
  const next = root.dataset.next || "/vault";
  location.replace(next.startsWith("/") && !next.startsWith("//") ? next : "/vault");
}

let rkey = "";

function showRecoveryKey() {
  rkey = pz.newRecoveryKey();
  document.getElementById("rkey-text").textContent = rkey;
  step("rkey");
}

// ---- forms

function onSubmit(id, handler) {
  const f = document.getElementById(id);
  if (!f) return;
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearError();
    const b = f.querySelector("button.primary");
    if (b) b.disabled = true;
    try {
      await handler(f);
    } catch (e) {
      fail(e);
    } finally {
      if (b) b.disabled = false;
    }
  });
}

onSubmit("f-login", async (f) => {
  const email = f.email.value.trim();
  const pre = await api("POST", "/api/prelogin", { email });
  const salt = pz.unb64u(pre.salt);
  const { auth, wrap } = await deriving(null, () => pz.keysFromPassword(f.password.value, salt, pre.kdf));
  step("login");
  let res;
  try {
    res = await api("POST", "/api/login", { email, auth: pz.b64u(auth) });
  } catch (e) {
    pz.wipe(wrap);
    throw e;
  }
  // The server accepted the auth key; the account key opens after the
  // second factor (the wrapped keys are only given to a full session).
  acct = { wrap, password: f.password.value };
  f.password.value = "";
  await afterPassword(res.next);
});

onSubmit("f-2fa", async (f) => {
  const res = await api("POST", "/api/login/2fa", { code: f.code.value.trim() });
  f.code.value = "";
  if (res.next === "done") await unlockAfterLogin();
});

onSubmit("f-enroll", async (f) => {
  const res = await api("POST", "/api/login/enroll", { code: f.code.value.trim() });
  const list = document.getElementById("codes-list");
  list.replaceChildren(...res.codes.map((c) => el("li", null, el("code", { text: c }))));
  step("codes");
});

document.getElementById("codes-next").addEventListener("click", async () => {
  clearError();
  try {
    if (pending) await finish();
    else await unlockAfterLogin();
  } catch (e) { fail(e); }
});

async function unlockAfterLogin() {
  if (pending) { await finish(); return; }
  const a = await api("GET", "/api/account");
  const keys = await pz.unlockAccount(acct.wrap, a);
  pz.wipe(acct.wrap);
  pending = keys;
  await finish();
}

onSubmit("f-create", async (f) => {
  const pw = checkNewPassword(f);
  const policy = { kdf: pz.DEFAULT_KDF };
  // An unknown address gets the key derivation of the policy.
  const pre = await api("POST", "/api/prelogin", { email: "-" });
  if (pz.validKDF(pre.kdf)) policy.kdf = pre.kdf;
  const acc = await deriving(t("Creating your keys…"), () => pz.newAccount(pw, policy.kdf));
  step("create");
  const body = {
    email: f.email.value.trim(), name: f.name.value.trim(),
    kdf: acc.kdf, salt: acc.salt, auth: acc.auth, wrapped_account_key: acc.wrapped_account_key,
    public_key: acc.public_key, wrapped_private_key: acc.wrapped_private_key, vault: acc.vault,
  };
  let res;
  if (mode === "setup") {
    body.token = f.token ? f.token.value.trim() : "";
    res = await api("POST", "/api/setup", body);
  } else {
    body.invite = root.dataset.invite;
    res = await api("POST", "/api/invite", body);
  }
  f.password.value = f.password2.value = "";
  pending = acc.keys;
  pendingAuth = acc.auth;
  await afterPassword(res.next);
});

document.getElementById("rkey-ok").addEventListener("change", (ev) => {
  document.getElementById("rkey-save").disabled = !ev.target.checked;
});
document.getElementById("rkey-print").addEventListener("click", () => printKey(rkey));
document.getElementById("rkey-save").addEventListener("click", async () => {
  clearError();
  try {
    const bundle = await pz.recoveryBundle(rkey, pendingAccountKey());
    await api("POST", "/api/account/recovery", Object.assign({ current_auth: pendingAuth }, bundle));
  } catch (e) {
    fail(e);
    return;
  }
  go();
});
document.getElementById("rkey-skip").addEventListener("click", () => go());

function pendingAccountKey() { return pending.accountKey; }

export function printKey(key) {
  const w = window.open("", "_blank", "noopener=no,width=600,height=400");
  if (!w) { copy(key, true); return; }
  const d = w.document;
  d.title = "PassZit — " + t("Recovery key");
  const h = d.createElement("h1"); h.textContent = "PassZit — " + t("Recovery key");
  const p = d.createElement("p"); p.textContent = t("Account") + ": " + (document.querySelector("input[name=email]") || {}).value;
  const k = d.createElement("pre"); k.textContent = key; k.style.fontSize = "22px";
  const n = d.createElement("p"); n.textContent = t("Keep this paper safe. Anyone with this key and your second factor can take over your vault.");
  d.body.append(h, p, k, n);
  w.print();
}

onSubmit("f-recover", async (f) => {
  const pw = checkNewPassword(f);
  const email = f.email.value.trim();
  let rk;
  try { rk = await pz.recoveryKeys(f.recovery.value); } catch (e) { throw new Error(t("This is not a recovery key.")); }
  const start = await api("POST", "/api/recover/start", { email, recovery_auth: pz.b64u(rk.auth), code: f.code ? f.code.value.trim() : "" });
  let accountKey;
  try {
    accountKey = await pz.open(rk.wrap, start.recovery_wrapped_key, pz.AAD.accountKey());
  } catch (e) {
    throw new Error(t("The recovery key does not open this account."));
  }
  const keys = await deriving(null, () => pz.rewrap(pw, accountKey, start.kdf));
  pz.wipe(accountKey);
  await api("POST", "/api/recover/finish", Object.assign({ ticket: start.ticket }, keys));
  f.password.value = f.password2.value = "";
  step("recovered");
});

wireStrength(root);
wireReveal(root);
loadTexts();
