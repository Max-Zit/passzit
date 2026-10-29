// Sign-in and unlock of the extension (used by the popup, and by the
// test harness of the test build). The master password is only used here,
// to derive keys; the keys go to the background, which keeps them.
import * as pz from "./pz/crypto.js";
import { api, settings, saveSettings, call, t } from "./ext.js";

pz.setArgonBase(api.runtime.getURL("pz/"));

export async function bg(type, data) {
  const r = await api.runtime.sendMessage(Object.assign({ type }, data || {}));
  if (!r) throw new Error(t("Something went wrong (%s).", "background"));
  if (!r.ok) { const e = new Error(r.error); e.status = r.status; throw e; }
  return r.data;
}

// signIn checks the master password with the server. It returns
// { next: "2fa", pending, wrap } when a second factor is needed; otherwise
// the extension is signed in and unlocked.
export async function signIn(origin, email, password, device) {
  const pre = await call(origin, "", "POST", "/api/ext/prelogin", { email });
  const { auth, wrap } = await pz.keysFromPassword(password, pz.unb64u(pre.salt), pre.kdf);
  const res = await call(origin, "", "POST", "/api/ext/login", { email, auth: pz.b64u(auth), device });
  pz.wipe(auth);
  await saveSettings({ server: origin, email, device, token: "" });
  if (res.next === "2fa") return { next: "2fa", pending: res.token, wrap };
  await finishSignIn(origin, res.token, wrap);
  return { next: "done" };
}

export async function secondFactor(origin, pending, wrap, code) {
  const res = await call(origin, pending, "POST", "/api/ext/login/2fa", { code });
  await finishSignIn(origin, res.token, wrap);
}

export async function finishSignIn(origin, token, wrap) {
  await saveSettings({ token });
  const acct = await call(origin, token, "GET", "/api/account");
  const keys = await pz.unlockAccount(wrap, acct);
  pz.wipe(wrap);
  await handOver(keys, acct);
}

// unlock opens the vault again with the master password.
export async function unlock(password) {
  const s = await settings();
  const acct = await call(s.server, s.token, "GET", "/api/account");
  const { auth, wrap } = await pz.keysFromPassword(password, pz.unb64u(acct.salt), acct.kdf);
  pz.wipe(auth);
  let keys;
  try {
    keys = await pz.unlockAccount(wrap, acct);
  } catch (e) {
    throw new Error(t("Wrong master password."));
  } finally {
    pz.wipe(wrap);
  }
  await handOver(keys, acct);
}

async function handOver(keys, acct) {
  await bg("unlocked", { keys: { a: pz.b64u(keys.accountKey), p: pz.b64u(keys.privateKey), u: pz.b64u(keys.publicKey) }, lock: acct.lock_minutes, clip: acct.clipboard_seconds });
  pz.wipe(keys.accountKey);
}
