// My account: change the master password, make or remove the recovery
// key. Both need the current master password; the keys are re-wrapped
// here in the browser.
import * as pz from "./crypto.js";
import { api, t, loadTexts, showError, nextFrame, confirmBox, unlockWithPassword, authFor, saveKeys, loadKeys, wireStrength, wireReveal, wireLogout, copy } from "./common.js";

await loadTexts();
const errBox = document.getElementById("pz-error");
const okBox = document.getElementById("pz-ok");

function ok(msg) { showError(errBox, ""); okBox.textContent = msg; okBox.hidden = false; okBox.scrollIntoView({ block: "nearest" }); }

function wire(id, handler) {
  const f = document.getElementById(id);
  if (!f) return;
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError(errBox, "");
    okBox.hidden = true;
    const b = ev.submitter || f.querySelector("button.primary");
    if (b && b.dataset.ask && !(await confirmBox(b.dataset.ask, b.textContent, true))) return;
    if (b) { b.disabled = true; b.classList.add("loading"); }
    await nextFrame();
    try {
      await handler(f, b ? b.value : "");
    } catch (e) {
      showError(errBox, e.message);
    } finally {
      if (b) { b.disabled = false; b.classList.remove("loading"); }
    }
  });
}

wire("f-password", async (f) => {
  const acct = await api("GET", "/api/account");
  const pw = f.password.value;
  if (pw.length < acct.min_length) throw new Error(t("The master password must have at least %d characters.", acct.min_length));
  if (pw !== f.password2.value) throw new Error(t("The master passwords do not match."));
  if (pw === f.current.value) throw new Error(t("The new master password must be different."));
  let opened;
  try {
    opened = await unlockWithPassword(acct, f.current.value);
  } catch (e) {
    throw new Error(t("The current master password is wrong."));
  }
  const keys = await pz.rewrap(pw, opened.keys.accountKey, acct.policy_kdf || acct.kdf);
  await api("POST", "/api/account/password", Object.assign({ current_auth: opened.auth }, keys));
  await saveKeys(opened.keys);
  f.reset();
  ok(t("Master password changed. Your other sessions were signed out."));
});

wire("f-recovery", async (f, op) => {
  const acct = await api("GET", "/api/account");
  if (op === "remove") {
    const auth = await authFor(acct, f.current.value);
    await api("POST", "/api/account/recovery", { current_auth: auth, recovery_auth: "", recovery_wrapped_key: "" });
    location.reload();
    return;
  }
  let opened;
  try {
    opened = await unlockWithPassword(acct, f.current.value);
  } catch (e) {
    throw new Error(t("The current master password is wrong."));
  }
  const key = pz.newRecoveryKey();
  const bundle = await pz.recoveryBundle(key, opened.keys.accountKey);
  await api("POST", "/api/account/recovery", Object.assign({ current_auth: opened.auth }, bundle));
  f.reset();
  document.getElementById("rkey-text").textContent = key;
  document.getElementById("rkey-show").hidden = false;
  ok(t("New recovery key saved. Store it now — it is shown only once."));
});

const pb = document.getElementById("rkey-print");
if (pb) pb.addEventListener("click", () => {
  const key = document.getElementById("rkey-text").textContent;
  const w = window.open("", "_blank", "width=600,height=400");
  if (!w) { copy(key, true); return; }
  const d = w.document;
  d.title = "PassZit — " + t("Recovery key");
  const h = d.createElement("h1"); h.textContent = "PassZit — " + t("Recovery key");
  const p = d.createElement("p"); p.textContent = t("Account") + ": " + document.body.querySelector(".uname").firstChild.textContent;
  const k = d.createElement("pre"); k.textContent = key; k.style.fontSize = "22px";
  const n = d.createElement("p"); n.textContent = t("Keep this paper safe. Anyone with this key and your second factor can take over your vault.");
  d.body.append(h, p, k, n);
  w.print();
});

wireStrength();
wireReveal();
wireLogout();

// The fingerprint of the own public key, computed here from the unlocked
// keys (not taken from the server, which could show a different one).
(async () => {
  const box = document.getElementById("pz-fingerprint");
  try {
    const keys = await loadKeys();
    if (box && keys && keys.publicKey) box.textContent = await pz.fingerprint(keys.publicKey);
  } catch (e) { /* locked */ }
})();

// Security keys and passkeys
import("./keys.js").then(({ keysSupported, registerKey }) => {
  const f = document.getElementById("f-key");
  if (!f) return;
  if (!keysSupported()) {
    f.hidden = true;
    document.getElementById("key-unsupported").hidden = false;
    return;
  }
  wire("f-key", async () => {
    try {
      await registerKey(f.name.value.trim());
    } catch (e) {
      if (e.name === "NotAllowedError" || e.name === "AbortError") throw new Error(t("The security key did not answer, or the request was cancelled."));
      if (e.name === "InvalidStateError") throw new Error(t("This security key is registered already."));
      throw e;
    }
    location.href = "/account#keys";
    location.reload();
  });
});

// Emergency access
import("./emergency.js").then(({ initEmergency }) => {
  const box = document.getElementById("pz-emergency");
  if (box) initEmergency(box, document.body.dataset.email || "").catch((e) => { box.textContent = e.message; });
});
