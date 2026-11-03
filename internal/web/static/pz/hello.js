// Quick unlock with a passkey of this device (Windows Hello, Touch ID,
// Android) through the WebAuthn PRF extension. The authenticator turns a
// stored salt into a secret that only it can produce; from that secret the
// browser derives a key that seals the account key. The server keeps the
// sealed account key and the salt, never the secret.
import * as pz from "./crypto.js";
import { api, t } from "./common.js";

const INFO = "passzit/quick-unlock-key/v1";
const b = (buf) => pz.b64u(new Uint8Array(buf));

export function helloSupported() {
  return !!(window.PublicKeyCredential && window.isSecureContext && navigator.credentials);
}

// helloLabel names the unlock the way the user knows it.
export function helloLabel() {
  if (/Windows/.test(navigator.userAgent)) return t("Unlock with Windows Hello");
  if (/Mac OS X|iPhone|iPad/.test(navigator.userAgent)) return t("Unlock with Touch ID or Face ID");
  return t("Unlock with a passkey of this device");
}

async function keyFrom(prfOutput) {
  return pz.derive(new Uint8Array(prfOutput), INFO);
}

function noPRF() {
  return new Error(t("This browser or device cannot unlock with a passkey (the PRF extension is missing). Use Chrome, Edge or Safari of a recent version."));
}

// setupHello creates a passkey on this device and stores the account key
// sealed under its PRF secret.
export async function setupHello(name, accountKey, email) {
  const salt = pz.random(32);
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: pz.random(32), // nothing is signed for the server; the PRF secret is the point
    rp: { id: location.hostname, name: "PassZit" },
    user: { id: pz.random(16), name: email, displayName: email },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
    attestation: "none",
    timeout: 120000,
    extensions: { prf: { eval: { first: salt } } },
  } });
  const ext = cred.getClientExtensionResults().prf || {};
  if (!ext.enabled && !ext.results) throw noPRF();
  const id = b(cred.rawId);
  // Some authenticators give the PRF output only when the passkey is used.
  let out = ext.results && ext.results.first;
  if (!out) out = await prfOf([{ id, salt: pz.b64u(salt) }]).then((r) => r.out);
  const key = await keyFrom(out);
  const wrapped = await pz.seal(key, accountKey, pz.AAD.unlockKey(id));
  pz.wipe(key);
  await api("POST", "/api/unlock-keys", { id, name, salt: pz.b64u(salt), wrapped });
}

// prfOf asks the authenticator for the PRF output of one of the passkeys.
async function prfOf(keys) {
  const evalBy = {};
  for (const k of keys) evalBy[k.id] = { first: pz.unb64u(k.salt) };
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: pz.random(32),
    rpId: location.hostname,
    allowCredentials: keys.map((k) => ({ type: "public-key", id: pz.unb64u(k.id) })),
    userVerification: "required",
    timeout: 120000,
    extensions: { prf: { evalByCredential: evalBy } },
  } });
  const r = cred.getClientExtensionResults().prf;
  if (!r || !r.results || !r.results.first) throw noPRF();
  return { id: b(cred.rawId), out: r.results.first };
}

// helloKeys lists the unlock passkeys of the account ([] when none or when
// the browser cannot use them).
export async function helloKeys() {
  if (!helloSupported()) return [];
  try { return (await api("GET", "/api/unlock-keys")).keys || []; } catch (e) { return []; }
}

// unlockWithHello returns the account key.
export async function unlockWithHello(keys) {
  const { id, out } = await prfOf(keys);
  const k = keys.find((x) => x.id === id);
  if (!k) throw new Error(t("This passkey does not unlock the vault."));
  const key = await keyFrom(out);
  try {
    const accountKey = await pz.open(key, k.wrapped, pz.AAD.unlockKey(id));
    api("POST", "/api/unlock-keys/" + encodeURIComponent(id) + "/used").catch(() => {});
    return accountKey;
  } finally {
    pz.wipe(key);
  }
}
