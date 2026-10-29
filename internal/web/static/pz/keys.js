// Security keys and passkeys (WebAuthn) as a second factor. The browser
// talks to the key; the server checks the answers.
import * as pz from "./crypto.js";
import { api } from "./common.js";

export function keysSupported() {
  return !!(window.PublicKeyCredential && window.isSecureContext && navigator.credentials);
}

const b = (buf) => pz.b64u(new Uint8Array(buf));

export async function registerKey(name) {
  const o = await api("POST", "/api/account/keys/start");
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: pz.unb64u(o.challenge),
    rp: { id: o.rp_id, name: o.rp_name },
    user: { id: pz.unb64u(o.user_id), name: o.user_name, displayName: o.user_name },
    pubKeyCredParams: o.algs.map((alg) => ({ type: "public-key", alg })),
    excludeCredentials: o.exclude.map((c) => ({ type: c.type, id: pz.unb64u(c.id) })),
    authenticatorSelection: { userVerification: "preferred", residentKey: "discouraged" },
    attestation: "none",
    timeout: 120000,
  } });
  await api("POST", "/api/account/keys", { name, registration: {
    id: b(cred.rawId), client_data: b(cred.response.clientDataJSON), attestation: b(cred.response.attestationObject),
  } });
}

export async function signInWithKey() {
  const o = await api("POST", "/api/login/key/start");
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: pz.unb64u(o.challenge),
    rpId: o.rp_id,
    allowCredentials: o.allow.map((c) => ({ type: c.type, id: pz.unb64u(c.id) })),
    userVerification: "preferred",
    timeout: 120000,
  } });
  return api("POST", "/api/login/key", {
    id: b(cred.rawId), client_data: b(cred.response.clientDataJSON),
    authenticator_data: b(cred.response.authenticatorData), signature: b(cred.response.signature),
  });
}
