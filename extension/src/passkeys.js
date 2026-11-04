// Passkeys kept in the vault: PassZit acts as a WebAuthn authenticator for
// websites. The private key (ECDSA P-256) is part of an encrypted vault
// item, so it reaches the user's other browsers like any login; signing
// happens here in the extension. Origin and relying party come from the
// page's real address, never from the page.
import * as pz from "./pz/crypto.js";
import { siteOf, isIPHost } from "./domain.js";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

// ---- CBOR (only what attestation objects and COSE keys need)

function cborHead(major, n) {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
  return [(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}

export function cbor(v) {
  const out = [];
  const put = (x) => {
    if (typeof x === "number") {
      if (x >= 0) out.push(...cborHead(0, x)); else out.push(...cborHead(1, -1 - x));
    } else if (typeof x === "string") {
      const b = enc.encode(x); out.push(...cborHead(3, b.length), ...b);
    } else if (x instanceof Uint8Array) {
      out.push(...cborHead(2, x.length), ...x);
    } else if (x instanceof Map) {
      out.push(...cborHead(5, x.size));
      for (const [k, val] of x) { put(k); put(val); }
    } else throw new Error("cbor: unsupported value");
  };
  put(v);
  return new Uint8Array(out);
}

const concat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const sha256 = async (b) => new Uint8Array(await subtle.digest("SHA-256", b));
const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]);

// rawToDer turns WebCrypto's r‖s into the DER signature WebAuthn uses.
export function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
  return concat(new Uint8Array([0x30, r.length + s.length]), r, s);
}

// rpCheck returns the relying party id for a page, or "" when the page may
// not use it: the id must be the page's host or a parent domain that is
// not a public suffix. As in browsers, IP addresses are no relying party
// ids, and plain HTTP is allowed only for localhost.
export function rpCheck(pageURL, wanted) {
  let u;
  try { u = new URL(pageURL); } catch (e) { return ""; }
  const host = u.hostname.toLowerCase();
  if (!host || isIPHost(host)) return "";
  const secure = u.protocol === "https:" || (u.protocol === "http:" && host === "localhost");
  if (!secure) return "";
  const rp = String(wanted || host).toLowerCase();
  if (isIPHost(rp)) return "";
  if (host !== rp && !host.endsWith("." + rp)) return "";
  const site = siteOf(host) || host;
  if (rp !== site && !rp.endsWith("." + site)) return "";
  return rp;
}

// No "user verified" flag: a click in PassZit's window is user presence,
// not verification (no PIN, password or biometric at that moment).
const FLAGS_GET = 0x19; // user present, backup eligible, backed up
const FLAGS_CREATE = 0x59; // … and attested credential data

// newPasskey makes a key pair and the answer to navigator.credentials.create.
export async function newPasskey({ rpId, origin, challenge, user }) {
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", kp.publicKey);
  const x = pz.unb64u(jwk.x), y = pz.unb64u(jwk.y);
  const credId = pz.random(16);
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
  const authData = concat(await sha256(enc.encode(rpId)), new Uint8Array([FLAGS_CREATE]), u32(0),
    new Uint8Array(16), new Uint8Array([credId.length >> 8, credId.length & 255]), credId, cose);
  const clientData = enc.encode(JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false }));
  const attestation = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
  const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
  return {
    stored: { credentialId: pz.b64u(credId), rpId, userHandle: user.id, userName: user.name || "", userDisplayName: user.displayName || "",
      privateKey: pz.b64u(pkcs8), algorithm: -7, created: new Date().toISOString() },
    answer: { op: "create", id: pz.b64u(credId), clientDataJSON: pz.b64u(clientData), attestationObject: pz.b64u(attestation),
      authenticatorData: pz.b64u(authData), publicKey: pz.b64u(spki) },
  };
}

// sign answers navigator.credentials.get with a stored passkey.
export async function sign(pk, { origin, challenge }) {
  const key = await subtle.importKey("pkcs8", pz.unb64u(pk.privateKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const authData = concat(await sha256(enc.encode(pk.rpId)), new Uint8Array([FLAGS_GET]), u32(0));
  const clientData = enc.encode(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
  const raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, concat(authData, await sha256(clientData))));
  return { op: "get", id: pk.credentialId, clientDataJSON: pz.b64u(clientData), authenticatorData: pz.b64u(authData),
    signature: pz.b64u(rawToDer(raw)), userHandle: pk.userHandle || "" };
}
