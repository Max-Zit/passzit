// PassZit client cryptography (web vault and browser extension).
// The same scheme as internal/vaultcrypto (Go), which is the reference:
// both are checked against the same test vectors. Everything secret stays
// in this browser; the server only receives the auth key and ciphertext.

const te = new TextEncoder();
const td = new TextDecoder();
const subtle = globalThis.crypto.subtle;

export const VERSION = 1;
export const DEFAULT_KDF = { alg: "argon2id", m: 64 * 1024, t: 3, p: 4 };

export const INFO = {
  auth: "passzit/auth/v1",
  wrap: "passzit/wrap/v1",
  recoveryAuth: "passzit/recovery-auth/v1",
  recoveryWrap: "passzit/recovery-wrap/v1",
  seal: "passzit/seal/v1",
};

export const AAD = {
  accountKey: () => "passzit/account-key/v1",
  privateKey: () => "passzit/private-key/v1",
  vaultKey: (vaultID) => "passzit/vault-key/v1|" + vaultID,
  item: (vaultID, itemID) => "passzit/item/v1|" + vaultID + "|" + itemID,
  folder: (folderID) => "passzit/folder/v1|" + folderID,
  session: () => "passzit/session/v1",
  export: () => "passzit/export/v1",
};

// ---- encodings

export function utf8(s) { return te.encode(s); }
export function fromUtf8(b) { return td.decode(b); }

export function b64u(bytes) {
  let s = "";
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("bad base64");
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hex(b) { return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }
export function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function random(n) { return globalThis.crypto.getRandomValues(new Uint8Array(n)); }

// uuid is a random (version 4) UUID: ids of items, folders and vaults are
// made by the client, because they are part of the encryption (AAD).
export function uuid() {
  if (globalThis.crypto.randomUUID) return globalThis.crypto.randomUUID();
  const b = random(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = hex(b);
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
}

// wipe overwrites a key that is no longer needed (best effort: JavaScript
// may hold copies elsewhere).
export function wipe(b) { if (b && b.fill) b.fill(0); }

// ---- Argon2id (WebAssembly built from Go's x/crypto by tools/buildwasm)

let argonReady = null;

// setArgonURL lets the extension point to its own copy of the module.
let argonBase = "/static/pz/";
export function setArgonBase(url) { argonBase = url; argonReady = null; }

function loadArgon() {
  if (!argonReady) {
    argonReady = (async () => {
      if (!globalThis.Go) await import(argonBase + "wasm_exec.js");
      const go = new globalThis.Go();
      const resp = await fetch(argonBase + "argon2.wasm");
      if (!resp.ok) throw new Error("argon2.wasm: " + resp.status);
      const { instance } = await WebAssembly.instantiate(await resp.arrayBuffer(), go.importObject);
      go.run(instance); // keeps running: it only exports pzArgon2id
      if (typeof globalThis.pzArgon2id !== "function") throw new Error("argon2 module did not start");
    })();
    argonReady.catch(() => { argonReady = null; });
  }
  return argonReady;
}

export function validKDF(k) {
  if (!k || typeof k !== "object") return false;
  if (k.alg === "argon2id") return k.m >= 19 * 1024 && k.m <= 1024 * 1024 && k.t >= 2 && k.t <= 20 && k.p >= 1 && k.p <= 16;
  if (k.alg === "pbkdf2-sha256") return k.t >= 600000 && k.t <= 10000000;
  return false;
}

// masterKey derives the 32-byte master key from the password.
export async function masterKey(password, salt, kdf) {
  if (!validKDF(kdf)) throw new Error("unsupported key derivation settings");
  const pw = utf8(password.normalize("NFC"));
  try {
    if (kdf.alg === "argon2id") {
      await loadArgon();
      const k = globalThis.pzArgon2id(pw, salt, kdf.t, kdf.m, kdf.p);
      if (!k) throw new Error("argon2 refused the parameters");
      return k;
    }
    const base = await subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: kdf.t }, base, 256));
  } finally {
    wipe(pw);
  }
}

// derive is HKDF-SHA256 (no salt) to 32 bytes.
export async function derive(key, info) {
  const k = await subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(info) }, k, 256));
}

// keysFromPassword returns the auth key (for the server) and the wrap key.
export async function keysFromPassword(password, salt, kdf) {
  const mk = await masterKey(password, salt, kdf);
  try {
    return { auth: await derive(mk, INFO.auth), wrap: await derive(mk, INFO.wrap) };
  } finally {
    wipe(mk);
  }
}

// ---- AES-256-GCM: base64url(0x01 ‖ nonce ‖ ciphertext ‖ tag)

async function aesKey(key, usage) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error("keys are 32 bytes");
  return subtle.importKey("raw", key, "AES-GCM", false, [usage]);
}

export async function seal(key, plain, aad, nonce) {
  const n = nonce || random(12);
  const k = await aesKey(key, "encrypt");
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: n, additionalData: utf8(aad) }, k, plain));
  const out = new Uint8Array(1 + 12 + ct.length);
  out[0] = VERSION;
  out.set(n, 1);
  out.set(ct, 13);
  return b64u(out);
}

export class DecryptError extends Error {
  constructor() { super("cannot decrypt (wrong key or damaged data)"); this.name = "DecryptError"; }
}

export async function open(key, sealed, aad) {
  let raw;
  try { raw = unb64u(sealed); } catch (e) { throw new DecryptError(); }
  if (raw.length < 1 + 12 + 16 || raw[0] !== VERSION) throw new DecryptError();
  const k = await aesKey(key, "decrypt");
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: raw.subarray(1, 13), additionalData: utf8(aad) }, k, raw.subarray(13)));
  } catch (e) {
    throw new DecryptError();
  }
}

export async function sealJSON(key, obj, aad) { return seal(key, utf8(JSON.stringify(obj)), aad); }
export async function openJSON(key, sealed, aad) { return JSON.parse(fromUtf8(await open(key, sealed, aad))); }

// ---- X25519 key pairs (sharing)

export async function newKeyPair() {
  const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  return {
    pub: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)),
    priv: new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey)),
  };
}

async function sealKey(shared, ephPub, recipientPub) {
  const salt = new Uint8Array(64);
  salt.set(ephPub, 0);
  salt.set(recipientPub, 32);
  const k = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: utf8(INFO.seal) }, k, 256));
}

// sealTo encrypts for the owner of an X25519 public key (see Go's SealTo).
export async function sealTo(recipientPub, plain, aad) {
  const pub = await subtle.importKey("raw", recipientPub, { name: "X25519" }, false, []);
  const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, eph.privateKey, 256));
  const k = await sealKey(shared, ephPub, recipientPub);
  const inner = unb64u(await seal(k, plain, aad));
  const out = new Uint8Array(32 + inner.length);
  out.set(ephPub, 0);
  out.set(inner, 32);
  wipe(k); wipe(shared);
  return b64u(out);
}

export async function openSealed(privPKCS8, myPub, sealed, aad) {
  let raw;
  try { raw = unb64u(sealed); } catch (e) { throw new DecryptError(); }
  if (raw.length < 32 + 1 + 12 + 16) throw new DecryptError();
  const priv = await subtle.importKey("pkcs8", privPKCS8, { name: "X25519" }, false, ["deriveBits"]);
  const ephPub = raw.slice(0, 32);
  const eph = await subtle.importKey("raw", ephPub, { name: "X25519" }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: eph }, priv, 256));
  const k = await sealKey(shared, ephPub, myPub);
  try {
    return await open(k, b64u(raw.subarray(32)), aad);
  } finally {
    wipe(k); wipe(shared);
  }
}

export async function fingerprint(pub) {
  const h = hex(new Uint8Array(await subtle.digest("SHA-256", pub)).subarray(0, 20));
  return h.match(/.{4}/g).join(" ");
}

// ---- recovery key: 160 random bits as base32 in groups of four

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function formatRecoveryKey(raw) {
  let bits = 0, val = 0, s = "";
  for (const x of raw) {
    val = (val << 8) | x; bits += 8;
    while (bits >= 5) { s += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) s += B32[(val << (5 - bits)) & 31];
  return s.match(/.{1,4}/g).join("-");
}

export function parseRecoveryKey(text) {
  const s = text.trim().replace(/[-\s]/g, "").toUpperCase().replace(/0/g, "O").replace(/1/g, "I").replace(/8/g, "B");
  if (s.length !== 32 || /[^A-Z2-7]/.test(s)) throw new Error("this is not a recovery key");
  const out = new Uint8Array(20);
  let bits = 0, val = 0, j = 0;
  for (const c of s) {
    val = (val << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { out[j++] = (val >>> (bits - 8)) & 255; bits -= 8; }
  }
  return out;
}

export function newRecoveryKey() { return formatRecoveryKey(random(20)); }

// ---- account creation and unlocking

// newAccount makes every key of a new account from the master password.
// The result holds what the server stores (all wrapped) and, in .keys,
// the plain keys for this session.
export async function newAccount(password, kdf) {
  const k = kdf || DEFAULT_KDF;
  const salt = random(16);
  const { auth, wrap } = await keysFromPassword(password, salt, k);
  const accountKey = random(32);
  const kp = await newKeyPair();
  const vaultID = uuid();
  const vaultKey = random(32);
  const out = {
    kdf: k,
    salt: b64u(salt),
    auth: b64u(auth),
    wrapped_account_key: await seal(wrap, accountKey, AAD.accountKey()),
    public_key: b64u(kp.pub),
    wrapped_private_key: await seal(accountKey, kp.priv, AAD.privateKey()),
    vault: { id: vaultID, wrapped_key: await seal(accountKey, vaultKey, AAD.vaultKey(vaultID)) },
    keys: { accountKey, privateKey: kp.priv, publicKey: kp.pub },
  };
  wipe(wrap); wipe(auth); wipe(vaultKey);
  return out;
}

// unlockAccount opens the account key with the wrap key; a wrong master
// password ends in DecryptError.
export async function unlockAccount(wrap, acct) {
  const accountKey = await open(wrap, acct.wrapped_account_key, AAD.accountKey());
  const privateKey = await open(accountKey, acct.wrapped_private_key, AAD.privateKey());
  return { accountKey, privateKey, publicKey: unb64u(acct.public_key) };
}

// rewrap wraps the account key under a new master password (change of the
// password, recovery, stronger key derivation).
export async function rewrap(password, accountKey, kdf) {
  const salt = random(16);
  const { auth, wrap } = await keysFromPassword(password, salt, kdf);
  const out = { kdf, salt: b64u(salt), auth: b64u(auth), wrapped_account_key: await seal(wrap, accountKey, AAD.accountKey()) };
  wipe(wrap); wipe(auth);
  return out;
}

// recoveryBundle prepares a recovery key: what the server stores.
export async function recoveryBundle(recoveryText, accountKey) {
  const raw = parseRecoveryKey(recoveryText);
  const out = {
    recovery_auth: b64u(await derive(raw, INFO.recoveryAuth)),
    recovery_wrapped_key: await seal(await derive(raw, INFO.recoveryWrap), accountKey, AAD.accountKey()),
  };
  wipe(raw);
  return out;
}

export async function recoveryKeys(recoveryText) {
  const raw = parseRecoveryKey(recoveryText);
  try {
    return { auth: await derive(raw, INFO.recoveryAuth), wrap: await derive(raw, INFO.recoveryWrap) };
  } finally {
    wipe(raw);
  }
}
