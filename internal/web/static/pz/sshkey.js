// SSH keys in the vault: make an Ed25519 key pair in the browser (OpenSSH
// format) and show fingerprints. The private key never leaves the browser
// unencrypted.

const te = new TextEncoder();

function u32(n) { return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }

function str(b) {
  const bytes = typeof b === "string" ? te.encode(b) : b;
  return concat(u32(bytes.length), bytes);
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// generate makes an Ed25519 key pair: { privateKey (OpenSSH PEM), publicKey, fingerprint }.
export async function generate(comment) {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const seed = pkcs8.slice(pkcs8.length - 32); // PKCS #8 of Ed25519 ends with the 32-byte seed
  const c = (comment || "").slice(0, 100);
  const pubBlob = concat(str("ssh-ed25519"), str(pub));
  const check = crypto.getRandomValues(new Uint8Array(4));
  let priv = concat(check, check, str("ssh-ed25519"), str(pub), str(concat(seed, pub)), str(c));
  const pad = [];
  for (let i = 1; (priv.length + pad.length) % 8 !== 0; i++) pad.push(i);
  priv = concat(priv, new Uint8Array(pad));
  const body = concat(te.encode("openssh-key-v1\0"), str("none"), str("none"), str(""), u32(1), str(pubBlob), str(priv));
  const lines = b64(body).match(/.{1,70}/g).join("\n");
  seed.fill(0);
  return {
    privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + lines + "\n-----END OPENSSH PRIVATE KEY-----\n",
    publicKey: "ssh-ed25519 " + b64(pubBlob) + (c ? " " + c : ""),
    fingerprint: await fingerprint("ssh-ed25519 " + b64(pubBlob)),
  };
}

// fingerprint is the OpenSSH SHA256 fingerprint of a public key line.
export async function fingerprint(publicKey) {
  const parts = (publicKey || "").trim().split(/\s+/);
  if (parts.length < 2) return "";
  let blob;
  try { blob = unb64(parts[1]); } catch (e) { return ""; }
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
  return "SHA256:" + b64(h).replace(/=+$/, "");
}
