// One-time codes (TOTP, RFC 6238) for logins that store an authenticator
// key. The key is part of the encrypted item; codes are made here.

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32(text) {
  const s = text.toUpperCase().replace(/[\s=-]/g, "");
  if (!s || /[^A-Z2-7]/.test(s)) throw new Error("not base32");
  const out = [];
  let bits = 0, val = 0;
  for (const c of s) {
    val = (val << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

// parse reads a key: base32 text, or an otpauth://totp/… address.
export function parse(input) {
  const s = (input || "").trim();
  if (!s) return null;
  const cfg = { algorithm: "SHA-1", digits: 6, period: 30, issuer: "", label: "" };
  let secret = s;
  if (/^otpauth:\/\//i.test(s)) {
    let u;
    try { u = new URL(s); } catch (e) { throw new Error("bad otpauth"); }
    if (u.host.toLowerCase() !== "totp") throw new Error("only TOTP");
    const q = u.searchParams;
    secret = q.get("secret") || "";
    const alg = (q.get("algorithm") || "SHA1").toUpperCase().replace("-", "");
    cfg.algorithm = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" }[alg];
    if (!cfg.algorithm) throw new Error("unknown algorithm");
    cfg.digits = parseInt(q.get("digits") || "6", 10);
    cfg.period = parseInt(q.get("period") || "30", 10);
    cfg.issuer = q.get("issuer") || "";
    cfg.label = decodeURIComponent(u.pathname.replace(/^\/+/, ""));
    if (![6, 7, 8].includes(cfg.digits) || !(cfg.period >= 10 && cfg.period <= 300)) throw new Error("bad parameters");
  }
  cfg.key = base32(secret);
  if (cfg.key.length < 10) throw new Error("key too short");
  return cfg;
}

// code returns the code at a time (ms) and the seconds it is still valid.
export async function code(cfg, now) {
  const t = Math.floor((now === undefined ? Date.now() : now) / 1000);
  const counter = Math.floor(t / cfg.period);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) { msg[i] = c & 255; c = Math.floor(c / 256); }
  const k = await crypto.subtle.importKey("raw", cfg.key, { name: "HMAC", hash: cfg.algorithm }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
  const off = mac[mac.length - 1] & 15;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  const value = String(bin % 10 ** cfg.digits).padStart(cfg.digits, "0");
  return { value, remaining: cfg.period - (t % cfg.period), period: cfg.period };
}
