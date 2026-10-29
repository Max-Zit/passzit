// Password and passphrase generator (web vault and extension). All
// randomness comes from crypto.getRandomValues, without modulo bias.
import { WORDS } from "./words.js";

const SETS = {
  lower: "abcdefghijkmnopqrstuvwxyz",
  upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  digits: "23456789",
  symbols: "!@#$%^&*-_=+?.,:;~",
};
// The similar-looking characters (l 1 I O 0) are left out unless asked for.
const SIMILAR = { lower: "l", upper: "IO", digits: "01" };

export const DEFAULTS = { kind: "password", length: 20, lower: true, upper: true, digits: true, symbols: true, similar: false,
  words: 5, separator: "-", capitalize: true, number: true };

// randomInt returns a uniform integer in [0, n).
export function randomInt(n) {
  if (n <= 0 || n > 0x100000000) throw new Error("range");
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

function pick(s) { return s[randomInt(s.length)]; }

function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// password makes a random password with at least one character of every
// chosen kind.
export function password(o) {
  const opt = Object.assign({}, DEFAULTS, o);
  const len = Math.max(4, Math.min(128, opt.length | 0));
  const sets = [];
  for (const k of ["lower", "upper", "digits", "symbols"]) {
    if (opt[k]) sets.push(SETS[k] + (opt.similar ? SIMILAR[k] || "" : ""));
  }
  if (!sets.length) sets.push(SETS.lower);
  const all = sets.join("");
  const out = sets.map(pick);
  while (out.length < len) out.push(pick(all));
  return shuffle(out).join("");
}

// passphrase makes words from the EFF list (12.9 bits each).
export function passphrase(o) {
  const opt = Object.assign({}, DEFAULTS, o);
  const n = Math.max(3, Math.min(20, opt.words | 0));
  const words = [];
  for (let i = 0; i < n; i++) {
    let w = WORDS[randomInt(WORDS.length)];
    if (opt.capitalize) w = w[0].toUpperCase() + w.slice(1);
    words.push(w);
  }
  if (opt.number) {
    const i = randomInt(n);
    words[i] += String(randomInt(10));
  }
  return words.join(opt.separator === undefined ? "-" : String(opt.separator).slice(0, 3));
}

export function generate(o) {
  return (o && o.kind === "passphrase") ? passphrase(o) : password(o);
}

// entropy estimates the strength of what generate makes with these options.
export function entropy(o) {
  const opt = Object.assign({}, DEFAULTS, o);
  if (opt.kind === "passphrase") {
    const n = Math.max(3, Math.min(20, opt.words | 0));
    return Math.round(n * Math.log2(WORDS.length) + (opt.number ? Math.log2(10 * n) : 0));
  }
  let pool = 0;
  for (const k of ["lower", "upper", "digits", "symbols"]) if (opt[k]) pool += SETS[k].length + (opt.similar ? (SIMILAR[k] || "").length : 0);
  return Math.round(Math.max(4, Math.min(128, opt.length | 0)) * Math.log2(Math.max(pool, 2)));
}

const PREFS = "pz.generator";

export function loadOptions() {
  try { return Object.assign({}, DEFAULTS, JSON.parse(localStorage.getItem(PREFS) || "{}")); } catch (e) { return Object.assign({}, DEFAULTS); }
}

export function saveOptions(o) {
  try { localStorage.setItem(PREFS, JSON.stringify(o)); } catch (e) { /* private mode */ }
}
