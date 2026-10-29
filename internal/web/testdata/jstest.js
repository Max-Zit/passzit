// Browser side of TestJavaScriptCrypto: runs static/pz/crypto.js and
// generator.js against the Go reference values (case.json) and writes the
// results back to the test server.
import * as pz from "/static/pz/crypto.js";
import { password, passphrase, randomInt } from "/static/pz/generator.js";

const out = {};
try {
  const c = await (await fetch("/case.json")).json();
  const salt = pz.unhex(c.salt);
  const mk = await pz.masterKey(c.password, salt, c.kdf);
  out.master = pz.hex(mk);
  out.auth = pz.hex(await pz.derive(mk, pz.INFO.auth));
  out.wrap = pz.hex(await pz.derive(mk, pz.INFO.wrap));
  out.pbkdf2 = pz.hex(await pz.masterKey(c.password, salt, { alg: "pbkdf2-sha256", t: 600000 }));
  out.sealed = await pz.seal(pz.unhex(c.key), pz.utf8(c.plain), c.aad, pz.unhex(c.nonce));
  // values made by Go open here
  out.goOpen = pz.fromUtf8(await pz.open(pz.unhex(c.key), c.goSealed, c.aad));
  out.goOpenSealed = pz.fromUtf8(await pz.openSealed(pz.unb64u(c.priv), pz.unb64u(c.pub), c.goSealedTo, "x"));
  try { await pz.open(pz.unhex(c.key), c.goSealed, "other"); out.wrongAAD = "opened"; } catch (e) { out.wrongAAD = e.name; }
  // values made here are opened by Go
  out.jsSealedTo = await pz.sealTo(pz.unb64u(c.pub), pz.utf8("from javascript"), "y");
  out.recovery = pz.formatRecoveryKey(pz.unhex(c.recoveryRaw));
  out.recoveryParsed = pz.hex(pz.parseRecoveryKey(c.recoveryText.toLowerCase().replace(/-/g, " ")));
  out.fingerprint = await pz.fingerprint(pz.unb64u(c.pub));
  // a whole account round trip in the browser
  const acc = await pz.newAccount("pässwörd-Test-123", { alg: "argon2id", m: 19456, t: 2, p: 1 });
  const keys = await pz.keysFromPassword("pässwörd-Test-123", pz.unb64u(acc.salt), acc.kdf);
  const opened = await pz.unlockAccount(keys.wrap, acc);
  out.accountRoundTrip = pz.hex(opened.accountKey) === pz.hex(acc.keys.accountKey) && pz.b64u(keys.auth) === acc.auth;
  out.account = { salt: acc.salt, auth: acc.auth, wrapped_account_key: acc.wrapped_account_key, account_key: pz.b64u(acc.keys.accountKey) };
  // generator
  const pw = password({ length: 32, lower: true, upper: true, digits: true, symbols: true });
  out.genPassword = pw.length === 32 && /[a-z]/.test(pw) && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw) && !/[lIO01]/.test(pw);
  out.genPhrase = passphrase({ words: 6, separator: "-", capitalize: true, number: false }).split("-").length === 6;
  const counts = new Array(6).fill(0);
  for (let i = 0; i < 60000; i++) counts[randomInt(6)]++;
  out.uniform = counts.every((n) => Math.abs(n - 10000) < 600);
  out.uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(pz.uuid());
} catch (e) {
  out.error = String(e && e.stack || e);
}
document.getElementById("result").textContent = JSON.stringify(out);
await fetch("/result", { method: "POST", body: JSON.stringify(out) });
