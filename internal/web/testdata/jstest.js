// Browser side of TestJavaScriptCrypto: runs static/pz/crypto.js and
// generator.js against the Go reference values (case.json) and writes the
// results back to the test server.
import * as pz from "/static/pz/crypto.js";
import { password, passphrase, randomInt } from "/static/pz/generator.js";
import { siteOf, match } from "/ext/domain.js";
import * as tr from "/static/pz/transfer.js";
import * as totp from "/static/pz/totp.js";
import * as sshkey from "/static/pz/sshkey.js";
import * as sl from "/static/pz/sendlink.js";
import * as qr from "/static/pz/qr.js";

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
  out.fileSealed = pz.b64u(await pz.sealBytes(pz.unhex(c.key), pz.utf8("file from javascript"), pz.AAD.file("f-1")));
  out.fileRoundTrip = pz.fromUtf8(await pz.openBytes(pz.unhex(c.key), pz.unb64u(out.fileSealed), pz.AAD.file("f-1"))) === "file from javascript";
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
  // registrable domains (Public Suffix List) and login matching
  const sites = { "www.example.com": "example.com", "a.b.example.co.uk": "example.co.uk", "foo.github.io": "foo.github.io", "github.io": "github.io",
    "city.kawasaki.jp": "city.kawasaki.jp", "x.y.kawasaki.jp": "x.y.kawasaki.jp", "192.168.1.10": "192.168.1.10", "intranet": "intranet", "shop.example.com.": "example.com" };
  out.sites = Object.entries(sites).filter(([h, want]) => siteOf(h) !== want).map(([h, want]) => h + "=" + siteOf(h) + " want " + want);
  const cases = [["https://github.com/login", "https://github.com/session", "host"], ["github.com", "https://gist.github.com/", "site"],
    ["https://a.github.io", "https://b.github.io", ""], ["https://example.com", "http://example.com", ""], ["http://example.com", "https://example.com", "host"],
    ["https://example.co.uk", "https://evil.co.uk", ""], ["https://10.0.0.1:8443", "https://10.0.0.1:8443/x", "host"], ["https://10.0.0.1:8443", "https://10.0.0.1/", ""],
    ["https://bank.example", "https://bank.example.evil.com", ""], ["javascript:alert(1)", "https://x.com", ""]];
  out.matches = cases.filter(([a, b, want]) => match(a, b) !== want).map(([a, b, want]) => a + " vs " + b + " = " + match(a, b) + " want " + want);
  // importers and exporters
  const imp = [];
  const expect = (name, cond, info) => { if (!cond) imp.push(name + ": " + JSON.stringify(info)); };
  let r = tr.detect("name,url,username,password,note\nGitHub,https://github.com/login,alice,pw1,hello\n");
  expect("chrome", r.items.length === 1 && r.items[0].login.username === "alice" && r.items[0].login.password === "pw1" && r.items[0].notes === "hello", r.items);
  r = tr.detect('"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\r\n"https://example.com","bob","p,w""2","","https://example.com","{x}","1","1","1"\r\n');
  expect("firefox", r.items.length === 1 && r.items[0].login.password === 'p,w"2' && r.items[0].name === "example.com", r.items);
  r = tr.detect("url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,Wifi key 42,Home Wi-Fi,Home,1\nhttps://a.com,u,p,,,A,Work\\Sub,0\n");
  expect("lastpass", r.items.length === 2 && r.items[0].type === "note" && r.items[0].notes === "Wifi key 42" && r.items[0].favorite && r.items[1].folder === "Work/Sub", r.items);
  r = tr.detect(JSON.stringify({ encrypted: false, folders: [{ id: "f1", name: "Bank" }], items: [
    { type: 1, name: "B", folderId: "f1", favorite: true, login: { username: "u", password: "p", totp: "JBSWY3DP", uris: [{ uri: "https://b.com" }] }, fields: [{ name: "PIN", value: "1234", type: 1 }] },
    { type: 2, name: "N", notes: "secret note" },
    { type: 3, name: "Visa", card: { cardholderName: "Ana", brand: "Visa", number: "4111111111111111", expMonth: "7", expYear: "2030", code: "123" } },
    { type: 4, name: "Me", identity: { firstName: "Ana", lastName: "Petrović", city: "Beograd", address2: "Sprat 2", address3: "Stan 5" } },
    { type: 99, name: "unknown is skipped" }] }));
  expect("bitwarden", r.items.length === 4 && r.items[0].folder === "Bank" && r.items[0].login.totp === "JBSWY3DP" && r.items[0].fields[0].hidden && r.items[1].type === "note" && r.items[2].card.number === "4111111111111111" && r.items[2].card.expYear === "2030" && r.items[2].login.username === "" && r.items[3].identity.last === "Petrović" && r.items[3].identity.address2 === "Sprat 2, Stan 5", r.items);
  r = tr.detect('<?xml version="1.0"?><KeePassFile><Meta><RecycleBinUUID>RB</RecycleBinUUID></Meta><Root><Group><UUID>R</UUID><Name>Root</Name>' +
    '<Entry><String><Key>Title</Key><Value>Top</Value></String><String><Key>Password</Key><Value ProtectInMemory="True">t</Value></String></Entry>' +
    '<Group><UUID>G</UUID><Name>Servers</Name><Entry><String><Key>Title</Key><Value>pve</Value></String><String><Key>UserName</Key><Value>root</Value></String>' +
    '<String><Key>Password</Key><Value ProtectInMemory="True">x&lt;y</Value></String><String><Key>URL</Key><Value>https://pve:8006</Value></String>' +
    '<String><Key>API key</Key><Value ProtectInMemory="True">k</Value></String></Entry>' +
    '<Group><UUID>G2</UUID><Name>Lab</Name><Entry><String><Key>Title</Key><Value>deep</Value></String><String><Key>Password</Key><Value>d</Value></String></Entry></Group></Group>' +
    '<Group><UUID>RB</UUID><Name>Recycle Bin</Name><Entry><String><Key>Title</Key><Value>gone</Value></String></Entry></Group></Group></Root></KeePassFile>');
  const kp = Object.fromEntries(r.items.map((i) => [i.name, i]));
  expect("keepass", r.items.length === 3 && kp.Top.folder === "" && kp.pve.folder === "Servers" && kp.pve.login.password === "x<y" && kp.pve.fields[0].hidden && kp.deep.folder === "Servers/Lab", r.items);
  const csv = tr.exportCSV([{ type: "login", name: "Q, \"quoted\"", folderName: "F", favorite: true, notes: "line1\nline2", login: { username: "u", password: "p\"w", urls: ["https://q.com", "https://r.com"], totp: "T" }, fields: [] }]);
  r = tr.detect(csv);
  expect("csv round trip", r.items.length === 1 && r.items[0].name === 'Q, "quoted"' && r.items[0].login.password === 'p"w' && r.items[0].login.urls.length === 2 && r.items[0].notes === "line1\nline2" && r.items[0].folder === "F" && r.items[0].login.totp === "T", r.items);
  const enc = await tr.exportEncrypted({ version: 1, items: [{ name: "x" }] }, "export-password-1", { alg: "argon2id", m: 19456, t: 2, p: 1 });
  const det = tr.detect(enc);
  const back = await tr.importEncrypted(det.encrypted, "export-password-1");
  let wrong = "opened";
  try { await tr.importEncrypted(det.encrypted, "wrong-password-1"); } catch (e) { wrong = e.name; }
  expect("encrypted export", back.items[0].name === "x" && wrong === "DecryptError" && !enc.includes('"x"'), { back, wrong });
  try { tr.detect("just some text"); imp.push("garbage accepted"); } catch (e) { /* refused */ }
  out.imports = imp;
  // TOTP: RFC 6238 test vectors (T = 59 s, 8 digits) and otpauth addresses
  const tv = [];
  for (const [alg, b32, want] of c.totp) {
    const cfg = totp.parse("otpauth://totp/x?secret=" + b32 + "&algorithm=" + alg + "&digits=8");
    const r2 = await totp.code(cfg, 59000);
    if (r2.value !== want || r2.remaining !== 1) tv.push(alg + " " + r2.value + " want " + want);
  }
  const plain = await totp.code(totp.parse(c.totp[0][1].toLowerCase().replace(/(.{4})/g, "$1 ")), 1111111109000);
  if (plain.value !== "081804") tv.push("plain base32 " + plain.value);
  out.totp = tv;
  // SSH keys made in the browser are checked by Go
  out.ssh = await sshkey.generate("test@passzit");
  // secret links: open again, with and without a password
  const s1 = await sl.sealSend({ text: "hello" }, "");
  out.send1 = (await sl.openSend(s1.id, s1.fragment, "", s1.data)).text === "hello" && s1.auth === "";
  const s2 = await sl.sealSend({ text: "pw" }, "secret pass");
  let wrongPw = false;
  try { await sl.openSend(s2.id, s2.fragment, "other", s2.data); } catch (e) { wrongPw = true; }
  out.send2 = wrongPw && (await sl.openSend(s2.id, s2.fragment, "secret pass", s2.data)).text === "pw" && s2.auth === await sl.authFor(s2.id, s2.fragment, "secret pass") && s2.auth.length === 43;
  // QR codes (authenticator keys) are read by qr.wasm
  out.qr = (await qr.readQR(await (await fetch("/qr.png")).blob())).join("|");
  // every page script and extension module must at least parse
  out.syntax = [];
  for (const m of ["/static/pz/vault.js", "/static/pz/auth.js", "/static/pz/account.js", "/static/pz/genpage.js", "/static/pz/genui.js", "/static/pz/common.js", "/static/pz/sharing.js", "/static/pz/keys.js", "/static/pz/sends.js", "/static/pz/sendlink.js", "/static/pz/emergency.js", "/static/pz/qr.js",
    "/ext/popup.js", "/ext/background.js", "/ext/client.js", "/ext/ext.js", "/ext/domain.js"]) {
    try { await import(m); } catch (e) { if (e instanceof SyntaxError) out.syntax.push(m + ": " + e.message); }
  }
  out.uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(pz.uuid());
} catch (e) {
  out.error = String(e && e.stack || e);
}
document.getElementById("result").textContent = JSON.stringify(out);
await fetch("/result", { method: "POST", body: JSON.stringify(out) });
