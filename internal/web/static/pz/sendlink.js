// Secret links (Send). The content is sealed here with a key that lives
// only in the link's #fragment; browsers never send the fragment to a
// server. An optional password adds a second key: the server only checks
// a value derived from it (to count wrong guesses), the content key needs
// the password itself.
import * as pz from "./crypto.js";

const aad = (id) => "passzit/send/v1|" + id;

async function keysFor(id, linkKey, password) {
  if (!password) return { content: await pz.derive(linkKey, "passzit/send-key/v1"), auth: "" };
  const pw = await pz.masterKey(password, pz.utf8("passzit/send/v1|" + id), { alg: "pbkdf2-sha256", t: 600000 });
  const both = new Uint8Array(linkKey.length + pw.length);
  both.set(linkKey);
  both.set(pw, linkKey.length);
  return { content: await pz.derive(both, "passzit/send-key/v1"), auth: pz.b64u(await pz.derive(pw, "passzit/send-auth/v1")) };
}

// sealSend makes a link: { id, data (base64url), auth, fragment }.
export async function sealSend(payload, password) {
  const id = pz.b64u(pz.random(16));
  const linkKey = pz.random(32);
  const k = await keysFor(id, linkKey, password);
  const data = await pz.sealBytes(k.content, pz.utf8(JSON.stringify(payload)), aad(id));
  return { id, data: pz.b64u(data), auth: k.auth, fragment: pz.b64u(linkKey) };
}

// authFor is the value the server checks for a password-protected link.
export async function authFor(id, fragment, password) {
  return (await keysFor(id, pz.unb64u(fragment), password)).auth;
}

// openSend opens what the server returned.
export async function openSend(id, fragment, password, dataB64) {
  const k = await keysFor(id, pz.unb64u(fragment), password);
  const plain = await pz.openBytes(k.content, pz.unb64u(dataB64), aad(id));
  return JSON.parse(pz.fromUtf8(plain));
}
