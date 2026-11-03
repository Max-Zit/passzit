// Runs in the page itself (only with "Use PassZit for passkeys" on): it
// lets PassZit answer passkey requests of the website. It holds no keys and
// sees no vault data — it passes the request to the extension (through
// passkey.js) and turns the extension's answer into what browsers return.
// When PassZit does not take a request (declined, locked, no passkey for
// the site), the browser's own passkeys answer as without PassZit.
(() => {
  if (window.__pzPasskeys || !navigator.credentials || !window.PublicKeyCredential) return;
  window.__pzPasskeys = true;
  const native = { create: navigator.credentials.create.bind(navigator.credentials), get: navigator.credentials.get.bind(navigator.credentials) };
  const b64u = (buf) => {
    const b = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const unb64u = (s) => {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const bytes = (v) => v instanceof ArrayBuffer || ArrayBuffer.isView(v);
  // plain JSON of the options: buffers become base64url
  const plain = (v) => {
    if (bytes(v)) return { $b: b64u(v) };
    if (Array.isArray(v)) return v.map(plain);
    if (v && typeof v === "object") { const o = {}; for (const k of Object.keys(v)) if (k !== "signal") o[k] = plain(v[k]); return o; }
    return v;
  };
  let seq = 0;
  const ask = (op, publicKey, mediation) => new Promise((resolve) => {
    const id = "pk" + Date.now() + "-" + (++seq);
    const onMsg = (e) => {
      if (e.source !== window || !e.data || e.data.type !== "pz-pk-res" || e.data.id !== id) return;
      window.removeEventListener("message", onMsg);
      resolve(e.data.answer || { ok: false });
    };
    window.addEventListener("message", onMsg);
    window.postMessage({ type: "pz-pk-req", id, op, mediation: mediation || "", options: plain(publicKey) }, location.origin);
  });
  // the credential as browsers give it (with the methods sites call)
  const credential = (r) => {
    const raw = unb64u(r.id);
    const response = r.op === "create"
      ? { clientDataJSON: unb64u(r.clientDataJSON), attestationObject: unb64u(r.attestationObject),
        getTransports: () => ["internal", "hybrid"], getAuthenticatorData: () => unb64u(r.authenticatorData),
        getPublicKey: () => unb64u(r.publicKey), getPublicKeyAlgorithm: () => -7 }
      : { clientDataJSON: unb64u(r.clientDataJSON), authenticatorData: unb64u(r.authenticatorData),
        signature: unb64u(r.signature), userHandle: r.userHandle ? unb64u(r.userHandle) : null };
    const cred = {
      id: r.id, rawId: raw, type: "public-key", authenticatorAttachment: "platform", response,
      getClientExtensionResults: () => (r.op === "create" ? { credProps: { rk: true } } : {}),
      toJSON: () => {
        const resp = {};
        for (const [k, v] of Object.entries(response)) if (typeof v !== "function") resp[k] = v === null ? null : b64u(v);
        if (r.op === "create") { resp.transports = ["internal", "hybrid"]; resp.publicKeyAlgorithm = -7; resp.publicKey = r.publicKey; resp.authenticatorData = r.authenticatorData; }
        return { id: r.id, rawId: r.id, type: "public-key", authenticatorAttachment: "platform", response: resp, clientExtensionResults: cred.getClientExtensionResults() };
      },
    };
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    return cred;
  };
  navigator.credentials.create = async function (opts) {
    if (!opts || !opts.publicKey) return native.create(opts);
    const r = await ask("create", opts.publicKey);
    if (r.error) throw new DOMException(r.error, "NotAllowedError");
    if (!r.ok) return native.create(opts);
    return credential(r);
  };
  navigator.credentials.get = async function (opts) {
    if (!opts || !opts.publicKey || opts.mediation === "conditional") return native.get(opts);
    const r = await ask("get", opts.publicKey, opts.mediation);
    if (r.error) throw new DOMException(r.error, "NotAllowedError");
    if (!r.ok) return native.get(opts);
    return credential(r);
  };
})();
