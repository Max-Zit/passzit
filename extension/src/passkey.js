// Passes the website's passkey requests (from passkey-page.js in the page)
// to the extension and its answers back. The extension decides by the
// page's real address, not by anything the page says.
(() => {
  const api = globalThis.browser || globalThis.chrome;
  if (window.__pzPasskeyBridge) return;
  window.__pzPasskeyBridge = true;
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin || !e.data || e.data.type !== "pz-pk-req") return;
    const m = e.data;
    if (typeof m.id !== "string" || m.id.length > 64 || (m.op !== "create" && m.op !== "get")) return;
    api.runtime.sendMessage({ type: "passkeyRequest", op: m.op, options: m.options }).then(
      // r = { ok, data: the handler's { ok, data: answer } }
      (r) => window.postMessage({ type: "pz-pk-res", id: m.id, answer: r && r.ok && r.data && r.data.ok ? r.data.data : { ok: false } }, location.origin),
      () => window.postMessage({ type: "pz-pk-res", id: m.id, answer: { ok: false } }, location.origin));
  });
})();
