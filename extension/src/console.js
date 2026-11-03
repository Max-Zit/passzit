// Runs only on the MaxZit consoles (WatchZit) the user added in the
// extension's settings. When the console's "Open with" button posts
// {type: "maxzit-open", nonce, tool, host, port, user, device}, the
// extension looks for a login saved for that device and opens the
// connection with it through the MaxZit Launcher; it answers
// {type: "maxzit-open-taken", nonce} so the console does not open the
// launcher without the password. The message never holds a password, and
// this script reads nothing else from the page.
(() => {
  const api = globalThis.browser || globalThis.chrome;
  if (window.__pzConsole) return;
  window.__pzConsole = true;
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin || !e.data || e.data.type !== "maxzit-open") return;
    const m = e.data;
    if (typeof m.nonce !== "string" || !/^[0-9a-f]{16,64}$/i.test(m.nonce)) return;
    const req = { type: "consoleOpen", tool: String(m.tool || ""), host: String(m.host || ""), port: Number(m.port) || 0, user: String(m.user || "") };
    api.runtime.sendMessage(req).then((r) => {
      if (!r || !r.ok || !r.data || !r.data.taken) return;
      window.postMessage({ type: "maxzit-open-taken", nonce: m.nonce }, location.origin);
    }, () => {});
  });
  // the connection itself may still fail after the console was told
  api.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "consoleOpenFailed" && typeof msg.error === "string") window.alert("PassZit: " + msg.error);
  });
})();
