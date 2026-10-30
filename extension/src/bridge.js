// Runs only on the vault and Launcher pages of the PassZit server this
// extension is signed in to: it tells the page that the extension is here
// and passes two requests on — "pair this browser with the MaxZit
// Launcher" and "open the connection of this item" (by its id; the
// extension uses its own copy of the vault). It reads nothing from the page.
(() => {
  const api = globalThis.browser || globalThis.chrome;
  const say = (msg) => window.postMessage(msg, location.origin);
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin || !e.data) return;
    const m = e.data;
    if (m.type === "pz-ext-ping") say({ type: "pz-ext-here" });
    if (m.type === "pz-launcher-pair") {
      api.runtime.sendMessage({ type: "launcherPair" }).then((r) => { if (r && r.ok) say({ type: "pz-launcher-paired" }); }, () => {});
    }
    if (m.type === "pz-connect" && typeof m.id === "string" && m.id.length <= 64) {
      api.runtime.sendMessage({ type: "pageConnect", id: m.id }).then(
        (r) => say(Object.assign({ type: "pz-connect-result", id: m.id, ok: !!(r && r.ok), error: r && r.error }, r && r.ok ? r.data : {})),
        (err) => say({ type: "pz-connect-result", id: m.id, ok: false, error: String(err && err.message || err) }));
    }
  });
  say({ type: "pz-ext-here" });
})();
