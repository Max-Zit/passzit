// Runs only on the vault and Launcher pages of the PassZit server this
// extension is signed in to: it tells the page that the extension is here
// and passes its requests on — pair this browser with the MaxZit Launcher,
// open the connection of an item (by its id; the extension uses its own
// copy of the vault), and share the unlocked state (one unlock and one lock
// for the page and the extension; the background checks the keys against
// the account). It reads nothing else from the page.
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
    if (m.type === "pz-keys-ask") {
      api.runtime.sendMessage({ type: "pageKeys", email: String(m.email || "") }).then((r) => say({ type: "pz-keys", keys: r && r.ok && r.data ? r.data.keys : null }), () => say({ type: "pz-keys", keys: null }));
    }
    if (m.type === "pz-keys-share" && m.keys) {
      api.runtime.sendMessage({ type: "pageUnlocked", email: String(m.email || ""), keys: m.keys }).catch(() => {});
    }
    if (m.type === "pz-lock") api.runtime.sendMessage({ type: "pageLock" }).catch(() => {});
    if (m.type === "pz-connect" && typeof m.id === "string" && m.id.length <= 64) {
      api.runtime.sendMessage({ type: "pageConnect", id: m.id }).then(
        (r) => say(Object.assign({ type: "pz-connect-result", id: m.id, ok: !!(r && r.ok), error: r && r.error }, r && r.ok ? r.data : {})),
        (err) => say({ type: "pz-connect-result", id: m.id, ok: false, error: String(err && err.message || err) }));
    }
  });
  say({ type: "pz-ext-here" });
})();
