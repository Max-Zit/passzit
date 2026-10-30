// Runs only on the Launcher page of the PassZit server this extension is
// signed in to: it tells the page that the extension is here and passes
// the page's "pair" request on. It reads nothing from the page.
(() => {
  const api = globalThis.browser || globalThis.chrome;
  const say = (type) => window.postMessage({ type }, location.origin);
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin || !e.data) return;
    if (e.data.type === "pz-ext-ping") say("pz-ext-here");
    if (e.data.type === "pz-launcher-pair") {
      api.runtime.sendMessage({ type: "launcherPair" }).then((r) => { if (r && r.ok) say("pz-launcher-paired"); }, () => {});
    }
  });
  say("pz-ext-here");
})();
