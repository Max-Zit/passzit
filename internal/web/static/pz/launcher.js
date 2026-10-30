// The Launcher page: "Pair this browser" asks the PassZit extension (its
// small script on this server's Launcher page) to open the MaxZit
// Launcher's pairing link. Nothing of the vault is involved.
import { loadTexts, t, wireLogout } from "./common.js";

await loadTexts();
wireLogout();

const btn = document.getElementById("pz-pair");
const state = document.getElementById("pz-pair-state");
let here = false;

window.addEventListener("message", (e) => {
  if (e.source !== window || e.origin !== location.origin || !e.data) return;
  if (e.data.type === "pz-ext-here") here = true;
  if (e.data.type === "pz-launcher-paired") state.textContent = t("The launcher opens: confirm the pairing in its window.");
});
window.postMessage({ type: "pz-ext-ping" }, location.origin);

btn.addEventListener("click", () => {
  if (!here) {
    state.textContent = t("The PassZit extension does not answer on this page. Install it (Browser extensions), sign in to this server with it, then reload this page.");
    return;
  }
  state.textContent = "";
  window.postMessage({ type: "pz-launcher-pair" }, location.origin);
});
