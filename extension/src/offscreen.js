// Offscreen document (Chromium): clears the clipboard after a copied
// password, because the background service worker has no clipboard.
chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== "offscreen-clear") return;
  const h = (e) => { e.clipboardData.setData("text/plain", ""); e.preventDefault(); };
  document.addEventListener("copy", h);
  document.execCommand("copy");
  document.removeEventListener("copy", h);
});
