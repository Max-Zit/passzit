// Offscreen document (Chromium): puts a password of a connection on the
// clipboard or clears it after a copied password, because the background
// service worker has no clipboard. Only the background asks (no tab).
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || (msg.type !== "offscreen-clear" && msg.type !== "offscreen-copy") || sender.tab) return;
  const text = msg.type === "offscreen-copy" ? String(msg.text || "") : "";
  const h = (e) => { e.clipboardData.setData("text/plain", text); e.preventDefault(); };
  document.addEventListener("copy", h);
  document.execCommand("copy");
  document.removeEventListener("copy", h);
});
