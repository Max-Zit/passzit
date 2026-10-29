// PassZit capture script (only with the optional permission for all
// sites): when a sign-in form is sent, it hands the user name and password
// to the extension, which offers to save them in its popup. Nothing is
// shown in the page and nothing is sent anywhere else.
(() => {
  const ext = globalThis.browser && globalThis.browser.runtime ? globalThis.browser : globalThis.chrome;
  let last = "";

  function visible(el) {
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1 && getComputedStyle(el).visibility !== "hidden";
  }

  function read(scope) {
    const root = scope || document;
    const pw = [...root.querySelectorAll("input[type=password]")].filter((p) => p.value && visible(p));
    if (!pw.length) return null;
    // A "new password" form (sign-up, change) has several: take the last new one.
    const target = pw.length > 1 ? pw[pw.length - 1] : pw[0];
    const texts = [...root.querySelectorAll("input")].filter((i) => ["text", "email", "tel", ""].includes((i.getAttribute("type") || "").toLowerCase()) && i.value && visible(i));
    const before = texts.filter((i) => target.compareDocumentPosition(i) & Node.DOCUMENT_POSITION_PRECEDING);
    const user = before.reverse().find((i) => i.type === "email" || /user|login|mail|account/i.test((i.name || "") + (i.id || "") + (i.autocomplete || ""))) || before[0];
    return { username: user ? user.value.trim() : "", password: target.value };
  }

  function send(scope) {
    const c = read(scope);
    if (!c) return;
    const key = c.username + "\u0000" + c.password;
    if (key === last) return;
    last = key;
    ext.runtime.sendMessage({ type: "capture", url: location.href, username: c.username, password: c.password }).catch(() => {});
  }

  document.addEventListener("submit", (ev) => send(ev.target), true);
  // Sign-ins without a real form submit (buttons with JavaScript, Enter key).
  document.addEventListener("click", (ev) => {
    const b = ev.target.closest && ev.target.closest("button, input[type=submit], [role=button]");
    if (b) send(b.form || b.closest("form") || document);
  }, true);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && ev.target instanceof HTMLInputElement && ev.target.type === "password") send(ev.target.form || document);
  }, true);
})();
