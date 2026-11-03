// Test harness of the extension (test builds only): drives the real
// background through the same calls as the popup, against a test server,
// and reports the results to it. Run by internal/web TestExtensionInBrowser.
import { api, saveSettings } from "../ext.js";
import { bg, signIn, unlock } from "../client.js";

const q = new URLSearchParams(location.search);
const extra = +(q.get("extra") || 0); // sample logins of the screenshot mode
const server = q.get("server"), email = q.get("email"), pw = q.get("pw"), site = q.get("site"), other = q.get("other");
const out = { steps: [] };
const step = (name, ok, info) => { out.steps.push({ name, ok: !!ok, info: info === undefined ? "" : String(info) }); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function openTab(url) {
  const tab = await api.tabs.create({ url, active: false });
  for (let i = 0; i < 100; i++) {
    const t = await api.tabs.get(tab.id);
    if (t.status === "complete") return t;
    await sleep(100);
  }
  return tab;
}

async function valuesIn(tabId) {
  const [r] = await api.scripting.executeScript({ target: { tabId }, func: () => [...document.querySelectorAll("input")].map((i) => i.name + "=" + i.value).join("&") });
  return r.result;
}

async function attempt(name, fn) {
  try { const v = await fn(); step(name, true, v); return v; } catch (e) { step(name, false, e.message); return null; }
}

try {
  // A freshly installed Firefox add-on gets its host permissions a moment later.
  let granted = false;
  for (let i = 0; i < 100 && !granted; i++) {
    granted = await api.permissions.contains({ origins: [new URL(site).origin + "/*"] });
    if (!granted) await sleep(100);
  }
  step("host permission", granted);
  // wrong password first: refused, nothing stored
  await attempt("wrong password refused", async () => {
    try { await signIn(server, email, pw + "x", "Harness"); } catch (e) { return e.message; }
    throw new Error("signed in with a wrong password");
  });
  await signIn(server, email, pw, "Harness Chrome");
  const st = await bg("status");
  step("signed in and unlocked", st.signedIn && st.unlocked);
  const all = await bg("search", { q: "" });
  step("items synced", all.items.length === 2 + extra, all.items.map((i) => i.name).join(","));
  const login = all.items.find((i) => i.name === "Test site");
  // fill on the right site
  const tab = await openTab(site);
  await attempt("fill", () => bg("fill", { id: login.id, tabId: tab.id }).then((r) => JSON.stringify(r)));
  const v = await valuesIn(tab.id);
  step("filled values", v.includes("user=alice%40example.com") || v.includes("user=alice@example.com"), v);
  step("password filled", v.includes("pass=S3cret-For-Test!"), v.replace(/pass=[^&]*/, "pass=…"));
  step("hidden field untouched", v.includes("trap=&") || v.endsWith("trap="), v.replace(/pass=[^&]*/, "pass=…"));
  // the next page asks for the one-time code: Fill puts it in
  const tabCode = await openTab(site.replace("/login", "/code"));
  const rc = await attempt("fill the one-time code", () => bg("fill", { id: login.id, tabId: tabCode.id }).then((r) => JSON.stringify(r)));
  const vc = await valuesIn(tabCode.id);
  step("code filled", /"code":true/.test(rc || "") && /^otp=\d{6}$/.test(vc), vc.replace(/\d/g, "#"));
  // the icon counts the logins of the site
  await saveSettings({ siteBadge: true });
  await bg("settingsChanged");
  let badgeText = "";
  for (let i = 0; i < 20 && badgeText !== "1"; i++) { badgeText = await api.action.getBadgeText({ tabId: tab.id }); if (badgeText !== "1") await sleep(100); }
  step("icon shows the login count", badgeText === String(1 + +(q.get("siteextra") || 0)), badgeText);
  await saveSettings({ siteBadge: false });
  await bg("settingsChanged");
  // the bridge script answers on the server's own Launcher page
  const regs = await api.scripting.getRegisteredContentScripts().catch((e) => [{ id: "error " + e.message }]);
  step("bridge registered", regs.some((r) => r.id === "pz-bridge"), JSON.stringify(regs.map((r) => [r.id, r.matches])));
  const probe = await openTab(server + "/launcher-probe");
  let title = "";
  for (let i = 0; i < 30 && title !== "here"; i++) { await sleep(100); title = (await api.tabs.get(probe.id)).title; }
  step("bridge answers on the Launcher page", title === "here", title);
  // the same server under its other loopback name (localhost ↔ 127.0.0.1)
  const twin = await openTab(server.replace("127.0.0.1", "localhost") + "/launcher-probe");
  let title2 = "";
  for (let i = 0; i < 30 && title2 !== "here"; i++) { await sleep(100); title2 = (await api.tabs.get(twin.id)).title; }
  step("bridge answers under localhost too", title2 === "here", title2);
  // one unlock: the vault page and the extension share the unlocked keys
  const vp = await openTab(server + "/vault-probe");
  // a just opened tab may not take scripts yet (Firefox): try again shortly
  const inPage = async (func, args) => {
    for (let i = 0; ; i++) {
      try { return (await api.scripting.executeScript({ target: { tabId: vp.id }, world: "MAIN", func, args }))[0].result; } catch (e) { if (i >= 30) throw e; await sleep(200); }
    }
  };
  const ask = (email) => new Promise((res) => {
    addEventListener("message", (e) => { if (e.data && e.data.type === "pz-keys") res(e.data.keys || null); });
    postMessage({ type: "pz-keys-ask", email }, location.origin);
    setTimeout(() => res("timeout"), 3000);
  });
  const post = (msg) => { postMessage(msg, location.origin); return true; };
  await sleep(300);
  const keys = await inPage(ask, ["alice@example.com"]);
  step("page gets the keys of the unlocked extension", keys && keys.a && keys.p && keys.u, keys ? "keys" : keys);
  step("no keys for another account", (await inPage(ask, ["bob@example.com"])) === null);
  await inPage(post, [{ type: "pz-lock" }]);
  let locked = false;
  for (let i = 0; i < 20 && !locked; i++) { await sleep(100); locked = !(await bg("status")).unlocked; }
  step("locking the page locks the extension", locked);
  const bad = Object.assign({}, keys, { a: keys.p });
  await inPage(post, [{ type: "pz-keys-share", email: "alice@example.com", keys: bad }]);
  await sleep(800);
  step("wrong keys are refused", !(await bg("status")).unlocked);
  await inPage(post, [{ type: "pz-keys-share", email: "alice@example.com", keys }]);
  let open = false;
  for (let i = 0; i < 30 && !open; i++) { await sleep(100); open = (await bg("status")).unlocked; }
  step("unlocking the page unlocks the extension", open);
  // another site: refused
  const tab2 = await openTab(other);
  await attempt("fill refused on another site", async () => {
    try { await bg("fill", { id: login.id, tabId: tab2.id }); } catch (e) { return e.message; }
    throw new Error("filled on another site");
  });
  const v2 = await valuesIn(tab2.id);
  step("other site untouched", !v2.includes("S3cret"), v2.replace(/pass=[^&]*/, "pass=…"));
  // offer to save: capture a sign-up form
  await saveSettings({ offerSave: true });
  await bg("settingsChanged");
  const tab3 = await openTab(site.replace("/login", "/signup"));
  await sleep(500);
  await api.scripting.executeScript({ target: { tabId: tab3.id }, func: () => {
    document.querySelector("[name=user]").value = "bob@example.com";
    document.querySelector("[name=pass]").value = "Brand-New-Pass-77";
    document.querySelector("button").click();
  } });
  let pend = 0;
  for (let i = 0; i < 30 && !pend; i++) { await sleep(100); pend = (await bg("status")).pending; }
  step("save offered", pend === 1, pend);
  await attempt("save the offer", () => bg("pending", { index: 0, action: "save" }).then(() => "saved"));
  const after = await bg("search", { q: "bob@example.com" });
  step("new login saved", after.items.length === 1, after.items.map((i) => i.name).join(","));
  // lock and unlock
  await bg("lock");
  step("locked", (await bg("search", { q: "" })).locked === true);
  await attempt("unlock refuses a wrong password", async () => {
    try { await unlock(pw + "x"); } catch (e) { return e.message; }
    throw new Error("unlocked with a wrong password");
  });
  await unlock(pw);
  step("unlocked again", (await bg("search", { q: "" })).items.length === 3 + extra);
  if (q.get("stay")) {
    step("left signed in for screenshots", true);
  } else {
    await bg("logout");
    step("signed out", !(await bg("status")).signedIn);
  }
} catch (e) {
  step("harness", false, e.stack || e.message);
}
document.getElementById("log").textContent = JSON.stringify(out, null, 1);
await fetch(server + "/harness-result", { method: "POST", body: JSON.stringify(out) });
