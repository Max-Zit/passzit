// Test harness of the extension (test builds only): drives the real
// background through the same calls as the popup, against a test server,
// and reports the results to it. Run by internal/web TestExtensionInBrowser.
import { api, saveSettings, sameServer, hostPattern, hostAllowed } from "../ext.js";
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

// mode=optional: the extension starts without host permissions, like one
// from a store, and asks for its server's host on a click (the test clicks).
// The server runs on a port other than 443: the permission must not name
// the port (Firefox ignores such patterns), yet the server, its vault page
// and a MaxZit console on that port must all work.
async function optionalMode() {
  try {
    step("starts without host access", !(await hostAllowed(server)));
    const granted = await new Promise((res) => {
      const btn = document.createElement("button");
      btn.textContent = "Allow";
      btn.style.cssText = "position:fixed;inset:0;width:100%;height:100%";
      btn.onclick = () => { btn.remove(); api.permissions.request({ origins: sameServer(server).map(hostPattern) }).then(res, (e) => res("error: " + e.message)); };
      document.body.append(btn);
    });
    step("host permission without the port granted", granted === true, granted);
    step("server reachable on port " + new URL(server).port, await hostAllowed(server));
    await signIn(server, email, pw, "Harness optional");
    step("signed in over the granted host", (await bg("status")).unlocked);
    await saveSettings({ consoles: [new URL(server).origin] });
    await bg("settingsChanged");
    const regs = await api.scripting.getRegisteredContentScripts().catch(() => []);
    step("bridge and console scripts registered", ["pz-bridge", "pz-console"].every((id) => regs.some((r) => r.id === id)), JSON.stringify(regs.map((r) => [r.id, r.matches])));
    const inTab = async (tabId, func) => {
      for (let i = 0; ; i++) {
        try { return (await api.scripting.executeScript({ target: { tabId }, world: "MAIN", func }))[0].result; } catch (e) { if (i >= 30) throw e; await sleep(200); }
      }
    };
    const vp = await openTab(server + "/vault-probe");
    await sleep(300);
    const info = await inTab(vp.id, () => new Promise((res) => {
      addEventListener("message", (e) => { if (e.data && e.data.type === "pz-link-info") res(e.data); });
      postMessage({ type: "pz-link-ask" }, location.origin);
      setTimeout(() => res(null), 3000);
    }));
    step("vault page on that port reaches the extension", info && info.device && info.signedIn === true, JSON.stringify(info));
    const cp = await openTab(server + "/console-probe");
    await sleep(300);
    const state = await inTab(cp.id, () => new Promise((res) => {
      addEventListener("message", (e) => { if (e.source === window && e.data && e.data.type === "maxzit-passzit") res(e.data.state); });
      postMessage({ type: "maxzit-passzit-ask" }, location.origin);
      setTimeout(() => res("no answer"), 1500);
    }));
    step("MaxZit console on that port reaches the extension", state === "ready", state);
    await saveSettings({ consoles: [] });
    await bg("logout");
  } catch (e) {
    step("harness", false, e.stack || e.message);
  }
}

if (q.get("mode") === "optional") await optionalMode(); else try {
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
  step("items synced", all.items.length === 3 + extra, all.items.map((i) => i.name).join(","));
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
  // a MaxZit console (WatchZit) the user added: "Open with" of a device with
  // a saved login is taken by PassZit, others are left to the console
  const consoleSite = server.replace("127.0.0.1", "localhost");
  await saveSettings({ consoles: [consoleSite] });
  await bg("settingsChanged");
  const regs2 = await api.scripting.getRegisteredContentScripts().catch(() => []);
  step("console script registered", regs2.some((r) => r.id === "pz-console"), JSON.stringify(regs2.map((r) => [r.id, r.matches])));
  const cp = await openTab(consoleSite + "/console-probe");
  const openWith = (tool, host) => new Promise((res) => {
    const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
    addEventListener("message", (e) => { if (e.source === window && e.data && e.data.type === "maxzit-open-taken" && e.data.nonce === nonce) res("taken"); });
    postMessage({ type: "maxzit-open", nonce, tool, host, port: 0, user: "", device: "probe" }, location.origin);
    setTimeout(() => res("not taken"), 400);
  });
  const inConsole = async (args) => {
    for (let i = 0; ; i++) {
      try { return (await api.scripting.executeScript({ target: { tabId: cp.id }, world: "MAIN", func: openWith, args }))[0].result; } catch (e) { if (i >= 30) throw e; await sleep(200); }
    }
  };
  await sleep(300);
  const state = async () => {
    for (let i = 0; ; i++) {
      try {
        return (await api.scripting.executeScript({ target: { tabId: cp.id }, world: "MAIN", func: () => new Promise((res) => {
          addEventListener("message", (e) => { if (e.source === window && e.data && e.data.type === "maxzit-passzit") res(e.data.state); });
          postMessage({ type: "maxzit-passzit-ask" }, location.origin);
          setTimeout(() => res("no answer"), 1000);
        }) }))[0].result;
      } catch (e) { if (i >= 30) throw e; await sleep(200); }
    }
  };
  const st1 = await state();
  step("console: PassZit tells the console it is ready", st1 === "ready", st1);
  step("console: unknown device left to the console", (await inConsole(["ssh", "10.99.99.99"])) === "not taken");
  step("console: other tool left to the console", (await inConsole(["rdp", "10.20.30.40"])) === "not taken");
  // last: opening it fails here (no launcher), and the page shows that
  step("console: device with a saved login taken", (await inConsole(["ssh", "10.20.30.40"])) === "taken");
  await api.tabs.remove(cp.id).catch(() => {});
  // locked: PassZit takes it and asks to unlock in a small window first
  await bg("lock");
  const cp2 = await openTab(consoleSite + "/console-probe");
  await sleep(300);
  let lockedAnswer = "";
  for (let i = 0; i < 30; i++) {
    try { lockedAnswer = (await api.scripting.executeScript({ target: { tabId: cp2.id }, world: "MAIN", func: openWith, args: ["ssh", "10.20.30.40"] }))[0].result; break; } catch (e) { await sleep(200); }
  }
  step("console: locked PassZit takes it", lockedAnswer === "taken", lockedAnswer);
  await sleep(500);
  const wins = await api.windows.getAll({ populate: true });
  const uw = wins.find((w) => (w.tabs || []).some((tb) => (tb.url || "").includes("popup.html?unlock=open")));
  step("console: an unlock window opens", !!uw, wins.length);
  const po = await bg("openPendingInfo").catch((e) => ({ error: e.message }));
  step("console: the unlock window names the console and the device", po && po.origin === new URL(consoleSite).origin && po.host === "10.20.30.40" && po.device === "probe", JSON.stringify(po));
  await unlock(pw);
  if (uw) await api.windows.remove(uw.id).catch(() => {});
  await api.tabs.remove(cp2.id).catch(() => {});
  await saveSettings({ consoles: [] });
  await bg("settingsChanged");
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
  step("unlocked again", (await bg("search", { q: "" })).items.length === 4 + extra);
  // offers captured while locked are checked again once it is open: the
  // same login again is dropped, a new password becomes an update
  const submit = async (user, pass) => {
    const tb = await openTab(site.replace("/login", "/signup"));
    await sleep(500);
    await api.scripting.executeScript({ target: { tabId: tb.id }, func: (u, p) => {
      document.querySelector("[name=user]").value = u;
      document.querySelector("[name=pass]").value = p;
      document.querySelector("button").click();
    }, args: [user, pass] });
    let n = 0;
    for (let i = 0; i < 30 && !n; i++) { await sleep(100); n = (await bg("status")).pending; }
    await api.tabs.remove(tb.id).catch(() => {});
    return n;
  };
  await bg("lock");
  step("locked: a saved login is captured", (await submit("bob@example.com", "Brand-New-Pass-77")) === 1);
  await unlock(pw);
  step("unlocked: the saved login is no longer offered", (await bg("status")).pending === 0, (await bg("status")).pending);
  await bg("lock");
  step("locked: a changed password is captured", (await submit("bob@example.com", "Changed-Pass-78")) === 1);
  await unlock(pw);
  step("unlocked: the changed password is still offered", (await bg("status")).pending === 1);
  await attempt("save the changed password", () => bg("pending", { index: 0, action: "save" }).then(() => "saved"));
  const bobs = await bg("search", { q: "bob@example.com" });
  step("saved as an update, not a second login", bobs.items.length === 1, bobs.items.length);
  step("all logins still there", (await bg("search", { q: "" })).items.length === 4 + extra);
  // cards and addresses: the identity fills the address fields, the card
  // the payment fields; nothing else is touched
  const co = await openTab(site.replace("/login", "/checkout"));
  await sleep(500);
  const fieldsOf = async () => (await api.scripting.executeScript({ target: { tabId: co.id }, func: () =>
    Object.fromEntries([...document.querySelectorAll("input, select")].map((f) => [f.name, f.value])) }))[0].result;
  const idItem = (await bg("search", { q: "Home address" })).items[0];
  const cardItem = (await bg("search", { q: "Test card" })).items[0];
  const r1 = await bg("fillForm", { id: idItem.id, tabId: co.id }).catch((e) => ({ error: e.message }));
  const f1 = await fieldsOf();
  step("identity fills the address", f1.fullname === "Alice Example" && f1.street === "Main Street 1" && f1.zip === "11000" && f1.city === "Belgrade" &&
    f1.country === "RS" && f1.mail === "alice@example.com" && f1.phone === "+381 11 123456", JSON.stringify([r1, f1]));
  step("identity leaves the card fields alone", !f1.cardholder && !f1.pan && !f1.cvc && !f1["exp-month"] && !f1.note, JSON.stringify(f1));
  const r2 = await bg("fillForm", { id: cardItem.id, tabId: co.id }).catch((e) => ({ error: e.message }));
  const f2 = await fieldsOf();
  step("card fills the payment fields", f2.cardholder === "Alice Example" && f2.pan === "4111111111111111" && f2["exp-month"] === "07" &&
    f2["exp-year"] === "2028" && f2.cvc === "123", JSON.stringify([r2, f2]));
  step("the card leaves the rest alone", f2.note === "" && f2.fullname === "Alice Example", JSON.stringify(f2));
  await attempt("a login is not filled as a form", async () => {
    try { await bg("fillForm", { id: login.id, tabId: co.id }); } catch (e) { return e.message; }
    throw new Error("filled a login as a form");
  });
  await api.tabs.remove(co.id).catch(() => {});
  // "Connect with the web vault": signed out, the vault page hands over a
  // device token the web session made (the fixture made it the same way)
  await bg("logout");
  await saveSettings({ server });
  await bg("settingsChanged");
  const info = await inPage(() => new Promise((res) => {
    addEventListener("message", (e) => { if (e.data && e.data.type === "pz-link-info") res(e.data); });
    postMessage({ type: "pz-link-ask" }, location.origin);
    setTimeout(() => res(null), 3000);
  }), []);
  step("link: the vault page reaches the signed-out extension", info && info.device && info.signedIn === false, JSON.stringify(info));
  const linked = await inPage((token, email) => new Promise((res) => {
    addEventListener("message", (e) => { if (e.data && e.data.type === "pz-ext-linked") res(e.data); });
    postMessage({ type: "pz-ext-link", token, email }, location.origin);
    setTimeout(() => res(null), 5000);
  }), [q.get("linktoken"), "bob@example.com"]);
  step("link: a token of another account is refused", linked && !linked.ok, JSON.stringify(linked));
  const linked2 = await inPage((token, email) => new Promise((res) => {
    addEventListener("message", (e) => { if (e.data && e.data.type === "pz-ext-linked") res(e.data); });
    postMessage({ type: "pz-ext-link", token, email }, location.origin);
    setTimeout(() => res(null), 5000);
  }), [q.get("linktoken"), "alice@example.com"]);
  step("link: the extension is signed in with the token", linked2 && linked2.ok && (await bg("status")).signedIn, JSON.stringify(linked2));
  await inPage(post, [{ type: "pz-keys-share", email: "alice@example.com", keys }]);
  let open2 = false;
  for (let i = 0; i < 30 && !open2; i++) { await sleep(100); open2 = (await bg("status")).unlocked; }
  step("link: one unlock opens it", open2);
  // passkeys: a website saves one in PassZit and signs in with it; the
  // answer must verify with the public key the website got
  await saveSettings({ passkeys: true });
  await bg("settingsChanged");
  // (on localhost: as in browsers, an IP address such as 127.0.0.1 is no
  // relying party, so PassZit's page script does not run there)
  const pkTab = await openTab(server.replace("127.0.0.1", "localhost") + "/passkey-probe");
  const inPk = async (func, args) => {
    for (let i = 0; ; i++) {
      try { return (await api.scripting.executeScript({ target: { tabId: pkTab.id }, world: "MAIN", func, args: args || [] }))[0].result; } catch (e) { if (i >= 30) throw e; await sleep(200); }
    }
  };
  const decide = async (choice) => {
    for (let i = 0; i < 50; i++) {
      const wins = await api.windows.getAll({ populate: true });
      for (const w of wins) for (const tb of w.tabs || []) {
        const m = /[?&]passkey=([^&]+)/.exec(tb.url || "");
        if (!m) continue;
        const info = await bg("passkeyPending", { id: m[1] });
        await bg("passkeyDecide", { id: m[1], choice, itemId: info.list && info.list[0] ? info.list[0].id : "" });
        await api.windows.remove(w.id).catch(() => {});
        return info;
      }
      await sleep(100);
    }
    return null;
  };
  await sleep(300);
  step("passkeys: page script present", await inPk(() => !!window.__pzPasskeys), "");
  await inPk(() => {
    const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
    window.__pkChallenge = rnd(32);
    window.__pkCreate = navigator.credentials.create({ publicKey: { challenge: window.__pkChallenge, rp: { name: "Passkey Probe" },
      user: { id: rnd(16), name: "alice@probe", displayName: "Alice" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }] } })
      .then((c) => ({ id: c.id, json: c.toJSON(), pub: c.toJSON().response.publicKey, flags: new Uint8Array(c.response.getAuthenticatorData())[32] }), (e) => ({ error: String(e) }));
    return true;
  });
  const cInfo = await decide("save");
  step("passkeys: PassZit asks before saving", cInfo && cInfo.op === "create", JSON.stringify(cInfo));
  const created = await inPk(() => Promise.race([window.__pkCreate, new Promise((r) => setTimeout(() => r({ error: "no answer" }), 15000))]));
  step("passkeys: the website gets a new passkey", created && created.id && created.json && created.json.response.attestationObject, JSON.stringify(created).slice(0, 200));
  // user present, backup eligible and backed up, attested data; no "user verified"
  step("passkeys: new passkey does not claim user verification", created && created.flags === 0x59, created && created.flags);
  await inPk(() => {
    const der2raw = (d) => {
      let o = 2;
      const take = () => { const n = d[o + 1]; let v = d.slice(o + 2, o + 2 + n); o += 2 + n; while (v.length > 32) v = v.slice(1); const r = new Uint8Array(32); r.set(v, 32 - v.length); return r; };
      const r = take(), s = take();
      const out = new Uint8Array(64); out.set(r); out.set(s, 32); return out;
    };
    const unb = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));
    window.__pkGet = (async () => {
      const ch = crypto.getRandomValues(new Uint8Array(32));
      const a = await navigator.credentials.get({ publicKey: { challenge: ch } });
      const created = await window.__pkCreate;
      const key = await crypto.subtle.importKey("spki", unb(created.pub), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      const cd = new Uint8Array(a.response.clientDataJSON);
      const signed = new Uint8Array([...new Uint8Array(a.response.authenticatorData), ...new Uint8Array(await crypto.subtle.digest("SHA-256", cd))]);
      const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, der2raw(new Uint8Array(a.response.signature)), signed);
      const client = JSON.parse(new TextDecoder().decode(cd));
      return { ok, same: a.id === created.id, origin: client.origin === location.origin, type: client.type, flags: new Uint8Array(a.response.authenticatorData)[32] };
    })().catch((e) => ({ error: String(e) }));
    return true;
  });
  const gInfo = await decide("use");
  step("passkeys: PassZit offers the saved passkey", gInfo && gInfo.op === "get" && gInfo.list.length === 1, JSON.stringify(gInfo));
  const got = await inPk(() => Promise.race([window.__pkGet, new Promise((r) => setTimeout(() => r({ error: "no answer" }), 15000))]));
  step("passkeys: the sign-in verifies with the website's public key", got && got.ok && got.same && got.origin && got.type === "webauthn.get", JSON.stringify(got));
  step("passkeys: the sign-in does not claim user verification", got && got.flags === 0x19, got && got.flags);
  step("passkeys: kept in the vault", (await bg("search", { q: "Passkey Probe" })).items.length === 1);
  // the site lists the saved passkey in excludeCredentials: PassZit shows it
  // in its window first; after OK the site gets InvalidStateError
  await inPk(() => {
    const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
    window.__pkExists = window.__pkCreate.then((c) => navigator.credentials.create({ publicKey: { challenge: rnd(32), rp: { name: "Passkey Probe" },
      user: { id: rnd(16), name: "alice@probe", displayName: "Alice" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ type: "public-key", id: c.json.rawId ? Uint8Array.from(atob(c.json.rawId.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0)) : rnd(16) }] } }))
      .then(() => ({ name: "created" }), (e) => ({ name: e && e.name }));
    return true;
  });
  const xInfo = await decide("ok");
  step("passkeys: an excluded passkey is shown in PassZit's window first", xInfo && xInfo.op === "exists", JSON.stringify(xInfo));
  const xRes = await inPk(() => Promise.race([window.__pkExists, new Promise((r) => setTimeout(() => r({ name: "no answer" }), 15000))]));
  step("passkeys: the site then gets InvalidStateError", xRes && xRes.name === "InvalidStateError", JSON.stringify(xRes));
  // a site that requires user verification: PassZit leaves it to the browser
  await inPk(() => { navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), userVerification: "required" } }).catch(() => {}); return true; });
  await sleep(1000);
  const uvWin = (await api.windows.getAll({ populate: true })).some((w) => (w.tabs || []).some((tb) => /[?&]passkey=/.test(tb.url || "")));
  step("passkeys: user verification required is left to the browser", !uvWin);
  await api.tabs.remove(pkTab.id).catch(() => {});
  // no page script on an IP address
  const ipTab = await openTab(server + "/passkey-probe");
  await sleep(300);
  const ipScript = (await api.scripting.executeScript({ target: { tabId: ipTab.id }, world: "MAIN", func: () => !!window.__pzPasskeys }).catch(() => [{ result: "error" }]))[0].result;
  step("passkeys: not on an IP address", ipScript === false, ipScript);
  await api.tabs.remove(ipTab.id).catch(() => {});
  await saveSettings({ passkeys: false });
  await bg("settingsChanged");
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
