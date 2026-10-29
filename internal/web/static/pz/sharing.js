// Shared vaults in the web vault. The vault key never reaches the server:
// it is sealed here to the X25519 public key of every member. Public keys
// come from the server, so a changed key of a known person is reported
// before anything is sealed to it (the confirmed fingerprints are kept
// sealed with the account key).
import * as pz from "./crypto.js";
import { t, api, el, icon, button, toast, confirmBox, ApiError } from "./common.js";

let C = null; // { S, render, sync, dialog, prompt1 } from vault.js

export function initSharing(ctx) { C = ctx; }

export const RIGHTS = ["use", "view", "edit", "manage"];

export function rightsLabel(r) {
  return { use: t("Use (no reading)"), view: t("Read"), edit: t("Read and change"), manage: t("Manage") }[r] || r;
}

export function canEditVault(id) {
  const v = C.S.vaults.get(id);
  return !!(v && v.key && (v.rights === "edit" || v.rights === "manage"));
}

export function vaultLabel(id) {
  const v = C.S.vaults.get(id);
  if (!v) return "";
  return v.kind === "personal" ? t("My vault") : v.name || t("Shared vault");
}

// ---- confirmed public keys

let known = null; // user id → { fp, email }

export async function loadKnown() {
  known = {};
  try {
    const r = await api("GET", "/api/account/known-keys");
    if (r.data) known = await pz.openJSON(C.S.keys.accountKey, r.data, pz.AAD.knownKeys());
  } catch (e) { console.warn("known keys", e); }
}

async function saveKnown() {
  await api("PUT", "/api/account/known-keys", { data: await pz.sealJSON(C.S.keys.accountKey, known, pz.AAD.knownKeys()) });
}

// keyCheck tells whether a person's public key is new, the confirmed one,
// or a different one than confirmed before.
async function keyCheck(userID, pubB64) {
  const fp = await pz.fingerprint(pz.unb64u(pubB64));
  const k = known && known[userID];
  return { fp, status: !k ? "new" : k.fp === fp ? "same" : "changed" };
}

async function remember(userID, email, fp) {
  if (!known) known = {};
  if (known[userID] && known[userID].fp === fp) return;
  known[userID] = { fp, email };
  await saveKnown();
}

function sealFor(pubB64, key, vaultID) {
  return pz.sealTo(pz.unb64u(pubB64), key, pz.AAD.vaultKey(vaultID));
}

// ---- creating a vault

export async function createVault() {
  const name = await C.prompt1(t("New shared vault"), t("Name"), "");
  if (!name) return;
  try {
    const id = pz.uuid();
    const key = pz.random(32);
    await api("POST", "/api/vaults", {
      id,
      data: await pz.seal(key, pz.utf8(name), pz.AAD.vaultName(id)),
      wrapped_key: await sealFor(pz.b64u(C.S.keys.publicKey), key, id),
    });
    await C.sync(0);
    C.S.view = "vault"; C.S.vault = id; C.S.selected = "";
    C.render();
    toast(t("The vault is created. Add members with the gear next to its name."));
  } catch (e) { toast(e.message, true); }
}

// ---- access that groups give, sealed by the managers' browsers

let pendingAt = 0;
export const warnings = new Map(); // user id → email, for changed keys

export async function completePending(force) {
  const managed = [...C.S.vaults.values()].some((v) => v.kind === "shared" && v.rights === "manage" && v.key);
  if (!managed || (!force && Date.now() - pendingAt < 60000)) return 0;
  pendingAt = Date.now();
  let done = 0;
  let list = [];
  try { list = await api("GET", "/api/vaults/pending"); } catch (e) { return 0; }
  for (const p of list) {
    const v = C.S.vaults.get(p.vault_id);
    if (!v || !v.key || v.needsRotation) continue; // a new key first
    const k = await keyCheck(p.user_id, p.public_key);
    if (k.status === "changed") { warnings.set(p.user_id, p.email); continue; }
    try {
      await api("PUT", "/api/vaults/" + p.vault_id + "/members", { user_id: p.user_id, wrapped_key: await sealFor(p.public_key, v.key, p.vault_id), rights: p.rights, group_id: p.group_id });
      await remember(p.user_id, p.email, k.fp);
      done++;
    } catch (e) { console.warn("pending access", e); }
  }
  return done;
}

// ---- a new vault key (after someone left)

export async function rotate(vaultID) {
  const v = C.S.vaults.get(vaultID);
  if (!v || !v.key) throw new Error(t("This vault cannot be opened."));
  const items = [...C.S.items.values()].filter((i) => i.vault_id === vaultID);
  if (items.some((i) => !i.data)) throw new Error(t("Some items of this vault cannot be decrypted; the key cannot be replaced."));
  const { members } = await api("GET", "/api/vaults/" + vaultID + "/members");
  const key = pz.random(32);
  const sealed = {};
  for (const m of members) {
    const k = await keyCheck(m.user_id, m.public_key);
    if (k.status === "changed" && !(await confirmBox(t("The key of %s has changed since you confirmed it. Seal the vault to the new key anyway?", m.email), t("Continue"), true))) {
      throw new Error(t("Stopped."));
    }
    sealed[m.user_id] = await sealFor(m.public_key, key, vaultID);
    await remember(m.user_id, m.email, k.fp);
  }
  const out = [];
  for (const it of items) out.push({ id: it.id, data: await pz.sealJSON(key, it.data, pz.AAD.item(vaultID, it.id)) });
  await api("POST", "/api/vaults/" + vaultID + "/rotate", {
    key_version: v.keyVersion, data: await pz.seal(key, pz.utf8(v.name || ""), pz.AAD.vaultName(vaultID)), members: sealed, items: out,
  });
  await C.sync(0);
}

// rotateBanner asks managers to replace the key of a vault that needs it.
export function rotateBanner(vaultID) {
  const v = C.S.vaults.get(vaultID);
  if (!v || !v.needsRotation || v.rights !== "manage") return null;
  const b = button(t("Replace the key now"), { class: "secondary sm", icon: "refresh", onclick: async () => {
    b.disabled = true;
    try { await rotate(vaultID); toast(t("The vault has a new key.")); C.render(); } catch (e) { toast(e.message, true); b.disabled = false; }
  } });
  return el("div", { class: "flash warn" }, icon("alert"), el("span", { text: t("Someone left this vault and still knows its key. Replace the key so that new items are safe from them.") }), b);
}

// ---- the vault dialog: members, groups, name

export async function openVault(vaultID) {
  const v = C.S.vaults.get(vaultID);
  if (!v) return;
  const manage = v.rights === "manage";
  const body = el("div", { class: "stack" }, el("p", { class: "busy" }, el("span", { class: "spinner" })));
  const d = C.dialog(vaultLabel(vaultID), body);
  const refresh = async () => {
    let data, dir = [], groups = [];
    try {
      data = await api("GET", "/api/vaults/" + vaultID + "/members");
      if (manage) [dir, groups] = await Promise.all([api("GET", "/api/directory"), api("GET", "/api/groups")]);
    } catch (e) { body.replaceChildren(el("div", { class: "flash err" }, icon("alert"), el("span", { text: e.message }))); return; }
    body.replaceChildren(...(await vaultBody(vaultID, v, manage, data, dir, groups, refresh, d)).filter(Boolean));
  };
  await refresh();
}

function dateInput(value) {
  const inp = el("input", { type: "date", class: "narrow", "aria-label": t("Access until") });
  if (value) inp.value = new Date(value).toISOString().slice(0, 10);
  inp.min = new Date(Date.now() + 864e5).toISOString().slice(0, 10);
  return inp;
}

// endOfDay turns a date field into the end of that day (local time).
function endOfDay(inp) {
  if (!inp.value) return null;
  const [y, m, dd] = inp.value.split("-").map(Number);
  return new Date(y, m - 1, dd, 23, 59, 59).toISOString();
}

function rightsSelect(cur, disabled) {
  return el("select", { class: "narrow", disabled, "aria-label": t("Rights") }, ...RIGHTS.map((r) => el("option", { value: r, selected: r === cur }, rightsLabel(r))));
}

async function vaultBody(vaultID, v, manage, data, dir, groups, refresh, dlg) {
  const S = C.S;
  const me = S.acct.email;
  const out = [];
  const guard = (fn) => async (ev) => {
    const b = ev && ev.currentTarget;
    if (b) b.disabled = true;
    try { await fn(); } catch (e) { toast(e instanceof ApiError || e instanceof Error ? e.message : String(e), true); } finally { if (b) b.disabled = false; }
  };
  const banner = rotateBanner(vaultID);
  if (banner) out.push(banner);
  for (const [id, email] of warnings) {
    if (data.members.some((m) => m.user_id === id) || manage) {
      out.push(el("div", { class: "flash err" }, icon("alert"), el("span", { text: t("The public key of %s has changed. Ask the person whether they set up their account again before you give access.", email) })));
    }
  }
  if (manage) {
    out.push(el("div", { class: "row" },
      button(t("Rename"), { class: "ghost sm", icon: "edit", onclick: guard(async () => {
        const name = await C.prompt1(t("Rename the vault"), t("Name"), v.name || "");
        if (!name || name === v.name) return;
        await api("PUT", "/api/vaults/" + vaultID, { data: await pz.seal(v.key, pz.utf8(name), pz.AAD.vaultName(vaultID)) });
        await C.sync(0); dlg.close(); C.render();
      }) })));
  }
  // members
  const rows = [];
  for (const m of data.members) {
    const fp = await pz.fingerprint(pz.unb64u(m.public_key));
    const self = m.email === me;
    const viaGroup = m.group_id != null;
    const r = rightsSelect(m.rights, !manage || viaGroup);
    const until = dateInput(m.expires_at);
    until.disabled = !manage || viaGroup;
    const save = async () => {
      await api("PUT", "/api/vaults/" + vaultID + "/members", { user_id: m.user_id, rights: r.value, expires_at: endOfDay(until) });
      toast(t("Saved."));
      await C.sync(0); C.render(); await refresh();
    };
    r.addEventListener("change", guard(save));
    until.addEventListener("change", guard(save));
    rows.push(el("tr", null,
      el("td", null, el("b", { text: m.email }), self ? el("small", { class: "muted", text: " (" + t("you") + ")" }) : null, m.disabled ? el("small", { class: "badge", text: t("disabled") }) : null,
        el("br"), el("small", { class: "muted mono", title: t("Fingerprint of the public key"), text: fp })),
      el("td", null, r, viaGroup ? el("small", { class: "muted", text: " " + t("through %s", m.group_name) }) : null),
      el("td", { class: "hide-sm" }, until),
      el("td", { class: "actions" }, manage && !self && !viaGroup ? button("", { class: "ghost sm", icon: "trash", aria: t("Remove"), title: t("Remove"), onclick: guard(async () => {
        if (!(await confirmBox(t("Remove %s from this vault? The vault then gets a new key.", m.email), t("Remove"), true))) return;
        await api("DELETE", "/api/vaults/" + vaultID + "/members/" + m.user_id);
        await C.sync(0);
        try { await rotate(vaultID); toast(t("Removed; the vault has a new key.")); } catch (e) { toast(e.message, true); }
        C.render(); await refresh();
      }) }) : null)));
  }
  out.push(el("h3", { text: t("Members") }), el("div", { class: "table-wrap" }, el("table", null,
    el("thead", null, el("tr", null, el("th", { text: t("Person") }), el("th", { text: t("Rights") }), el("th", { class: "hide-sm", text: t("Access until") }), el("th"))),
    el("tbody", null, ...rows))));
  out.push(el("p", { class: "small muted", text: t("Use: fill and copy, but not show passwords (in this browser and the extension). Read: see everything. Change: also add and edit items. Manage: also members and the vault itself. Anyone who can use an item can find out its password with some effort; do not rely on Use against people with bad intent.") }));
  if (manage) {
    const members = new Set(data.members.map((m) => m.user_id));
    const pick = el("select", { "aria-label": t("Person") }, el("option", { value: "" }, t("Choose a person…")),
      ...dir.filter((u) => !members.has(u.id)).map((u) => el("option", { value: u.id }, u.email + (u.display_name ? " — " + u.display_name : ""))));
    const r = rightsSelect("view", false);
    const until = dateInput("");
    out.push(el("h3", { text: t("Add a person") }), el("div", { class: "row wrap" }, pick, r, until,
      button(t("Add"), { class: "primary sm", icon: "plus", onclick: guard(async () => {
        const u = dir.find((x) => String(x.id) === pick.value);
        if (!u) return;
        const k = await keyCheck(u.id, u.public_key);
        const q = k.status === "changed"
          ? t("Warning: the key of %s is not the one you confirmed before. Fingerprint now: %s. Add the person anyway?", u.email, k.fp)
          : t("Fingerprint of %s: %s. The person sees it under My account. Add?", u.email, k.fp);
        if (!(await confirmBox(q, t("Add"), k.status === "changed"))) return;
        await api("PUT", "/api/vaults/" + vaultID + "/members", { user_id: u.id, wrapped_key: await sealFor(u.public_key, v.key, vaultID), rights: r.value, expires_at: endOfDay(until) });
        await remember(u.id, u.email, k.fp);
        warnings.delete(u.id);
        toast(t("Added."));
        await refresh();
      }) })),
    el("p", { class: "small muted", text: t("An end date ends the access by itself (time-limited access); the vault then gets a new key the next time a manager opens it.") }));
    // groups
    const grows = data.groups.map((g) => {
      const gr = rightsSelect(g.rights, false);
      gr.addEventListener("change", guard(async () => { await api("PUT", "/api/vaults/" + vaultID + "/groups", { group_id: g.group_id, rights: gr.value }); await C.sync(0); await refresh(); }));
      return el("tr", null, el("td", null, el("b", { text: g.name }), el("small", { class: "muted", text: " · " + t("%d members", g.members) })), el("td", null, gr),
        el("td", { class: "actions" }, button("", { class: "ghost sm", icon: "trash", aria: t("Remove"), title: t("Remove"), onclick: guard(async () => {
          if (!(await confirmBox(t("Take the access of the group %s away? The vault then gets a new key.", g.name), t("Remove"), true))) return;
          await api("DELETE", "/api/vaults/" + vaultID + "/groups/" + g.group_id);
          await C.sync(0);
          try { await rotate(vaultID); } catch (e) { toast(e.message, true); }
          C.render(); await refresh();
        }) })));
    });
    const has = new Set(data.groups.map((g) => g.group_id));
    const gpick = el("select", { "aria-label": t("Group") }, el("option", { value: "" }, t("Choose a group…")),
      ...groups.filter((g) => !has.has(g.id)).map((g) => el("option", { value: g.id }, g.name + " (" + g.members + ")")));
    const gr = rightsSelect("view", false);
    out.push(el("h3", { text: t("Groups") }),
      grows.length ? el("div", { class: "table-wrap" }, el("table", null, el("tbody", null, ...grows))) : el("p", { class: "small muted", text: groups.length ? t("No group has access.") : t("There are no groups yet; administrators make them under Groups.") }),
      groups.length ? el("div", { class: "row wrap" }, gpick, gr, button(t("Give access"), { class: "secondary sm", icon: "plus", onclick: guard(async () => {
        if (!gpick.value) return;
        await api("PUT", "/api/vaults/" + vaultID + "/groups", { group_id: Number(gpick.value), rights: gr.value });
        await C.sync(0);
        const n = await completePending(true);
        toast(t("Access given to %d people.", n));
        await refresh();
      }) })) : null);
  }
  // leave or delete
  const foot = el("div", { class: "row vactions" });
  foot.append(button(t("Leave the vault"), { class: "ghost", icon: "back", onclick: guard(async () => {
    if (!(await confirmBox(t("Leave the vault %s? You lose access to its items.", vaultLabel(vaultID)), t("Leave"), true))) return;
    const myID = (data.members.find((m) => m.email === me) || {}).user_id;
    await api("DELETE", "/api/vaults/" + vaultID + "/members/" + myID);
    dlg.close(); C.S.view = "all"; C.S.vault = ""; await C.sync(0); C.render();
  }) }));
  if (manage) {
    foot.append(button(t("Delete the vault"), { class: "danger", icon: "trash", onclick: guard(async () => {
      if (!(await confirmBox(t("Delete the vault %s with all its items for everyone? This cannot be undone.", vaultLabel(vaultID)), t("Delete"), true))) return;
      await api("DELETE", "/api/vaults/" + vaultID);
      dlg.close(); C.S.view = "all"; C.S.vault = ""; await C.sync(0); C.render();
    }) }));
  }
  out.push(foot);
  return out;
}
