// Emergency access on My account. A user seals the own account key to a
// trusted person's public key; the server hands it out only after that
// person asked and the waiting time passed (or the user approved). The
// person then reads the user's personal vault here, in the browser.
import * as pz from "./crypto.js";
import { t, api, el, icon, button, toast, confirmBox, copy, loadKeys } from "./common.js";

const aad = (grantor, grantee) => "passzit/emergency/v1|" + grantor.toLowerCase() + "|" + grantee.toLowerCase();
const fmt = (s) => s ? new Date(s).toLocaleString() : "";

function dialog(title, ...body) {
  const d = el("dialog", { class: "dlg wide" });
  d.append(el("div", { class: "row spread" }, el("h2", { text: title }),
    el("button", { type: "button", class: "iconbtn", "aria-label": t("Close"), onclick: () => d.close() }, icon("x"))), ...body);
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

function status(e) {
  if (!e.requested_at) return t("No request");
  if (e.open) return e.approved_at ? t("Open (approved)") : t("Open (waiting time over)");
  return t("Requested; opens %s", fmt(e.ready_at));
}

export async function initEmergency(box, myEmail) {
  const keys = await loadKeys().catch(() => null);
  const guard = (fn) => async (ev) => {
    const b = ev && ev.currentTarget;
    if (b) b.disabled = true;
    try { await fn(); } catch (e) { toast(e.message, true); } finally { if (b) b.disabled = false; }
  };
  const refresh = async () => {
    let data, dir = [];
    try {
      data = await api("GET", "/api/emergency");
      dir = await api("GET", "/api/directory");
    } catch (e) { box.replaceChildren(el("p", { class: "muted", text: e.message })); return; }
    const out = [];
    // people I trust
    out.push(el("h3", { text: t("People you trust") }));
    if (data.contacts.length) {
      out.push(el("div", { class: "table-wrap" }, el("table", null, el("tbody", null, ...data.contacts.map((e) => el("tr", null,
        el("td", null, el("b", { text: e.grantee }), el("br"), el("small", { class: "muted", text: t("Waiting time: %d days", e.wait_days) })),
        el("td", { text: status(e) }),
        el("td", { class: "actions nowrap" },
          e.requested_at && !e.open ? button(t("Approve now"), { class: "secondary sm", onclick: guard(async () => {
            if (!(await confirmBox(t("Open your vault to %s now?", e.grantee), t("Approve now"), true))) return;
            await api("POST", "/api/emergency/" + e.id + "/approve"); await refresh();
          }) }) : null,
          e.requested_at ? button(t("Reject"), { class: "ghost sm", onclick: guard(async () => { await api("POST", "/api/emergency/" + e.id + "/reject"); await refresh(); }) }) : null,
          button("", { class: "ghost sm", icon: "trash", aria: t("Remove"), title: t("Remove"), onclick: guard(async () => {
            if (!(await confirmBox(t("Remove %s as emergency contact?", e.grantee), t("Remove"), true))) return;
            await api("DELETE", "/api/emergency/" + e.id); await refresh();
          }) }))))))));
    } else {
      out.push(el("p", { class: "small muted", text: t("Nobody yet.") }));
    }
    if (keys) {
      const have = new Set(data.contacts.map((e) => e.grantee_id));
      const pick = el("select", { "aria-label": t("Person") }, el("option", { value: "" }, t("Choose a person…")),
        ...dir.filter((u) => u.email !== myEmail && !have.has(u.id)).map((u) => el("option", { value: u.id }, u.email)));
      const wait = el("input", { type: "number", min: 0, max: 90, value: 7, class: "narrow", "aria-label": t("Waiting time (days)") });
      out.push(el("div", { class: "row wrap" }, pick, el("label", { class: "row" }, t("Waiting time (days)"), wait),
        button(t("Add"), { class: "primary sm", icon: "plus", onclick: guard(async () => {
          const u = dir.find((x) => String(x.id) === pick.value);
          if (!u) return;
          const fp = await pz.fingerprint(pz.unb64u(u.public_key));
          if (!(await confirmBox(t("%s can ask for access to your personal vault; after %d days without your answer it opens. Fingerprint of the person's key: %s. Add?", u.email, +wait.value, fp), t("Add"), false))) return;
          const sealed = await pz.sealTo(pz.unb64u(u.public_key), keys.accountKey, aad(myEmail, u.email));
          await api("POST", "/api/emergency", { grantee_id: u.id, sealed_key: sealed, wait_days: +wait.value });
          toast(t("Added.")); await refresh();
        }) })));
    } else {
      out.push(el("p", { class: "small muted", text: t("Unlock the vault to add a person.") }));
    }
    // people who trust me
    out.push(el("h3", { text: t("People who trust you") }));
    if (data.grants.length) {
      out.push(el("div", { class: "table-wrap" }, el("table", null, el("tbody", null, ...data.grants.map((e) => el("tr", null,
        el("td", null, el("b", { text: e.grantor }), el("br"), el("small", { class: "muted", text: t("Waiting time: %d days", e.wait_days) })),
        el("td", { text: status(e) }),
        el("td", { class: "actions nowrap" },
          !e.requested_at ? button(t("Request access"), { class: "secondary sm", onclick: guard(async () => {
            if (!(await confirmBox(t("Ask for access to the vault of %s? The person sees the request and can reject it within %d days.", e.grantor, e.wait_days), t("Request access"), true))) return;
            await api("POST", "/api/emergency/" + e.id + "/request"); await refresh();
          }) }) : null,
          e.open ? button(t("Open the vault"), { class: "primary sm", icon: "lock", onclick: guard(() => openGranted(e, keys, myEmail)) }) : null,
          button("", { class: "ghost sm", icon: "trash", aria: t("Remove"), title: t("Remove"), onclick: guard(async () => {
            if (!(await confirmBox(t("Stop being the emergency contact of %s?", e.grantor), t("Remove"), true))) return;
            await api("DELETE", "/api/emergency/" + e.id); await refresh();
          }) }))))))));
    } else {
      out.push(el("p", { class: "small muted", text: t("Nobody yet.") }));
    }
    box.replaceChildren(...out);
  };
  await refresh();
}

async function openGranted(e, keys, myEmail) {
  if (!keys) throw new Error(t("Unlock the vault first."));
  const v = await api("GET", "/api/emergency/" + e.id + "/vault");
  const accountKey = await pz.openSealed(keys.privateKey, keys.publicKey, v.sealed_key, aad(v.grantor, myEmail));
  const vaultKey = await pz.open(accountKey, v.wrapped_key, pz.AAD.vaultKey(v.vault_id));
  const rows = [];
  for (const it of v.items) {
    let d = null;
    try { d = await pz.openJSON(vaultKey, it.data, pz.AAD.item(v.vault_id, it.id)); } catch (x) { /* damaged */ }
    if (!d) continue;
    const fields = [];
    const add = (label, value, secret) => {
      if (!value) return;
      const shown = el("code", { class: "mono", text: secret ? "••••••••" : value });
      fields.push(el("div", { class: "row" }, el("small", { class: "muted", text: label + ":" }), shown,
        secret ? button("", { class: "ghost sm", icon: "eye", aria: t("Show"), onclick: () => { shown.textContent = shown.textContent === "••••••••" ? value : "••••••••"; } }) : null,
        button("", { class: "ghost sm", icon: "copy", aria: t("Copy"), onclick: () => copy(value, secret) })));
    };
    if (d.login) {
      add(t("User name"), d.login.username, false);
      add(t("Password"), d.login.password, true);
      for (const u of d.login.urls || []) add(t("Website"), u, false);
    }
    if (d.notes) add(t("Notes"), d.notes, true);
    rows.push(el("li", null, el("b", { text: d.name || "?" }), ...fields));
  }
  dialog(t("Vault of %s", v.grantor),
    el("p", { class: "small muted", text: t("Read only. Copy what you need; the access is in the audit log.") }),
    rows.length ? el("ul", { class: "elist" }, ...rows) : el("p", { class: "muted", text: t("The vault is empty.") }));
}
