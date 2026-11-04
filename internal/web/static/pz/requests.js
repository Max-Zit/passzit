// Requests for access in the web vault: ask for more rights in a team vault
// for some hours, or ask a person (a manager or an administrator) for
// access to a vault one is not in; managers and the person asked approve
// or reject here. Rights given this way end by themselves.
import { t, api, el, button, toast } from "./common.js";
import { RIGHTS, rightsLabel, vaultLabel, grantMember } from "./sharing.js";

let C = null; // { S, render, sync, dialog, fmtDate } from vault.js

export function initRequests(ctx) { C = ctx; }

const HOURS = [[1, "1 hour"], [4, "4 hours"], [8, "8 hours"], [24, "1 day"], [72, "3 days"], [168, "1 week"], [720, "30 days"]];

function hoursSelect() {
  return el("select", { class: "narrow", "aria-label": t("For how long") }, ...HOURS.map(([h, l]) => el("option", { value: h, selected: h === 4 }, t(l))));
}

function hoursText(h) {
  const f = HOURS.find(([x]) => x === h);
  return f ? t(f[1]) : t("%d hours", h);
}

// refreshCount fetches how many requests wait for this user (the badge).
export async function refreshCount() {
  try {
    const list = await api("GET", "/api/requests");
    C.S.requestsWaiting = list.filter((q) => q.decide).length;
  } catch (e) { C.S.requestsWaiting = 0; }
}

function statusText(s) {
  return { pending: t("waiting"), approved: t("approved"), rejected: t("rejected"), cancelled: t("withdrawn"), expired: t("not decided in time") }[s] || s;
}

// openRequests shows the requests; vaultID preselects "more rights" there.
export async function openRequests(vaultID) {
  const body = el("div", { class: "stack" }, el("p", { class: "muted", text: t("Loading…") }));
  const d = C.dialog(t("Access requests"), body);
  const guard = (fn) => async (ev) => {
    const b = ev && ev.currentTarget;
    if (b) b.disabled = true;
    try { await fn(); } catch (e) { toast(e.message || String(e), true); } finally { if (b) b.disabled = false; }
  };
  let dir = null;
  const fill = async () => {
    const list = await api("GET", "/api/requests");
    C.S.requestsWaiting = list.filter((q) => q.decide).length;
    const out = [];
    // waiting for this user's decision
    const mine = list.filter((q) => q.mine);
    const decide = list.filter((q) => q.decide);
    if (decide.length) {
      out.push(el("h3", { text: t("Waiting for your decision") }));
      for (const q of decide) out.push(decideRow(q));
    }
    out.push(el("h3", { text: t("Ask for access") }), askForm(vaultID));
    out.push(el("h3", { text: t("Your requests") }));
    out.push(mine.length ? el("ul", { class: "vitems plain" }, ...mine.map((q) => el("li", null,
      el("b", { text: q.vault_id ? vaultLabel(q.vault_id) : t("to %s", q.asked_email) }), " · " + rightsLabel(q.rights) + " · " + hoursText(q.hours) + " · ",
      el("span", { class: q.status === "approved" ? "badge ok" : q.status === "pending" ? "badge" : "badge muted", text: statusText(q.status) }),
      el("br"), el("small", { class: "muted", text: C.fmtDate(q.created_at) + (q.decided_by ? " · " + t("decided by %s", q.decided_by) : "") + " · " + q.reason }),
      q.status === "pending" ? button(t("Withdraw"), { class: "ghost sm", onclick: guard(async () => { await api("DELETE", "/api/requests/" + q.id); await fill(); }) }) : null)))
      : el("p", { class: "small muted", text: t("You have not asked for access in the last 30 days.") }));
    body.replaceChildren(...out);
  };

  // a request someone else made, for this user to decide
  const decideRow = (q) => {
    const where = q.vault_id ? t("More rights in %s", vaultLabel(q.vault_id)) : t("Access to a vault you manage");
    const head = el("p", null, el("b", { text: q.email }), " · " + where + ": " + rightsLabel(q.rights) + " · " + hoursText(q.hours),
      q.current_rights ? el("small", { class: "muted", text: " (" + t("now: %s", rightsLabel(q.current_rights)) + ")" }) : null,
      el("br"), el("small", { class: "muted", text: C.fmtDate(q.created_at) + " · " + t("Reason: %s", q.reason) }));
    const reject = button(t("Reject"), { class: "ghost sm", onclick: guard(async () => {
      await api("POST", "/api/requests/" + q.id + "/decide", { approve: false });
      toast(t("Rejected."));
      await fill();
    }) });
    if (q.vault_id) {
      return el("div", { class: "box" }, head, el("div", { class: "row" },
        button(t("Approve"), { class: "primary sm", onclick: guard(async () => {
          await api("POST", "/api/requests/" + q.id + "/decide", { approve: true });
          toast(t("Approved; the rights end by themselves after %s.", hoursText(q.hours)));
          await C.sync(0); C.render(); await fill();
        }) }), reject));
    }
    // through a person: choose the vault (one this user manages)
    const own = [...C.S.vaults.entries()].filter(([, v]) => v.kind === "shared" && v.rights === "manage");
    const pick = el("select", { "aria-label": t("Vault") }, el("option", { value: "" }, t("Choose a vault…")),
      ...own.map(([id]) => el("option", { value: id }, vaultLabel(id))));
    return el("div", { class: "box" }, head, el("div", { class: "row wrap" }, pick,
      button(t("Give access"), { class: "primary sm", onclick: guard(async () => {
        if (!pick.value) { toast(t("Choose a vault."), true); return; }
        const members = (await api("GET", "/api/vaults/" + pick.value + "/members")).members || [];
        let added = false;
        if (!members.some((m) => m.user_id === q.user_id)) {
          const until = new Date(Date.now() + q.hours * 3600e3).toISOString();
          if (!(await grantMember(pick.value, { user_id: q.user_id, email: q.email, public_key: q.public_key }, q.rights, until))) return;
          added = true;
        }
        try {
          await api("POST", "/api/requests/" + q.id + "/decide", { approve: true, vault_id: pick.value });
        } catch (e) {
          // not approved (withdrawn or ended meanwhile?): the access given for it goes again
          if (!added) throw e;
          let undone = true;
          await api("DELETE", "/api/vaults/" + pick.value + "/members/" + q.user_id).catch(() => { undone = false; });
          await C.sync(0); C.render(); await fill().catch(() => {});
          throw new Error(e.message + " " + (undone ? t("The person was removed from the vault again.") : t("The person could not be removed from the vault again: remove them under Members and settings.")));
        }
        toast(t("Approved; the access ends by itself after %s.", hoursText(q.hours)));
        await C.sync(0); C.render(); await fill();
      }) }), reject),
      own.length ? null : el("p", { class: "small muted", text: t("You manage no team vault; reject the request or ask a manager to give the access.") }));
  };

  // the form for a new request
  const askForm = (pre) => {
    const shared = [...C.S.vaults.entries()].filter(([, v]) => v.kind === "shared" && v.rights !== "manage");
    const mode = el("select", { "aria-label": t("What do you need?") },
      el("option", { value: "more", selected: !!pre || shared.length > 0 }, t("More rights in a team vault I am in")),
      el("option", { value: "person", selected: !pre && !shared.length }, t("Access to a vault I am not in")));
    const vault = el("select", { "aria-label": t("Vault") }, ...shared.map(([id]) => el("option", { value: id, selected: id === pre }, vaultLabel(id))));
    const person = el("select", { "aria-label": t("Person") }, el("option", { value: "" }, t("Choose a person…")));
    const rights = el("select", { class: "narrow", "aria-label": t("Rights") }, ...RIGHTS.map((r) => el("option", { value: r, selected: r === "view" }, rightsLabel(r))));
    const hours = hoursSelect();
    const reason = el("input", { maxlength: 500, placeholder: t("Why do you need it? For example: fixing the backup of the Proxmox host"), required: true });
    const vaultRow = el("label", null, t("Vault"), vault);
    const personRow = el("label", null, t("Ask"), person, el("small", { text: t("A manager of the vault or an administrator. The person gives you the access in the vault.") }));
    const show = async () => {
      const more = mode.value === "more";
      vaultRow.hidden = !more;
      personRow.hidden = more;
      if (!more && !dir) {
        dir = await api("GET", "/api/directory");
        person.append(...dir.filter((u) => u.email !== C.S.acct.email).map((u) => el("option", { value: u.id }, u.email + (u.display_name ? " — " + u.display_name : ""))));
      }
    };
    mode.addEventListener("change", () => show().catch((e) => toast(e.message, true)));
    show().catch(() => {});
    return el("div", { class: "stack" }, el("label", null, t("What do you need?"), mode), vaultRow, personRow,
      el("div", { class: "grid2" }, el("label", null, t("Rights"), rights), el("label", null, t("For how long"), hours)),
      el("label", null, t("Reason"), reason),
      el("div", { class: "row" }, button(t("Send the request"), { class: "primary", onclick: guard(async () => {
        const q = { rights: rights.value, hours: Number(hours.value), reason: reason.value.trim() };
        if (mode.value === "more") { if (!vault.value) { toast(t("You are in no team vault; ask a person instead."), true); return; } q.vault_id = vault.value; }
        else { if (!person.value) { toast(t("Choose a person."), true); return; } q.asked_id = Number(person.value); }
        if (!q.reason) { toast(t("Say in a few words why you need the access."), true); return; }
        await api("POST", "/api/requests", q);
        toast(t("Sent. You get an e-mail when it is decided (if the server sends e-mail)."));
        await fill();
      }) })),
      el("small", { class: "muted", text: t("Rights given for a request end by themselves. Every request and decision is kept in the audit log.") }));
  };

  try { await fill(); } catch (e) { body.replaceChildren(el("p", { class: "err", text: e.message })); }
  d.addEventListener("close", () => C.render());
}
