// Secret links in the web vault: make one (from a text, a file or an
// item), list them, delete them.
import { t, api, el, icon, button, toast, copy, confirmBox } from "./common.js";
import { sealSend } from "./sendlink.js";
import * as pz from "./crypto.js";

let C = null; // { dialog, fmtDate }

export function initSends(ctx) { C = ctx; }

const HOURS = [[1, "1 hour"], [24, "1 day"], [72, "3 days"], [168, "7 days"], [720, "30 days"]];

// itemText is what "Send a copy" puts into a link.
export function itemText(d) {
  const lines = [d.name || ""];
  if (d.login) {
    if (d.login.username) lines.push(t("User name") + ": " + d.login.username);
    if (d.login.password) lines.push(t("Password") + ": " + d.login.password);
    for (const u of d.login.urls || []) lines.push(t("Website") + ": " + u);
  }
  if (d.notes) lines.push("", d.notes);
  return lines.join("\n").trim();
}

export function openSends(prefill) {
  const text = el("textarea", { rows: 6, maxlength: 50000, placeholder: t("The secret: a password, a note, connection details …") }, prefill || "");
  const file = el("input", { type: "file" });
  const hours = el("select", null, ...HOURS.map(([h, l]) => el("option", { value: h, selected: h === 24 }, t(l))));
  const views = el("input", { type: "number", min: 1, max: 100, value: 1, class: "narrow" });
  const pw = el("input", { type: "password", autocomplete: "new-password", placeholder: t("optional") });
  const out = el("div", { class: "stack", hidden: true });
  const list = el("div");
  const make = button(t("Make the link"), { class: "primary", icon: "link", onclick: async () => {
    if (!text.value.trim() && !file.files.length) { toast(t("Enter a text or choose a file."), true); return; }
    make.disabled = true;
    make.classList.add("loading");
    try {
      const payload = { text: text.value };
      if (file.files.length) {
        const f = file.files[0];
        if (f.size > 8 << 20) throw new Error(t("The file is larger than %d MB.", 8));
        payload.file = { name: f.name.slice(0, 200), type: (f.type || "").slice(0, 100), data: pz.b64u(new Uint8Array(await f.arrayBuffer())) };
      }
      const s = await sealSend(payload, pw.value);
      await api("POST", "/api/sends", { id: s.id, data: s.data, auth: s.auth || undefined, max_views: +views.value || 1, hours: +hours.value });
      const link = location.origin + "/send/" + s.id + "#" + s.fragment;
      const box = el("input", { value: link, readonly: true, class: "mono" });
      out.replaceChildren(el("div", { class: "flash ok" }, icon("check"), el("span", { text: t("The link is ready. Send it to the person; with a password, tell it on another way (phone, message).") })),
        el("div", { class: "row" }, box, button(t("Copy"), { class: "secondary", icon: "copy", onclick: () => copy(link, false) })),
        el("p", { class: "small muted", text: t("The key is in the part after #; the server never sees it. Copy the link now: it cannot be shown again.") }));
      out.hidden = false;
      text.value = ""; pw.value = ""; file.value = "";
      await refresh();
    } catch (e) { toast(e.message, true); } finally { make.disabled = false; make.classList.remove("loading"); }
  } });
  const refresh = async () => {
    let sends = [];
    try { sends = await api("GET", "/api/sends"); } catch (e) { list.replaceChildren(el("p", { class: "small muted", text: e.message })); return; }
    if (!sends.length) { list.replaceChildren(el("p", { class: "small muted", text: t("No secret links yet.") })); return; }
    const now = Date.now();
    list.replaceChildren(el("div", { class: "table-wrap" }, el("table", null,
      el("thead", null, el("tr", null, el("th", { text: t("Made") }), el("th", { text: t("Opened") }), el("th", { text: t("Ends") }), el("th"))),
      el("tbody", null, ...sends.map((s) => {
        const done = s.views >= s.max_views || new Date(s.expires_at).getTime() < now;
        return el("tr", { class: done ? "muted" : "" },
          el("td", null, C.fmtDate(s.created_at), s.protected ? el("span", { title: t("with a password") }, " ", icon("lock")) : null),
          el("td", { text: s.views + " / " + s.max_views }),
          el("td", { text: done ? t("ended") : C.fmtDate(s.expires_at) }),
          el("td", { class: "actions" }, button("", { class: "ghost sm", icon: "trash", aria: t("Delete"), title: t("Delete"), onclick: async () => {
            if (!(await confirmBox(t("Delete this link? It stops working at once."), t("Delete"), true))) return;
            try { await api("DELETE", "/api/sends/" + s.id); await refresh(); } catch (e) { toast(e.message, true); }
          } })));
      })))));
  };
  C.dialog(t("Secret links"),
    el("p", { class: "muted", text: t("A secret link gives one person a password or a file without an account: encrypted in this browser, opened a limited number of times, then gone.") }),
    el("label", null, t("Text"), text),
    el("label", null, t("File"), file, el("small", { text: t("optional, up to 8 MB") })),
    el("div", { class: "grid2" }, el("label", null, t("Works for"), hours), el("label", null, t("Can be opened"), views)),
    el("label", null, t("Password of the link"), pw),
    el("div", { class: "row" }, make), out,
    el("h3", { text: t("Your links") }), list);
  refresh();
}
