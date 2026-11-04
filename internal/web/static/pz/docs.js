// Documentation of an item: a page with headings, text, lists, links,
// tables and pictures (instructions for a device, for example). It is kept
// as an encrypted file of the item, its pictures as encrypted files too;
// the server sees only sealed bytes. Everything shown goes through clean(),
// which keeps a short list of tags and attributes and drops the rest, so a
// page written by one member cannot run code in another member's vault.
import * as pz from "./crypto.js";
import { t, api, el, icon, button, toast } from "./common.js";

let C = null; // { S, saveItem, render, canEditItem, fmtDate, dialog, prompt1 } from vault.js

export function initDocs(ctx) { C = ctx; }

const MAX_HTML = 2 << 20;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// ---- the allowed page: tags (some renamed) and their attributes

const KEEP = {
  P: "p", DIV: "p", BR: "br", H1: "h2", H2: "h2", H3: "h3", H4: "h4", H5: "h4", H6: "h4",
  B: "b", STRONG: "b", I: "i", EM: "i", U: "u", S: "s", STRIKE: "s", DEL: "s",
  UL: "ul", OL: "ol", LI: "li", A: "a", BLOCKQUOTE: "blockquote", PRE: "pre", CODE: "code", HR: "hr", IMG: "img",
  TABLE: "table", THEAD: "thead", TBODY: "tbody", TR: "tr", TH: "th", TD: "td",
};
// dropped with everything inside
const DROP = new Set(["SCRIPT", "STYLE", "TEMPLATE", "IFRAME", "OBJECT", "EMBED", "SVG", "MATH", "NOSCRIPT", "TITLE", "HEAD", "META", "LINK", "FORM", "INPUT", "BUTTON", "SELECT", "TEXTAREA", "VIDEO", "AUDIO", "CANVAS"]);

function safeHref(h) {
  const v = String(h || "").trim();
  return /^(https?:\/\/|mailto:)/i.test(v) ? v : "";
}

// clean copies the allowed part of a node tree into doc (a document or a
// fragment's owner); unknown tags give way to their content.
function clean(src, doc, files) {
  const out = doc.createDocumentFragment();
  for (const n of src.childNodes) {
    if (n.nodeType === 3) { out.append(doc.createTextNode(n.nodeValue)); continue; }
    if (n.nodeType !== 1) continue;
    const tag = n.tagName.toUpperCase();
    if (DROP.has(tag)) continue;
    const to = KEEP[tag];
    if (!to) { out.append(clean(n, doc, files)); continue; }
    const e = doc.createElement(to);
    if (to === "a") {
      const h = safeHref(n.getAttribute("href"));
      if (!h) { out.append(clean(n, doc, files)); continue; }
      e.setAttribute("href", h);
    }
    if (to === "img") {
      const id = n.getAttribute("data-att") || "";
      if (!UUID.test(id) || (files && !files.has(id))) continue;
      e.setAttribute("data-att", id);
      const alt = (n.getAttribute("alt") || "").slice(0, 200);
      if (alt) e.setAttribute("alt", alt);
      out.append(e);
      continue;
    }
    if ((to === "td" || to === "th") && /^[1-9]$/.test(n.getAttribute("colspan") || "")) e.setAttribute("colspan", n.getAttribute("colspan"));
    if (to !== "br" && to !== "hr") e.append(clean(n, doc, files));
    out.append(e);
  }
  return out;
}

function parse(html) {
  return new DOMParser().parseFromString(String(html || ""), "text/html").body;
}

// cleanHTML turns any HTML into the stored form.
export function cleanHTML(html, files) {
  const doc = document.implementation.createHTMLDocument("");
  const box = doc.createElement("div");
  box.append(clean(parse(html), doc, files));
  return box.innerHTML;
}

function plainText(html) {
  return (parse(html).textContent || "").replace(/\s+/g, " ").trim();
}

// ---- files (the page and its pictures), sealed here

async function putFile(item, bytes) {
  const st = await api("GET", "/api/storage");
  if (bytes.length + 64 > st.max_file) throw new Error(t("The file is larger than %d MB.", Math.floor(st.max_file / 1048576)));
  const key = pz.random(32);
  const id = pz.uuid();
  const sealed = await pz.sealBytes(key, bytes, pz.AAD.file(id));
  const r = await fetch("/api/items/" + item.id + "/files/" + id, { method: "PUT", body: sealed, credentials: "same-origin", headers: { "Content-Type": "application/octet-stream" } });
  if (!r.ok) {
    let m = "";
    try { m = (await r.json()).message; } catch (e) { /* no JSON */ }
    throw new Error(m || t("Something went wrong (%s).", r.status));
  }
  return { id, key: pz.b64u(key), size: bytes.length };
}

async function getFile(f) {
  const r = await fetch("/api/files/" + f.id, { credentials: "same-origin", cache: "no-store" });
  if (!r.ok) throw new Error(t("Something went wrong (%s).", r.status));
  return await pz.openBytes(pz.unb64u(f.key), new Uint8Array(await r.arrayBuffer()), pz.AAD.file(f.id));
}

const picCache = new Map(); // file id → data: URL (decrypted pictures of this tab)

async function picURL(f) {
  if (picCache.has(f.id)) return picCache.get(f.id);
  const bytes = await getFile(f);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  const type = /^image\/(png|jpeg|gif|webp)$/.test(f.type) ? f.type : "image/png";
  const url = "data:" + type + ";base64," + btoa(bin);
  picCache.set(f.id, url);
  return url;
}

// docID is the file id of an item's page ("" without one).
function docID(d) { return d && d.doc && d.doc.file ? d.doc.file.id : ""; }

function docFiles(d) {
  return new Map((d.attachments || []).filter((a) => a.doc).map((a) => [a.id, a]));
}

async function loadHTML(d) {
  if (!d.doc || !d.doc.file) return "";
  return pz.fromUtf8(await getFile(d.doc.file));
}

// showPictures puts the decrypted pictures into a cleaned page.
function showPictures(root, files) {
  for (const img of root.querySelectorAll("img[data-att]")) {
    const f = files.get(img.getAttribute("data-att"));
    if (f) picURL(f).then((u) => { img.src = u; }, () => { img.alt = t("The picture could not be loaded."); });
  }
}

function rendered(html, files) {
  const box = el("div", { class: "docpage" });
  box.append(clean(parse(html), document, files));
  for (const a of box.querySelectorAll("a")) { a.target = "_blank"; a.rel = "noopener noreferrer"; }
  showPictures(box, files);
  return box;
}

// ---- the item view: a short preview and the button that opens the page

export function docField(it, hidden) {
  const d = it.data;
  const can = !it.deleted_at && C.canEditItem(it);
  if (!d.doc && !can) return null;
  if (hidden) return el("div", { class: "vfield" }, el("label", { text: t("Documentation") }), el("p", { class: "small muted", text: t("Hidden: you may use this item, not read it.") }));
  return el("div", { class: "vfield" }, el("label", { text: t("Documentation") }),
    d.doc ? el("p", { class: "small" }, d.doc.preview || "", el("br"), el("small", { class: "muted", text: t("Changed %s", C.fmtDate(d.doc.updated)) + (d.doc.by ? " " + t("by %s", d.doc.by) : "") })) : null,
    el("div", { class: "row" }, d.doc ? button(t("Open the documentation"), { class: "secondary sm", icon: "note", onclick: () => openDoc(it, false) }) : null,
      can ? button(d.doc ? t("Edit") : t("Write documentation"), { class: "ghost sm", icon: "edit", onclick: () => openDoc(it, true) }) : null));
}

// ---- the page: reading, or the editor

export async function openDoc(item, edit) {
  const body = el("div", { class: "stack" }, el("p", { class: "muted", text: t("Loading…") }));
  const d0 = C.dialog(t("Documentation: %s", item.data.name || ""), body);
  d0.classList.add("docdlg");
  let html = "";
  // the page file html was read from: a save checks that it is still the item's
  let htmlDoc = docID(item.data);
  let saving = false, closed = false;
  try { html = await loadHTML(item.data); } catch (e) { body.replaceChildren(el("p", { class: "err", text: e.message })); return; }
  // no closing while a save runs (its pictures would be removed under it)
  d0.addEventListener("cancel", (ev) => { if (saving) ev.preventDefault(); });
  d0.addEventListener("close", () => { closed = true; });
  const closeBtn = d0.querySelector(".row.spread .iconbtn");
  const read = () => {
    const it = C.S.items.get(item.id) || item;
    const can = !it.deleted_at && C.canEditItem(it);
    body.replaceChildren(html ? rendered(html, docFiles(it.data)) : el("p", { class: "muted", text: t("There is no documentation yet.") }),
      can ? el("div", { class: "row end" }, button(t("Edit"), { class: "primary", icon: "edit", onclick: () => editor() })) : null);
  };
  const editor = () => {
    const it = C.S.items.get(item.id) || item;
    const files = docFiles(it.data);
    const added = []; // pictures uploaded in this editor (removed again on cancel)
    const page = el("div", { class: "docpage docedit", contenteditable: "true", spellcheck: "true", role: "textbox", "aria-multiline": "true", "aria-label": t("Documentation") });
    page.append(clean(parse(html), document, files));
    showPictures(page, files);
    try { document.execCommand("styleWithCSS", false, false); document.execCommand("defaultParagraphSeparator", false, "p"); } catch (e) { /* older browsers */ }
    const cmd = (c, v) => () => { page.focus(); document.execCommand(c, false, v); };
    const tb = (label, title, fn, cls) => el("button", { type: "button", class: "ghost sm" + (cls ? " " + cls : ""), title, "aria-label": title, onmousedown: (ev) => ev.preventDefault(), onclick: fn }, label);
    const insertPicture = async (file) => {
      if (!/^image\/(png|jpeg|gif|webp)$/.test(file.type)) { toast(t("Choose a PNG, JPEG, GIF or WebP picture."), true); return; }
      const bytes = new Uint8Array(await file.arrayBuffer());
      const f = await putFile(it, bytes);
      // the dialog closed during the upload: nobody uses the picture
      if (closed) { await api("DELETE", "/api/files/" + f.id).catch(() => {}); return; }
      const meta = { id: f.id, name: (file.name || "picture").slice(0, 200), size: f.size, type: file.type, key: f.key, doc: true };
      files.set(f.id, meta);
      added.push(meta);
      const img = document.createElement("img");
      img.setAttribute("data-att", f.id);
      img.setAttribute("alt", meta.name);
      img.src = await picURL(meta);
      page.focus();
      const sel = getSelection();
      if (sel.rangeCount && page.contains(sel.getRangeAt(0).commonAncestorContainer)) {
        const r = sel.getRangeAt(0);
        r.deleteContents();
        r.insertNode(img);
        r.setStartAfter(img);
        sel.removeAllRanges();
        sel.addRange(r);
      } else page.append(img);
    };
    const picIn = el("input", { type: "file", accept: "image/png,image/jpeg,image/gif,image/webp", hidden: true, multiple: true });
    picIn.addEventListener("change", async () => {
      for (const f of picIn.files) { try { await insertPicture(f); } catch (e) { toast(e.message, true); } }
      picIn.value = "";
    });
    const link = async () => {
      const sel = getSelection();
      const range = sel.rangeCount ? sel.getRangeAt(0).cloneRange() : null;
      const url = await C.prompt1(t("Link"), t("Web address (https://…)"), "https://");
      if (!url) return;
      if (!safeHref(url)) { toast(t("Only https://, http:// and mailto: links are allowed."), true); return; }
      page.focus();
      if (range) { sel.removeAllRanges(); sel.addRange(range); }
      if (range && !range.collapsed) document.execCommand("createLink", false, url);
      else document.execCommand("insertHTML", false, cleanHTML('<a href="' + url.replace(/"/g, "%22") + '">' + url.replace(/</g, "&lt;") + "</a>"));
    };
    const table = () => {
      page.focus();
      document.execCommand("insertHTML", false, "<table><tbody><tr><th>" + t("Name") + "</th><th>" + t("Value") + "</th></tr><tr><td><br></td><td><br></td></tr><tr><td><br></td><td><br></td></tr></tbody></table><p><br></p>");
    };
    // pasted and dropped pictures become files; pasted HTML is cleaned
    page.addEventListener("paste", async (ev) => {
      const cd = ev.clipboardData;
      if (!cd) return;
      const pics = [...cd.files].filter((f) => f.type.startsWith("image/"));
      ev.preventDefault();
      if (pics.length) { for (const f of pics) { try { await insertPicture(f); } catch (e) { toast(e.message, true); } } return; }
      const h = cd.getData("text/html");
      if (h) document.execCommand("insertHTML", false, cleanHTML(h, new Map()));
      else document.execCommand("insertText", false, cd.getData("text/plain"));
    });
    page.addEventListener("drop", async (ev) => {
      const pics = [...(ev.dataTransfer && ev.dataTransfer.files || [])].filter((f) => f.type.startsWith("image/"));
      if (!pics.length) { ev.preventDefault(); return; }
      ev.preventDefault();
      for (const f of pics) { try { await insertPicture(f); } catch (e) { toast(e.message, true); } }
    });
    const bar = el("div", { class: "doctools", role: "toolbar", "aria-label": t("Formatting") },
      tb("¶", t("Paragraph"), cmd("formatBlock", "<p>")), tb("H2", t("Heading"), cmd("formatBlock", "<h2>")), tb("H3", t("Subheading"), cmd("formatBlock", "<h3>")),
      tb("B", t("Bold"), cmd("bold"), "b"), tb("I", t("Italic"), cmd("italic"), "i"), tb("U", t("Underline"), cmd("underline"), "u"), tb("S", t("Strikethrough"), cmd("strikeThrough"), "s"),
      tb("•", t("Bulleted list"), cmd("insertUnorderedList")), tb("1.", t("Numbered list"), cmd("insertOrderedList")),
      tb("❝", t("Quote"), cmd("formatBlock", "<blockquote>")), tb("</>", t("Code (commands, configuration)"), cmd("formatBlock", "<pre>")),
      tb("―", t("Line"), cmd("insertHorizontalRule")), tb("▦", t("Table"), table), tb(icon("link"), t("Link"), () => link().catch((e) => toast(e.message, true))),
      tb(icon("upload"), t("Picture"), () => picIn.click()), tb("⨯", t("Clear the formatting"), cmd("removeFormat")),
      tb("↶", t("Undo"), cmd("undo")), tb("↷", t("Redo"), cmd("redo")), picIn);
    const save = button(t("Save"), { class: "primary", onclick: async () => {
      save.disabled = cancel.disabled = true;
      saving = true;
      if (closeBtn) closeBtn.disabled = true;
      try {
        const used = await store(it, page, files);
        // what the saved page shows is no longer removed on closing
        for (let i = added.length - 1; i >= 0; i--) if (used.has(added[i].id)) added.splice(i, 1);
        read();
      } catch (e) { toast(e.message, true); } finally {
        saving = false;
        save.disabled = cancel.disabled = false;
        if (closeBtn) closeBtn.disabled = false;
      }
    } });
    const cancel = button(t("Cancel"), { class: "ghost", onclick: async () => {
      for (const f of added) await api("DELETE", "/api/files/" + f.id).catch(() => {});
      added.length = 0;
      if (html) read(); else d0.close();
    } });
    d0.addEventListener("close", () => { for (const f of added) api("DELETE", "/api/files/" + f.id).catch(() => {}); });
    body.replaceChildren(bar, page, el("small", { class: "muted", text: t("Paste or drop screenshots straight into the page. Text, pictures and files are encrypted in this browser like the rest of the item.") }),
      el("div", { class: "row end" }, cancel, save));
    page.focus();
  };
  // store seals the page as a file, points the item at it and removes the
  // former page and the pictures it no longer shows. When someone else saved
  // the page meanwhile, nothing is saved or removed: the text stays in the
  // editor. Returns the pictures the saved page uses.
  const store = async (it, page, files) => {
    const stored = cleanHTML(page.innerHTML, files);
    if (stored.length > MAX_HTML) throw new Error(t("The documentation is too long (at most 2 MB of text)."));
    const used = new Set([...parse(stored).querySelectorAll("img[data-att]")].map((i) => i.getAttribute("data-att")));
    const cur = C.S.items.get(it.id) || it;
    if (!cur.data || docID(cur.data) !== htmlDoc) {
      throw new Error(t("Someone else changed this documentation while you were editing it. Your text is still here: copy what you need, then cancel and open the documentation again."));
    }
    const old = cur.data.doc && cur.data.doc.file;
    const empty = !plainText(stored) && !used.size;
    let doc = null;
    if (!empty) {
      const f = await putFile(cur, pz.utf8(stored));
      const text = plainText(stored);
      doc = { file: { id: f.id, key: f.key, size: f.size }, preview: text.length > 200 ? text.slice(0, 200) + "…" : text, updated: new Date().toISOString(), by: C.S.acct.email };
    }
    // pictures this editor did not know (files: the page it opened and the
    // uploads) are kept, never removed
    const keep = (cur.data.attachments || []).filter((a) => !a.doc || used.has(a.id) || !files.has(a.id));
    for (const f of files.values()) if (used.has(f.id) && !keep.some((a) => a.id === f.id)) keep.push(f);
    const gone = (cur.data.attachments || []).filter((a) => a.doc && !used.has(a.id) && files.has(a.id));
    const data = Object.assign({}, cur.data, { attachments: keep });
    if (doc) data.doc = doc; else delete data.doc;
    try {
      await C.saveItem(cur, data);
    } catch (e) {
      if (doc) await api("DELETE", "/api/files/" + doc.file.id).catch(() => {});
      throw e;
    }
    if (old) await api("DELETE", "/api/files/" + old.id).catch(() => {});
    for (const f of gone) await api("DELETE", "/api/files/" + f.id).catch(() => {});
    for (const f of files.values()) if (!used.has(f.id)) await api("DELETE", "/api/files/" + f.id).catch(() => {});
    html = stored;
    htmlDoc = doc ? doc.file.id : "";
    toast(empty ? t("The documentation was removed.") : t("Saved."));
    C.render();
    return used;
  };
  if (edit && !C.canEditItem(item)) edit = false;
  if (edit) editor(); else read();
}
