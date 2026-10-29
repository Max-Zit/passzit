// The generator panel, used on its own page and in the item editor.
import { generate, entropy, loadOptions, saveOptions } from "./generator.js";
import { t, el, icon, button, copy } from "./common.js";

// generatorPanel builds the controls; onUse (optional) takes the result.
export function generatorPanel(onUse) {
  const o = loadOptions();
  const out = el("output", { class: "genout mono", "aria-live": "polite" });
  const meter = el("span", { class: "meter" }, el("i"), el("small"));
  let value = "";

  const regen = () => {
    value = generate(o);
    out.textContent = value;
    const bits = entropy(o);
    meter.dataset.score = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    meter.querySelector("small").textContent = "~" + bits + " " + t("bits");
    saveOptions(o);
  };

  const check = (key, label) => {
    const c = el("input", { type: "checkbox", checked: o[key], onchange: () => { o[key] = c.checked; regen(); } });
    return el("label", { class: "check" }, c, " " + label);
  };
  const range = (key, label, min, maxv) => {
    const n = el("b", { text: String(o[key]) });
    const r = el("input", { type: "range", min, max: maxv, value: o[key], oninput: () => { o[key] = +r.value; n.textContent = r.value; regen(); } });
    return el("label", { class: "rangefield" }, el("span", null, label, " ", n), r);
  };

  const pwOpts = el("div", { class: "genopts" }, range("length", t("Length"), 8, 64),
    el("div", { class: "checks" }, check("lower", "a–z"), check("upper", "A–Z"), check("digits", "0–9"), check("symbols", "!@#$"), check("similar", t("Similar characters (l 1 I O 0)"))));
  const sep = el("input", { value: o.separator, maxlength: 3, class: "sep", "aria-label": t("Separator"), oninput: () => { o.separator = sep.value; regen(); } });
  const phOpts = el("div", { class: "genopts" }, range("words", t("Words"), 3, 12),
    el("div", { class: "checks" }, check("capitalize", t("Capital letters")), check("number", t("Add a digit")),
      el("label", { class: "inline" }, t("Separator") + " ", sep)));

  const kinds = el("div", { class: "seg", role: "radiogroup" });
  const setKind = (k) => {
    o.kind = k;
    for (const b of kinds.children) b.classList.toggle("on", b.dataset.kind === k);
    pwOpts.hidden = k !== "password";
    phOpts.hidden = k !== "passphrase";
    regen();
  };
  kinds.append(
    el("button", { type: "button", dataset: { kind: "password" }, onclick: () => setKind("password") }, t("Password")),
    el("button", { type: "button", dataset: { kind: "passphrase" }, onclick: () => setKind("passphrase") }, t("Passphrase")));

  const actions = el("div", { class: "row" },
    button(t("New"), { icon: "refresh", onclick: regen }),
    button(t("Copy"), { icon: "copy", onclick: () => copy(value, true) }));
  if (onUse) actions.append(button(t("Use this password"), { class: "primary", icon: "check", onclick: () => onUse(value) }));

  const box = el("div", { class: "generator" }, kinds, el("div", { class: "genresult" }, out), meter, pwOpts, phOpts, actions);
  setKind(o.kind === "passphrase" ? "passphrase" : "password");
  return box;
}


