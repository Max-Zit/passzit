// The page a recipient of a secret link opens. The key comes from the
// link's #fragment and stays in this page.
import { api, t, loadTexts, showError, copy } from "./common.js";
import { authFor, openSend } from "./sendlink.js";

await loadTexts();
const root = document.getElementById("pz-send");
const errBox = document.getElementById("pz-error");
const id = location.pathname.split("/").pop();
const fragment = location.hash.slice(1);
// The fragment is not needed in the address bar any more (or in history).
history.replaceState(null, "", location.pathname);

function step(name) {
  for (const s of root.querySelectorAll("section[data-step]")) s.hidden = s.dataset.step !== name;
}

let protectedLink = false;
try {
  if (!fragment) throw new Error(t("The link is incomplete: the part after # is missing."));
  const st = await api("GET", "/api/send/" + id);
  protectedLink = st.protected;
  document.getElementById("pw-row").hidden = !protectedLink;
} catch (e) {
  if (e.status === 410) step("gone"); else showError(errBox, e.message);
}

const f = document.getElementById("f-open");
f.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(errBox, "");
  const b = f.querySelector("button");
  b.disabled = true;
  try {
    const pw = protectedLink ? f.password.value : "";
    const body = protectedLink ? { auth: await authFor(id, fragment, pw) } : {};
    const res = await api("POST", "/api/send/" + id + "/open", body);
    const payload = await openSend(id, fragment, pw, res.data);
    const text = document.getElementById("send-text");
    text.textContent = payload.text || "";
    text.hidden = !payload.text;
    document.getElementById("send-copy").onclick = () => copy(payload.text || "", true);
    document.getElementById("send-copy").hidden = !payload.text;
    if (payload.file) {
      const a = document.getElementById("send-file");
      const bytes = Uint8Array.from(atob(payload.file.data.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
      a.href = URL.createObjectURL(new Blob([bytes], { type: payload.file.type || "application/octet-stream" }));
      a.download = payload.file.name;
      a.querySelector("span").textContent = t("Download %s", payload.file.name);
      a.hidden = false;
    }
    document.getElementById("send-left").textContent = res.left > 0 ? t("The link can be opened %d more times.", res.left) : t("The link does not work any more now.");
    f.password.value = "";
    step("shown");
  } catch (e) {
    if (e.status === 410) step("gone"); else showError(errBox, e.message || t("The secret could not be opened."));
  } finally {
    b.disabled = false;
  }
});
