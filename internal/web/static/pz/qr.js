// Reading QR codes in the browser (qr.wasm, built from internal/qrscan), for
// authenticator keys that a website shows only as a QR code. The image and
// the key stay on this computer.

const base = new URL("./", import.meta.url).href;
let ready = null;

function load() {
  if (!ready) {
    ready = (async () => {
      if (!globalThis.Go) await import(base + "wasm_exec.js");
      const go = new globalThis.Go();
      const resp = await fetch(base + "qr.wasm");
      if (!resp.ok) throw new Error("qr.wasm: " + resp.status);
      const { instance } = await WebAssembly.instantiate(await resp.arrayBuffer(), go.importObject);
      go.run(instance); // keeps running: it only exports pzReadQR
      if (typeof globalThis.pzReadQR !== "function") throw new Error("QR module did not start");
    })();
    ready.catch(() => { ready = null; });
  }
  return ready;
}

// Large images are scaled down to this many pixels (a QR code on a 4K
// screen still has several pixels per module).
const MAX = 9000000;

// readQR returns the texts of the QR codes in an image (a Blob or File).
export async function readQR(blob) {
  const [bmp] = await Promise.all([createImageBitmap(blob), load()]);
  const f = Math.min(1, Math.sqrt(MAX / (bmp.width * bmp.height)));
  const w = Math.max(1, Math.round(bmp.width * f)), h = Math.max(1, Math.round(bmp.height * f));
  const canvas = typeof OffscreenCanvas === "function" ? new OffscreenCanvas(w, h) : Object.assign(document.createElement("canvas"), { width: w, height: h });
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0, w, h);
  bmp.close();
  const px = ctx.getImageData(0, 0, w, h).data;
  const out = globalThis.pzReadQR(px, w, h);
  px.fill(0);
  return out ? Array.from(out) : [];
}

// authenticatorKeys keeps the otpauth://totp/ addresses of a QR code list.
export function authenticatorKeys(texts) {
  return texts.filter((s) => /^otpauth:\/\/totp\//i.test(s));
}
