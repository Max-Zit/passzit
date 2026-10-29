// PassZit service worker: lets the web vault be installed as an app and
// shows a page when the server cannot be reached. It never caches vault
// data or API answers; pages always come from the server.
const CACHE = "pz-shell-v1";
const OFFLINE = "/static/offline.html";

self.addEventListener("install", (ev) => {
  ev.waitUntil(caches.open(CACHE).then((c) => c.addAll([OFFLINE, "/static/app.css", "/static/favicon.svg"])).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (ev) => {
  ev.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", (ev) => {
  const r = ev.request;
  if (r.method !== "GET" || r.mode !== "navigate" || new URL(r.url).origin !== self.location.origin) return;
  ev.respondWith(fetch(r).catch(() => caches.match(OFFLINE)));
});
