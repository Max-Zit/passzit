// Which sites belong together: logins are matched by registrable domain
// ("eTLD+1": shop.example.co.uk → example.co.uk) using the Public Suffix
// List, so a login for one github.io page is never offered on another.
import { RULES } from "./psl-rules.js";

const plain = new Set();
const wildcard = new Set(); // "*.ck" is stored as "ck"
const exception = new Set();
for (const r of RULES.split(",")) {
  if (r.startsWith("!")) exception.add(r.slice(1));
  else if (r.startsWith("*.")) wildcard.add(r.slice(2));
  else plain.add(r);
}

function isIP(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":") || host.startsWith("[");
}

// publicSuffix returns the public suffix of a lower-case ASCII host name.
export function publicSuffix(host) {
  const labels = host.split(".");
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join(".");
    if (exception.has(cand)) return labels.slice(i + 1).join(".");
    if (plain.has(cand)) return cand;
    if (i + 1 < labels.length && wildcard.has(labels.slice(i + 1).join("."))) return cand;
  }
  return labels[labels.length - 1]; // the default rule "*"
}

// siteOf is the registrable domain of a host; IP addresses, single labels
// (intranet names, localhost) and bare suffixes stand for themselves.
export function siteOf(host) {
  const h = (host || "").toLowerCase().replace(/\.$/, "");
  if (!h || isIP(h) || !h.includes(".")) return h;
  const suffix = publicSuffix(h);
  if (h === suffix) return h;
  const rest = h.slice(0, h.length - suffix.length - 1).split(".");
  return rest[rest.length - 1] + "." + suffix;
}

// parse reads a website as stored in an item ("github.com", "https://…").
export function parse(url) {
  if (!url) return null;
  const full = /^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : "https://" + url;
  try {
    const u = new URL(full);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    return { protocol: u.protocol, host: u.host, hostname: u.hostname, origin: u.origin, site: siteOf(u.hostname) };
  } catch (e) {
    return null;
  }
}

// match tells how an item's website fits the page: "host" (same host
// name), "site" (same registrable domain) or "" (no match). A login saved
// for HTTPS is not offered on plain HTTP of the same site.
export function match(itemURL, pageURL) {
  const a = parse(itemURL), b = parse(pageURL);
  if (!a || !b || !a.site || a.site !== b.site) return "";
  if (a.protocol === "https:" && b.protocol !== "https:") return "";
  if (isIP(a.hostname) || !a.hostname.includes(".")) {
    // addresses and intranet names: the whole host (and port) must agree
    return a.host === b.host ? "host" : "";
  }
  return a.hostname === b.hostname ? "host" : "site";
}
