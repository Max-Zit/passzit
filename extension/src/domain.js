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
    return { protocol: u.protocol, host: u.host, hostname: u.hostname, port: u.port, origin: u.origin, site: siteOf(u.hostname) };
  } catch (e) {
    return null;
  }
}

// match tells how an item's website fits the page: "host" (same host
// name), "site" (same registrable domain) or "" (no match). A login saved
// for HTTPS is not offered on plain HTTP of the same site.
//
// An IP address or intranet name (no dot) saved without a scheme
// ("192.168.1.1", "nas", "nas:5000") names no scheme: such devices often
// speak plain HTTP, so it fits http and https; without a port it fits every
// port of the device, with a port only that port. A domain name saved
// without a scheme stays HTTPS only: a plain-HTTP page of a public site can
// be changed on the way, and "github.com" means the real, encrypted site.
export function match(itemURL, pageURL) {
  const a = parse(itemURL), b = parse(pageURL);
  if (!a || !b || !a.site || a.site !== b.site) return "";
  if (local(a.hostname)) {
    // addresses and intranet names: the whole host (and port) must agree
    if (a.hostname !== b.hostname) return "";
    if (bare(itemURL)) return !a.port || a.port === b.port ? "host" : "";
    if (a.protocol === "https:" && b.protocol !== "https:") return "";
    return a.host === b.host ? "host" : "";
  }
  if (a.protocol === "https:" && b.protocol !== "https:") return "";
  return a.hostname === b.hostname ? "host" : "site";
}

const bare = (u) => !/^[a-z][a-z0-9+.-]*:\/\//i.test(String(u || "").trim());
const local = (h) => isIP(h) || !h.includes(".");

// exact tells whether an item's website is the page's own host and port:
// the only match that is filled without asking (keyboard shortcut). An
// address of a device saved without a port counts for all its ports.
export function exact(itemURL, pageURL) {
  if (match(itemURL, pageURL) !== "host") return false;
  const a = parse(itemURL), b = parse(pageURL);
  return a.host === b.host || (local(a.hostname) && bare(itemURL) && !a.port);
}

// isIPHost tells whether a URL host name is an IP address (v4 or [v6]).
export function isIPHost(host) { return isIP(String(host || "").toLowerCase()); }
