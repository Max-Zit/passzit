# PassZit — architecture proposal (draft, 2026-10-29)

Status: **approved by Stefan on 2026-10-29** (accounts only by invitation; 2FA mandatory, off only on test servers; policy values changeable in the settings). Version 0.1 is built on develop.

PassZit is a self-hosted password manager: a Go server with PostgreSQL, a web
vault and admin console in the browser, and browser extensions. It follows the
layout of WatchZit/ControlZit (Go server, html/template console, JSON i18n
catalogs, numbered SQL migrations, embedded PostgreSQL for development) and
BackupZit's release machinery (signed self-update, update channels, appliance
images, Linux packages). All code is written in this repository; nothing is
shared at runtime with the other products.

The one rule above all others: **a stolen server, database or backup must not
reveal any secret.** Encryption and decryption happen only on the client.

## 1. Components

| Component | What it does |
|---|---|
| `passzit-server` (Linux; Windows for development) | HTTPS console + JSON API, accounts, sign-in (auth hash, 2FA), stores only ciphertext, audit log, admin console, root helper for self-update/appliance settings |
| PostgreSQL | Accounts, wrapped keys, encrypted items, sessions/devices, audit log, settings |
| Web vault (served by the server, plain JavaScript modules, no framework) | Sign-up, unlock, items, folders, search, generator, import/export — all crypto in the browser |
| Browser extension (Manifest V3, one code base) | Chrome, Edge, Opera, Brave, Vivaldi (Chromium package) and Firefox (Gecko package); unlock, fill, save, generator |
| `passzit-helper` (later, Windows first, per user) | Native-messaging host of the extension: opens SSH/RDP/WinBox with credentials after the user confirms (see 8) |

## 2. Cryptography (zero knowledge)

All primitives come from WebCrypto, except Argon2id.

**Argon2id in the browser:** `golang.org/x/crypto/argon2` (BSD-3, already used
by the other products) compiled by us to WebAssembly (`GOOS=js GOARCH=wasm`) —
no third-party JavaScript. Spike on 2026-10-29 in Chromium 152 on Stefan's PC:
64 MiB / t=3 / p=4 → 0.65 s, 128 MiB → 0.98 s; the module is 2.0 MB (0.6 MB
gzip), loaded only on the unlock screen. Results will be checked against the
RFC 9106 test vectors and against native Go. PBKDF2-SHA256 with 600 000
iterations (0.13 s) stays as fallback only for clients without WebAssembly.

**Keys of an account**

```
master password ──Argon2id(salt, m=64 MiB, t=3, p=4)──► master key (32 B, never leaves the client)
master key ──HKDF-SHA256 "passzit/auth/v1"──► auth key  ──► sent to the server at sign-in
master key ──HKDF-SHA256 "passzit/wrap/v1"──► wrap key  ──► unwraps the account key
account key  = random 256-bit AES-GCM key, stored on the server wrapped by the wrap key
key pair     = X25519 (WebCrypto), private key wrapped by the account key, public key plain
vault key    = random 256-bit key per vault; personal vault: wrapped by the account key;
               shared vault: sealed to each member's X25519 public key (ephemeral ECDH + HKDF + AES-GCM)
item         = JSON (name, URLs, user, password, notes, TOTP secret, custom fields …)
               AES-256-GCM under the vault key, 96-bit random nonce,
               AAD = "passzit/item/v1" ‖ vault id ‖ item id  (ciphertexts cannot be swapped between items)
```

- **Everything about an item is encrypted**, including name, URLs and folder
  names. The server sees only ids, sizes, timestamps and the vault membership.
  Search and URL matching run on decrypted data in the client.
- **Server side:** the auth key is hashed again with argon2id (server's own
  salt) before it is stored; the server never sees the master password, the
  master key or any other key in plain form.
- **Salt and KDF parameters** are per user, stored on the server and returned by
  a pre-login call. For unknown e-mail addresses the server returns a
  deterministic fake salt (HMAC of the address with a server secret) so
  addresses cannot be probed. Parameters are versioned; the client upgrades
  them at the next unlock (re-wrap the account key, no item re-encryption).
- **Changing the master password** re-wraps only the account key; existing
  sessions on other devices are ended.
- **Recovery:** without the master password the vault cannot be opened — the UI
  and the guide say so clearly at sign-up. Optional **recovery key** (random,
  128 bits, shown once as groups of letters/digits, optionally printed) wraps
  the account key a second time. An organisation admin recovery policy comes
  later with organisations and is visible to the user.
- **Public keys of other users** (sharing) can be substituted by a malicious
  server. Mitigation: show a key fingerprint for members, remember keys that
  were confirmed once and warn when one changes.
- **Honest limit of every web vault:** the server delivers the web vault's
  JavaScript, so a fully compromised server could serve modified code. The
  extension's code comes from the store/package and cannot be changed by the
  server, so the guide recommends the extension for everyday use. The web vault
  uses strict CSP, no third-party scripts and Subresource Integrity on its own
  files.
- **Test vectors:** fixed vectors (KDF, HKDF, item encryption) checked in Go
  and in JavaScript, so every client produces the same bytes; an end-to-end test
  records every request body the server receives and fails if a known plaintext
  (password, name, URL, note) appears in it.

## 3. Server security (from BackupZit/ControlZit/WatchZit)

HTTPS only; argon2id; TOTP 2FA with recovery codes (later WebAuthn/passkeys);
login rate limits and lockouts, `--unblock-ip`; IP allow-list; roles (admin,
user; later organisation roles); hash-chained audit log; sessions with short
lifetime, idle timeout and a device list (sign out a device); CSRF via
Origin/Sec-Fetch-Site; strict CSP without inline scripts/styles;
Secure/HttpOnly/SameSite=Strict cookies; no secrets in logs; console backup
encrypted with a backup password (the vault data is ciphertext anyway).

- **Extension sessions** use a bearer token (device token + short-lived access
  token) instead of cookies, listed under the user's devices and revocable.
- **Certificates:** extensions need a certificate the browser trusts. Built-in
  ACME (Let's Encrypt, HTTP-01 or DNS-01 later), uploaded certificate, or the
  self-signed setup certificate only for the first sign-in.
- **Registration:** admin invites by default; optional open sign-up limited to
  e-mail domains (setting).
- **E-mail** (invites, new-device sign-in notice) over SMTP like BackupZit;
  e-mails never contain secrets.

## 4. Web vault and console

Same look as the other products: dark sidebar #0f172a, indigo #4f46e5/#818cf8,
cards, light/dark with the moon button, 14 languages (en de fr es it pt nl pl
cs sr tr ru zh ja), built-in user guide in all languages, logo variant C.

- Admin and account pages (users, invites, sessions, audit, settings, update,
  backup, guide) are server-rendered html/template like WatchZit.
- Vault pages are the same layout, filled by our JavaScript from encrypted JSON;
  the i18n catalogs are shared with the JavaScript.
- Lock after inactivity (default 15 min), lock on close; keys only in memory.
- Clipboard is cleared after 30 s (when the browser allows it).

## 5. Browser extension

- One source tree `extension/`, plain ES modules, no npm runtime dependencies;
  a Go tool (`tools/extpack`) produces the Chromium zip (Chrome, Edge, Opera,
  Brave, Vivaldi) and the Firefox zip (manifest differences, `browser.*` vs
  `chrome.*` handled by a small own shim). The crypto module is the same file
  as in the web vault.
- **Permissions, minimal by default:** `storage`, `activeTab`, `scripting`,
  `alarms`, `contextMenus`, and the PassZit server origin. Filling on demand
  (popup click, keyboard shortcut, context menu) needs no access to all sites.
  "Offer to save new logins" and the inline field icon need access to all
  sites — an **optional** permission the user switches on in the extension's
  settings, with an explanation.
- Unlocked keys live in the service worker / `storage.session` (memory only),
  cleared on lock, browser exit and timeout. The vault is never injected into
  the page; content scripts receive only the one login being filled.
- **Fill rules:** URL match by registrable domain (eTLD+1, own copy of the
  Public Suffix List, MPL-2.0 data — compatible) with options exact host /
  starts-with / never; no fill into cross-origin iframes without asking; only
  visible fields; no automatic fill on page load by default (protects against
  invisible-form harvesting); HTTP pages warn; clickjacking: fill only from our
  own popup/prompt, the inline menu is rendered in an extension iframe.
- Store publishing only when Stefan says so, with his accounts.

## 6. Data model (first version)

`users` (email, name, role, kdf params, salt, server hash of auth key, wrapped
account key, public key, wrapped private key, recovery-wrapped account key,
TOTP), `devices`/`sessions`, `vaults` (personal for now), `vault_keys` (user,
vault, wrapped key), `items` (id, vault, encrypted blob, revision, deleted_at
for trash), `folders` (encrypted name), `audit`, `settings`, `invites`.
Every change bumps a revision so clients sync only what changed.

## 7. What is reused from the other products

Taken from WatchZit/ControlZit (Stefan's own code, same license) and adapted:
auth (argon2id, TOTP), store/migrations, web layout/render/i18n tooling,
netacl, tlsutil, logfile, testdb, update + relsign + helper, packaging
(nfpm, systemd, install.sh), appliance image builder, CI/security workflows,
THIRD_PARTY_LICENSES tool. From BackupZit: four-eyes approval (later, for
sensitive admin actions), LDAP/SSO (later, sign-in only — the master password
is still needed to decrypt), console backup/restore, update channels.

Improvements over the others, proposed: built-in ACME certificates (all
products would profit), WebAuthn as second factor, and device tokens for
non-browser clients.

## 8. WatchZit and local tools (later, to confirm)

Because the server cannot decrypt, credentials are always released by an
unlocked client.

- **Browser:** a WatchZit item field "WatchZit device" (or matching by host/IP).
  On the WatchZit device page the extension offers "Sign in with PassZit" for
  the device's web UI — normal fill.
- **Local tools:** a small signed `passzit-helper` registered as the
  extension's **native-messaging host** (no `passzit://` URL handler for
  secrets: a URL handler can be triggered by any web page). WatchZit's existing
  `watchzit://open` link names the device; the extension finds the item, asks
  the user to confirm, and hands the credential to the helper over stdin:
  - **RDP:** temporary `cmdkey /generic:TERMSRV/<host>` entry, start `mstsc`,
    delete the entry after the connection starts. No password on a command line.
  - **SSH with a key:** the helper acts as an SSH agent (Windows OpenSSH named
    pipe / Pageant) holding the key for that one session.
  - **SSH with a password:** PuTTY `-pwfile` with a temporary file readable only
    by the user, deleted right after start (PuTTY ≥ 0.77); OpenSSH has no safe
    way, so the password is put on the clipboard (auto-clear).
  - **WinBox:** accepts the password only on its command line — visible to other
    processes of the same user while WinBox runs. Offered with that warning, or
    clipboard mode.
  - Honest limit: once a password is handed to another program, PassZit cannot
    protect it inside that program.

## 9. Version order (proposal)

| Version | Content |
|---|---|
| 0.1 | Server base (setup token, admin, TLS, allow-list, rate limits, 2FA, sessions/devices, audit, 14 languages), invites/sign-up, client crypto (Argon2id WASM, keys, test vectors), **web vault**: logins and secure notes, folders, favourites, search, trash, password generator (+ passphrases), lock/auto-lock, recovery key, change master password |
| 0.2 | **Extension** Chromium + Firefox: sign in, unlock, matching logins, fill, save/update prompt, generator, auto-lock, clipboard clear; tested on bz-win11 in Chrome, Edge, Firefox, Opera |
| 0.3 | Import (Chrome/Edge/Firefox CSV, Bitwarden JSON/CSV, KeePass XML, 1Password, LastPass), export (encrypted JSON, plain CSV with warning), item history |
| 0.4 | More item types (cards, identities, SSH keys), TOTP codes, encrypted attachments, password health (weak, reused, old; optional breach check with k-anonymity) |
| 0.5 | Packaging: Linux packages, install.sh, signed self-update, testing/official channels, appliance ISO/OVA/qcow2/VHDX, ACME, encrypted console backup, user guide complete, PWA |
| 0.6 | Organisations: shared vaults, groups, rights (view / use without seeing / edit / manage), policies (master-password strength, 2FA required, export allowed), LDAP/SSO sign-in, WebAuthn |
| 0.7 | Time-limited and one-time access, secret links (Send; key in the URL fragment), emergency access, per-item access log, four-eyes for sensitive admin actions |
| 0.8 | WatchZit integration and `passzit-helper` |
| later | Passkeys in the vault, Safari, mobile apps |

## 10. Tests and tools

Go: unit tests, go vet, staticcheck, govulncheck, gosec; JavaScript: own small
test runner in a headless browser (Chrome on CI), crypto vectors shared with
Go; Semgrep, Trivy, Gitleaks and OWASP ZAP from the lab scanner (CT 270); a
"server never sees plaintext" end-to-end test; console checked in the preview
at desktop and 375 px, light and dark; extensions in real browsers on bz-win11.
Lab IDs on Proxmox: 9900–9999.
