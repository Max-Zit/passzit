# PassZit — architecture (0.9.x)

This document describes how PassZit 0.9.x is built. It started as the design
proposal approved by Stefan on 2026-10-29 (accounts only by invitation; 2FA
mandatory, off only on test servers; policy values changeable in the
settings) and is kept up to date with the code.

PassZit is a self-hosted password manager: a Go server with PostgreSQL, a web
vault and admin console in the browser, and browser extensions. It follows the
layout of WatchZit/RMMZit (Go server, html/template console, JSON i18n
catalogs, numbered SQL migrations, embedded PostgreSQL for development) and
BackupZit's release machinery (signed self-update, update channels, appliance
images, Linux packages). All code is written in this repository; nothing is
shared at runtime with the other products.

The one rule above all others: **a stolen server, database or backup must not
reveal any secret.** Encryption and decryption happen only on the client.

## 1. Components

| Component | What it does |
|---|---|
| `passzit-server` (Linux; Windows for development) | HTTPS console + JSON API, accounts, sign-in (auth hash, 2FA), stores only ciphertext, audit log, admin console; `passzit-server --helper` is the root side for self-update, time zone, network and restart |
| PostgreSQL | Accounts, wrapped keys, encrypted items, sessions/devices, audit log, settings |
| Web vault (served by the server, plain JavaScript modules, no framework) | Unlock, items, folders, search, generator, import/export, sharing — all crypto in the browser |
| Browser extension (Manifest V3, one code base) | Chrome, Edge, Opera, Brave, Vivaldi (Chromium package) and Firefox (Gecko package); unlock, fill, save, generator, passkeys, opening remote connections |
| MaxZit Launcher (shared with WatchZit) / `passzit-helper` | Native-messaging host of the extension: opens RDP, SSH, WinSCP, WinBox, VNC and Telnet with credentials (see 8). The console offers the MaxZit Launcher; `passzit-helper` remains for Linux |
| `passzit` command line (Linux, Windows, macOS) | Reads logins and one-time codes in scripts and changes device passwords (`passzit rotate`), decrypting on its own computer |

## 2. Cryptography (zero knowledge)

All primitives come from WebCrypto, except Argon2id.

**Argon2id in the browser:** `golang.org/x/crypto/argon2` (BSD-3, already used
by the other products) compiled by us to WebAssembly (`GOOS=js GOARCH=wasm`) —
no third-party JavaScript. Measured on 2026-10-29 in Chromium 152 on Stefan's
PC: 64 MiB / t=3 / p=4 → 0.65 s, 128 MiB → 0.98 s; the module is 2.0 MB
(0.6 MB gzip), loaded only on the unlock screen. PBKDF2-SHA256 with 600 000
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
  Search and URL matching run on decrypted data in the client. Attachments and
  item documentation (a page with headings, lists, tables, code, links and
  pictures) are encrypted as files of the item.
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
  and the guide say so clearly. Optional **recovery key** (random, 128 bits,
  shown once as groups of letters/digits, optionally printed) wraps the account
  key a second time. **Quick unlock** (Windows Hello, Touch ID, phone screen
  lock): a platform passkey's WebAuthn PRF output, run through HKDF, seals the
  account key a third time per device; the server stores the sealed copy and
  the PRF salt only (table `unlock_keys`, web sessions only). The account key
  survives password changes, so these copies stay valid.
- **Passkeys in the vault:** the extension answers `navigator.credentials` for
  websites when the user switches it on. The relying party is checked against
  the tab's real address and the user confirms in PassZit's own window. A saved
  passkey (ECDSA P-256, "none" attestation) is an ordinary encrypted vault
  item; signing happens only in the extension.
- **Public keys of other users** (sharing) can be substituted by a malicious
  server. Mitigation: the client shows key fingerprints of members, keeps the
  confirmed fingerprints (sealed with the account key) and reports a changed
  key of a known person before anything is sealed to it.
- **Honest limit of every web vault:** the server delivers the web vault's
  JavaScript, so a fully compromised server could serve modified code. The
  extension's code comes from the store/package and cannot be changed by the
  server, so the guide recommends the extension for everyday use. The web vault
  uses a strict CSP and no third-party scripts.
- **Test vectors:** fixed vectors (KDF, HKDF, item encryption) checked in Go
  and in JavaScript, so every client produces the same bytes; an end-to-end test
  checks that a known plaintext never reaches the server.

## 3. Server security

HTTPS only; argon2id; mandatory two-factor sign-in (TOTP, WebAuthn security
keys and passkeys, recovery codes); login rate limits and lockouts,
`--unblock-ip`; IP allow-list; roles; hash-chained audit log; sessions with
lifetime, idle timeout and a device list (sign out a device); CSRF via
Origin/Sec-Fetch-Site; strict CSP without inline scripts/styles;
Secure/HttpOnly/SameSite=Strict cookies; no secrets in logs; console backup
encrypted with a backup password (the vault data is ciphertext anyway).

- **Extension sessions** use a bearer token (device token + short-lived access
  token) instead of cookies, listed under the user's devices and revocable.
  The extension connects with only the server address: the signed-in,
  unlocked web vault creates the device token after the user agrees and hands
  it to the extension (e-mail and master password remain as an alternative).
- **Certificates:** extensions need a certificate the browser trusts. Built-in
  ACME (Let's Encrypt, HTTP-01, or DNS-01 through Cloudflare for servers that
  are not reachable from the internet; the Cloudflare token is sealed with the
  server's secret key), an uploaded certificate, or the self-signed setup
  certificate for the first sign-in.
- **Registration:** only by invitation.
- **Sign-in:** local accounts, LDAP and SSO (OIDC, SAML). External sign-in only
  replaces the account password; the master password is still needed to
  decrypt.
- **E-mail notifications** over SMTP (adapted from BackupZit): administrators
  get mail about the server (certificate renewal, console backups, four-eyes
  requests), users about what concerns them (invitations, emergency access,
  access requests). Messages never contain secrets.

## 4. Web vault and console

Same look as the other products: dark sidebar #0f172a, indigo #4f46e5/#818cf8,
cards, light/dark with the moon button, interface in 14 languages (en de fr es
it pt nl pl cs sr tr ru zh ja), built-in user guide in English and Serbian,
logo variant C.

- Admin and account pages (users, invites, sessions, audit, settings, update,
  backup, guide) are server-rendered html/template like WatchZit.
- Vault pages are the same layout, filled by our JavaScript from encrypted JSON;
  the i18n catalogs are shared with the JavaScript.
- **Lock:** no automatic lock by default (policy lock time 0): the vault stays
  open until the user locks it or closes the browser. The policy or the user
  can set a lock time. Keys live only in memory. The web vault and the
  extension share one unlock: unlocking or locking one does the same to the
  other (the keys are checked against the account).
- Clipboard is cleared after 30 s by default (policy setting; when the browser
  allows it).
- **Teams:** shared vaults with per-member and per-group rights (connect and
  fill, see passwords, add and change, manage), time-limited access, access
  requests with approval (more rights for some hours, approved by managers),
  secret links, emergency access, per-item access log, four-eyes approval,
  password history with restore.

## 5. Browser extension

- One source tree `extension/`, plain ES modules, no npm runtime dependencies;
  a Go tool (`tools/extpack`) produces the Chromium zip (Chrome, Edge, Opera,
  Brave, Vivaldi) and the Firefox zip (manifest differences, `browser.*` vs
  `chrome.*` handled by a small own shim). The crypto module is the same file
  as in the web vault.
- The extension has its own version (`extension/VERSION`), so an unchanged
  extension keeps its version across server releases. The WebAssembly
  modules in it (Argon2id, QR reader) and `wasm_exec.js` are built with
  their own fixed Go version (`wasmToolchain` in `tools/buildwasm`), so a Go
  update of the server (go.mod) does not change the extension; that version
  is raised together with `extension/VERSION` when a Go fix concerns the
  modules.
- **Permissions:** `storage`, `activeTab`, `scripting`, `alarms`,
  `clipboardWrite`, `offscreen`, `nativeMessaging`. Access to sites is an
  **optional** host permission: the PassZit server and the MaxZit consoles the
  user adds, and all sites only when the user switches on "offer to save
  logins".
- Unlocked keys live in `storage.session` (memory only, never written to
  disk), cleared on lock and browser exit. The vault is never injected into
  the page; the page receives only the one login being filled, and only in the
  top frame.
- **Fill rules:** URL match by registrable domain (eTLD+1, own copy of the
  Public Suffix List, MPL-2.0 data — compatible), with an exact-host option.
- Store publishing only when Stefan says so, with his accounts.

## 6. Data model

Numbered migrations in `internal/store/migrations`: `users` (email, name,
role, KDF params, salt, server hash of auth key, wrapped account key, public
key, wrapped private key, recovery-wrapped account key, TOTP), `sessions`
(web and extension devices), `vaults` (personal and shared), `vault_members`
(user, vault, wrapped key, rights), `groups`, `group_members`, `vault_groups`,
`items` (id, vault, encrypted blob, revision), `folders` (encrypted name),
`attachments`, `tombstones`, `webauthn_credentials`, `unlock_keys`, `sends`
(secret links), `emergency_contacts`, `item_access`, `approvals` (four-eyes),
`access_requests`, `audit_log`, `settings`, `invites`, `login_blocks`.
Every change bumps a revision so clients sync only what changed.

## 7. What is reused from the other products

Taken from WatchZit/RMMZit (Stefan's own code, same license) and adapted:
auth (argon2id, TOTP), store/migrations, web layout/render/i18n tooling,
netacl, tlsutil, logfile, testdb, update + relsign + helper, packaging
(nfpm, systemd, install.sh), appliance image builder, CI/security workflows,
THIRD_PARTY_LICENSES tool. From BackupZit: four-eyes approval, LDAP/SSO
sign-in, console backup/restore, update channels, the SMTP sender. The MaxZit
Launcher comes from the WatchZit release.

## 8. Remote connections and WatchZit

Because the server cannot decrypt, credentials are always released by an
unlocked client.

- **Launcher:** the MaxZit Launcher (or `passzit-helper` on Linux) is the
  extension's **native-messaging host** and accepts only a paired extension
  (no `passzit://` URL handler for secrets: a URL handler can be triggered by
  any web page). It trusts nothing in a message beyond the wish: the tool must
  be known, and host, port and user pass strict character checks.
  - **RDP:** on Windows a credential for `TERMSRV/<host>` exists for a few
    seconds while `mstsc` starts; on Linux `xfreerdp` reads it from stdin. No
    password on a command line.
  - **SSH with a password:** PuTTY reads it from a file only the user can read
    (`-pwfile`, PuTTY ≥ 0.77), removed right after the start; without PuTTY,
    OpenSSH starts and the extension puts the password on the clipboard
    (cleared after the policy's time).
  - **SSH with a key:** OpenSSH reads it from a temporary file only the user
    can read, removed shortly after the start.
  - **WinBox** accepts the password only on its command line — visible to
    other processes of the same user while WinBox runs; the extension warns
    before.
  - **WinSCP, VNC viewers and Telnet** ask for the password themselves; the
    extension puts it on the clipboard.
  - Honest limit: once a password is handed to another program, PassZit cannot
    protect it inside that program.
- **WatchZit (one click):** the user adds MaxZit consoles in the extension's
  settings. When WatchZit's "Open with" is used on a device and an unlocked
  vault holds a login with the same address and tool, the extension takes the
  request and opens it through the launcher with the stored credentials.
  Locked or no match: the console opens the launcher as before.
- **Password rotation:** `passzit rotate` changes a device password over SSH
  (Linux, MikroTik, Windows) on the computer it runs on: a new password is
  made, the device is changed with the old one, the new one is checked with a
  fresh sign-in, and only then is the item saved (the old password goes into
  its history). Items opt in with a method and an interval; `passzit rotate
  --due` from cron or the Task Scheduler changes all that are due.

## 9. Versions

| Version | Content |
|---|---|
| 0.1–0.8 (development) | Server base, client crypto, web vault, extension, import/export, item types, TOTP, attachments, password health, packaging and appliance images, ACME, console backup, sharing, groups, LDAP/SSO, WebAuthn, secret links, emergency access, four-eyes, launcher |
| 0.9.0 | First public release (November 2026) |
| 0.9.x | WatchZit one-click opening, passkeys in the vault, quick unlock, DNS-01 certificates, e-mail notifications, `passzit` command line and `passzit rotate`, access requests, item documentation, password restore, shared unlock of web vault and extension |
| later | Safari, mobile apps, more import formats |

## 10. Tests and tools

Go: unit tests, go vet, staticcheck, govulncheck, gosec, race detector and
fuzzing on CI; JavaScript: own small test runner in a headless browser (Chrome
on CI), crypto vectors shared with Go; both extensions tested in real Chrome
and Firefox; Semgrep, Trivy, Gitleaks and OWASP ZAP from the lab scanner
(CT 270); a "server never sees plaintext" end-to-end test; console checked at
desktop and 375 px, light and dark. Details: [SECURITY.md](../SECURITY.md).
Lab IDs on Proxmox: 9900–9999.
