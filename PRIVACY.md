# PassZit privacy policy

PassZit is a self-hosted password manager made by MaxZit (office@maxzit.com). This policy covers the PassZit browser extension for Chrome, Edge, Firefox and other browsers, and the PassZit server software.

## Who has your data

PassZit has no central service. The extension talks only to **the PassZit server you or your organisation run**; you enter its address when you sign in. MaxZit does not run that server and receives no data from the extension or the server.

## What the extension handles

- **Vault items** (logins, passwords, one-time codes, notes and other items you store) are encrypted and decrypted **in your browser** with keys derived from your master password (Argon2id, AES-256-GCM). The server stores only encrypted data; neither the server nor MaxZit can read it.
- **Settings** kept in the browser's local storage: the server address, your e-mail address, a device token of your server and your choices in the extension. No password or vault key is stored on disk.
- **Unlocked keys** stay in the browser's session memory until you lock the vault or close the browser.
- **The current page's address** is compared with your logins in the browser, to offer the right login. It is not sent anywhere.
- **Page content:** when you fill or save a login, the extension reads and writes only the login fields of the page you are on. Saving a new login sends it, encrypted, to your server.
- **Passkeys** (only with *Use PassZit for passkeys* switched on): a small script on websites passes their passkey requests to the extension, which asks you in its own window. A passkey you save is a vault item, encrypted like any other; its private key is used only inside the extension, and the website receives only the signature it asked for.
- **Screenshot of the visible tab:** only when you choose *Scan QR code* to add a one-time code. The image is read in the browser and not stored or sent.
- **Remote connections:** when you open an RDP, SSH or similar item, the extension passes the connection to the MaxZit Launcher or PassZit helper on your computer through native messaging, after you paired them.

## What PassZit does not do

- No analytics, tracking, advertising or telemetry.
- No selling or sharing of data with third parties.
- No remote code: everything the extension runs is part of the package.

## Your server

Your server keeps the encrypted vault, your account (e-mail address, an Argon2id hash of a separate authentication key, two-factor settings), sessions and an audit log. The operator of that server — you or your organisation — decides how long it is kept and who can access it.

## Contact

Questions: office@maxzit.com. Security issues: see [SECURITY.md](SECURITY.md).

Last updated: 2026-11-03.
