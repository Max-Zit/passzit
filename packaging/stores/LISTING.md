# Store listings of the PassZit extension

Texts and answers for Chrome Web Store, Microsoft Edge Add-ons and Firefox
Add-ons (AMO). Package: `passzit-extension-chromium-V.zip` (Chrome, Edge) and
`passzit-extension-firefox-V.zip` (AMO) from the release. Images are in
`images/` (store-1..4.png 1280×800 screenshots, store-tile.png 440×280; icon:
`extension/src/icons/icon-128.png`). They are made by the extension test:
`PZ_EXT_SHOTS=dir` with `TestExtensionInBrowser` on Linux (CT 9901), framed by
`frame.html`. After a store publishes the extension, put its page
into `extensionStores` in `internal/web/extensions.go`.

- Name: **PassZit**
- Publisher / developer: MaxZit, office@maxzit.com, https://maxzit.com
- Homepage: https://github.com/Max-Zit/passzit
- Support: https://github.com/Max-Zit/passzit/issues
- Privacy policy: https://github.com/Max-Zit/passzit/blob/develop/PRIVACY.md (switch to main after the next release)
- License: AGPL-3.0-only (source: https://github.com/Max-Zit/passzit)
- Category: Chrome "Productivity → Tools" (or "Privacy & Security"), Edge "Productivity", AMO "Privacy & Security"
- Language: English (the extension follows the browser language: en de fr es it pt nl pl cs sr tr ru zh ja)

## Short description (max. 132 characters)

Fill and save passwords and one-time codes from your own PassZit server. End-to-end encrypted, open source, self-hosted.

## Detailed description

<!-- Chrome Web Store rejected a list of protocol names as keyword spam (2026-11-03, "Yellow Argon"): keep tool names out of the description. -->

PassZit is a free, open-source password manager you run on your own server. This extension connects your browser to it.

- Fills user name, password and the one-time code (2FA) on the website they belong to — only on the matching site.
- Offers to save new logins and changed passwords.
- Generates strong passwords and passphrases.
- Searches all your vaults, including team vaults shared with you.
- Adds one-time codes by scanning the QR code on the page.
- Opens remote desktop and terminal connections of your logins through the MaxZit Launcher on Windows.
- One unlock for the extension and the web vault; unlock with Windows Hello in the web vault.

Everything is encrypted in your browser (Argon2id, AES-256-GCM). Your server stores only encrypted data, and the extension talks to no one but your server — no tracking, no analytics.

You need a PassZit server: install it with one command, a deb/rpm package or a ready VM image from https://github.com/Max-Zit/passzit.

## Single purpose (Chrome)

Fill, save and manage the logins of the user's own PassZit password manager server in the browser.

## Permission justifications (Chrome, Edge)

- **storage:** keeps the server address, e-mail address, device token and settings (local) and the unlocked keys until the browser closes (session storage, not on disk).
- **activeTab:** reads the address of the current tab and fills the login fields there when the user clicks the icon or presses the shortcut.
- **scripting:** runs the fill script in the current tab when the user fills a login, and the save offer only on sites the user allowed.
- **alarms:** locks the vault after the inactivity time the user or the server policy set (if any), clears a copied password after the set time and refreshes the vault from the server every 5 minutes.
- **clipboardWrite:** copies a password, user name or one-time code when the user clicks Copy, and clears it again after the set time.
- **offscreen:** clears the clipboard after the set time (service workers cannot reach the clipboard).
- **nativeMessaging:** opens RDP, SSH and similar connections through the MaxZit Launcher or PassZit helper that the user installed and paired.
- **Optional host permissions (https://\*/\*, http://\*/\*):** requested at sign-in for the user's own server only; for all sites only if the user switches on "offer to save new logins" or the site badge.

## Remote code (Chrome)

No. All JavaScript and WebAssembly (Argon2id, QR reader) are in the package.

## Data usage (Chrome privacy practices)

- Collected: **Authentication information** and **Website content**, used only for the single purpose and sent only to the user's own PassZit server, encrypted end to end.
- Certify: not sold to third parties; not used or transferred for purposes unrelated to the single purpose; not used for creditworthiness or lending.

## Firefox (AMO)

- Add-on id: `passzit@maxzit.com`, minimum Firefox 128.
- Listed (public) channel, so updates come from AMO.
- Source code: the package contains no minified or generated JavaScript except `wasm_exec.js` (Go's WebAssembly loader) and the two `.wasm` modules; give reviewers the release tag and `go run ./tools/buildwasm` / `go run ./tools/extpack -version V` to rebuild them.
- Data collection: review `data_collection_permissions` (now `none`) against Mozilla's rules at submission — the extension sends only end-to-end encrypted data to the server the user configured.

## Test account for reviewers

Reviewers need a PassZit server. Give them a demo server address and a test account in the reviewer notes (never a real one).
