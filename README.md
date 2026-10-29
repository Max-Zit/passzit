<p align="center"><img src="brand/passzit-logo-on-light.svg" alt="PassZit" height="64"></p>

# PassZit

**Free, open-source, self-hosted password manager** for people and teams — your own server, end-to-end encrypted vaults, and browser extensions for Chrome, Edge, Firefox, Opera and Brave.

> **Status:** in development on the `develop` branch. There is no release yet; follow the repository or [Discussions](https://github.com/Max-Zit/passzit/discussions) for news.

## What works today

- **End-to-end encryption, zero knowledge:** the browser derives keys from the master password with Argon2id (64 MiB, 3 passes), encrypts every item — name, user name, password, websites, notes, files — with AES-256-GCM and sends only ciphertext. The server stores an argon2id hash of a separate auth key and never sees the master password or any key it could use. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **Web vault:** logins with one-time codes (TOTP), secure notes, cards, identities, SSH keys (Ed25519 generated in the browser), encrypted file attachments, own fields, folders, favourites, search, trash, password history, password health report with an optional breach check (k-anonymity, the password never leaves the browser), auto-lock and clipboard clearing; installable as an app.
- **Browser extensions** for Chrome, Edge, Opera, Brave, Vivaldi and Firefox: fill logins only on the matching site (Public Suffix List), offer to save new and changed logins, generator, search, auto-lock.
- **Import and export:** Chrome, Edge, Firefox, Safari, Bitwarden, KeePass/KeePassXC, 1Password, LastPass and generic CSV; encrypted PassZit export.
- **Password generator:** random passwords and passphrases from the EFF word list.
- **Accounts:** only by invitation; mandatory two-factor sign-in (TOTP + recovery codes); recovery key for a forgotten master password; master-password change without re-encrypting the items.
- **Administration:** roles, vault policy (lock time, clipboard, key derivation, minimum length, trash, file limits, breach check), sessions and sign-in blocks, IP allow-list, hash-chained audit log, built-in user guide; 14 languages.
- **Operation:** one-line installer with signature check, deb/rpm packages (amd64, arm64), appliance images (OVA, QCOW2, VHDX, ISO), signed self-update with rollback and Stable/Testing channels, encrypted daily console backups with SFTP copy and restore.

## Planned

- **Shared vaults** for teams with per-user rights (view, use, edit, manage), groups, LDAP/SSO sign-in, WebAuthn/passkeys.
- **Time-limited and one-time access**, secret links, emergency access, per-item access log, four-eyes approval.
- Opening devices from [WatchZit](https://github.com/Max-Zit/watchzit) with stored credentials.

## Building

```sh
go run ./tools/buildwasm                          # Argon2id WebAssembly module for the browser
go build -o passzit-server ./cmd/passzit-server
./passzit-server --dev-embedded-db --data-dir ./data --listen 127.0.0.1:8443
```

Open `https://127.0.0.1:8443`, enter the setup token from `./data/setup-token.txt` and create the first administrator. Tests: `go test ./...` (the browser-crypto test runs when Chrome or Edge is installed).

PassZit is made by [MaxZit](https://maxzit.com), like [BackupZit](https://github.com/Max-Zit/backupzit), [ControlZit](https://github.com/Max-Zit/controlzit) and [WatchZit](https://github.com/Max-Zit/watchzit).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE). Third-party components: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Paid support will be offered by MaxZit.
