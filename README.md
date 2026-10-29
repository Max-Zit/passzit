<p align="center"><img src="brand/passzit-logo-on-light.svg" alt="PassZit" height="64"></p>

# PassZit

**Free, open-source, self-hosted password manager** for people and teams — your own server, end-to-end encrypted vaults, and browser extensions for Chrome, Edge, Firefox, Opera and Brave.

> **Status:** in development on the `develop` branch. There is no release yet; follow the repository or [Discussions](https://github.com/Max-Zit/passzit/discussions) for news.

## What works today

- **End-to-end encryption, zero knowledge:** the browser derives keys from the master password with Argon2id (64 MiB, 3 passes), encrypts every item — name, user name, password, websites, notes — with AES-256-GCM and sends only ciphertext. The server stores an argon2id hash of a separate auth key and never sees the master password or any key it could use. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **Web vault:** logins and secure notes, own fields, folders, favourites, search, trash, password history, auto-lock and clipboard clearing.
- **Password generator:** random passwords and passphrases from the EFF word list.
- **Accounts:** only by invitation; mandatory two-factor sign-in (TOTP + recovery codes); recovery key for a forgotten master password; master-password change without re-encrypting the items.
- **Administration:** roles, vault policy (lock time, clipboard, key derivation, minimum length, trash), sessions and sign-in blocks, IP allow-list, hash-chained audit log, built-in user guide; 14 languages.

## Planned

- **Browser extensions** that fill and save logins, generate strong passwords and work with the web vault (next).
- Import from browsers and other password managers, encrypted export.
- Cards, identities, SSH keys, TOTP codes, encrypted attachments, password health with a breach check that never sends the password.
- **Shared vaults** for teams with per-user rights (view, use, edit, manage), **time-limited and one-time access**, secret links, emergency access.
- Linux packages, appliance images, signed self-update, built-in Let's Encrypt, WebAuthn/passkeys, LDAP/SSO sign-in.
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
