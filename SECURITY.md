# Security policy

## Supported versions

Security fixes are released for the newest version. PassZit is before 1.0: update to each new release (the console offers it under Settings → Updates and server).

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open the [Security tab](https://github.com/Max-Zit/passzit/security) of this repository.
2. Click **Report a vulnerability** and describe the problem, the affected version and how to reproduce it.

We confirm reports within a few working days, fix confirmed problems in a new release and credit the reporter in the release notes unless they prefer otherwise.

## How releases are protected

- Every release has a manifest signed with the PassZit release key (ed25519); the console's update and `install.sh` verify the signature and checksums before installing.
- Release packages are built from tagged commits of this repository; the appliance images carry a written source offer (`SOURCE-CODE.txt`). The browser extension has its own version (`extension/VERSION`); the store packages are built from the tag of that extension version (for example `v0.9.4`), which can be older than the current server release when the extension did not change (the source archive is attached to the Firefox submission).

## How PassZit is tested

PassZit is end-to-end encrypted: the server only stores sealed data. The tests check the server, the web vault, the browser extensions and the command line separately, because a mistake in any of them could expose a vault.

**On every change** (GitHub Actions):

- build for Linux and Windows, gofmt, `go vet`, the full test suite against an embedded PostgreSQL, with the web vault's crypto, the importers and both browser extensions running in a real Chrome; the whole suite again with the Go **race detector**;
- **fuzzing** of every parser that reads untrusted input: passkey and WebAuthn data (CBOR, authenticator data, COSE keys, client data, whole registrations and sign-ins), the native messages and connection plans of the MaxZit Launcher, sealed vault data and recovery keys, sharing data, e-mail addresses, backup files on restore, network allow-lists, authenticator secrets, SSO state, SAML metadata and responses, sign-in redirects, uploaded certificates, the JSON requests of the web vault, the browser extension, the command line, sharing and access requests, the command line's authenticator codes and vault items, and QR pictures; in the browser, imported files (CSV, Bitwarden, KeePass, PassZit) are mutated thousands of times and encrypted exports damaged;
- staticcheck and gosec (Linux and Windows), govulncheck (a known vulnerability in called code fails the build unless it is listed with a reason and an end date in `.govulncheck-accepted`), Gitleaks, CodeQL, Dependabot, secret scanning with push protection and the [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Max-Zit/passzit).

**Before every release**, in a test lab:

- source code: Semgrep, Trivy and Gitleaks;
- the running console: an authenticated OWASP ZAP scan of a freshly installed appliance, a crawl of every page as administrator and as user in English and Serbian, and probes that every administrator route refuses users and every route refuses requests without a session;
- the appliance image: Trivy over its operating-system packages, a Lynis hardening audit, testssl.sh on the console port (8443) and Nuclei; OpenVAS / Greenbone for larger releases;
- code reviews of the server's rights, the web vault's crypto and the browser extension, and the appliance images imported on Proxmox, VMware ESXi and Hyper-V.

Findings are fixed before the release; accepted risks are documented in the release notes and in the guide (Security → Honest limits).
