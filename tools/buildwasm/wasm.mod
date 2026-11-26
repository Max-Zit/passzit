// The dependencies of the browser extension's WebAssembly modules (Argon2id
// from golang.org/x/crypto, the QR reader with gozxing and golang.org/x/text),
// kept apart from the server's go.mod: a dependency update of the server
// (for example a fix in a package the modules do not use) does not change the
// extension. Raise these together with extension/VERSION when a fix concerns
// the modules. tools/buildwasm builds with -modfile=tools/buildwasm/wasm.mod.
module github.com/max-zit/passzit

go 1.27.0

require (
	github.com/makiuchi-d/gozxing v0.1.1
	golang.org/x/crypto v0.58.0
	golang.org/x/text v0.43.0
)

require (
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)
