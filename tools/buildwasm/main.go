// buildwasm builds the WebAssembly modules of the browser clients
// (Argon2id from tools/argon2wasm, the QR code reader from tools/qrwasm)
// into internal/web/static/pz together with Go's wasm_exec.js. Run it
// from the repository root before building the server:
//
//	go run ./tools/buildwasm
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/max-zit/passzit/internal/licenses"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "buildwasm:", err)
		os.Exit(1)
	}
}

func run() error {
	out := filepath.Join("internal", "web", "static", "pz")
	if err := os.MkdirAll(out, 0o750); err != nil {
		return err
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		return err
	}
	for _, m := range []string{"argon2", "qr"} {
		cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", filepath.Join(out, m+".wasm"), "./tools/"+m+"wasm") // #nosec G204 -- fixed arguments
		cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	gr, err := exec.Command(goBin, "env", "GOROOT").Output() // #nosec G204 -- fixed arguments
	if err != nil {
		return err
	}
	src := filepath.Join(strings.TrimSpace(string(gr)), "lib", "wasm", "wasm_exec.js")
	b, err := os.ReadFile(src) // #nosec G304 -- Go's own file
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "wasm_exec.js"), b, 0o644); err != nil { // #nosec G306 G703 -- public web asset at a fixed path
		return err
	}
	if err := writeNotices(filepath.Join(out, "wasm-licenses.txt"), strings.TrimSpace(string(gr))); err != nil {
		return err
	}
	fmt.Println("wrote argon2.wasm, qr.wasm, wasm_exec.js and wasm-licenses.txt to", out)
	return nil
}

// writeNotices writes the license texts of everything compiled into the
// WebAssembly modules (the browser extension ships them in
// THIRD_PARTY_LICENSES.txt). A module without a known AGPL-compatible
// license stops the build.
func writeNotices(file, goroot string) error {
	cache, err := licenses.GoEnv("GOMODCACHE")
	if err != nil {
		return err
	}
	in := map[string][]string{} // module@version → wasm files
	var keys []string
	for _, m := range []string{"argon2", "qr"} {
		mods, err := licenses.WasmModules("./tools/" + m + "wasm")
		if err != nil {
			return err
		}
		for p, v := range mods {
			k := p + " " + v
			if in[k] == nil {
				keys = append(keys, k)
			}
			in[k] = append(in[k], "pz/"+m+".wasm")
		}
	}
	sort.Strings(keys)
	goLicense, err := os.ReadFile(filepath.Join(goroot, "LICENSE")) // #nosec G304 -- Go's own file
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("== Go standard library and runtime (BSD-3-Clause) — in pz/argon2.wasm, pz/qr.wasm and pz/wasm_exec.js ==\n\n")
	b.WriteString(strings.TrimSpace(string(goLicense)) + "\n\n")
	for _, k := range keys {
		f := strings.Fields(k)
		dir := licenses.ModuleDir(cache, f[0], f[1])
		text, err := licenses.Text(dir)
		kind := licenses.Detect(text)
		if err != nil || kind == "" {
			return fmt.Errorf("%s %s: license not recognized (%v); check it by hand", f[0], f[1], err)
		}
		fmt.Fprintf(&b, "== %s %s (%s) — in %s ==\n\n%s\n\n", f[0], f[1], kind, strings.Join(in[k], ", "), strings.TrimSpace(text))
		if n := licenses.Notice(dir); n != "" {
			fmt.Fprintf(&b, "-- NOTICE of %s --\n\n%s\n\n", f[0], strings.TrimSpace(n))
		}
	}
	return os.WriteFile(file, []byte(b.String()), 0o644) // #nosec G306 G703 -- public notice at a fixed path
}
