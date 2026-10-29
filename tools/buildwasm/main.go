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
	"strings"
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
	fmt.Println("wrote argon2.wasm, qr.wasm and wasm_exec.js to", out)
	return nil
}
