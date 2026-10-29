// buildwasm builds the Argon2id WebAssembly module of the browser clients
// (tools/argon2wasm) into internal/web/static/pz together with Go's
// wasm_exec.js. Run it from the repository root before building the server:
//
//	go run ./tools/buildwasm
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", filepath.Join(out, "argon2.wasm"), "./tools/argon2wasm") // #nosec G204 -- fixed arguments
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
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
	if err := os.WriteFile(filepath.Join(out, "wasm_exec.js"), b, 0o644); err != nil { // #nosec G306 -- public web asset
		return err
	}
	fmt.Println("wrote", filepath.Join(out, "argon2.wasm"), "and wasm_exec.js")
	return nil
}
