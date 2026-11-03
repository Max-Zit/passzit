// Package licenses finds the license texts of Go modules in the module
// cache and tells whether they are compatible with the AGPL-3.0. It serves
// tools/licenses (THIRD_PARTY_LICENSES.md of the programs) and
// tools/buildwasm (the notices of the WebAssembly modules that ship in the
// browser extension).
package licenses

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// kinds maps a phrase of the license text to its name; all are compatible
// with the AGPL-3.0.
var kinds = []struct{ phrase, name string }{
	{"Apache License", "Apache-2.0"},
	{"Mozilla Public License", "MPL-2.0"},
	{"Redistribution and use in source and binary forms", "BSD"},
	{"Permission is hereby granted, free of charge", "MIT"},
	{"Permission to use, copy, modify, and", "ISC"},
	{"public domain", "Public domain"},
}

// Detect names the license of a text, or "" when it is not a known
// AGPL-compatible one.
func Detect(text string) string {
	for _, k := range kinds {
		if strings.Contains(text, k.phrase) {
			if k.name == "BSD" && strings.Contains(text, "Neither the name") {
				return "BSD-3-Clause"
			}
			if k.name == "BSD" {
				return "BSD-2-Clause"
			}
			return k.name
		}
	}
	return ""
}

// Text finds the license file of a module directory.
func Text(dir string) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		n := strings.ToUpper(e.Name())
		if !e.IsDir() && (strings.HasPrefix(n, "LICENSE") || strings.HasPrefix(n, "LICENCE") || strings.HasPrefix(n, "COPYING")) {
			b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- module cache
			return string(b), err
		}
	}
	// Some modules state it in the README only.
	for _, name := range []string{"README.md", "README"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil { // #nosec G304 -- module cache
			return string(b), nil
		}
	}
	return "", fmt.Errorf("no license file in %s", dir)
}

// Notice returns the NOTICE file of a module (Apache-2.0 §4d), or "".
func Notice(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if !e.IsDir() && strings.HasPrefix(strings.ToUpper(e.Name()), "NOTICE") {
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil { // #nosec G304 -- module cache
				return string(b)
			}
		}
	}
	return ""
}

// WasmModules lists the modules (outside the main module) of a package
// built for the browser (GOOS=js GOARCH=wasm), path → version.
func WasmModules(pkg string) (map[string]string, error) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}", pkg) // #nosec G204 -- a package of this repository
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pkg, err)
	}
	mods := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			mods[f[0]] = f[1]
		}
	}
	return mods, nil
}

// GoEnv returns a value of `go env`.
func GoEnv(name string) (string, error) {
	out, err := exec.Command("go", "env", name).Output() // #nosec G204 -- fixed command
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ModuleDir is the directory of a module version in the module cache.
func ModuleDir(cache, path, version string) string {
	return filepath.Join(cache, EscapePath(path)+"@"+version)
}

// EscapePath applies the module cache case encoding (!x for X).
func EscapePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + 'a' - 'A')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
