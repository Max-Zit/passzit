// licenses writes THIRD_PARTY_LICENSES.md: every module linked into the
// given PassZit programs with its license text, read from the Go module
// cache. It fails when a license is not known to be compatible with the
// AGPL-3.0, so a new dependency is checked before a release.
//
//	go run ./tools/licenses -out THIRD_PARTY_LICENSES.md bin/passzit-server ./tools/qrwasm
//
// A package directory (./tools/…) stands for a browser module: its
// dependencies are listed for GOOS=js GOARCH=wasm.
package main

import (
	"bytes"
	"debug/buildinfo"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/max-zit/passzit/internal/licenses"
)

// wasmDeps lists the modules of a browser module (outside the main module).
func wasmDeps(pkg string) map[string]string {
	mods, err := licenses.WasmModules(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return mods
}

func goEnv(name string) string {
	v, err := licenses.GoEnv(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return v
}

func main() {
	out := flag.String("out", "THIRD_PARTY_LICENSES.md", "file to write")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: licenses -out FILE BINARY…")
		os.Exit(2)
	}
	mods := map[string]string{}
	goVersion := ""
	for _, bin := range flag.Args() {
		if strings.HasPrefix(bin, "./") {
			if st, err := os.Stat(bin); err == nil && st.IsDir() {
				for p, v := range wasmDeps(bin) {
					mods[p] = v
				}
				continue
			}
		}
		bi, err := buildinfo.ReadFile(bin)
		if err != nil {
			fmt.Fprintln(os.Stderr, bin+":", err)
			os.Exit(1)
		}
		goVersion = bi.GoVersion
		for _, d := range bi.Deps {
			if d.Replace != nil {
				d = d.Replace
			}
			mods[d.Path] = d.Version
		}
	}
	paths := make([]string, 0, len(mods))
	for p := range mods {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	cache := goEnv("GOMODCACHE")
	var b bytes.Buffer
	b.WriteString("# Third-party licenses\n\nPassZit is licensed under the GNU Affero General Public License v3.0 (see LICENSE).\n")
	b.WriteString("Its programs contain the following components under their own licenses, all compatible with the AGPL-3.0.\n\n")
	b.WriteString("| Component | Version | License |\n|---|---|---|\n")
	b.WriteString("| Go standard library and runtime | " + goVersion + " | BSD-3-Clause |\n")
	type entry struct{ path, version, kind, text string }
	var list []entry
	failed := false
	for _, p := range paths {
		dir := licenses.ModuleDir(cache, p, mods[p])
		text, err := licenses.Text(dir)
		kind := licenses.Detect(text)
		if err != nil || kind == "" {
			fmt.Fprintf(os.Stderr, "%s %s: license not recognized (%v); check it by hand\n", p, mods[p], err)
			failed = true
			continue
		}
		list = append(list, entry{p, mods[p], kind, text})
		fmt.Fprintf(&b, "| %s | %s | %s |\n", p, mods[p], kind)
	}
	b.WriteString("\nOther components:\n\n")
	b.WriteString("- PostgreSQL (PostgreSQL License) is the database; with the development option `--dev-embedded-db` the server downloads PostgreSQL binaries (Zonky embedded-postgres-binaries, Apache-2.0) and runs them.\n")
	b.WriteString("- The browser module `argon2.wasm` is golang.org/x/crypto/argon2 with the Go runtime compiled to WebAssembly; `wasm_exec.js` comes from the Go distribution (both BSD-3-Clause, see below).\n")
	b.WriteString("- Passphrases use the EFF Large Wordlist by the Electronic Frontier Foundation (https://www.eff.org/dice), licensed under the Creative Commons Attribution 3.0 United States License (https://creativecommons.org/licenses/by/3.0/us/). The list is used unchanged.\n")
	b.WriteString("- The browser extension matches websites with the Public Suffix List (https://publicsuffix.org), Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/), converted unchanged into extension/src/psl-rules.js.\n")
	b.WriteString("- Some icons of the console are based on Feather Icons (MIT License, see below).\n\n")
	goroot := goEnv("GOROOT")
	if t, err := os.ReadFile(filepath.Join(goroot, "LICENSE")); err == nil { // #nosec G304 -- Go installation
		b.WriteString("## Go standard library and runtime\n\n```\n" + strings.TrimSpace(string(t)) + "\n```\n\n")
	}
	for _, e := range list {
		fmt.Fprintf(&b, "## %s %s (%s)\n\n```\n%s\n```\n\n", e.path, e.version, e.kind, strings.TrimSpace(e.text))
	}
	b.WriteString("## Feather Icons (MIT)\n\n```\n" + featherLicense + "\n```\n")
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil { // #nosec G306 -- a public document
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%s: %d modules\n", *out, len(list))
	if failed {
		os.Exit(1)
	}
}

// featherLicense is the license of Feather Icons (github.com/feathericons/feather),
// on which some icons of the console are based.
const featherLicense = `The MIT License (MIT)

Copyright (c) 2013-2017 Cole Bemis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`
