package extpack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/max-zit/passzit/internal/licenses"
)

// Every package carries the extension's license and the notices of all
// third-party code in it (Apache-2.0 and BSD require them with each copy).
func TestPackagesCarryLicenses(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "internal", "web", "static", "pz", "wasm-licenses.txt")); err != nil {
		t.Skip("the WebAssembly modules are not built (go run ./tools/buildwasm)")
	}
	agpl, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, pkg := range []string{"github.com/max-zit/passzit/tools/argon2wasm", "github.com/max-zit/passzit/tools/qrwasm"} {
		mods, err := licenses.WasmModules(pkg)
		if err != nil {
			t.Fatal(err)
		}
		for p, v := range mods {
			want = append(want, p+" "+v)
		}
	}
	want = append(want, "Go standard library and runtime", "Public Suffix List (MPL-2.0)", "Mozilla Public License Version 2.0",
		"EFF Large Wordlist (CC BY 3.0 US)", "creativecommons.org/licenses/by/3.0/us")
	for _, target := range Targets {
		files, err := Files(DirSources(root), Options{Target: target, Version: "1.2.3"})
		if err != nil {
			t.Fatal(err)
		}
		if string(files["LICENSE"]) != string(agpl) {
			t.Errorf("%s: LICENSE is not the repository's AGPL-3.0 text", target)
		}
		tp := string(files["THIRD_PARTY_LICENSES.txt"])
		for _, w := range want {
			if !strings.Contains(tp, w) {
				t.Errorf("%s: THIRD_PARTY_LICENSES.txt does not name %q", target, w)
			}
		}
	}
}
