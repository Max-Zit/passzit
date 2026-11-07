package web

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/max-zit/passzit/extension"
	"github.com/max-zit/passzit/internal/extpack"
)

// The browser extension has its own version (extension/VERSION) so that a
// server release with an unchanged extension needs no new review in the
// browser stores. extension/SOURCES.sha256 records what that version
// contains; when the packed extension changes, this test fails until
// extension/VERSION is raised and the hash written again:
//
//	PZ_EXT_HASH=update go test ./internal/web -run TestExtensionVersion
func TestExtensionVersion(t *testing.T) {
	if _, err := os.Stat(filepath.Join("static", "pz", "argon2.wasm")); err != nil {
		t.Skip("argon2.wasm is not built (go run ./tools/buildwasm)")
	}
	v := extension.Version()
	if !extpack.ValidVersion(v) {
		t.Fatalf("extension/VERSION %q is no x.y.z version", v)
	}
	h := sha256.New()
	for _, target := range []string{"chromium", "firefox"} {
		files, err := extpack.Files(extpack.DirSources(filepath.Join("..", "..")), extpack.Options{Target: target, Version: "0.0.0"})
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			h.Write([]byte(target + "/" + n + "\x00"))
			h.Write(files[n])
			h.Write([]byte{0})
		}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	path := filepath.Join("..", "..", "extension", "SOURCES.sha256")
	if os.Getenv("PZ_EXT_HASH") == "update" {
		if err := os.WriteFile(path, []byte(sum+"  "+v+"\n"), 0o644); err != nil { // #nosec G306 -- a file of the repository
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a file of the repository
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(raw))
	switch {
	case len(f) != 2:
		t.Fatalf("%s: want \"<sha256>  <version>\"", path)
	case f[0] != sum && f[1] == v:
		t.Fatalf("the packed extension changed but extension/VERSION is still %s: raise it, then PZ_EXT_HASH=update go test ./internal/web -run TestExtensionVersion", v)
	case f[0] != sum || f[1] != v:
		t.Fatalf("extension/VERSION is %s; record its contents: PZ_EXT_HASH=update go test ./internal/web -run TestExtensionVersion", v)
	}
}

// Releases offer the extension under its own version, development builds
// under 0.0.0.
func TestExtensionDownloadVersion(t *testing.T) {
	if got := (&Server{Version: "9.9.9"}).extensionVersion(); got != extension.Version() {
		t.Fatalf("release offers extension %s, want %s", got, extension.Version())
	}
	if got := (&Server{Version: "dev"}).extensionVersion(); got != "0.0.0" {
		t.Fatalf("development build offers extension %s", got)
	}
}
