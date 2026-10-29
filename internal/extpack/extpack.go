// Package extpack builds the PassZit browser extension from extension/src:
// one build for Chromium browsers (Chrome, Edge, Opera, Brave, Vivaldi) and
// one for Firefox. The crypto and generator modules, the WebAssembly modules
// and the translations come from the server (internal/web), so both clients
// share one implementation. The server packs the same files for its
// download page; tools/extpack writes them to disk.
package extpack

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Targets are the builds.
var Targets = []string{"chromium", "firefox"}

var shared = []string{"crypto.js", "generator.js", "words.js", "totp.js", "qr.js", "argon2.wasm", "qr.wasm", "wasm_exec.js"}

// Sources are the parts of a build: the extension (extension/src), the
// shared browser modules (internal/web/static/pz) and the catalogs
// (internal/web/i18n/*.json, at the top of I18n).
type Sources struct {
	Ext, Pz, I18n fs.FS
	Test          fs.FS // extension/test, for test builds only
}

// DirSources reads the sources from a repository checkout.
func DirSources(root string) Sources {
	return Sources{
		Ext:  os.DirFS(filepath.Join(root, "extension", "src")),
		Pz:   os.DirFS(filepath.Join(root, "internal", "web", "static", "pz")),
		I18n: os.DirFS(filepath.Join(root, "internal", "web", "i18n")),
		Test: os.DirFS(filepath.Join(root, "extension", "test")),
	}
}

// Options describe a build.
type Options struct {
	Root    string // repository root (Build)
	Target  string // chromium or firefox
	Version string // x.y.z
	Out     string // output directory (Build)
	// Test adds the harness (extension/test) and host permissions for
	// loopback test servers; Key fixes the extension id (Chromium).
	Test bool
	Key  string
}

var versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// ValidVersion tells whether v can be an extension version.
func ValidVersion(v string) bool { return versionRE.MatchString(v) }

// Build writes an unpacked extension into o.Out.
func Build(o Options) error {
	files, err := Files(DirSources(o.Root), o)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(o.Out); err != nil {
		return err
	}
	for name, b := range files {
		dst := filepath.Join(o.Out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil { // #nosec G703 -- paths inside the build directory
			return err
		}
	}
	return nil
}

// Files returns the files of a build by their path in the extension.
func Files(src Sources, o Options) (map[string][]byte, error) {
	if !ValidVersion(o.Version) {
		return nil, fmt.Errorf("the version must look like 0.2.0")
	}
	files := map[string][]byte{}
	err := fs.WalkDir(src.Ext, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == "manifest.json" {
			return err
		}
		if o.Target == "firefox" && strings.HasPrefix(path.Base(p), "offscreen") {
			return nil
		}
		b, err := fs.ReadFile(src.Ext, p)
		files[p] = b
		return err
	})
	if err != nil {
		return nil, err
	}
	if o.Test && src.Test != nil {
		ents, _ := fs.ReadDir(src.Test, ".")
		for _, e := range ents {
			if b, err := fs.ReadFile(src.Test, e.Name()); err == nil && !e.IsDir() {
				files["test/"+e.Name()] = b
			}
		}
	}
	for _, f := range shared {
		b, err := fs.ReadFile(src.Pz, f)
		if err != nil {
			return nil, fmt.Errorf("%w (run go run ./tools/buildwasm first)", err)
		}
		files["pz/"+f] = b
	}
	if err := addTexts(src, files); err != nil {
		return nil, err
	}
	m, err := manifest(src, o)
	if err != nil {
		return nil, err
	}
	files["manifest.json"] = m
	return files, nil
}

// TextRE finds the texts the extension translates: t("…").
var TextRE = regexp.MustCompile(`\bt\("((?:[^"\\]|\\.)+)"`)

// Texts lists the English texts of the extension's scripts.
func Texts(root string) (map[string]bool, error) {
	return texts(os.DirFS(filepath.Join(root, "extension", "src")))
}

func texts(ext fs.FS) (map[string]bool, error) {
	keys := map[string]bool{}
	names, _ := fs.Glob(ext, "*.js")
	for _, f := range names {
		b, err := fs.ReadFile(ext, f)
		if err != nil {
			return nil, err
		}
		for _, m := range TextRE.FindAllStringSubmatch(string(b), -1) {
			var s string
			if json.Unmarshal([]byte(`"`+m[1]+`"`), &s) == nil {
				keys[s] = true
			}
		}
	}
	return keys, nil
}

// addTexts puts the translations of the extension's texts into
// i18n/<lang>.json.
func addTexts(src Sources, files map[string][]byte) error {
	keys, err := texts(src.Ext)
	if err != nil {
		return err
	}
	cats, _ := fs.Glob(src.I18n, "*.json")
	for _, c := range cats {
		raw, err := fs.ReadFile(src.I18n, c)
		if err != nil {
			return err
		}
		all := map[string]string{}
		if err := json.Unmarshal(raw, &all); err != nil {
			return fmt.Errorf("%s: %w", c, err)
		}
		mine := map[string]string{}
		for k := range keys {
			if v := all[k]; v != "" {
				mine[k] = v
			}
		}
		b, _ := json.Marshal(mine)
		files["i18n/"+path.Base(c)] = b
	}
	return nil
}

func manifest(src Sources, o Options) ([]byte, error) {
	raw, err := fs.ReadFile(src.Ext, "manifest.json")
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["version"] = o.Version
	if o.Target == "firefox" {
		m["background"] = map[string]any{"scripts": []string{"background.js"}, "type": "module"}
		perms := []string{}
		for _, p := range m["permissions"].([]any) {
			if p != "offscreen" {
				perms = append(perms, p.(string))
			}
		}
		m["permissions"] = perms
		delete(m, "minimum_chrome_version")
		m["browser_specific_settings"] = map[string]any{"gecko": map[string]any{"id": "passzit@maxzit.com", "strict_min_version": "128.0",
			"data_collection_permissions": map[string]any{"required": []string{"none"}}}}
	}
	if o.Test {
		m["host_permissions"] = []string{"https://*/*", "http://*/*", "http://127.0.0.1/*", "http://localhost/*"} // as granted by a user who lets the extension offer to save
		m["name"] = "PassZit (test build)"
		// Firefox's WebDriver BiDi may not open extension pages: a test page
		// links to the harness instead.
		m["web_accessible_resources"] = []map[string]any{{"resources": []string{"test/*"}, "matches": []string{"http://127.0.0.1/*"}}}
	}
	if o.Key != "" {
		m["key"] = o.Key
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ZipFiles packs files with fixed times and sorted names (same input, same
// zip).
func ZipFiles(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, n := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: stamp})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(files[n]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Zip packs the build directory dir into the file name.
func Zip(dir, name string) error {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p) // #nosec G304 G122 -- files of our own build directory
		files[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		return err
	}
	b, err := ZipFiles(files)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return err
	}
	return os.WriteFile(name, b, 0o644) // #nosec G306 G703 -- a release file
}
