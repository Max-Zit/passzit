// Package extpack builds the PassZit browser extension from extension/src:
// one build for Chromium browsers (Chrome, Edge, Opera, Brave, Vivaldi) and
// one for Firefox. The crypto and generator modules, the Argon2id
// WebAssembly module and the translations come from the server
// (internal/web), so both clients share one implementation.
package extpack

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Targets are the builds.
var Targets = []string{"chromium", "firefox"}

var shared = []string{"crypto.js", "generator.js", "words.js", "argon2.wasm", "wasm_exec.js"}

// Options describe a build.
type Options struct {
	Root    string // repository root
	Target  string // chromium or firefox
	Version string // x.y.z
	Out     string // output directory
	// Test adds the harness (extension/test) and host permissions for
	// loopback test servers; Key fixes the extension id (Chromium).
	Test bool
	Key  string
}

var versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// Build writes an unpacked extension into o.Out.
func Build(o Options) error {
	if !versionRE.MatchString(o.Version) {
		return fmt.Errorf("the version must look like 0.2.0")
	}
	if err := os.RemoveAll(o.Out); err != nil {
		return err
	}
	src := filepath.Join(o.Root, "extension", "src")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(p) == "manifest.json" {
			return err
		}
		if o.Target == "firefox" && strings.HasPrefix(filepath.Base(p), "offscreen") {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		return copyFile(p, filepath.Join(o.Out, rel))
	})
	if err != nil {
		return err
	}
	if o.Test {
		files, _ := filepath.Glob(filepath.Join(o.Root, "extension", "test", "*"))
		for _, f := range files {
			if err := copyFile(f, filepath.Join(o.Out, "test", filepath.Base(f))); err != nil {
				return err
			}
		}
	}
	for _, f := range shared {
		if err := copyFile(filepath.Join(o.Root, "internal", "web", "static", "pz", f), filepath.Join(o.Out, "pz", f)); err != nil {
			return fmt.Errorf("%w (run go run ./tools/buildwasm first)", err)
		}
	}
	if err := writeTexts(o.Root, o.Out); err != nil {
		return err
	}
	return writeManifest(o)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src) // #nosec G304 -- files of this repository
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600) // #nosec G703 -- paths inside the build directory of this repository
}

// TextRE finds the texts the extension translates: t("…").
var TextRE = regexp.MustCompile(`\bt\("((?:[^"\\]|\\.)+)"`)

// Texts lists the English texts of the extension's scripts.
func Texts(root string) (map[string]bool, error) {
	keys := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(root, "extension", "src", "*.js"))
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- files of this repository
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

// writeTexts puts the translations of the extension's texts into
// i18n/<lang>.json.
func writeTexts(root, out string) error {
	keys, err := Texts(root)
	if err != nil {
		return err
	}
	cats, _ := filepath.Glob(filepath.Join(root, "internal", "web", "i18n", "*.json"))
	for _, c := range cats {
		raw, err := os.ReadFile(c) // #nosec G304 -- files of this repository
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
		if err := os.MkdirAll(filepath.Join(out, "i18n"), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "i18n", filepath.Base(c)), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeManifest(o Options) error {
	raw, err := os.ReadFile(filepath.Join(o.Root, "extension", "src", "manifest.json"))
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
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
		return err
	}
	return os.WriteFile(filepath.Join(o.Out, "manifest.json"), append(b, '\n'), 0o600)
}

// Zip packs a build with fixed times and sorted names (same input, same zip).
func Zip(dir, name string) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return err
	}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	f, err := os.Create(name) // #nosec G304 -- the output file of the build
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range files {
		rel, _ := filepath.Rel(dir, p)
		w, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate, Modified: stamp})
		if err != nil {
			return err
		}
		src, err := os.Open(p) // #nosec G304 -- files of the build
		if err != nil {
			return err
		}
		_, err = io.Copy(w, src)
		_ = src.Close()
		if err != nil {
			return err
		}
	}
	return zw.Close()
}
