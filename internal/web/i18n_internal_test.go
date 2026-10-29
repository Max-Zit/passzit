package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/max-zit/passzit/internal/extpack"
)

// uiTexts collects the English texts of the console: template {{.T "…"}}
// calls, the messages in the Go code that reach the page, and t("…") in
// the browser scripts.
func uiTexts(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	tmpl := regexp.MustCompile(`\.T "((?:[^"\\]|\\.)+)"`)
	files, _ := filepath.Glob("templates/*.html")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range tmpl.FindAllStringSubmatch(string(b), -1) {
			out[unescapeText(m[1])] = true
		}
	}
	// Go: messages passed to translate/msg/T/redirect/show* and errors.
	goMsg := regexp.MustCompile(`(?:translate\([^,\n]+, |s\.msg\(r, |\.T\(|redirect\(w, r, [^\n]*?, |redirectErr\(w, r, [^,\n]+, |show\w+\(w, r, http\.Status\w+, [^"\n]*?|errors\.New\(|uiMsg\()"((?:[^"\\]|\\.)+)"`)
	for _, dir := range []string{".", "../store", "../vaultcrypto"} {
		gofiles, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range gofiles {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, _ := os.ReadFile(f)
			for _, m := range goMsg.FindAllStringSubmatch(string(b), -1) {
				if m[1] != "" {
					out[unescapeText(m[1])] = true
				}
			}
		}
	}
	for k := range out {
		if strings.HasPrefix(k, "/") {
			delete(out, k)
		}
	}
	for _, k := range jsTexts {
		out[k] = true
	}
	// the browser extension takes its texts from the same catalogs
	ext, err := extpack.Texts(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for k := range ext {
		out[k] = true
	}
	for _, p := range DocPages {
		out[p.Title] = true
	}
	// Composed elsewhere.
	for _, s := range []string{"The address is already used.", "Not found.", "Weak", "Fair", "Good", "Strong", "Login", "Secure note", "Item", "Card", "Identity", "SSH key", "Cards", "Identities", "SSH keys", "Stable", "Testing (release candidates)", "1 hour", "1 day", "3 days", "7 days", "30 days",
		// kinds of a new item (vault.js KINDS)
		"Website login", "User name and password of a website", "Credentials", "User name and password without a website", "Remote Desktop (RDP)", "Windows computers and servers", "SSH with a password", "Linux servers, switches and routers",
		"A key pair for SSH sign-in", "WinBox (MikroTik)", "MikroTik routers and switches", "Encrypted text", "Payment card", "Name, address and contact details"} {
		out[s] = true
	}
	return out
}

func unescapeText(s string) string {
	var u string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &u); err != nil {
		return s
	}
	return u
}

// TestCatalogsComplete fails when a console text has no translation in one
// of the languages. PZ_I18N_DUMP=file writes the list of texts (for
// tools/i18n).
func TestCatalogsComplete(t *testing.T) {
	texts := uiTexts(t)
	keys := make([]string, 0, len(texts))
	for k := range texts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if p := os.Getenv("PZ_I18N_DUMP"); p != "" {
		var b bytes.Buffer
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		e.SetIndent("", " ")
		_ = e.Encode(keys)
		if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range Languages[1:] {
		var missing []string
		for _, k := range keys {
			if catalogs[l.Code][k] == "" {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s: %d texts without translation, e.g. %q", l.Code, len(missing), missing[0])
		}
		// format verbs must match
		verbs := regexp.MustCompile(`%[sdv]`)
		for k, v := range catalogs[l.Code] {
			if strings.Join(verbs.FindAllString(k, -1), "") != strings.Join(verbs.FindAllString(v, -1), "") {
				t.Errorf("%s: format verbs differ in %q → %q", l.Code, k, v)
			}
		}
	}
}
