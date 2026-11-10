package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPassphraseWords keeps the passphrase list (static/pz/words.js, also in
// the extension) at 7776 different words of lowercase letters only: no
// hyphen, space or other character a user might pick as the separator, so
// a phrase always splits back into its words, and 12.9 bits per word.
func TestPassphraseWords(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("static", "pz", "words.js"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`WORDS = "([^"]*)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no WORDS in words.js")
	}
	words := strings.Split(string(m[1]), " ")
	if len(words) != 7776 {
		t.Errorf("%d words, want 7776 (6^5)", len(words))
	}
	only := regexp.MustCompile(`^[a-z]+$`)
	seen := map[string]bool{}
	for _, w := range words {
		if !only.MatchString(w) {
			t.Errorf("word %q has other characters than a-z", w)
		}
		if seen[w] {
			t.Errorf("word %q twice", w)
		}
		seen[w] = true
	}
}
