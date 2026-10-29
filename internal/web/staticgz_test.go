package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The static text files go out gzip-compressed when the browser accepts it.
func TestStaticGzip(t *testing.T) {
	h := gzipStatic(os.DirFS("static"), http.FileServer(http.Dir("static")))
	r := httptest.NewRequest("GET", "/pz/words.js", nil)
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("headers %v", w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	want, _ := os.ReadFile("static/pz/words.js")
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("body: %v", err)
	}
	if w.Body.Len() > len(want)/2 {
		t.Fatalf("hardly compressed: %d of %d", w.Body.Len(), len(want))
	}
	// without gzip the file server answers as before
	r = httptest.NewRequest("GET", "/pz/words.js", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Content-Encoding") != "" || !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatal("plain request was compressed")
	}
}
