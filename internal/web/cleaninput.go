package web

import (
	"bytes"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// PostgreSQL text cannot hold a NUL character nor invalid UTF-8, so such
// input made a query fail with 500. It is refused with 400 up front: in the
// query string and in form posts (cleanInput), and in JSON bodies as the
// escape \u0000 (readJSON; Go already replaces invalid UTF-8 in JSON).

const badInputMessage = "The request contains characters that are not allowed."

// cleanValues reports whether all keys and values are valid UTF-8 without NUL.
func cleanValues(vals url.Values) bool {
	ok := func(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
	for k, vs := range vals {
		if !ok(k) {
			return false
		}
		for _, v := range vs {
			if !ok(v) {
				return false
			}
		}
	}
	return true
}

// cleanInput refuses requests whose query or form post holds a NUL character
// or invalid UTF-8. Multipart uploads and JSON are left to their handlers.
func (s *Server) cleanInput(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err == nil && !cleanValues(q) {
			http.Error(w, badInputMessage, http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct == "application/x-www-form-urlencoded" {
				if err := r.ParseForm(); err == nil && !cleanValues(r.PostForm) {
					http.Error(w, badInputMessage, http.StatusBadRequest)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// jsonHasNUL reports the JSON escape of a NUL character in a body.
func jsonHasNUL(b []byte) bool { return bytes.Contains(b, []byte(`\u0000`)) }
