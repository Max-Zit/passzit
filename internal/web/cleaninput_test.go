package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestBadInputRefused: a NUL character or invalid UTF-8 (which PostgreSQL
// text cannot hold) gives 400 instead of a failed query (500) — in form
// posts, in the query string and in JSON — and normal input still works.
// The OWASP ZAP scan of 0.9.8 found 500s on /groups/{id}, /settings/email
// and /audit.
func TestBadInputRefused(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	gid, err := e.st.SaveGroup(context.Background(), 0, "Ops", "")
	if err != nil {
		t.Fatal(err)
	}
	group := "/groups/" + strconv.FormatInt(gid, 10)
	for _, c := range []struct {
		path string
		vals url.Values
	}{
		{group, url.Values{"name": {"Ops\x00"}}},
		{group, url.Values{"name": {"Ops"}, "description": {"bad \xff\xfe"}}},
		{"/settings/email", url.Values{"host": {"smtp\x00.example"}}},
		{"/users/invite", url.Values{"email\x00": {"x@example.com"}}},
	} {
		if code, body := admin.form(c.path, c.vals); code != http.StatusBadRequest || !strings.Contains(body, badInputMessage) {
			t.Errorf("POST %s %v: %d %.80s", c.path, c.vals, code, body)
		}
	}
	for _, q := range []string{"/audit?q=%00", "/audit?q=%FF", "/users?q=a%00b"} {
		if code, _ := admin.get(q); code != http.StatusBadRequest {
			t.Errorf("GET %s: %d", q, code)
		}
	}
	if code, body := admin.do("POST", "/api/requests", map[string]string{"reason": "x\x00y"}, nil); code != http.StatusBadRequest || !strings.Contains(body, badInputMessage) {
		t.Errorf("JSON with NUL: %d %.80s", code, body)
	}
	// normal input still goes through
	if code, _ := admin.form(group, url.Values{"name": {"Ops – Beograd ✓"}, "description": {"Šđčćž"}}); code != http.StatusSeeOther {
		t.Fatalf("normal save: %d", code)
	}
	if code, _ := admin.get("/audit?q=Ops"); code != http.StatusOK {
		t.Fatalf("normal search: %d", code)
	}
}
