package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestExtensionLinkFromVault(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	var lr extLoginResp
	admin.must("POST", "/api/ext/link", map[string]string{"device": "Chrome on Windows"}, &lr)
	if !strings.HasPrefix(lr.Token, "pzd_") || lr.Next != "done" {
		t.Fatalf("link: %+v", lr)
	}
	// the token is a full extension session
	var acct accountResp
	if c := e.bearer(lr.Token, "GET", "/api/account", nil, &acct); c != http.StatusOK || acct.Email != admin.email {
		t.Fatalf("account with the linked token: %d %q", c, acct.Email)
	}
	// an extension cannot make more tokens with its own
	if c := e.bearer(lr.Token, "POST", "/api/ext/link", map[string]string{"device": "x"}, nil); c != http.StatusForbidden {
		t.Fatalf("link from an extension session: %d", c)
	}
	// it shows under the sessions of the account
	if _, page := admin.get("/account"); !strings.Contains(page, "Chrome on Windows") {
		t.Fatal("linked extension not listed")
	}
}
