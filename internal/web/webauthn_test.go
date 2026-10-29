package web

import (
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/max-zit/passzit/internal/webauthn"
	"github.com/max-zit/passzit/internal/webauthn/webauthntest"
)

func TestSecurityKeys(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	origin := e.ts.URL
	// register a key in a full session
	var o createOptions
	admin.must("POST", "/api/account/keys/start", nil, &o)
	if o.RPID != "127.0.0.1" || len(o.Algs) == 0 {
		t.Fatalf("options %+v", o)
	}
	key := webauthntest.New(webauthn.AlgES256)
	if code, _ := admin.do("POST", "/api/account/keys", keyRegisterReq{Name: "YubiKey", Reg: key.Register(o.RPID, "https://evil.example", o.Challenge)}, nil); code != http.StatusBadRequest {
		t.Fatalf("foreign origin registered: %d", code)
	}
	admin.must("POST", "/api/account/keys/start", nil, &o)
	admin.must("POST", "/api/account/keys", keyRegisterReq{Name: "YubiKey", Reg: key.Register(o.RPID, origin, o.Challenge)}, nil)
	// the challenge is used once
	if code, _ := admin.do("POST", "/api/account/keys", keyRegisterReq{Name: "again", Reg: key.Register(o.RPID, origin, o.Challenge)}, nil); code != http.StatusBadRequest {
		t.Fatalf("challenge used twice: %d", code)
	}
	// sign in with the master password, then the key instead of a code
	signIn := func() *client {
		c := e.client()
		c.email, c.pw = admin.email, admin.pw
		a, _ := c.authKey(c.email, c.pw)
		var lr loginResp
		c.must("POST", "/api/login", map[string]string{"email": c.email, "auth": a}, &lr)
		if lr.Next != "2fa" {
			t.Fatalf("after the password: %+v", lr)
		}
		return c
	}
	c := signIn()
	var g getOptions
	c.must("POST", "/api/login/key/start", nil, &g)
	if len(g.Allow) != 1 {
		t.Fatalf("allowed keys %+v", g.Allow)
	}
	var lr loginResp
	c.must("POST", "/api/login/key", key.SignIn(g.RPID, origin, g.Challenge), &lr)
	if lr.Next != "done" {
		t.Fatalf("key sign-in: %+v", lr)
	}
	if code, _ := c.do("GET", "/api/account", nil, nil); code != http.StatusOK {
		t.Fatalf("not signed in after the key: %d", code)
	}
	// another key with the same id, a replay and no challenge are refused
	c = signIn()
	c.must("POST", "/api/login/key/start", nil, &g)
	fake := webauthntest.New(webauthn.AlgES256)
	fake.ID = key.ID
	if code, _ := c.do("POST", "/api/login/key", fake.SignIn(g.RPID, origin, g.Challenge), nil); code != http.StatusUnauthorized {
		t.Fatalf("fake key: %d", code)
	}
	if code, _ := c.do("POST", "/api/login/key", key.SignIn(g.RPID, origin, g.Challenge), nil); code != http.StatusUnauthorized {
		t.Fatalf("challenge reused after a failure: %d", code)
	}
	// without the password step there is nothing to answer
	jar, _ := cookiejar.New(nil)
	anon := e.client()
	anon.hc.Jar = jar
	if code, _ := anon.do("POST", "/api/login/key/start", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("key sign-in without the password: %d", code)
	}
	// the account page lists the key; removing it
	code, page := admin.get("/account")
	if code != http.StatusOK || !strings.Contains(page, "YubiKey") {
		t.Fatalf("account page: %d", code)
	}
	keys, _ := e.st.SecurityKeys(t.Context(), 1)
	admin.form("/account/keys/delete", map[string][]string{"id": {keys[0].ID}})
	if keys, _ := e.st.SecurityKeys(t.Context(), 1); len(keys) != 0 {
		t.Fatal("key not removed")
	}
}
