package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeIdP is a minimal OpenID Connect provider for the tests.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	nonce  string
	email  string
	groups []string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		claims := map[string]any{"iss": f.srv.URL, "aud": "passzit", "sub": "user-1", "email": f.email, "nonce": f.nonce, "groups": f.groups,
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
		f.mu.Unlock()
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		b, _ := json.Marshal(claims)
		obj, _ := sig.Sign(b)
		tok, _ := obj.CompactSerialize()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": tok, "expires_in": 300})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// raw makes a request with the client's cookies and returns the answer
// (redirects are not followed).
func (c *client) rawGet(path string) *http.Response {
	c.e.t.Helper()
	resp, err := c.hc.Get(c.e.ts.URL + path)
	if err != nil {
		c.e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// ssoSignIn goes through the identity provider and returns where the
// server sent the browser.
func (c *client) ssoSignIn(f *fakeIdP) string {
	c.e.t.Helper()
	resp := c.rawGet("/login/sso")
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), f.srv.URL+"/auth") {
		c.e.t.Fatalf("sso start went to %q", resp.Header.Get("Location"))
	}
	f.mu.Lock()
	f.nonce = loc.Query().Get("nonce")
	f.mu.Unlock()
	resp = c.rawGet("/login/sso/callback?state=" + url.QueryEscape(loc.Query().Get("state")) + "&code=abc")
	return resp.Header.Get("Location")
}

func TestCompanySignIn(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	gid, _ := e.st.SaveGroup(ctx, 0, "Ops", "")
	idp := newFakeIdP(t)
	c := SSOSettings{Protocol: "oidc", Label: "Company", Issuer: idp.srv.URL, ClientID: "passzit", ClientSecret: e.st.SealSecret("settings.sso.client", "secret"),
		Required: true, SyncGroups: true}
	if err := e.st.SetSetting(ctx, settingSSO, c); err != nil {
		t.Fatal(err)
	}
	// required: bob cannot sign in with the master password alone, the admin can
	fresh := func() *client {
		x := e.client()
		x.email, x.pw, x.totp = bob.email, bob.pw, bob.totp
		return x
	}
	b2 := fresh()
	a, _ := b2.authKey(b2.email, b2.pw)
	if code, body := b2.do("POST", "/api/login", map[string]string{"email": b2.email, "auth": a}, nil); code != http.StatusForbidden || !strings.Contains(body, "Company") {
		t.Fatalf("sign-in without the identity provider: %d %s", code, body)
	}
	admin.login()
	// the identity provider confirms bob; the master password finishes the sign-in
	idp.email, idp.groups = "bob@example.com", []string{"Ops", "Unknown"}
	if to := b2.ssoSignIn(idp); to != "/login?sso=bob%40example.com" {
		t.Fatalf("after the identity provider: %q", to)
	}
	var lr loginResp
	b2.must("POST", "/api/login", map[string]string{"email": b2.email, "auth": a}, &lr)
	if lr.Next != "done" {
		t.Fatalf("with single sign-on: %+v", lr)
	}
	if g, _ := e.st.Group(ctx, gid); len(g.Members) != 1 {
		t.Fatalf("group not synced: %+v", g)
	}
	// the confirmation is used up
	b3 := fresh()
	b3.hc.Jar = b2.hc.Jar
	if code, _ := b3.do("POST", "/api/login", map[string]string{"email": b3.email, "auth": a}, nil); code != http.StatusForbidden {
		t.Fatalf("confirmation used twice: %d", code)
	}
	// an address without an account is refused; a wrong state too
	idp.email = "mallory@example.com"
	if to := fresh().ssoSignIn(idp); to != "/login" {
		t.Fatalf("unknown address went to %q", to)
	}
	if resp := fresh().rawGet("/login/sso/callback?state=forged&code=abc"); resp.Header.Get("Location") != "/login" {
		t.Fatal("forged state accepted")
	}
	// with the own second factor required, the code still follows
	c.RequireTOTP = true
	_ = e.st.SetSetting(ctx, settingSSO, c)
	idp.email = "bob@example.com"
	b4 := fresh()
	b4.ssoSignIn(idp)
	b4.must("POST", "/api/login", map[string]string{"email": b4.email, "auth": a}, &lr)
	if lr.Next != "2fa" {
		t.Fatalf("second factor not asked: %+v", lr)
	}
	// LDAP: an unreachable directory stops users, not administrators
	_ = e.st.SetSetting(ctx, settingSSO, SSOSettings{})
	l := LDAPSettings{Enabled: true, URL: "ldaps://127.0.0.1:1", BindDN: "cn=x", BindPassword: e.st.SealSecret("settings.ldap.bind", "pw"), BaseDN: "dc=x", UserFilter: defaultUserFilter}
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
	_ = e.st.SetSetting(ctx, settingLDAP, l)
	if code, body := fresh().do("POST", "/api/login", map[string]string{"email": bob.email, "auth": a}, nil); code != http.StatusForbidden || !strings.Contains(body, "directory") {
		t.Fatalf("user with an unreachable directory: %d %s", code, body)
	}
	admin.login()
	for _, bad := range []LDAPSettings{
		{Enabled: true, URL: "ldap://dc", BindDN: "x", BindPassword: "y", BaseDN: "z", UserFilter: defaultUserFilter},
		{Enabled: true, URL: "ldaps://dc", BindDN: "x", BindPassword: "y", BaseDN: "z", UserFilter: "(mail=x)"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if len(groupNames([]string{"CN=Ops,OU=Groups,DC=example,DC=local", "Plain"})) != 2 || groupNames([]string{"CN=Ops,DC=x"})[0] != "Ops" {
		t.Error("group names from DNs")
	}
}
