package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/testdb"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

func TestMain(m *testing.M) { os.Exit(testdb.Main(m)) }

// fastKDF keeps the tests quick (the minimum the server accepts).
var fastKDF = vaultcrypto.KDF{Alg: "argon2id", M: 19 * 1024, T: 2, P: 1}

type env struct {
	t     *testing.T
	st    *store.Store
	srv   *Server
	ts    *httptest.Server
	clock time.Time
	ip    string // client address the server sees

	mu     sync.Mutex
	bodies []string // every request body sent to the server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.UseSecretKey(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(ctx, st, log)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, srv: srv, clock: time.Now(), ip: "127.0.0.1"}
	srv.SetClock(func() time.Time { return e.clock })
	srv.SetSetupToken("setup-token-123")
	if err := srv.store.SetSetting(ctx, settingPolicy, Policy{LockMinutes: 15, ClipboardSeconds: 30, KDF: fastKDF, MinPasswordLength: 12, TrashDays: 30}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	e.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = e.ip + ":40000"
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(e.ts.Close)
	return e
}

// tick moves the server clock to the next TOTP step.
func (e *env) tick() { e.clock = e.clock.Add(31 * time.Second) }

// client is a browser with its own cookies, using the Go reference crypto.
type client struct {
	e      *env
	hc     *http.Client
	email  string
	pw     string
	totp   string
	keys   struct{ account, private, public []byte }
	vaults map[string][]byte
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, hc: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		vaults: map[string][]byte{}}
}

func (c *client) do(method, path string, body any, out any) (int, string) {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		c.e.mu.Lock()
		c.e.bodies = append(c.e.bodies, string(b))
		c.e.mu.Unlock()
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", c.e.ts.URL)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.e.t.Fatalf("%s %s: %v: %s", method, path, err, raw)
		}
	}
	return resp.StatusCode, string(raw)
}

func (c *client) must(method, path string, body, out any) {
	c.e.t.Helper()
	if code, raw := c.do(method, path, body, out); code >= 300 {
		c.e.t.Fatalf("%s %s = %d: %s", method, path, code, raw)
	}
}

func (c *client) form(path string, vals url.Values) (int, string) {
	c.e.t.Helper()
	c.e.mu.Lock()
	c.e.bodies = append(c.e.bodies, vals.Encode())
	c.e.mu.Unlock()
	req, _ := http.NewRequest(http.MethodPost, c.e.ts.URL+path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", c.e.ts.URL)
	resp, err := c.hc.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func (c *client) get(path string) (int, string) {
	c.e.t.Helper()
	return c.do(http.MethodGet, path, nil, nil)
}

func b64(b []byte) string { return vaultcrypto.B64.EncodeToString(b) }

func mustB64(t *testing.T, s string) []byte {
	b, err := vaultcrypto.B64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newAccount makes the keys of a new account like the web vault does.
func (c *client) newAccount(email, pw string) map[string]any {
	t := c.e.t
	salt := vaultcrypto.Random(16)
	mk, err := vaultcrypto.MasterKey(pw, salt, fastKDF)
	if err != nil {
		t.Fatal(err)
	}
	wrap := vaultcrypto.Derive(mk, vaultcrypto.InfoWrap)
	acct := vaultcrypto.Random(32)
	pub, priv, err := vaultcrypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	vid := newUUID()
	vkey := vaultcrypto.Random(32)
	wa, _ := vaultcrypto.Seal(wrap, acct, vaultcrypto.AADAccountKey())
	wp, _ := vaultcrypto.Seal(acct, priv, vaultcrypto.AADPrivateKey())
	wv, _ := vaultcrypto.Seal(acct, vkey, vaultcrypto.AADVaultKey(vid))
	c.email, c.pw = email, pw
	c.keys.account, c.keys.private, c.keys.public = acct, priv, pub
	c.vaults[vid] = vkey
	return map[string]any{"email": email, "name": "Test", "kdf": fastKDF, "salt": b64(salt), "auth": b64(vaultcrypto.Derive(mk, vaultcrypto.InfoAuth)),
		"wrapped_account_key": wa, "public_key": b64(pub), "wrapped_private_key": wp, "vault": map[string]string{"id": vid, "wrapped_key": wv}}
}

func newUUID() string {
	b := vaultcrypto.Random(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// authKey derives the auth key of a password for an address (prelogin first).
func (c *client) authKey(email, pw string) (string, []byte) {
	var pre preloginResp
	c.must("POST", "/api/prelogin", map[string]string{"email": email}, &pre)
	mk, err := vaultcrypto.MasterKey(pw, mustB64(c.e.t, pre.Salt), pre.KDF)
	if err != nil {
		c.e.t.Fatal(err)
	}
	return b64(vaultcrypto.Derive(mk, vaultcrypto.InfoAuth)), vaultcrypto.Derive(mk, vaultcrypto.InfoWrap)
}

func (c *client) code() string {
	c.e.tick()
	step := c.e.clock.Unix() / 30
	code, err := auth.TOTPCode(c.totp, step)
	if err != nil {
		c.e.t.Fatal(err)
	}
	return code
}

// enroll finishes the mandatory authenticator setup.
func (c *client) enroll() []string {
	var en enrollResp
	c.must("GET", "/api/login/enroll", nil, &en)
	c.totp = en.Secret
	var done enrollDone
	c.must("POST", "/api/login/enroll", map[string]string{"code": c.code()}, &done)
	if done.Next != "done" || len(done.Codes) != 10 {
		c.e.t.Fatalf("enroll: %+v", done)
	}
	return done.Codes
}

// login signs in with the master password and the authenticator.
func (c *client) login() {
	t := c.e.t
	a, wrap := c.authKey(c.email, c.pw)
	var lr loginResp
	c.must("POST", "/api/login", map[string]string{"email": c.email, "auth": a}, &lr)
	if lr.Next == "2fa" {
		c.must("POST", "/api/login/2fa", map[string]string{"code": c.code()}, &lr)
	}
	if lr.Next != "done" {
		t.Fatalf("login: %+v", lr)
	}
	var acct accountResp
	c.must("GET", "/api/account", nil, &acct)
	k, err := vaultcrypto.Open(wrap, acct.WrappedAccountKey, vaultcrypto.AADAccountKey())
	if err != nil {
		t.Fatal("unlock:", err)
	}
	c.keys.account = k
}

func (c *client) sync(since int64) store.Sync {
	var s store.Sync
	c.must("GET", fmt.Sprintf("/api/sync?since=%d", since), nil, &s)
	for _, v := range s.Vaults {
		if v.Kind == "personal" {
			k, err := vaultcrypto.Open(c.keys.account, v.WrappedKey, vaultcrypto.AADVaultKey(v.ID))
			if err != nil {
				c.e.t.Fatal("vault key:", err)
			}
			c.vaults[v.ID] = k
		}
	}
	return s
}

func (c *client) personal() string {
	s := c.sync(0)
	for _, v := range s.Vaults {
		if v.Kind == "personal" {
			return v.ID
		}
	}
	c.e.t.Fatal("no personal vault")
	return ""
}

func (c *client) sealItem(vaultID, id string, data map[string]any) string {
	b, _ := json.Marshal(data)
	s, err := vaultcrypto.Seal(c.vaults[vaultID], b, vaultcrypto.AADItem(vaultID, id))
	if err != nil {
		c.e.t.Fatal(err)
	}
	return s
}

// setupAdmin runs the first-run setup with 2FA.
func (e *env) setupAdmin() *client {
	c := e.client()
	body := c.newAccount("admin@example.com", "Admin-Master-Password-1")
	body["token"] = "setup-token-123"
	var lr loginResp
	c.must("POST", "/api/setup", body, &lr)
	if lr.Next != "enroll" {
		e.t.Fatalf("setup next = %q", lr.Next)
	}
	c.enroll()
	return c
}

// ---- tests

func TestSetupLoginAndVault(t *testing.T) {
	e := newEnv(t)
	c := e.client()

	// wrong setup token
	body := c.newAccount("admin@example.com", "Admin-Master-Password-1")
	body["token"] = "wrong"
	if code, _ := c.do("POST", "/api/setup", body, nil); code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", code)
	}
	admin := e.setupAdmin()
	// a second setup is refused
	if code, _ := c.do("POST", "/api/setup", body, nil); code != http.StatusConflict {
		t.Fatalf("second setup: %d", code)
	}
	// pages need a full session
	if code, _ := c.get("/vault"); code != http.StatusSeeOther {
		t.Fatalf("vault without session: %d", code)
	}
	if code, _ := c.get("/api/sync"); code != http.StatusUnauthorized {
		t.Fatalf("api without session: %d", code)
	}

	// sign in again in a fresh browser with the second factor
	b := e.client()
	b.email, b.pw, b.totp = admin.email, admin.pw, admin.totp
	b.login()
	vid := b.personal()

	// create an item; the plaintext never reaches the server
	id := newUUID()
	secret := map[string]any{"type": "login", "name": "Example Bank", "login": map[string]any{"username": "alice-in-wonder", "password": "Tr0ub4dor&3-xyzzy", "urls": []string{"https://bank.example.org"}}, "notes": "PIN is 4711"}
	var rev revResp
	b.must("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: b.sealItem(vid, id, secret)}, &rev)
	// creating it again (revision 0) conflicts
	if code, _ := b.do("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: b.sealItem(vid, id, secret)}, nil); code != http.StatusConflict {
		t.Fatalf("duplicate create: %d", code)
	}
	// a change based on an old revision conflicts
	secret["name"] = "Example Bank 2"
	var rev2 revResp
	b.must("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: b.sealItem(vid, id, secret), Revision: rev.Revision}, &rev2)
	if code, _ := b.do("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: b.sealItem(vid, id, secret), Revision: rev.Revision}, nil); code != http.StatusConflict {
		t.Fatalf("stale change: %d", code)
	}
	// a sealed item for another id cannot be moved (AAD binds vault and id)
	s := b.sync(0)
	if len(s.Items) != 1 {
		t.Fatalf("items = %d", len(s.Items))
	}
	if _, err := vaultcrypto.Open(b.vaults[vid], s.Items[0].Data, vaultcrypto.AADItem(vid, newUUID())); err == nil {
		t.Fatal("item opened under another id")
	}
	plain, err := vaultcrypto.Open(b.vaults[vid], s.Items[0].Data, vaultcrypto.AADItem(vid, id))
	if err != nil || !strings.Contains(string(plain), "Example Bank 2") {
		t.Fatalf("decrypt: %s %v", plain, err)
	}
	// incremental sync sees only newer changes
	if d := b.sync(rev2.Revision); len(d.Items) != 0 {
		t.Fatalf("incremental: %d items", len(d.Items))
	}
	// folders, trash, restore, purge
	fid := newUUID()
	fdata, _ := vaultcrypto.Seal(b.keys.account, []byte("Banking"), vaultcrypto.AADFolder(fid))
	b.must("PUT", "/api/folders/"+fid, putFolderReq{Data: fdata}, &rev)
	b.must("POST", "/api/items/"+id+"/trash", nil, &rev)
	if code, _ := b.do("DELETE", "/api/items/"+id, nil, nil); code != http.StatusOK {
		t.Fatalf("purge from trash: %d", code)
	}
	if d := b.sync(rev.Revision); len(d.Removed) != 1 || d.Removed[0] != id {
		t.Fatalf("removed = %v", d.Removed)
	}
	if code, _ := b.do("POST", "/api/items/"+id+"/restore", nil, nil); code != http.StatusNotFound {
		t.Fatalf("restore purged: %d", code)
	}
	b.must("DELETE", "/api/folders/"+fid, nil, &rev)
	var r struct{ Revision int64 }
	b.must("GET", "/api/revision", nil, &r)
	if r.Revision < rev.Revision {
		t.Fatalf("revision %d < %d", r.Revision, rev.Revision)
	}

	// Nothing secret was ever sent: no password, no item text, no folder name.
	e.mu.Lock()
	all := strings.Join(e.bodies, "\n")
	e.mu.Unlock()
	for _, w := range []string{"Admin-Master-Password-1", "Example Bank", "alice-in-wonder", "Tr0ub4dor", "bank.example.org", "4711", "Banking"} {
		if strings.Contains(all, w) {
			t.Errorf("the server received %q in plain text", w)
		}
	}
}

func TestInvitesAndIsolation(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	// only admins invite
	code, page := admin.form("/users/invite", url.Values{"email": {"bob@example.com"}, "role": {"user"}})
	if code != http.StatusOK {
		t.Fatalf("invite: %d", code)
	}
	m := regexp.MustCompile(`/invite/(pzi_[A-Za-z0-9_-]+)`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no invitation link on the page")
	}
	tok := m[1]
	bob := e.client()
	if code, _ := bob.get("/invite/" + tok); code != http.StatusOK {
		t.Fatalf("invite page: %d", code)
	}
	body := bob.newAccount("mallory@example.com", "Bob-Master-Password-22")
	body["invite"] = tok
	if code, _ := bob.do("POST", "/api/invite", body, nil); code != http.StatusBadRequest {
		t.Fatalf("other address: %d", code)
	}
	body = bob.newAccount("bob@example.com", "Bob-Master-Password-22")
	body["invite"] = tok
	var lr loginResp
	bob.must("POST", "/api/invite", body, &lr)
	bob.enroll()
	// the link works once
	eve := e.client()
	body2 := eve.newAccount("bob@example.com", "Eve-Master-Password-333")
	body2["invite"] = tok
	if code, _ := eve.do("POST", "/api/invite", body2, nil); code != http.StatusNotFound {
		t.Fatalf("reused invitation: %d", code)
	}
	// users are not administrators
	if code, _ := bob.get("/users"); code != http.StatusForbidden {
		t.Fatalf("user list as user: %d", code)
	}
	// admin's item cannot be touched by bob
	avid := admin.personal()
	id := newUUID()
	admin.must("PUT", "/api/items/"+id, putItemReq{VaultID: avid, Data: admin.sealItem(avid, id, map[string]any{"name": "x"})}, nil)
	if code, _ := bob.do("PUT", "/api/items/"+newUUID(), putItemReq{VaultID: avid, Data: admin.sealItem(avid, id, map[string]any{"name": "y"})}, nil); code != http.StatusForbidden {
		t.Fatalf("write into another vault: %d", code)
	}
	if code, _ := bob.do("POST", "/api/items/"+id+"/trash", nil, nil); code != http.StatusNotFound {
		t.Fatalf("trash another user's item: %d", code)
	}
	if s := bob.sync(0); len(s.Items) != 0 || len(s.Vaults) != 1 {
		t.Fatalf("bob sees %d items in %d vaults", len(s.Items), len(s.Vaults))
	}
	// deleting bob needs his address typed
	u, _ := e.st.UserByEmail(context.Background(), "bob@example.com")
	if code, _ := admin.form(fmt.Sprintf("/users/%d/delete", u.ID), url.Values{"confirm": {"nope"}}); code != http.StatusBadRequest {
		t.Fatalf("delete without confirmation: %d", code)
	}
	if code, _ := admin.form(fmt.Sprintf("/users/%d/delete", u.ID), url.Values{"confirm": {"bob@example.com"}}); code != http.StatusSeeOther {
		t.Fatalf("delete: %d", code)
	}
	if _, err := e.st.UserByEmail(context.Background(), "bob@example.com"); err != store.ErrNotFound {
		t.Fatal("bob still exists")
	}
}

func TestSignInProtection(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	c := e.client()
	// prelogin: unknown addresses get stable, address-bound fake salts
	var a1, a2, b1 preloginResp
	c.must("POST", "/api/prelogin", map[string]string{"email": "ghost@example.com"}, &a1)
	c.must("POST", "/api/prelogin", map[string]string{"email": "Ghost@Example.com"}, &a2)
	c.must("POST", "/api/prelogin", map[string]string{"email": "other@example.com"}, &b1)
	if a1.Salt != a2.Salt || a1.Salt == b1.Salt || B64LenOK(a1.Salt) != 16 {
		t.Fatalf("fake salts %q %q %q", a1.Salt, a2.Salt, b1.Salt)
	}
	// wrong master password from a LAN address: blocked after 5 tries
	right, _ := c.authKey(admin.email, admin.pw)
	e.ip = "10.1.2.3"
	wrong := b64(vaultcrypto.Random(32))
	for i := 0; i < 5; i++ {
		if code, _ := c.do("POST", "/api/login", map[string]string{"email": admin.email, "auth": wrong}, nil); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, _ := c.do("POST", "/api/login", map[string]string{"email": admin.email, "auth": right}, nil); code != http.StatusTooManyRequests {
		t.Fatalf("blocked address: %d", code)
	}
	e.ip = "127.0.0.1"
	// wrong second factor; a used code does not work twice
	var lr loginResp
	c.must("POST", "/api/login", map[string]string{"email": admin.email, "auth": right}, &lr)
	if code, _ := c.do("POST", "/api/login/2fa", map[string]string{"code": "000000"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", code)
	}
	c.totp = admin.totp
	code1 := c.code()
	c.must("POST", "/api/login/2fa", map[string]string{"code": code1}, &lr)
	d := e.client()
	d.must("POST", "/api/login", map[string]string{"email": admin.email, "auth": right}, &lr)
	if code, _ := d.do("POST", "/api/login/2fa", map[string]string{"code": code1}, nil); code != http.StatusUnauthorized {
		t.Fatalf("replayed code: %d", code)
	}
	// cross-site requests and headers
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/session/lock", nil)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site POST: %d", resp.StatusCode)
	}
	resp, err = c.hc.Get(e.ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self' 'wasm-unsafe-eval'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP %q", csp)
	}
	// the audit chain is intact
	chk, err := e.st.VerifyAudit(context.Background())
	if err != nil || !chk.OK {
		t.Fatalf("audit: %+v %v", chk, err)
	}
}

// B64LenOK is store.B64Len (shorter name in the test).
func B64LenOK(s string) int { return store.B64Len(s) }

func TestRecoveryAndPasswordChange(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	ctx := context.Background()
	curAuth, _ := admin.authKey(admin.email, admin.pw)

	// recovery key
	rk := vaultcrypto.NewRecoveryKey()
	raw, _ := vaultcrypto.ParseRecoveryKey(rk)
	ra := b64(vaultcrypto.Derive(raw, vaultcrypto.InfoRecoveryAuth))
	rw, _ := vaultcrypto.Seal(vaultcrypto.Derive(raw, vaultcrypto.InfoRecoveryWrap), admin.keys.account, vaultcrypto.AADAccountKey())
	if code, _ := admin.do("POST", "/api/account/recovery", recoveryReq{CurrentAuth: b64(vaultcrypto.Random(32)), RecoveryAuth: ra, RecoveryWrappedKey: rw}, nil); code != http.StatusForbidden {
		t.Fatalf("recovery key without the master password: %d", code)
	}
	admin.must("POST", "/api/account/recovery", recoveryReq{CurrentAuth: curAuth, RecoveryAuth: ra, RecoveryWrappedKey: rw}, nil)

	// change the master password
	newPw := "Changed-Master-Password-2"
	salt := vaultcrypto.Random(16)
	mk, _ := vaultcrypto.MasterKey(newPw, salt, fastKDF)
	wa, _ := vaultcrypto.Seal(vaultcrypto.Derive(mk, vaultcrypto.InfoWrap), admin.keys.account, vaultcrypto.AADAccountKey())
	keys := store.Keys{KDF: fastKDF, Salt: b64(salt), Auth: b64(vaultcrypto.Derive(mk, vaultcrypto.InfoAuth)), WrappedAccountKey: wa}
	admin.must("POST", "/api/account/password", changePasswordReq{CurrentAuth: curAuth, Keys: keys}, nil)
	admin.pw = newPw
	other := e.client()
	other.email, other.pw, other.totp = admin.email, newPw, admin.totp
	other.login()

	// forget it, recover with the recovery key and the second factor
	r := e.client()
	r.totp = admin.totp
	if code, _ := r.do("POST", "/api/recover/start", recoverStartReq{Email: admin.email, RecoveryAuth: b64(vaultcrypto.Random(32)), Code: r.code()}, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong recovery key: %d", code)
	}
	var st recoverStartResp
	r.must("POST", "/api/recover/start", recoverStartReq{Email: admin.email, RecoveryAuth: ra, Code: r.code()}, &st)
	ak, err := vaultcrypto.Open(vaultcrypto.Derive(raw, vaultcrypto.InfoRecoveryWrap), st.RecoveryWrappedKey, vaultcrypto.AADAccountKey())
	if err != nil {
		t.Fatal(err)
	}
	pw3 := "Recovered-Master-Password-3"
	salt3 := vaultcrypto.Random(16)
	mk3, _ := vaultcrypto.MasterKey(pw3, salt3, fastKDF)
	wa3, _ := vaultcrypto.Seal(vaultcrypto.Derive(mk3, vaultcrypto.InfoWrap), ak, vaultcrypto.AADAccountKey())
	r.must("POST", "/api/recover/finish", recoverFinishReq{Ticket: st.Ticket, Keys: store.Keys{KDF: fastKDF, Salt: b64(salt3), Auth: b64(vaultcrypto.Derive(mk3, vaultcrypto.InfoAuth)), WrappedAccountKey: wa3}}, nil)
	if code, _ := r.do("POST", "/api/recover/finish", recoverFinishReq{Ticket: st.Ticket, Keys: store.Keys{KDF: fastKDF, Salt: b64(salt3), Auth: b64(vaultcrypto.Derive(mk3, vaultcrypto.InfoAuth)), WrappedAccountKey: wa3}}, nil); code != http.StatusUnauthorized {
		t.Fatalf("ticket reused: %d", code)
	}
	// all sessions ended; the new password opens the same account key
	if code, _ := other.get("/api/sync"); code != http.StatusUnauthorized {
		t.Fatalf("old session after recovery: %d", code)
	}
	n := e.client()
	n.email, n.pw, n.totp = admin.email, pw3, admin.totp
	n.login()
	if !bytes.Equal(n.keys.account, admin.keys.account) {
		t.Fatal("the account key changed")
	}
	u, _ := e.st.UserByEmail(ctx, admin.email)
	if !u.HasRecovery {
		t.Fatal("recovery key lost")
	}
}

func TestPagesRender(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	if code, _ := c.get("/setup"); code != http.StatusOK {
		t.Fatalf("setup page: %d", code)
	}
	admin := e.setupAdmin()
	pages := []string{"/vault", "/generator", "/account", "/users", "/users/1", "/audit", "/settings/policy", "/settings/security", "/settings/network", "/docs"}
	for _, p := range DocPages {
		pages = append(pages, "/docs/"+p.Slug)
	}
	pages = append(pages, "/docs/search?q=master")
	for _, l := range Languages {
		admin.form("/lang", url.Values{"lang": {l.Code}})
		for _, p := range pages {
			code, body := admin.get(p)
			if code != http.StatusOK {
				t.Fatalf("%s %s: %d %s", l.Code, p, code, body)
			}
			if !strings.Contains(body, `lang="`+l.Code+`"`) {
				t.Fatalf("%s %s: wrong language", l.Code, p)
			}
		}
		if code, _ := admin.get("/i18n/" + l.Code + ".json"); code != http.StatusOK {
			t.Fatalf("i18n %s: %d", l.Code, code)
		}
	}
	if code, _ := admin.get("/login"); code != http.StatusOK {
		t.Fatalf("login page: %d", code)
	}
	if code, _ := admin.get("/recover"); code != http.StatusOK {
		t.Fatalf("recover page: %d", code)
	}
	if code, _ := admin.get("/invite/pzi_nope"); code != http.StatusNotFound {
		t.Fatalf("bad invitation page: %d", code)
	}
}

func TestPolicyAndPrefs(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	code, _ := admin.form("/settings/policy", url.Values{"lock_minutes": {"10"}, "clipboard_seconds": {"20"}, "min_password_length": {"14"}, "trash_days": {"7"},
		"kdf_m": {"8"}, "kdf_t": {"3"}, "kdf_p": {"4"}})
	if code != http.StatusBadRequest {
		t.Fatalf("too weak key derivation accepted: %d", code)
	}
	if code, _ := admin.form("/settings/policy", url.Values{"lock_minutes": {"10"}, "clipboard_seconds": {"20"}, "min_password_length": {"14"}, "trash_days": {"7"},
		"kdf_m": {"32"}, "kdf_t": {"3"}, "kdf_p": {"2"}}); code != http.StatusSeeOther {
		t.Fatalf("policy: %d", code)
	}
	// a user may choose shorter times, not longer ones
	if code, _ := admin.form("/account/profile", url.Values{"lock_minutes": {"30"}}); code != http.StatusBadRequest {
		t.Fatalf("longer lock accepted: %d", code)
	}
	admin.form("/account/profile", url.Values{"lock_minutes": {"5"}})
	var a accountResp
	admin.must("GET", "/api/account", nil, &a)
	if a.LockMinutes != 5 || a.ClipboardSeconds != 20 || a.PolicyKDF.M != 32*1024 || a.MinLength != 14 {
		t.Fatalf("account policy %+v", a)
	}
	// the key-derivation upgrade accepts only the policy's settings
	cur, _ := admin.authKey(admin.email, admin.pw)
	salt := vaultcrypto.Random(16)
	mk, _ := vaultcrypto.MasterKey(admin.pw, salt, a.PolicyKDF)
	wa, _ := vaultcrypto.Seal(vaultcrypto.Derive(mk, vaultcrypto.InfoWrap), admin.keys.account, vaultcrypto.AADAccountKey())
	k := store.Keys{KDF: a.PolicyKDF, Salt: b64(salt), Auth: b64(vaultcrypto.Derive(mk, vaultcrypto.InfoAuth)), WrappedAccountKey: wa}
	weak := k
	weak.KDF = fastKDF
	if code, _ := admin.do("POST", "/api/account/kdf", changePasswordReq{CurrentAuth: cur, Keys: weak}, nil); code != http.StatusBadRequest {
		t.Fatalf("weaker upgrade: %d", code)
	}
	admin.must("POST", "/api/account/kdf", changePasswordReq{CurrentAuth: cur, Keys: k}, nil)
	var pre preloginResp
	admin.must("POST", "/api/prelogin", map[string]string{"email": admin.email}, &pre)
	if pre.KDF != a.PolicyKDF {
		t.Fatalf("kdf after upgrade %+v", pre.KDF)
	}
}

func TestDevNo2FA(t *testing.T) {
	e := newEnv(t)
	e.srv.DevNo2FA = true
	c := e.client()
	body := c.newAccount("admin@example.com", "Admin-Master-Password-1")
	body["token"] = "setup-token-123"
	var lr loginResp
	c.must("POST", "/api/setup", body, &lr)
	if lr.Next != "done" {
		t.Fatalf("next = %q", lr.Next)
	}
	if code, _ := c.get("/api/sync"); code != http.StatusOK {
		t.Fatalf("sync: %d", code)
	}
	if _, page := c.get("/vault"); !strings.Contains(page, "two-factor sign-in is switched off") {
		t.Fatal("no test-mode warning")
	}
}
