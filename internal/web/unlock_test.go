package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
	"github.com/max-zit/passzit/internal/webauthn"
)

func TestUnlockKeys(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	enc := func(n int) string { return webauthn.B64.EncodeToString(vaultcrypto.Random(n)) }
	k := unlockKeyJSON{ID: enc(32), Name: "Office laptop", Salt: enc(32), Wrapped: enc(61)}

	// bad sizes are refused
	bad := k
	bad.Salt = enc(16)
	if code, _ := admin.do("POST", "/api/unlock-keys", bad, nil); code != http.StatusBadRequest {
		t.Fatalf("short salt: %d", code)
	}
	admin.must("POST", "/api/unlock-keys", k, nil)
	if code, _ := admin.do("POST", "/api/unlock-keys", k, nil); code != http.StatusConflict {
		t.Fatalf("same passkey twice: %d", code)
	}
	var list struct {
		Keys []unlockKeyJSON `json:"keys"`
	}
	admin.must("GET", "/api/unlock-keys", nil, &list)
	if len(list.Keys) != 1 || list.Keys[0] != k {
		t.Fatalf("list: %+v", list)
	}
	admin.must("POST", "/api/unlock-keys/"+k.ID+"/used", nil, nil)
	if code, _ := admin.do("POST", "/api/unlock-keys/nope/used", nil, nil); code != http.StatusNotFound {
		t.Fatalf("unknown passkey used: %d", code)
	}

	// extension sessions cannot read or add them
	a, _ := admin.authKey(admin.email, admin.pw)
	var lr extLoginResp
	if c := e.bearer("", "POST", "/api/ext/login", extLoginReq{Email: admin.email, Auth: a, Device: "Chrome on test"}, &lr); c != http.StatusOK {
		t.Fatalf("ext login: %d", c)
	}
	if c := e.bearer(lr.Token, "POST", "/api/ext/login/2fa", codeReq{Code: admin.code()}, &lr); c != http.StatusOK {
		t.Fatalf("ext 2fa: %d", c)
	}
	if c := e.bearer(lr.Token, "GET", "/api/unlock-keys", nil, nil); c != http.StatusForbidden {
		t.Fatalf("extension reads unlock keys: %d", c)
	}
	if c := e.bearer(lr.Token, "POST", "/api/unlock-keys", k, nil); c != http.StatusForbidden {
		t.Fatalf("extension adds unlock keys: %d", c)
	}

	// the account page lists it; removing it
	code, page := admin.get("/account")
	if code != http.StatusOK || !strings.Contains(page, "Office laptop") {
		t.Fatalf("account page: %d", code)
	}
	admin.form("/account/unlock/delete", map[string][]string{"id": {k.ID}})
	if keys, _ := e.st.UnlockKeys(t.Context(), 1); len(keys) != 0 {
		t.Fatal("unlock key not removed")
	}
	for _, a := range []string{"unlock.key.add", "unlock.key.use", "unlock.key.remove"} {
		if l, err := e.st.AuditEntries(t.Context(), store.AuditFilter{Query: a, Limit: 5}); err != nil || len(l) == 0 {
			t.Fatalf("audit %s missing", a)
		}
	}
}
