package web

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

func memberOf(t *testing.T, c *client, vid, email string) store.Member {
	t.Helper()
	var list struct {
		Members []store.Member `json:"members"`
	}
	c.must("GET", "/api/vaults/"+vid+"/members", nil, &list)
	for _, m := range list.Members {
		if m.Email == email {
			return m
		}
	}
	t.Fatalf("%s is not a member", email)
	return store.Member{}
}

func TestAccessRequests(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	carol := e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	vid := newUUID()
	vkey := vaultcrypto.Random(32)
	name, _ := vaultcrypto.Seal(vkey, []byte("Ops"), vaultcrypto.AADVaultName(vid))
	self, _ := vaultcrypto.SealTo(admin.keys.public, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("POST", "/api/vaults", createVaultReq{ID: vid, Data: name, WrappedKey: self}, nil)
	bobID, bobPub := admin.directoryKey("bob@example.com")
	wk, _ := vaultcrypto.SealTo(bobPub, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, WrappedKey: wk, Rights: "use"}, nil)

	// bob (use) asks for reading rights for 2 hours
	var made map[string]int64
	bob.must("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: "view", Hours: 2, Reason: "fix the backup"}, &made)
	if code, _ := bob.do("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: "edit", Hours: 2, Reason: "again"}, nil); code != http.StatusConflict {
		t.Fatalf("a second open request: %d", code)
	}
	if code, _ := bob.do("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: "view", Hours: 2}, nil); code != http.StatusBadRequest {
		t.Fatalf("a request without reason: %d", code)
	}
	if code, _ := carol.do("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: "view", Hours: 2, Reason: "x"}, nil); code != http.StatusNotFound {
		t.Fatalf("more rights in a vault carol is not in: %d", code)
	}
	id := made["id"]
	path := "/api/requests/" + itoa(id) + "/decide"
	if code, _ := bob.do("POST", path, decideReq{Approve: true}, nil); code != http.StatusForbidden {
		t.Fatalf("approving the own request: %d", code)
	}
	if code, _ := carol.do("POST", path, decideReq{Approve: true}, nil); code != http.StatusNotFound && code != http.StatusForbidden {
		t.Fatalf("approving as a stranger: %d", code)
	}
	var list []store.AccessRequest
	admin.must("GET", "/api/requests", nil, &list)
	if len(list) != 1 || !list[0].Decide || list[0].CurrentRights != "use" || list[0].Email != "bob@example.com" {
		t.Fatalf("manager's list %+v", list)
	}
	var carolList []store.AccessRequest
	carol.must("GET", "/api/requests", nil, &carolList)
	if len(carolList) != 0 {
		t.Fatalf("carol sees %d requests", len(carolList))
	}
	admin.must("POST", path, decideReq{Approve: true}, nil)
	m := memberOf(t, admin, vid, "bob@example.com")
	if m.Rights != "view" || m.BaseRights != "use" || m.RightsUntil == nil {
		t.Fatalf("after approval %+v", m)
	}
	if code, _ := admin.do("POST", path, decideReq{Approve: true}, nil); code != http.StatusConflict {
		t.Fatalf("deciding twice: %d", code)
	}
	// the rights come back by themselves
	e.clock = e.clock.Add(3 * time.Hour)
	admin.login()
	bob.login()
	carol.login()
	if n, err := e.st.ExpireRights(ctx); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if m := memberOf(t, admin, vid, "bob@example.com"); m.Rights != "use" || m.BaseRights != "" || m.RightsUntil != nil {
		t.Fatalf("after the end %+v", m)
	}

	// carol is in no vault: she asks the administrator, who gives the access
	adminID, _ := bob.directoryKey("admin@example.com")
	carol.must("POST", "/api/requests", store.NewAccessRequest{AskedID: adminID, Rights: "edit", Hours: 1, Reason: "new firewall"}, &made)
	cpath := "/api/requests/" + itoa(made["id"]) + "/decide"
	if code, _ := admin.do("POST", cpath, decideReq{Approve: true, VaultID: vid}, nil); code != http.StatusBadRequest {
		t.Fatalf("approving before giving the access: %d", code)
	}
	carolID, carolPub := admin.directoryKey("carol@example.com")
	cwk, _ := vaultcrypto.SealTo(carolPub, vkey, vaultcrypto.AADVaultKey(vid))
	until := e.clock.Add(time.Hour)
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: carolID, WrappedKey: cwk, Rights: "edit", ExpiresAt: &until}, nil)
	var done store.AccessRequest
	admin.must("POST", cpath, decideReq{Approve: true, VaultID: vid}, &done)
	if done.Status != "approved" || done.VaultID != vid || done.DecidedBy != "admin@example.com" {
		t.Fatalf("decided %+v", done)
	}
	carol.must("GET", "/api/requests", nil, &carolList)
	if len(carolList) != 1 || !carolList[0].Mine || carolList[0].Status != "approved" || carolList[0].PublicKey != "" {
		t.Fatalf("carol's own list %+v", carolList)
	}

	// withdrawing
	bob.must("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: "manage", Hours: 8, Reason: "holiday cover"}, &made)
	if code, _ := bob.do("DELETE", "/api/requests/"+itoa(made["id"]), nil, nil); code != http.StatusNoContent {
		t.Fatalf("withdraw: %d", code)
	}
	if code, _ := admin.do("POST", "/api/requests/"+itoa(made["id"])+"/decide", decideReq{Approve: true}, nil); code != http.StatusConflict {
		t.Fatalf("deciding a withdrawn request: %d", code)
	}

	// a manager who changes the rights by hand ends the temporary rights
	bob.must("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: "edit", Hours: 4, Reason: "migration"}, &made)
	admin.must("POST", "/api/requests/"+itoa(made["id"])+"/decide", decideReq{Approve: true}, nil)
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, Rights: "view"}, nil)
	e.clock = e.clock.Add(5 * time.Hour)
	admin.login()
	_, _ = e.st.ExpireRights(ctx)
	if m := memberOf(t, admin, vid, "bob@example.com"); m.Rights != "view" || m.RightsUntil != nil {
		t.Fatalf("hand-set rights %+v", m)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestAccessLogSource(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	vid := newUUID()
	vkey := vaultcrypto.Random(32)
	name, _ := vaultcrypto.Seal(vkey, []byte("Ops"), vaultcrypto.AADVaultName(vid))
	self, _ := vaultcrypto.SealTo(admin.keys.public, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("POST", "/api/vaults", createVaultReq{ID: vid, Data: name, WrappedKey: self}, nil)
	admin.sync(0)
	item := newUUID()
	admin.must("PUT", "/api/items/"+item, putItemReq{VaultID: vid, Data: admin.sealItem(vid, item, map[string]any{"name": "pve"})}, nil)
	// a web session is always "web", whatever it claims
	admin.must("POST", "/api/items/"+item+"/access", accessReq{Action: "changed", Via: "console"}, nil)
	if code, _ := admin.do("POST", "/api/items/"+item+"/access", accessReq{Action: "explode"}, nil); code != http.StatusNoContent {
		t.Fatalf("unknown action: %d", code)
	}
	var log []store.AccessEntry
	admin.must("GET", "/api/items/"+item+"/access", nil, &log)
	if len(log) != 1 || log[0].Via != "web" || log[0].Action != "changed" {
		t.Fatalf("log %+v", log)
	}
	// the policy tells clients how many former passwords to keep
	var acct accountResp
	admin.must("GET", "/api/account", nil, &acct)
	if acct.HistoryCount != 10 {
		t.Fatalf("history count %d", acct.HistoryCount)
	}
	for ua, want := range map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0": "Edge · Windows",
		"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0":                                                "Firefox · Linux",
		"curl/8": "",
	} {
		if got := browserOf(ua); got != want {
			t.Errorf("browserOf(%q) = %q, want %q", ua, got, want)
		}
	}
}
