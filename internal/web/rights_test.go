package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// sharedVault makes a shared vault managed by c and returns its id and key.
func sharedVault(t *testing.T, c *client, title string) (string, []byte) {
	t.Helper()
	vid := newUUID()
	vkey := vaultcrypto.Random(32)
	name, _ := vaultcrypto.Seal(vkey, []byte(title), vaultcrypto.AADVaultName(vid))
	self, _ := vaultcrypto.SealTo(c.keys.public, vkey, vaultcrypto.AADVaultKey(vid))
	c.must("POST", "/api/vaults", createVaultReq{ID: vid, Data: name, WrappedKey: self}, nil)
	return vid, vkey
}

// addMember lets manager m give email access to the vault.
func addMember(t *testing.T, m *client, vid string, vkey []byte, email, rights string, until *time.Time) int64 {
	t.Helper()
	id, pub := m.directoryKey(email)
	wk, _ := vaultcrypto.SealTo(pub, vkey, vaultcrypto.AADVaultKey(vid))
	m.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: id, WrappedKey: wk, Rights: rights, ExpiresAt: until}, nil)
	return id
}

// grantTemporary: u asks for rights for some hours, manager m approves.
func grantTemporary(t *testing.T, u, m *client, vid, rights string, hours int) {
	t.Helper()
	var made map[string]int64
	u.must("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: rights, Hours: hours, Reason: "test"}, &made)
	m.must("POST", "/api/requests/"+itoa(made["id"])+"/decide", decideReq{Approve: true}, nil)
}

// inviteAdmin makes a second administrator.
func (e *env) inviteAdmin(admin *client, email, pw string) *client {
	e.t.Helper()
	code, page := admin.form("/users/invite", url.Values{"email": {email}, "role": {"admin"}})
	if code != http.StatusOK || !strings.Contains(page, "/invite/") {
		e.t.Fatalf("invite admin: %d", code)
	}
	c := e.client()
	tok := page[strings.Index(page, "/invite/")+8:]
	tok = tok[:strings.IndexAny(tok, "<\"")]
	body := c.newAccount(email, pw)
	body["invite"] = tok
	c.must("POST", "/api/invite", body, nil)
	c.enroll()
	return c
}

func TestFourEyesBypasses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	second := e.inviteAdmin(admin, "second@example.com", "Second-Master-Password-1")
	e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	p := DefaultPolicy
	p.KDF, p.FourEyes = fastKDF, true
	_ = e.st.SetSetting(ctx, settingPolicy, p)
	carol, _ := e.st.UserByEmail(ctx, "carol@example.com")
	if code, _ := admin.form(fmt.Sprintf("/users/%d/delete", carol.ID), url.Values{"confirm": {"carol@example.com"}}); code != http.StatusSeeOther {
		t.Fatalf("held delete: %d", code)
	}
	list, _ := e.st.Approvals(ctx)
	target := list[0].ID
	// push the own request out of the list the page shows (100 entries)
	for i := 0; i < 100; i++ {
		admin.form("/settings/policy", url.Values{"lock_minutes": {"15"}, "clipboard_seconds": {"30"}, "min_password_length": {"12"}, "trash_days": {"30"},
			"max_file_mb": {"10"}, "storage_mb": {"500"}, "kdf_m": {"19"}, "kdf_t": {"2"}, "kdf_p": {"1"}, "four_eyes": {"1"}})
	}
	admin.form(fmt.Sprintf("/approvals/%d/approve", target), nil)
	if _, err := e.st.UserByEmail(ctx, "carol@example.com"); err != nil {
		t.Fatal("the requester approved the own request")
	}
	if _, err := e.st.TakeApproval(ctx, target, "ADMIN@example.com", "approved"); !errors.Is(err, store.ErrOwnApproval) {
		t.Fatalf("store: own approval: %v", err)
	}
	// an unknown decision does nothing
	admin.form(fmt.Sprintf("/approvals/%d/maybe", target), nil)
	if _, err := e.st.UserByEmail(ctx, "carol@example.com"); err != nil {
		t.Fatal("an unknown decision approved")
	}

	// taking the role from the other administrator or disabling them waits
	e.clock = e.clock.Add(time.Minute) // newer than the 100 above in the list
	sec, _ := e.st.UserByEmail(ctx, "second@example.com")
	path := fmt.Sprintf("/users/%d", sec.ID)
	if code, _ := admin.form(path, url.Values{"role": {"user"}}); code != http.StatusSeeOther {
		t.Fatalf("held demotion: %d", code)
	}
	if code, _ := admin.form(path, url.Values{"role": {"admin"}, "disabled": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("held disable: %d", code)
	}
	if u, _ := e.st.UserByEmail(ctx, "second@example.com"); u.Role != store.RoleAdmin || u.Disabled {
		t.Fatalf("changed without approval: %+v", u)
	}
	list, _ = e.st.Approvals(ctx)
	var demote int64
	for _, a := range list {
		if a.Action == "user.demote" && a.Status == "pending" {
			demote = a.ID
		}
	}
	if demote == 0 {
		t.Fatal("no held demotion")
	}
	// the other administrator approves it: done
	second.form(fmt.Sprintf("/approvals/%d/approve", demote), nil)
	if u, _ := e.st.UserByEmail(ctx, "second@example.com"); u.Role != store.RoleUser {
		t.Fatalf("not demoted after the approval: %s", u.Role)
	}
}

func TestOwnMembershipAndGroups(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	vid, vkey := sharedVault(t, admin, "Ops")
	gid, err := e.st.SaveGroup(ctx, 0, "Ops team", "")
	if err != nil {
		t.Fatal(err)
	}
	bobID, bobPub := admin.directoryKey("bob@example.com")
	if err := e.st.SetGroupMembers(ctx, gid, []int64{bobID}); err != nil {
		t.Fatal(err)
	}
	admin.must("PUT", "/api/vaults/"+vid+"/groups", vaultGroupReq{GroupID: gid, Rights: "view"}, nil)
	wk, _ := vaultcrypto.SealTo(bobPub, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, WrappedKey: wk, GroupID: &gid}, nil)
	// only managers (and administrators) see the groups
	if code, _ := bob.do("GET", "/api/groups", nil, nil); code != http.StatusForbidden {
		t.Fatalf("groups for a reader: %d", code)
	}
	grantTemporary(t, bob, admin, vid, "manage", 1)
	bob.must("GET", "/api/groups", nil, nil)
	// temporary rights cannot be made permanent by their holder
	if code, _ := bob.do("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, Rights: "manage"}, nil); code != http.StatusForbidden {
		t.Fatalf("own membership: %d", code)
	}
	if code, _ := bob.do("PUT", "/api/vaults/"+vid+"/groups", vaultGroupReq{GroupID: gid, Rights: "manage"}, nil); code != http.StatusForbidden {
		t.Fatalf("own group with temporary rights: %d", code)
	}
	if m := memberOf(t, admin, vid, "bob@example.com"); m.Rights != "manage" || m.BaseRights != "view" || m.RightsUntil == nil {
		t.Fatalf("bob after the refused changes %+v", m)
	}
	// a manager does not change their own membership either
	adminID, _ := admin.directoryKey("admin@example.com")
	if code, _ := admin.do("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: adminID, Rights: "view"}, nil); code != http.StatusForbidden {
		t.Fatalf("manager's own membership: %d", code)
	}
}

func TestPermanentManager(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	carol := e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	dave := e.inviteUser(admin, "dave@example.com", "Dave-Master-Password-44")
	vid, vkey := sharedVault(t, admin, "Ops")
	addMember(t, admin, vid, vkey, "bob@example.com", "view", nil)
	addMember(t, admin, vid, vkey, "carol@example.com", "view", nil)
	adminID, _ := admin.directoryKey("admin@example.com")
	// a temporary manager cannot remove the only permanent one
	grantTemporary(t, bob, admin, vid, "manage", 2)
	if code, _ := bob.do("DELETE", fmt.Sprintf("/api/vaults/%s/members/%d", vid, adminID), nil, nil); code != http.StatusConflict {
		t.Fatalf("removing the last permanent manager: %d", code)
	}
	// time-limited managers do not count
	until := e.clock.Add(48 * time.Hour)
	daveID := addMember(t, admin, vid, vkey, "dave@example.com", "manage", nil)
	dave.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: adminID, Rights: "manage", ExpiresAt: &until}, nil)
	if code, _ := admin.do("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: daveID, Rights: "manage", ExpiresAt: &until}, nil); code != http.StatusConflict {
		t.Fatalf("an end for the last permanent manager: %d", code)
	}
	if code, _ := admin.do("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: daveID, Rights: "edit"}, nil); code != http.StatusConflict {
		t.Fatalf("fewer rights for the last permanent manager: %d", code)
	}
	// others may leave, temporary managers too
	bobID, _ := admin.directoryKey("bob@example.com")
	carolID, _ := admin.directoryKey("carol@example.com")
	bob.must("DELETE", fmt.Sprintf("/api/vaults/%s/members/%d", vid, bobID), nil, nil)
	carol.must("DELETE", fmt.Sprintf("/api/vaults/%s/members/%d", vid, carolID), nil, nil)
	// the last permanent manager is neither deleted nor disabled
	code, page := admin.form(fmt.Sprintf("/users/%d/delete", daveID), url.Values{"confirm": {"dave@example.com"}})
	if code != http.StatusBadRequest || !strings.Contains(page, "last manager of a shared vault") {
		t.Fatalf("deleting the last manager: %d", code)
	}
	if code, _ := admin.form(fmt.Sprintf("/users/%d", daveID), url.Values{"role": {"user"}, "disabled": {"1"}}); code != http.StatusBadRequest {
		t.Fatalf("disabling the last manager: %d", code)
	}
	if u, err := e.st.UserByEmail(ctx, "dave@example.com"); err != nil || u.Disabled {
		t.Fatalf("dave %+v %v", u, err)
	}
	// once another member manages for good, it works
	addMember(t, dave, vid, vkey, "carol@example.com", "manage", nil)
	if code, _ := admin.form(fmt.Sprintf("/users/%d", daveID), url.Values{"role": {"user"}, "disabled": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("disabling a manager with a successor: %d", code)
	}
}

func TestAccessLogStaysWithVault(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	vid, vkey := sharedVault(t, admin, "Ops")
	addMember(t, admin, vid, vkey, "bob@example.com", "edit", nil)
	bob.sync(0)
	item := newUUID()
	var rev revResp
	bob.must("PUT", "/api/items/"+item, putItemReq{VaultID: vid, Data: bob.sealItem(vid, item, map[string]any{"name": "router"})}, &rev)
	admin.must("POST", "/api/items/"+item+"/access", accessReq{Action: "copy"}, nil)
	if code, _ := bob.do("GET", "/api/items/"+item+"/access", nil, nil); code != http.StatusForbidden {
		t.Fatalf("log for an editor: %d", code)
	}
	// moved to bob's own vault, where bob manages: the log stays behind
	pv := bob.personal()
	bob.must("POST", "/api/items/"+item+"/move", moveReq{VaultID: pv, Data: bob.sealItem(pv, item, map[string]any{"name": "router"}), Revision: rev.Revision}, nil)
	var log []store.AccessEntry
	bob.must("GET", "/api/items/"+item+"/access", nil, &log)
	if len(log) != 0 {
		t.Fatalf("the moved item shows the vault's log: %+v", log)
	}
}

func TestApprovalOnlyRaises(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	vid, vkey := sharedVault(t, admin, "Ops")
	bobID := addMember(t, admin, vid, vkey, "bob@example.com", "view", nil)
	var made map[string]int64
	bob.must("POST", "/api/requests", store.NewAccessRequest{VaultID: vid, Rights: "edit", Hours: 2, Reason: "migration"}, &made)
	// meanwhile bob became a manager for good
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, Rights: "manage"}, nil)
	var done store.AccessRequest
	admin.must("POST", "/api/requests/"+itoa(made["id"])+"/decide", decideReq{Approve: true}, &done)
	if done.Status != "approved" {
		t.Fatalf("decided %+v", done)
	}
	if m := memberOf(t, admin, vid, "bob@example.com"); m.Rights != "manage" || m.RightsUntil != nil || m.BaseRights != "" {
		t.Fatalf("an approval lowered the rights: %+v", m)
	}
}

func TestExactExpiry(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	carol := e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	vid, vkey := sharedVault(t, admin, "Ops")
	addMember(t, admin, vid, vkey, "bob@example.com", "view", nil)
	until := e.clock.Add(time.Hour)
	addMember(t, admin, vid, vkey, "carol@example.com", "view", &until)
	grantTemporary(t, bob, admin, vid, "edit", 1)
	bob.sync(0)
	item := newUUID()
	bob.must("PUT", "/api/items/"+item, putItemReq{VaultID: vid, Data: bob.sealItem(vid, item, map[string]any{"name": "a"})}, nil)
	// the times pass; the housekeeping has not run yet
	e.clock = e.clock.Add(2 * time.Hour)
	admin.login()
	bob.login()
	carol.login()
	other := newUUID()
	if code, _ := bob.do("PUT", "/api/items/"+other, putItemReq{VaultID: vid, Data: bob.sealItem(vid, other, map[string]any{"name": "b"})}, nil); code != http.StatusForbidden {
		t.Fatalf("writing after the temporary rights ended: %d", code)
	}
	for _, v := range bob.sync(0).Vaults {
		if v.ID == vid && v.Rights != "view" {
			t.Fatalf("bob's rights after the end: %s", v.Rights)
		}
	}
	if m := memberOf(t, admin, vid, "bob@example.com"); m.Rights != "view" || m.RightsUntil != nil {
		t.Fatalf("member list after the end %+v", m)
	}
	s := carol.sync(0)
	for _, v := range s.Vaults {
		if v.ID == vid {
			t.Fatal("carol still gets the vault after her access ended")
		}
	}
	for _, it := range s.Items {
		if it.VaultID == vid {
			t.Fatal("carol still gets items after her access ended")
		}
	}
	if code, _ := carol.do("GET", "/api/vaults/"+vid+"/members", nil, nil); code != http.StatusNotFound {
		t.Fatalf("members after the end: %d", code)
	}
}

func TestCSRFOnExtLink(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/ext/link", strings.NewReader(`{"device":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := admin.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site link with the session cookie: %d", resp.StatusCode)
	}
	// the same from the web vault works
	admin.must("POST", "/api/ext/link", map[string]string{"device": "x"}, nil)
}

func TestSendsCountTowardStorage(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin() // the test policy: files up to 1 MB, 2 MB per user
	data := sealedBlob(900 << 10)
	send := func() int {
		id := vaultcrypto.B64.EncodeToString(vaultcrypto.Random(16))
		code, _ := admin.do("POST", "/api/sends", createSendReq{ID: id, Data: b64Encode(data), MaxViews: 1, Hours: 1}, nil)
		return code
	}
	if a, b := send(), send(); a != http.StatusOK || b != http.StatusOK {
		t.Fatalf("two links: %d %d", a, b)
	}
	if code := send(); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a link beyond the storage: %d", code)
	}
	var st map[string]int64
	admin.must("GET", "/api/storage", nil, &st)
	if st["used"] != 2*(900<<10) {
		t.Fatalf("storage used %d", st["used"])
	}
}
