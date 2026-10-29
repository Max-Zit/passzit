package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

func sealedBlob(n int) []byte {
	b := vaultcrypto.Random(n)
	b[0] = 1
	return b
}

func TestSecretLinks(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	data := sealedBlob(200)
	id := vaultcrypto.B64.EncodeToString(vaultcrypto.Random(16))
	admin.must("POST", "/api/sends", createSendReq{ID: id, Data: b64Encode(data), MaxViews: 2, Hours: 24}, nil)
	var list []store.Send
	admin.must("GET", "/api/sends", nil, &list)
	if len(list) != 1 || list[0].Size != 200 || list[0].Protected {
		t.Fatalf("links %+v", list)
	}
	// a recipient without an account
	anon := e.client()
	if code, page := anon.get("/send/" + id); code != http.StatusOK || !strings.Contains(page, "send.js") {
		t.Fatalf("link page: %d", code)
	}
	var st map[string]bool
	anon.must("GET", "/api/send/"+id, nil, &st)
	if st["protected"] {
		t.Fatal("unprotected link reported as protected")
	}
	var got struct {
		Data string `json:"data"`
		Left int    `json:"left"`
	}
	anon.must("POST", "/api/send/"+id+"/open", openSendReq{}, &got)
	if raw, _ := b64Decode(got.Data); !bytes.Equal(raw, data) || got.Left != 1 {
		t.Fatalf("first opening: left %d", got.Left)
	}
	anon.must("POST", "/api/send/"+id+"/open", openSendReq{}, &got)
	if code, _ := anon.do("POST", "/api/send/"+id+"/open", openSendReq{}, nil); code != http.StatusGone {
		t.Fatalf("third opening of a two-time link: %d", code)
	}
	if code, _ := anon.do("GET", "/api/send/"+id, nil, nil); code != http.StatusGone {
		t.Fatalf("state of a used link: %d", code)
	}
	// with a password: the server checks the derived value
	pid := vaultcrypto.B64.EncodeToString(vaultcrypto.Random(16))
	good := vaultcrypto.B64.EncodeToString(vaultcrypto.Random(32))
	admin.must("POST", "/api/sends", createSendReq{ID: pid, Data: b64Encode(data), Auth: good, MaxViews: 1, Hours: 1}, nil)
	anon.must("GET", "/api/send/"+pid, nil, &st)
	if !st["protected"] {
		t.Fatal("protected link not reported")
	}
	if code, _ := anon.do("POST", "/api/send/"+pid+"/open", openSendReq{Auth: vaultcrypto.B64.EncodeToString(vaultcrypto.Random(32))}, nil); code != http.StatusForbidden {
		t.Fatalf("wrong password: %d", code)
	}
	anon.must("POST", "/api/send/"+pid+"/open", openSendReq{Auth: good}, &got)
	if raw, _ := b64Decode(got.Data); !bytes.Equal(raw, data) {
		t.Fatal("protected content differs")
	}
	// expiry, deletion, limits, policy
	xid := vaultcrypto.B64.EncodeToString(vaultcrypto.Random(16))
	admin.must("POST", "/api/sends", createSendReq{ID: xid, Data: b64Encode(data), MaxViews: 5, Hours: 1}, nil)
	e.clock = e.clock.Add(2 * time.Hour)
	if code, _ := anon.do("POST", "/api/send/"+xid+"/open", openSendReq{}, nil); code != http.StatusGone {
		t.Fatalf("expired link: %d", code)
	}
	e.clock = e.clock.Add(-2 * time.Hour)
	if code, _ := admin.do("POST", "/api/sends", createSendReq{ID: "short", Data: b64Encode(data), MaxViews: 1, Hours: 1}, nil); code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", code)
	}
	if code, _ := admin.do("POST", "/api/sends", createSendReq{ID: vaultcrypto.B64.EncodeToString(vaultcrypto.Random(16)), Data: b64Encode(data), MaxViews: 1, Hours: 31 * 24}, nil); code != http.StatusBadRequest {
		t.Fatalf("too long: %d", code)
	}
	admin.must("DELETE", "/api/sends/"+xid, nil, nil)
	p := DefaultPolicy
	p.KDF, p.NoSends = fastKDF, true
	_ = e.st.SetSetting(context.Background(), settingPolicy, p)
	if code, _ := admin.do("POST", "/api/sends", createSendReq{ID: vaultcrypto.B64.EncodeToString(vaultcrypto.Random(16)), Data: b64Encode(data), MaxViews: 1, Hours: 1}, nil); code != http.StatusForbidden {
		t.Fatalf("links against the policy: %d", code)
	}
}

func TestEmergencyAccess(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	pv := admin.personal()
	item := newUUID()
	admin.must("PUT", "/api/items/"+item, putItemReq{VaultID: pv, Data: admin.sealItem(pv, item, map[string]any{"name": "bank", "password": "in-case-of-emergency"})}, nil)
	bobID, bobPub := admin.directoryKey("bob@example.com")
	aad := "passzit/emergency/v1|admin@example.com|bob@example.com"
	sealed, _ := vaultcrypto.SealTo(bobPub, admin.keys.account, aad)
	admin.must("POST", "/api/emergency", addEmergencyReq{GranteeID: bobID, SealedKey: sealed, WaitDays: 2}, nil)
	var lists struct {
		Contacts []store.Emergency `json:"contacts"`
		Grants   []store.Emergency `json:"grants"`
	}
	bob.must("GET", "/api/emergency", nil, &lists)
	if len(lists.Grants) != 1 || lists.Grants[0].Grantor != "admin@example.com" {
		t.Fatalf("bob's grants %+v", lists.Grants)
	}
	id := lists.Grants[0].ID
	// nothing before a request and the waiting time
	if code, _ := bob.do("GET", fmt.Sprintf("/api/emergency/%d/vault", id), nil, nil); code != http.StatusForbidden {
		t.Fatalf("vault before a request: %d", code)
	}
	bob.must("POST", fmt.Sprintf("/api/emergency/%d/request", id), nil, nil)
	if code, _ := bob.do("GET", fmt.Sprintf("/api/emergency/%d/vault", id), nil, nil); code != http.StatusForbidden {
		t.Fatalf("vault during the waiting time: %d", code)
	}
	// the grantor rejects; bob asks again; the waiting time passes
	admin.must("POST", fmt.Sprintf("/api/emergency/%d/reject", id), nil, nil)
	bob.must("POST", fmt.Sprintf("/api/emergency/%d/request", id), nil, nil)
	if code, _ := bob.do("POST", fmt.Sprintf("/api/emergency/%d/approve", id), nil, nil); code != http.StatusNotFound {
		t.Fatalf("grantee approved himself: %d", code)
	}
	e.clock = e.clock.Add(49 * time.Hour)
	bob.login()
	var v store.EmergencyVault
	bob.must("GET", fmt.Sprintf("/api/emergency/%d/vault", id), nil, &v)
	ak, err := vaultcrypto.OpenSealed(bob.keys.private, v.SealedKey, aad)
	if err != nil {
		t.Fatal("sealed account key:", err)
	}
	vk, err := vaultcrypto.Open(ak, v.WrappedKey, vaultcrypto.AADVaultKey(v.VaultID))
	if err != nil || len(v.Items) != 1 {
		t.Fatalf("vault key: %v, %d items", err, len(v.Items))
	}
	if p, err := vaultcrypto.Open(vk, v.Items[0].Data, vaultcrypto.AADItem(v.VaultID, v.Items[0].ID)); err != nil || !strings.Contains(string(p), "in-case-of-emergency") {
		t.Fatalf("item: %v", err)
	}
	// strangers get nothing; removal ends it
	admin.login()
	carol := e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	if code, _ := carol.do("GET", fmt.Sprintf("/api/emergency/%d/vault", id), nil, nil); code != http.StatusNotFound {
		t.Fatalf("stranger: %d", code)
	}
	admin.must("DELETE", fmt.Sprintf("/api/emergency/%d", id), nil, nil)
	if code, _ := bob.do("GET", fmt.Sprintf("/api/emergency/%d/vault", id), nil, nil); code != http.StatusNotFound {
		t.Fatalf("after removal: %d", code)
	}
}

func TestItemAccessLog(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	vid := newUUID()
	vkey := vaultcrypto.Random(32)
	name, _ := vaultcrypto.Seal(vkey, []byte("Ops"), vaultcrypto.AADVaultName(vid))
	self, _ := vaultcrypto.SealTo(admin.keys.public, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("POST", "/api/vaults", createVaultReq{ID: vid, Data: name, WrappedKey: self}, nil)
	admin.sync(0)
	item := newUUID()
	admin.must("PUT", "/api/items/"+item, putItemReq{VaultID: vid, Data: admin.sealItem(vid, item, map[string]any{"name": "router"})}, nil)
	bobID, bobPub := admin.directoryKey("bob@example.com")
	wk, _ := vaultcrypto.SealTo(bobPub, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, WrappedKey: wk, Rights: "use"}, nil)
	if code, _ := bob.do("POST", "/api/items/"+item+"/access", accessReq{Action: "copy"}, nil); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	bob.do("POST", "/api/items/"+item+"/access", accessReq{Action: "fill"}, nil)
	var log []store.AccessEntry
	admin.must("GET", "/api/items/"+item+"/access", nil, &log)
	if len(log) != 2 || log[0].Email != "bob@example.com" {
		t.Fatalf("log %+v", log)
	}
	if code, _ := bob.do("GET", "/api/items/"+item+"/access", nil, nil); code != http.StatusForbidden {
		t.Fatalf("log for a non-manager: %d", code)
	}
	// personal items are not logged; reports for foreign items do nothing
	pv := admin.personal()
	pitem := newUUID()
	admin.must("PUT", "/api/items/"+pitem, putItemReq{VaultID: pv, Data: admin.sealItem(pv, pitem, map[string]any{"name": "x"})}, nil)
	bob.do("POST", "/api/items/"+pitem+"/access", accessReq{Action: "copy"}, nil)
	admin.do("POST", "/api/items/"+pitem+"/access", accessReq{Action: "copy"}, nil)
	var n int
	_ = e.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM item_access WHERE item_id=$1`, pitem).Scan(&n)
	if n != 0 {
		t.Fatalf("personal item logged %d times", n)
	}
}

func TestFourEyes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	// a second administrator (before the rule is on)
	code, page := admin.form("/users/invite", url.Values{"email": {"second@example.com"}, "role": {"admin"}})
	if code != http.StatusOK || !strings.Contains(page, "/invite/") {
		t.Fatalf("invite admin: %d", code)
	}
	second := e.client()
	tok := page[strings.Index(page, "/invite/")+8:]
	tok = tok[:strings.IndexAny(tok, "<\"")]
	body := second.newAccount("second@example.com", "Second-Master-Password-1")
	body["invite"] = tok
	second.must("POST", "/api/invite", body, nil)
	second.enroll()
	carol := e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	_ = carol
	p := DefaultPolicy
	p.KDF, p.FourEyes = fastKDF, true
	_ = e.st.SetSetting(ctx, settingPolicy, p)
	u, _ := e.st.UserByEmail(ctx, "carol@example.com")
	// the delete waits
	if code, _ := admin.form(fmt.Sprintf("/users/%d/delete", u.ID), url.Values{"confirm": {"carol@example.com"}}); code != http.StatusSeeOther {
		t.Fatalf("held delete: %d", code)
	}
	if _, err := e.st.UserByEmail(ctx, "carol@example.com"); err != nil {
		t.Fatal("deleted without approval")
	}
	list, _ := e.st.Approvals(ctx)
	if len(list) != 1 || list[0].Status != "pending" || strings.Contains(fmt.Sprint(list[0].Form), "carol@example.com") {
		t.Fatalf("approvals %+v", list)
	}
	id := list[0].ID
	// not by the requester
	admin.form(fmt.Sprintf("/approvals/%d/approve", id), nil)
	if _, err := e.st.UserByEmail(ctx, "carol@example.com"); err != nil {
		t.Fatal("approved by the requester")
	}
	// the second administrator approves: done
	second.form(fmt.Sprintf("/approvals/%d/approve", id), nil)
	if _, err := e.st.UserByEmail(ctx, "carol@example.com"); err == nil {
		t.Fatal("not deleted after the approval")
	}
	list, _ = e.st.Approvals(ctx)
	if list[0].Status != "approved" || list[0].DecidedBy != "second@example.com" {
		t.Fatalf("after approval %+v", list[0])
	}
	// turning the rule off needs approval too; a rejection keeps it on
	if code, _ := admin.form("/settings/policy", url.Values{"lock_minutes": {"15"}, "clipboard_seconds": {"30"}, "min_password_length": {"12"}, "trash_days": {"30"},
		"max_file_mb": {"10"}, "storage_mb": {"500"}, "kdf_m": {"19"}, "kdf_t": {"2"}, "kdf_p": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("policy change: %d", code)
	}
	list, _ = e.st.Approvals(ctx)
	second.form(fmt.Sprintf("/approvals/%d/reject", list[0].ID), nil)
	if !e.srv.policy(ctx).FourEyes {
		t.Fatal("rule turned off without approval")
	}
}
