package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// directoryKey finds a user's id and public key in the directory.
func (c *client) directoryKey(email string) (int64, []byte) {
	c.e.t.Helper()
	var d []store.DirectoryEntry
	c.must("GET", "/api/directory", nil, &d)
	for _, x := range d {
		if x.Email == email {
			k, err := vaultcrypto.B64.DecodeString(x.PublicKey)
			if err != nil {
				c.e.t.Fatal(err)
			}
			return x.ID, k
		}
	}
	c.e.t.Fatalf("%s not in the directory", email)
	return 0, nil
}

func TestSharedVaults(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	carol := e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	// admin makes a shared vault: the key sealed to the own public key
	vid := newUUID()
	vkey := vaultcrypto.Random(32)
	name, _ := vaultcrypto.Seal(vkey, []byte("Team"), vaultcrypto.AADVaultName(vid))
	self, _ := vaultcrypto.SealTo(admin.keys.public, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("POST", "/api/vaults", createVaultReq{ID: vid, Data: name, WrappedKey: self}, nil)
	admin.sync(0)
	if !bytes.Equal(admin.vaults[vid], vkey) {
		t.Fatal("the shared vault key does not open")
	}
	item := newUUID()
	admin.must("PUT", "/api/items/"+item, putItemReq{VaultID: vid, Data: admin.sealItem(vid, item, map[string]any{"name": "router", "password": "team-secret"})}, nil)
	if code, _ := bob.do("GET", "/api/vaults/"+vid+"/members", nil, nil); code != http.StatusNotFound {
		t.Fatalf("members as a stranger: %d", code)
	}
	// bob joins with view rights
	bobID, bobPub := admin.directoryKey("bob@example.com")
	wk, _ := vaultcrypto.SealTo(bobPub, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, WrappedKey: wk, Rights: "view"}, nil)
	s := bob.sync(0)
	if len(s.Items) != 1 || !bytes.Equal(bob.vaults[vid], vkey) {
		t.Fatalf("bob sees %d items", len(s.Items))
	}
	if p, err := vaultcrypto.Open(bob.vaults[vid], s.Items[0].Data, vaultcrypto.AADItem(vid, item)); err != nil || !strings.Contains(string(p), "team-secret") {
		t.Fatalf("bob cannot read the item: %v", err)
	}
	if code, _ := bob.do("PUT", "/api/items/"+newUUID(), putItemReq{VaultID: vid, Data: bob.sealItem(vid, item, map[string]any{"name": "x"})}, nil); code != http.StatusForbidden {
		t.Fatalf("view member wrote: %d", code)
	}
	carolID, carolPub := bob.directoryKey("carol@example.com")
	wc, _ := vaultcrypto.SealTo(carolPub, vkey, vaultcrypto.AADVaultKey(vid))
	if code, _ := bob.do("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: carolID, WrappedKey: wc, Rights: "view"}, nil); code != http.StatusForbidden {
		t.Fatalf("view member added a member: %d", code)
	}
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, Rights: "edit"}, nil)
	bitem := newUUID()
	bob.must("PUT", "/api/items/"+bitem, putItemReq{VaultID: vid, Data: bob.sealItem(vid, bitem, map[string]any{"name": "from bob"})}, nil)
	// the last manager cannot step down
	adminID, _ := admin.directoryKey("admin@example.com")
	if code, _ := admin.do("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: adminID, Rights: "edit"}, nil); code != http.StatusConflict {
		t.Fatalf("last manager stepped down: %d", code)
	}
	// moving a personal item into the shared vault
	pv := admin.personal()
	pitem := newUUID()
	var pr revResp
	admin.must("PUT", "/api/items/"+pitem, putItemReq{VaultID: pv, Data: admin.sealItem(pv, pitem, map[string]any{"name": "moved"})}, &pr)
	admin.must("POST", "/api/items/"+pitem+"/move", moveReq{VaultID: vid, Data: admin.sealItem(vid, pitem, map[string]any{"name": "moved"}), Revision: pr.Revision}, nil)
	if s := bob.sync(0); len(s.Items) != 3 {
		t.Fatalf("bob sees %d items after the move", len(s.Items))
	}
	if code, _ := bob.do("POST", "/api/items/"+pitem+"/move", moveReq{VaultID: bob.personal(), Data: name, Revision: 1}, nil); code != http.StatusConflict {
		t.Fatalf("move with an old revision: %d", code)
	}
	// bob is removed: the vault needs a new key, bob sees nothing of it
	before := bob.sync(0).Revision
	admin.must("DELETE", fmt.Sprintf("/api/vaults/%s/members/%d", vid, bobID), nil, nil)
	if s := bob.sync(before); !s.Full || len(s.Items) != 0 || len(s.Vaults) != 1 {
		t.Fatalf("bob after removal: full=%v items=%d vaults=%d", s.Full, len(s.Items), len(s.Vaults))
	}
	var ref store.VaultRef
	for _, v := range admin.sync(0).Vaults {
		if v.ID == vid {
			ref = v
		}
	}
	if !ref.NeedsRotation || ref.KeyVersion != 1 {
		t.Fatalf("vault after removal %+v", ref)
	}
	// rotation: an incomplete one is refused, a complete one gives version 2
	nkey := vaultcrypto.Random(32)
	nname, _ := vaultcrypto.Seal(nkey, []byte("Team"), vaultcrypto.AADVaultName(vid))
	nself, _ := vaultcrypto.SealTo(admin.keys.public, nkey, vaultcrypto.AADVaultKey(vid))
	rot := store.Rotation{KeyVersion: 1, Data: nname, Members: map[int64]string{adminID: nself}}
	if code, _ := admin.do("POST", "/api/vaults/"+vid+"/rotate", rot, nil); code != http.StatusConflict {
		t.Fatalf("rotation without items: %d", code)
	}
	admin.vaults[vid] = nkey
	for _, id := range []string{item, bitem, pitem} {
		rot.Items = append(rot.Items, store.RotatedItem{ID: id, Data: admin.sealItem(vid, id, map[string]any{"name": "again"})})
	}
	admin.must("POST", "/api/vaults/"+vid+"/rotate", rot, nil)
	if code, _ := admin.do("POST", "/api/vaults/"+vid+"/rotate", rot, nil); code != http.StatusConflict {
		t.Fatalf("second rotation with the old version: %d", code)
	}
	for _, v := range admin.sync(0).Vaults {
		if v.ID == vid && (v.NeedsRotation || v.KeyVersion != 2 || !bytes.Equal(admin.vaults[vid], nkey)) {
			t.Fatalf("after rotation %+v", v)
		}
	}
	// groups: access waits until a manager seals the key
	gid, err := e.st.SaveGroup(ctx, 0, "Ops", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetGroupMembers(ctx, gid, []int64{carolID}); err != nil {
		t.Fatal(err)
	}
	admin.must("PUT", "/api/vaults/"+vid+"/groups", vaultGroupReq{GroupID: gid, Rights: "view"}, nil)
	var pend []store.Pending
	admin.must("GET", "/api/vaults/pending", nil, &pend)
	if len(pend) != 1 || pend[0].UserID != carolID || pend[0].Rights != "view" {
		t.Fatalf("pending %+v", pend)
	}
	wc, _ = vaultcrypto.SealTo(carolPub, nkey, vaultcrypto.AADVaultKey(vid))
	// the rights come from the group, not from the request
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: carolID, WrappedKey: wc, Rights: "manage", GroupID: &gid}, nil)
	var mem vaultMembersResp
	carol.must("GET", "/api/vaults/"+vid+"/members", nil, &mem)
	for _, m := range mem.Members {
		if m.UserID == carolID && (m.Rights != "view" || m.GroupID == nil) {
			t.Fatalf("carol through the group: %+v", m)
		}
	}
	if s := carol.sync(0); len(s.Items) != 3 {
		t.Fatalf("carol sees %d items", len(s.Items))
	}
	admin.must("GET", "/api/vaults/pending", nil, &pend)
	if len(pend) != 0 {
		t.Fatalf("still pending %+v", pend)
	}
	// leaving the group ends the access and asks for a new key
	if err := e.st.SetGroupMembers(ctx, gid, nil); err != nil {
		t.Fatal(err)
	}
	if s := carol.sync(0); len(s.Items) != 0 {
		t.Fatalf("carol after leaving the group: %d items", len(s.Items))
	}
	// time-limited access ends by itself
	future := e.clock.Add(48 * 3600e9)
	wb, _ := vaultcrypto.SealTo(bobPub, nkey, vaultcrypto.AADVaultKey(vid))
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, WrappedKey: wb, Rights: "view", ExpiresAt: &future}, nil)
	if s := bob.sync(0); len(s.Items) != 3 {
		t.Fatalf("bob with time-limited access sees %d items", len(s.Items))
	}
	e.clock = future.Add(1e9)
	if n, err := e.st.ExpireMemberships(ctx); err != nil || n != 1 {
		t.Fatalf("expired %d, %v", n, err)
	}
	// the sessions ran out too: sign in again
	bob.login()
	admin.login()
	if s := bob.sync(0); len(s.Items) != 0 {
		t.Fatal("expired access still works")
	}
	// export policy
	p := DefaultPolicy
	p.KDF = fastKDF
	p.NoExport = true
	_ = e.st.SetSetting(ctx, settingPolicy, p)
	if code, _ := admin.do("POST", "/api/account/event", eventReq{Event: "export", Count: 1}, nil); code != http.StatusForbidden {
		t.Fatalf("export allowed against the policy: %d", code)
	}
	// deleting the vault
	admin.must("DELETE", "/api/vaults/"+vid, nil, nil)
	for _, v := range admin.sync(0).Vaults {
		if v.ID == vid {
			t.Fatal("deleted vault still listed")
		}
	}
	// the server never saw a vault key or the item's password
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.bodies {
		if strings.Contains(b, "team-secret") || strings.Contains(b, vaultcrypto.B64.EncodeToString(vkey)) || strings.Contains(b, vaultcrypto.B64.EncodeToString(nkey)) {
			t.Fatal("a secret reached the server")
		}
	}
}
