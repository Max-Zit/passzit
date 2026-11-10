package web

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// TestGroupOrphanProtection: when the only manager of a shared vault
// manages it through a group, the group page warns, and neither taking
// them out of the group nor deleting the group goes through; the company
// directory still decides (the change happens, the administrators hear of
// it).
func TestGroupOrphanProtection(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.setupAdmin()
	bob := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	vid, vkey := sharedVault(t, admin, "Ops")
	gid, err := e.st.SaveGroup(ctx, 0, "Ops managers", "")
	if err != nil {
		t.Fatal(err)
	}
	bobID, bobPub := admin.directoryKey("bob@example.com")
	if err := e.st.SetGroupMembers(ctx, gid, []int64{bobID}); err != nil {
		t.Fatal(err)
	}
	admin.must("PUT", "/api/vaults/"+vid+"/groups", vaultGroupReq{GroupID: gid, Rights: "manage"}, nil)
	wk, _ := vaultcrypto.SealTo(bobPub, vkey, vaultcrypto.AADVaultKey(vid))
	admin.must("PUT", "/api/vaults/"+vid+"/members", store.MemberChange{UserID: bobID, WrappedKey: wk, GroupID: &gid}, nil)
	if m := memberOf(t, admin, vid, "bob@example.com"); m.Rights != "manage" {
		t.Fatalf("bob through the group: %+v", m)
	}
	// the administrator leaves: bob manages the vault only through the group
	adminID, _ := admin.directoryKey("admin@example.com")
	bob.must("DELETE", fmt.Sprintf("/api/vaults/%s/members/%d", vid, adminID), nil, nil)

	sole, only, err := e.st.GroupManagers(ctx, gid)
	if err != nil || sole[bobID] != 1 || only != 1 {
		t.Fatalf("group managers: %v %d %v", sole, only, err)
	}
	_, page := admin.get(fmt.Sprintf("/groups/%d", gid))
	if !strings.Contains(page, "only manager of 1 shared vault(s)") || !strings.Contains(page, "1 shared vault(s) are managed only through this group") {
		t.Fatal("the group page does not warn")
	}
	// taking bob out of the group or deleting it is refused, with the reason
	var oe *store.OrphanError
	if err := e.st.SetGroupMembers(ctx, gid, nil); !errors.As(err, &oe) || oe.Vaults != 1 || len(oe.Users) != 1 || oe.Users[0] != "bob@example.com" {
		t.Fatalf("leaving the group: %v", err)
	}
	if err := e.st.DeleteGroup(ctx, gid); !errors.As(err, &oe) {
		t.Fatalf("deleting the group: %v", err)
	}
	admin.form(fmt.Sprintf("/groups/%d", gid), url.Values{"name": {"Ops managers"}})
	_, page = admin.get(fmt.Sprintf("/groups/%d", gid))
	if !strings.Contains(page, "would be left without a manager") || !strings.Contains(page, "bob@example.com") {
		t.Fatal("the refused save does not explain why")
	}
	admin.form(fmt.Sprintf("/groups/%d/delete", gid), nil)
	_, page = admin.get(fmt.Sprintf("/groups/%d", gid))
	if !strings.Contains(page, "would be left without a manager") {
		t.Fatal("the refused delete does not explain why")
	}
	if m := memberOf(t, bob, vid, "bob@example.com"); m.Rights != "manage" {
		t.Fatalf("bob after the refused changes: %+v", m)
	}
	// with a second permanent manager outside the group it goes through
	e.inviteUser(admin, "carol@example.com", "Carol-Master-Password-3")
	addMember(t, bob, vid, vkey, "carol@example.com", "manage", nil)
	if err := e.st.SetGroupMembers(ctx, gid, nil); err != nil {
		t.Fatalf("leaving the group with another manager: %v", err)
	}
	if err := e.st.SetGroupMembers(ctx, gid, []int64{bobID}); err != nil {
		t.Fatal(err)
	}

	// the company directory decides: the change happens and is counted
	vid2, vkey2 := sharedVault(t, admin, "Infra")
	admin.must("PUT", "/api/vaults/"+vid2+"/groups", vaultGroupReq{GroupID: gid, Rights: "manage"}, nil)
	wk2, _ := vaultcrypto.SealTo(bobPub, vkey2, vaultcrypto.AADVaultKey(vid2))
	admin.must("PUT", "/api/vaults/"+vid2+"/members", store.MemberChange{UserID: bobID, WrappedKey: wk2, GroupID: &gid}, nil)
	bob.must("DELETE", fmt.Sprintf("/api/vaults/%s/members/%d", vid2, adminID), nil, nil)
	n, err := e.st.SetUserGroups(ctx, bobID, nil)
	if err != nil || n != 1 {
		t.Fatalf("directory sync: %d %v", n, err)
	}
}
