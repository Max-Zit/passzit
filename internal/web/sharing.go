package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/max-zit/passzit/internal/store"
)

// ---- shared vaults: the browser seals the vault key to each member's
// public key; the server keeps the members and their rights.

func (s *Server) sharingErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrLastManager):
		apiError(w, http.StatusConflict, "last_manager", s.msg(r, "A vault needs at least one manager."))
	case errors.Is(err, store.ErrConflict):
		apiError(w, http.StatusConflict, "exists", s.msg(r, "The name is already used."))
	default:
		s.vaultErr(w, r, err)
	}
}

func (s *Server) apiDirectory(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.Directory(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

type createVaultReq struct {
	ID         string `json:"id"`
	Data       string `json:"data"`
	WrappedKey string `json:"wrapped_key"`
}

func (s *Server) apiCreateVault(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if s.policy(r.Context()).SharedAdminsOnly && u.Role != "admin" {
		apiError(w, http.StatusForbidden, "forbidden", s.msg(r, "Only administrators may create shared vaults."))
		return
	}
	var q createVaultReq
	if !readJSON(w, r, 8<<10, &q) {
		return
	}
	if err := s.store.CreateVault(r.Context(), u.ID, q.ID, q.Data, q.WrappedKey); err != nil {
		s.sharingErr(w, r, err)
		return
	}
	s.audit(r, "vault.create", "vault:"+q.ID, "shared vault created")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type vaultDataReq struct {
	Data string `json:"data"`
}

func (s *Server) apiRenameVault(w http.ResponseWriter, r *http.Request) {
	var q vaultDataReq
	if !readJSON(w, r, 4<<10, &q) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.RenameVault(r.Context(), userFrom(r).ID, id, q.Data); err != nil {
		s.sharingErr(w, r, err)
		return
	}
	s.audit(r, "vault.rename", "vault:"+id, "shared vault renamed")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiDeleteVault(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteVault(r.Context(), userFrom(r).ID, id); err != nil {
		s.sharingErr(w, r, err)
		return
	}
	s.audit(r, "vault.delete", "vault:"+id, "shared vault deleted with its items")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type vaultMembersResp struct {
	Members []store.Member     `json:"members"`
	Groups  []store.VaultGroup `json:"groups"`
}

func (s *Server) apiVaultMembers(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id := r.PathValue("id")
	m, err := s.store.VaultMembers(r.Context(), u.ID, id)
	if err != nil {
		s.sharingErr(w, r, err)
		return
	}
	g, err := s.store.VaultGroups(r.Context(), u.ID, id)
	if err != nil {
		s.sharingErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, vaultMembersResp{Members: m, Groups: g})
}

func (s *Server) apiPutMember(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var q store.MemberChange
	if !readJSON(w, r, 4<<10, &q) {
		return
	}
	id := r.PathValue("id")
	added, err := s.store.PutMember(r.Context(), u.ID, u.Email, id, q)
	if err != nil {
		s.sharingErr(w, r, err)
		return
	}
	what := "rights of user %d set to %s"
	if added {
		what = "user %d added with rights %s"
	}
	if q.ExpiresAt != nil {
		s.audit(r, "vault.member", "vault:"+id, what+" until %s", q.UserID, q.Rights, q.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	} else {
		s.audit(r, "vault.member", "vault:"+id, what, q.UserID, q.Rights)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiRemoveMember(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id := r.PathValue("id")
	target, err := strconv.ParseInt(r.PathValue("user"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "not_found", s.msg(r, "Not found."))
		return
	}
	if err := s.store.RemoveMember(r.Context(), u.ID, id, target); err != nil {
		s.sharingErr(w, r, err)
		return
	}
	if target == u.ID {
		s.audit(r, "vault.leave", "vault:"+id, "left the shared vault")
	} else {
		s.audit(r, "vault.member.remove", "vault:"+id, "user %d removed", target)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiRotateVault(w http.ResponseWriter, r *http.Request) {
	var q store.Rotation
	if !readJSON(w, r, 64<<20, &q) {
		return
	}
	id := r.PathValue("id")
	rev, err := s.store.RotateVault(r.Context(), userFrom(r).ID, id, q)
	if err != nil {
		s.sharingErr(w, r, err)
		return
	}
	s.audit(r, "vault.rotate", "vault:"+id, "new vault key (%d members, %d items sealed again)", len(q.Members), len(q.Items))
	writeJSON(w, http.StatusOK, revResp{Revision: rev})
}

type vaultGroupReq struct {
	GroupID int64  `json:"group_id"`
	Rights  string `json:"rights"`
}

func (s *Server) apiPutVaultGroup(w http.ResponseWriter, r *http.Request) {
	var q vaultGroupReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.PutVaultGroup(r.Context(), userFrom(r).ID, id, q.GroupID, q.Rights); err != nil {
		s.sharingErr(w, r, err)
		return
	}
	s.audit(r, "vault.group", "vault:"+id, "group %d given rights %s", q.GroupID, q.Rights)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiRemoveVaultGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	g, err := strconv.ParseInt(r.PathValue("group"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "not_found", s.msg(r, "Not found."))
		return
	}
	if err := s.store.RemoveVaultGroup(r.Context(), userFrom(r).ID, id, g); err != nil {
		s.sharingErr(w, r, err)
		return
	}
	s.audit(r, "vault.group.remove", "vault:"+id, "group %d removed", g)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiPendingAccess(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.PendingAccess(r.Context(), userFrom(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if p == nil {
		p = []store.Pending{}
	}
	writeJSON(w, http.StatusOK, p)
}

type groupRef struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Members int    `json:"members"`
}

// apiGroups lists the groups (names only) for vault managers.
func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request) {
	all, err := s.store.Groups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := make([]groupRef, 0, len(all))
	for _, g := range all {
		out = append(out, groupRef{ID: g.ID, Name: g.Name, Members: len(g.Members)})
	}
	writeJSON(w, http.StatusOK, out)
}

type moveReq struct {
	VaultID  string `json:"vault_id"`
	Data     string `json:"data"`
	Revision int64  `json:"revision"`
}

func (s *Server) apiMoveItem(w http.ResponseWriter, r *http.Request) {
	var q moveReq
	if !readJSON(w, r, store.MaxItemData+1024, &q) {
		return
	}
	rev, err := s.store.MoveItem(r.Context(), userFrom(r).ID, r.PathValue("id"), q.VaultID, q.Data, q.Revision)
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, revResp{Revision: rev})
}

func (s *Server) apiKnownKeys(w http.ResponseWriter, r *http.Request) {
	k, err := s.store.KnownKeys(r.Context(), userFrom(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, vaultDataReq{Data: k})
}

func (s *Server) apiSetKnownKeys(w http.ResponseWriter, r *http.Request) {
	var q vaultDataReq
	if !readJSON(w, r, 300<<10, &q) {
		return
	}
	if err := s.store.SetKnownKeys(r.Context(), userFrom(r).ID, q.Data); err != nil {
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
