package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/passzit/internal/store"
)

// Groups (administrators): a vault manager gives a group access to a
// shared vault; its members get the vault key from a manager's browser.

type groupsData struct {
	Groups []store.Group
	Users  []*store.User
	Edit   *store.Group
	Member map[int64]bool
}

func (s *Server) showGroups(w http.ResponseWriter, r *http.Request, edit *store.Group) {
	groups, err := s.store.Groups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	users, err := s.store.Users(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &groupsData{Groups: groups, Edit: edit, Member: map[int64]bool{}}
	for _, u := range users {
		if !u.Disabled {
			d.Users = append(d.Users, u)
		}
	}
	if edit != nil {
		for _, id := range edit.Members {
			d.Member[id] = true
		}
	}
	s.render(w, r, http.StatusOK, "groups", &Page{Title: "Groups", Nav: "groups", Data: d})
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) { s.showGroups(w, r, nil) }

func (s *Server) handleGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	g, err := s.store.Group(r.Context(), id)
	if err != nil {
		s.notFound(w, r)
		return
	}
	s.showGroups(w, r, g)
}

func groupErr(err error) string {
	if errors.Is(err, store.ErrConflict) {
		return "The name is already used."
	}
	return strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
}

func (s *Server) handleGroupSave(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64) // 0 for a new group
	back := "/groups"
	if id > 0 {
		back = fmt.Sprintf("/groups/%d", id)
	}
	gid, err := s.store.SaveGroup(r.Context(), id, r.FormValue("name"), strings.TrimSpace(r.FormValue("description")))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.redirectErr(w, r, back, groupErr(err))
		return
	}
	if id > 0 {
		var members []int64
		for _, v := range r.Form["member"] {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				members = append(members, n)
			}
		}
		if err := s.store.SetGroupMembers(r.Context(), id, members); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "group.update", fmt.Sprintf("group:%d", id), "group %q saved with %d member(s)", r.FormValue("name"), len(members))
		s.redirect(w, r, back, "Saved. Vault managers give new members access when they open their vault.")
		return
	}
	s.audit(r, "group.create", fmt.Sprintf("group:%d", gid), "group %q created", r.FormValue("name"))
	s.redirect(w, r, fmt.Sprintf("/groups/%d", gid), "The group is created. Choose its members.")
}

func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	g, err := s.store.Group(r.Context(), id)
	if err != nil {
		s.notFound(w, r)
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "group.delete", fmt.Sprintf("group:%d", id), "group %q deleted (members lost the access it gave)", g.Name)
	s.redirect(w, r, "/groups", "Deleted.")
}
