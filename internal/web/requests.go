package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/max-zit/passzit/internal/store"
)

// ---- requests for access (more rights for some hours, or access through
// a manager or an administrator)

func (s *Server) apiRequests(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.AccessRequests(r.Context(), userFrom(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if list == nil {
		list = []store.AccessRequest{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) requestErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrRequestOpen), errors.Is(err, store.ErrRightsHeld), errors.Is(err, store.ErrRequestClosed), errors.Is(err, store.ErrTooManyOpen):
		apiError(w, http.StatusConflict, "conflict", s.msg(r, err.Error()))
	case errors.Is(err, store.ErrForbidden):
		apiError(w, http.StatusForbidden, "forbidden", s.msg(r, "You may not decide this request."))
	default:
		s.vaultErr(w, r, err)
	}
}

func (s *Server) apiCreateRequest(w http.ResponseWriter, r *http.Request) {
	var q store.NewAccessRequest
	if !readJSON(w, r, 4096, &q) {
		return
	}
	u := userFrom(r)
	id, err := s.store.CreateAccessRequest(r.Context(), u.ID, q)
	if err != nil {
		s.requestErr(w, r, err)
		return
	}
	s.audit(r, "access.request", u.Email, "asked for %s for %d hours (request %d)", q.Rights, q.Hours, id)
	// the managers of the vault, or the person asked, hear of it
	if list, err := s.store.RequestDeciders(r.Context(), id); err == nil {
		m := mailText{Subject: "A request for access is waiting",
			Lines: [][]any{{"%s asks for access (%s) for %d hours.", u.Email, rightsName(q.Rights), q.Hours}, {"Reason: %s", q.Reason},
				{"Approve or reject it in the web vault under Tools → Access requests."}}}
		for _, d := range list {
			s.notifyUser(r.Context(), d.Email, d.Lang, m, "/vault?requests=1")
		}
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// rightsName is the English name of rights for texts (translated with them).
func rightsName(r string) string {
	return map[string]string{"use": "Use (no reading)", "view": "Read", "edit": "Read and change", "manage": "Manage"}[r]
}

type decideReq struct {
	Approve bool   `json:"approve"`
	VaultID string `json:"vault_id"`
}

func (s *Server) apiDecideRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "not_found", s.msg(r, "Not found."))
		return
	}
	var q decideReq
	if !readJSON(w, r, 1024, &q) {
		return
	}
	u := userFrom(r)
	req, err := s.store.DecideAccessRequest(r.Context(), u, id, q.Approve, q.VaultID)
	if err != nil {
		s.requestErr(w, r, err)
		return
	}
	s.audit(r, "access.request."+req.Status, req.Email, "request %d for %s, %d hours", id, req.Rights, req.Hours)
	if rcpt, err := s.store.UserByID(r.Context(), req.UserID); err == nil {
		m := mailText{Subject: "Your request for access was rejected", Lines: [][]any{{"%s rejected your request for access.", u.Email}}}
		if q.Approve {
			m = mailText{Subject: "Your request for access was approved",
				Lines: [][]any{{"%s approved your request for access (%s) for %d hours.", u.Email, rightsName(req.Rights), req.Hours}, {"The access ends by itself."}}}
		}
		s.notifyUser(r.Context(), rcpt.Email, rcpt.Lang, m, "/vault")
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) apiCancelRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "not_found", s.msg(r, "Not found."))
		return
	}
	if err := s.store.CancelAccessRequest(r.Context(), userFrom(r).ID, id); err != nil {
		s.requestErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
