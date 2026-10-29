package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/store"
)

// The browser extensions sign in with the master password (its auth key)
// and the second factor like the web vault, but get a device token instead
// of a cookie: Authorization: Bearer pzd_…. With it they use the same
// /api/… endpoints as the web vault (sync, items, account). The token
// lives for ExtDays and ends earlier after ExtIdleDays without use; users
// see their extensions under My account and can sign them out.

// extRequest reports a request of an extension: its sign-in, or an API
// call with a device token and no cookie.
func extRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/ext/") {
		return true
	}
	if bearerToken(r) == "" {
		return false
	}
	_, err := r.Cookie(cookieName(r))
	return err != nil
}

type extLoginReq struct {
	Email  string `json:"email"`
	Auth   string `json:"auth"`
	Device string `json:"device"`
}

type extLoginResp struct {
	Next  string `json:"next"` // "2fa" or "done"
	Token string `json:"token"`
}

func (s *Server) extLife(r *http.Request) time.Duration {
	return time.Duration(s.security(r.Context()).ExtDays) * 24 * time.Hour
}

// apiExtLogin checks the master password of an extension sign-in.
func (s *Server) apiExtLogin(w http.ResponseWriter, r *http.Request) {
	var q extLoginReq
	if !readJSON(w, r, 2<<10, &q) {
		return
	}
	q.Email = strings.TrimSpace(q.Email)
	if !s.guardOK(w, r, q.Email) {
		return
	}
	ip := clientIP(r)
	var u *store.User
	err := store.ErrNotFound
	if store.B64Len(q.Auth) == 32 {
		u, err = s.store.CheckAuth(r.Context(), q.Email, q.Auth)
	}
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		s.guard.fail(r.Context(), ip, q.Email, "master password (extension)")
		s.auditAs(r, q.Email, "login.failed", "user:"+q.Email, "wrong e-mail address or master password (extension)")
		apiError(w, http.StatusUnauthorized, "wrong", s.msg(r, "Wrong e-mail address or master password."))
		return
	}
	device := strings.TrimSpace(q.Device)
	if device == "" {
		device = "Browser extension"
	}
	if msg := s.directoryCheck(r, u, false); msg != "" {
		apiError(w, http.StatusForbidden, "directory", msg)
		return
	}
	n := store.NewSession{UserID: u.ID, Kind: store.KindExt, Device: device, IP: ip, UserAgent: r.UserAgent()}
	if s.DevNo2FA {
		n.Stage, n.Life = store.StageFull, s.extLife(r)
		tok, _, err := s.store.StartSession(r.Context(), n)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		s.guard.success(ip, u.Email)
		_ = s.store.MarkLogin(r.Context(), u.ID)
		s.auditAs(r, u.Email, "login", "user:"+u.Email, "extension %q signed in (master password only, test mode)", device)
		writeJSON(w, http.StatusOK, extLoginResp{Next: "done", Token: tok})
		return
	}
	if !u.TOTPEnabled {
		apiError(w, http.StatusForbidden, "enroll", s.msg(r, "Set up two-factor sign-in in the web vault first."))
		return
	}
	n.Stage, n.Life = store.StageMFA, store.MFATimeout
	tok, _, err := s.store.StartSession(r.Context(), n)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, extLoginResp{Next: "2fa", Token: tok})
}

// apiExtLogin2FA finishes an extension sign-in with the second factor; the
// request carries the pending token, the answer the device token.
func (s *Server) apiExtLogin2FA(w http.ResponseWriter, r *http.Request) {
	x, u := s.mfaUser(r)
	if u == nil || x.Kind != store.KindExt {
		apiError(w, http.StatusUnauthorized, "signed_out", s.msg(r, "The sign-in took too long. Start again."))
		return
	}
	var q codeReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() || s.guard.userThrottled(u.Email) {
		_ = s.store.DeleteSession(r.Context(), x.Hash)
		apiError(w, http.StatusTooManyRequests, "blocked", s.msg(r, "Too many failed attempts. Try again later."))
		return
	}
	ok, how, err := s.checkSecondFactor(r.Context(), u, q.Code)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.guard.fail(r.Context(), ip, u.Email, "second factor (extension)")
		s.auditAs(r, u.Email, "login.failed", "user:"+u.Email, "wrong second-factor code (extension)")
		apiError(w, http.StatusUnauthorized, "wrong", s.msg(r, "The code is wrong or was already used."))
		return
	}
	tok, err := s.store.PromoteSession(r.Context(), x, s.extLife(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	_ = s.store.MarkLogin(r.Context(), u.ID)
	s.guard.success(ip, u.Email)
	s.auditAs(r, u.Email, "login", "user:"+u.Email, "extension %q signed in (%s)", x.Device, how)
	writeJSON(w, http.StatusOK, extLoginResp{Next: "done", Token: tok})
}

// apiExtLogout ends the extension's session.
func (s *Server) apiExtLogout(w http.ResponseWriter, r *http.Request) {
	if x := sessionFrom(r); x != nil && x.Kind == store.KindExt {
		_ = s.store.DeleteSession(r.Context(), x.Hash)
		if u := userFrom(r); u != nil {
			s.audit(r, "logout", "user:"+u.Email, "extension %q signed out", x.Device)
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSessionSignout ends one session of the signed-in user (My account).
func (s *Server) handleSessionSignout(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	x, err := s.store.DeleteUserSession(r.Context(), u.ID, r.PathValue("id"))
	if err != nil {
		s.redirectErr(w, r, "/account", "Not found.")
		return
	}
	what := "web session from " + x.IP
	if x.Kind == store.KindExt {
		what = "extension " + x.Device
	}
	s.audit(r, "account.signout", "user:"+u.Email, "signed out %s", what)
	s.redirect(w, r, "/account", "Signed out.")
}
