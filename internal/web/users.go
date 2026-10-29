package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/store"
)

type usersData struct {
	Users    []*store.User // active
	Disabled []*store.User
	Invites  []*store.Invite
	Email    string
	Role     string
	// NewLink is an invitation link just created (shown once).
	NewLink  string
	NewEmail string
	Now      time.Time
	Days     int
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	s.showUsers(w, r, http.StatusOK, &usersData{Role: store.RoleUser}, "")
}

func (s *Server) showUsers(w http.ResponseWriter, r *http.Request, status int, d *usersData, errMsg string) {
	all, err := s.store.Users(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Users, d.Disabled = nil, nil
	for _, u := range all {
		if u.Disabled {
			d.Disabled = append(d.Disabled, u)
		} else {
			d.Users = append(d.Users, u)
		}
	}
	if d.Invites, err = s.store.Invites(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Now, d.Days = s.now(), s.security(r.Context()).InviteDays
	p := &Page{Title: "Users", Nav: "users", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "users", p)
}

// publicBase is the address users reach the server under.
func (s *Server) publicBase(r *http.Request) string {
	if n, err := s.Network(r.Context()); err == nil && n.PublicURL != "" {
		return n.PublicURL
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("role") == store.RoleAdmin && s.holdForApproval(w, r, "user.invite-admin", "invite "+strings.TrimSpace(r.FormValue("email"))+" as administrator", "/users") {
		return
	}
	d := &usersData{Email: strings.TrimSpace(r.FormValue("email")), Role: r.FormValue("role")}
	days := s.security(r.Context()).InviteDays
	tok, inv, err := s.store.CreateInvite(r.Context(), d.Email, d.Role, userFrom(r).Email, time.Duration(days)*24*time.Hour)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			err = uiMsg("There is already an account with this address.")
		}
		s.showUsers(w, r, http.StatusBadRequest, d, storeErr(err))
		return
	}
	s.audit(r, "invite.create", "user:"+inv.Email, "invitation as %s, valid %d days", inv.Role, days)
	s.showUsers(w, r, http.StatusOK, &usersData{Role: store.RoleUser, NewLink: s.publicBase(r) + "/invite/" + tok, NewEmail: inv.Email}, "")
}

func (s *Server) handleInviteDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	inv, err := s.store.DeleteInvite(r.Context(), id)
	if err != nil {
		s.redirectErr(w, r, "/users", "The invitation was already used or withdrawn.")
		return
	}
	s.audit(r, "invite.delete", "user:"+inv.Email, "invitation withdrawn")
	s.redirect(w, r, "/users", "Invitation withdrawn.")
}

type userData struct {
	U    *store.User
	Self bool
}

func (s *Server) loadUser(w http.ResponseWriter, r *http.Request) *store.User {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	u, err := s.store.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return u
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	if u := s.loadUser(w, r); u != nil {
		s.showUser(w, r, http.StatusOK, u, "")
	}
}

func (s *Server) showUser(w http.ResponseWriter, r *http.Request, status int, u *store.User, errMsg string) {
	p := &Page{Title: u.Email, Nav: "users", Data: &userData{U: u, Self: u.ID == userFrom(r).ID}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "user", p)
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	u := s.loadUser(w, r)
	if u == nil {
		return
	}
	role, disabled := r.FormValue("role"), r.FormValue("disabled") == "1"
	if role == store.RoleAdmin && u.Role != store.RoleAdmin && s.holdForApproval(w, r, "user.admin", "make "+u.Email+" an administrator", fmt.Sprintf("/users/%d", u.ID)) {
		return
	}
	if u.ID == userFrom(r).ID {
		disabled = false
	}
	if err := s.store.UpdateUser(r.Context(), u.ID, r.FormValue("display_name"), role, disabled); err != nil {
		s.showUser(w, r, http.StatusBadRequest, u, storeErr(err))
		return
	}
	s.audit(r, "user.update", "user:"+u.Email, "role %s, disabled %v", role, disabled)
	s.redirect(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "Saved.")
}

func (s *Server) handleUserReset2FA(w http.ResponseWriter, r *http.Request) {
	u := s.loadUser(w, r)
	if u == nil {
		return
	}
	if s.holdForApproval(w, r, "user.reset-2fa", "reset the two-factor sign-in of "+u.Email, fmt.Sprintf("/users/%d", u.ID)) {
		return
	}
	if u.ID == userFrom(r).ID {
		s.showUser(w, r, http.StatusBadRequest, u, "You cannot reset your own two-factor sign-in; ask another administrator.")
		return
	}
	if err := s.store.ResetTwoFactor(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "2fa.reset", "user:"+u.Email, "two-factor sign-in reset by an administrator")
	s.redirect(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "Two-factor sign-in reset. The user sets it up again at the next sign-in.")
}

// handleUserDelete removes an account with its vault: the administrator
// must type the address, because nobody can bring the data back.
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	u := s.loadUser(w, r)
	if u == nil {
		return
	}
	if s.holdForApproval(w, r, "user.delete", "delete the user "+u.Email, fmt.Sprintf("/users/%d", u.ID)) {
		return
	}
	if u.ID == userFrom(r).ID {
		s.showUser(w, r, http.StatusBadRequest, u, "You cannot delete your own account.")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), u.Email) {
		s.showUser(w, r, http.StatusBadRequest, u, "Type the e-mail address of the account to confirm.")
		return
	}
	if err := s.store.DeleteUser(r.Context(), u.ID); err != nil {
		s.showUser(w, r, http.StatusBadRequest, u, storeErr(err))
		return
	}
	s.audit(r, "user.delete", "user:"+u.Email, "account and personal vault deleted")
	s.redirect(w, r, "/users", "The account and its vault were deleted.")
}

// ---- own account

type accountData struct {
	Sessions []store.Session
	Current  string
	Codes    []string
	CodesN   int
	Policy   Policy
	Keys     []store.SecurityKey
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.showAccount(w, r, http.StatusOK, &accountData{}, "")
}

func (s *Server) showAccount(w http.ResponseWriter, r *http.Request, status int, d *accountData, errMsg string) {
	u := userFrom(r)
	list, err := s.store.UserSessions(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Sessions, d.Current = list, sessionFrom(r).Hash
	if tf, err := s.store.GetTwoFactor(r.Context(), u.ID); err == nil {
		d.CodesN = len(tf.Codes)
	}
	d.Policy = s.policy(r.Context())
	if d.Keys, err = s.store.SecurityKeys(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	p := &Page{Title: "My account", Nav: "account", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, u), errMsg)
	}
	s.render(w, r, status, "account", p)
}

// handleAccountProfile saves the name and the own lock/clipboard times.
func (s *Server) handleAccountProfile(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if err := s.store.UpdateUser(r.Context(), u.ID, r.FormValue("display_name"), u.Role, false); err != nil {
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, storeErr(err))
		return
	}
	pol := s.policy(r.Context())
	p := store.Prefs{LockMinutes: formInt(r, "lock_minutes"), ClipboardSeconds: formInt(r, "clipboard_seconds")}
	if p.LockMinutes < 0 || p.LockMinutes > pol.LockMinutes || p.ClipboardSeconds < 0 || p.ClipboardSeconds > pol.ClipboardSeconds ||
		p.ClipboardSeconds > 0 && p.ClipboardSeconds < 5 {
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, "Choose times up to the limits of your administrator (or empty for the default).")
		return
	}
	if err := s.store.SetPrefs(r.Context(), u.ID, p); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.redirect(w, r, "/account", "Saved.")
}

// handleAccountCodes makes new recovery codes; it needs a current
// authenticator code, so a forgotten open browser is not enough.
func (s *Server) handleAccountCodes(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := auth.TOTPVerify(tf.Secret, r.FormValue("code"), s.now(), tf.LastStep)
	if ok {
		ok, _ = s.store.UseTOTPStep(r.Context(), u.ID, step)
	}
	if !ok {
		s.guard.fail(r.Context(), clientIP(r), u.Email, "recovery codes")
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, "The code is wrong or was already used.")
		return
	}
	plain, hashed := auth.NewRecoveryCodes()
	if err := s.store.SetRecoveryCodes(r.Context(), u.ID, hashed); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "2fa.recovery", "user:"+u.Email, "new recovery codes made; the old ones no longer work")
	s.showAccount(w, r, http.StatusOK, &accountData{Codes: plain}, "")
}

func (s *Server) handleAccountSignout(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	list, err := s.store.UserSessions(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	cur := sessionFrom(r).Hash
	n := 0
	for _, x := range list {
		if x.Hash != cur {
			_ = s.store.DeleteSession(r.Context(), x.Hash)
			n++
		}
	}
	s.audit(r, "account.signout", "user:"+u.Email, "signed out %d other sessions", n)
	s.redirect(w, r, "/account", "Your other sessions were signed out.")
}

// userTable is the argument of the usertable template.
type userTable struct {
	P     *Page
	Users []*store.User
}

func init() {
	funcs["userTable"] = func(p *Page, us []*store.User) userTable { return userTable{P: p, Users: us} }
}

// ---- vault pages (filled by static/pz/vault.js)

func (s *Server) handleVault(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "vault", &Page{Title: "Vault", Nav: "vault"})
}

func (s *Server) handleGenerator(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "generator", &Page{Title: "Password generator", Nav: "generator"})
}
