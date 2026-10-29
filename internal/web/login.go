package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/netacl"
	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
)

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func sessionFrom(r *http.Request) *store.Session {
	x, _ := r.Context().Value(ctxSession).(*store.Session)
	return x
}

// cookieName: the __Host- prefix makes browsers refuse the cookie unless
// it is Secure, host-only and for path / (not possible on the dev HTTP listener).
func cookieName(r *http.Request) string {
	if r.TLS != nil {
		return "__Host-pzsession"
	}
	return "pzsession"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, tok string, life time.Duration) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: cookieName(r), Value: tok, Path: "/", MaxAge: int(life.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: cookieName(r), Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

// bearerToken returns the device token of an API request of an extension
// (Authorization: Bearer pzd_…); browsers never add it by themselves, so
// such requests need no CSRF check.
func bearerToken(r *http.Request) string {
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return ""
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer pzd_") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

// idleLimit is the inactivity limit of a session kind.
func (s *Server) idleLimit(ctx context.Context) func(string) time.Duration {
	sec := s.security(ctx)
	return func(kind string) time.Duration {
		if kind == store.KindExt {
			return time.Duration(sec.ExtIdleDays) * 24 * time.Hour
		}
		return time.Duration(sec.IdleMinutes) * time.Minute
	}
}

// loadSession puts the user of a full session into the request context
// (and the session of any stage). Web sessions come from the cookie,
// extension sessions from the Authorization header.
func (s *Server) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		tok, kind := bearerToken(r), store.KindExt
		if tok == "" {
			c, err := r.Cookie(cookieName(r))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			tok, kind = c.Value, store.KindWeb
		}
		x, err := s.store.SessionByToken(r.Context(), tok, s.idleLimit(r.Context()))
		if err == nil && x.Kind != kind {
			err = store.ErrNotFound // a device token is no cookie and the other way round
		}
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.serverError(w, r, err)
				return
			}
			if kind == store.KindWeb {
				s.clearSessionCookie(w, r)
			}
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), ctxSession, x)
		if x.Stage == store.StageFull {
			u, err := s.store.UserByID(r.Context(), x.UserID)
			if err != nil || u.Disabled {
				_ = s.store.DeleteSession(r.Context(), x.Hash)
				s.clearSessionCookie(w, r)
				next.ServeHTTP(w, r)
				return
			}
			_ = s.store.TouchSession(r.Context(), x, clientIP(r))
			ctx = context.WithValue(ctx, ctxUser, u)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireUser sends visitors without a full session to the sign-in.
func (s *Server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r) == nil {
			if n, err := s.store.UserCount(r.Context()); err == nil && n == 0 {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(safeNext(r.URL.RequestURI())), http.StatusSeeOther)
				return
			}
			http.Error(w, "signed out", http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

// requireAPIUser answers JSON requests without a full session with 401.
func (s *Server) requireAPIUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r) == nil {
			apiError(w, http.StatusUnauthorized, "signed_out", "You are signed out.")
			return
		}
		next(w, r)
	})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r).IsAdmin() {
			s.forbidden(w, r)
			return
		}
		next(w, r)
	}
}

// safeNext keeps only local paths (no open redirects).
func safeNext(p string) string {
	// Browsers drop tabs and newlines from URLs, so "/<TAB>/evil.example"
	// would become "//evil.example": refuse every control character.
	if strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "/vault"
	}
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || p == "/" {
		return "/vault"
	}
	return p
}

// ---- JSON helpers

type apiErr struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiErr{Error: code, Message: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON decodes a request body of at most max bytes.
func readJSON(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "bad_request", "JSON expected.")
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "The request could not be read.")
		return false
	}
	return true
}

// msg translates a message for the request's language.
func (s *Server) msg(r *http.Request, key string, args ...any) string {
	return translate(s.lang(r, userFrom(r)), key, args...)
}

// ---- pages (the forms are driven by static/pz/auth.js)

type authPage struct {
	Mode      string // setup, login, invite, recover
	NeedToken bool
	Email     string
	Invite    string
	Next      string
	MinLength int
}

func (s *Server) authPage(w http.ResponseWriter, r *http.Request, title string, d *authPage) {
	d.MinLength = s.policy(r.Context()).MinPasswordLength
	s.render(w, r, http.StatusOK, "auth", &Page{Title: title, Data: d})
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if n, err := s.store.UserCount(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	} else if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.authPage(w, r, "Set up PassZit", &authPage{Mode: "setup", NeedToken: s.setupToken != ""})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if n, err := s.store.UserCount(r.Context()); err == nil && n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.authPage(w, r, "Sign in", &authPage{Mode: "login", Next: safeNext(r.FormValue("next"))})
}

func (s *Server) handleInvitePage(w http.ResponseWriter, r *http.Request) {
	inv, err := s.store.InviteByToken(r.Context(), r.PathValue("token"))
	if err != nil {
		p := &Page{Title: "Invitation", Error: s.msg(r, "This invitation link does not work any more. Ask your administrator for a new one.")}
		s.render(w, r, http.StatusNotFound, "message", p)
		return
	}
	s.authPage(w, r, "Create your account", &authPage{Mode: "invite", Email: inv.Email, Invite: r.PathValue("token")})
}

func (s *Server) handleRecoverPage(w http.ResponseWriter, r *http.Request) {
	s.authPage(w, r, "Recover your account", &authPage{Mode: "recover"})
}

// ---- prelogin, sign-in, second factor

type preloginReq struct {
	Email string `json:"email"`
}

type preloginResp struct {
	KDF  vaultcrypto.KDF `json:"kdf"`
	Salt string          `json:"salt"`
}

// apiPrelogin tells the client how to derive the keys of an address.
func (s *Server) apiPrelogin(w http.ResponseWriter, r *http.Request) {
	var q preloginReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	if !s.guardOK(w, r, "") {
		return
	}
	k, salt, err := s.store.Prelogin(r.Context(), q.Email, s.policy(r.Context()).KDF)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, preloginResp{KDF: k, Salt: salt})
}

// guardOK refuses blocked addresses and throttled users.
func (s *Server) guardOK(w http.ResponseWriter, r *http.Request, email string) bool {
	if until := s.guard.blocked(r.Context(), clientIP(r)); !until.IsZero() {
		apiError(w, http.StatusTooManyRequests, "blocked", s.msg(r, "Too many failed attempts from your address. Try again after %s.", until.Local().Format("15:04")))
		return false
	}
	if s.guard.userThrottled(email) {
		apiError(w, http.StatusTooManyRequests, "blocked", s.msg(r, "Too many failed attempts for this account. Try again later."))
		return false
	}
	return true
}

type loginReq struct {
	Email string `json:"email"`
	Auth  string `json:"auth"`
}

type loginResp struct {
	Next string `json:"next"` // "2fa", "enroll" or "done"
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	var q loginReq
	if !readJSON(w, r, 2<<10, &q) {
		return
	}
	q.Email = strings.TrimSpace(q.Email)
	if !s.guardOK(w, r, q.Email) {
		if store.B64Len(q.Auth) == 32 {
			auth.BurnTime(q.Auth)
		}
		return
	}
	ip := clientIP(r)
	var u *store.User
	var err error
	if store.B64Len(q.Auth) == 32 {
		u, err = s.store.CheckAuth(r.Context(), q.Email, q.Auth)
	} else {
		err = store.ErrNotFound
	}
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		s.guard.fail(r.Context(), ip, q.Email, "master password")
		s.auditAs(r, q.Email, "login.failed", "user:"+q.Email, "wrong e-mail address or master password")
		apiError(w, http.StatusUnauthorized, "wrong", s.msg(r, "Wrong e-mail address or master password."))
		return
	}
	if s.DevNo2FA {
		x := &store.Session{UserID: u.ID, IP: ip, UserAgent: r.UserAgent()}
		if s.finishLogin(w, r, x, u, "master password only, test mode") {
			writeJSON(w, http.StatusOK, loginResp{Next: "done"})
		}
		return
	}
	tok, _, err := s.store.CreateSession(r.Context(), u.ID, store.StageMFA, store.MFATimeout, ip, r.UserAgent())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, tok, store.MFATimeout)
	next := "2fa"
	if !u.TOTPEnabled {
		next = "enroll"
	}
	writeJSON(w, http.StatusOK, loginResp{Next: next})
}

// mfaUser is the user of a verified sign-in waiting for its second factor.
func (s *Server) mfaUser(r *http.Request) (*store.Session, *store.User) {
	x := sessionFrom(r)
	if x == nil || x.Stage != store.StageMFA {
		return nil, nil
	}
	u, err := s.store.UserByID(r.Context(), x.UserID)
	if err != nil || u.Disabled {
		return nil, nil
	}
	return x, u
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, x *store.Session, u *store.User, how string) bool {
	sec := s.security(r.Context())
	life := time.Duration(sec.SessionHours) * time.Hour
	tok, err := s.store.PromoteSession(r.Context(), x, life)
	if err != nil {
		s.serverError(w, r, err)
		return false
	}
	s.setSessionCookie(w, r, tok, life)
	_ = s.store.MarkLogin(r.Context(), u.ID)
	s.guard.success(clientIP(r), u.Email)
	s.auditAs(r, u.Email, "login", "user:"+u.Email, "signed in (%s)", how)
	return true
}

type codeReq struct {
	Code string `json:"code"`
}

func (s *Server) apiLogin2FA(w http.ResponseWriter, r *http.Request) {
	x, u := s.mfaUser(r)
	if u == nil {
		apiError(w, http.StatusUnauthorized, "signed_out", s.msg(r, "The sign-in took too long. Start again."))
		return
	}
	var q codeReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	if !u.TOTPEnabled {
		apiError(w, http.StatusConflict, "enroll", "Set up two-factor sign-in first.")
		return
	}
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() || s.guard.userThrottled(u.Email) {
		_ = s.store.DeleteSession(r.Context(), x.Hash)
		s.clearSessionCookie(w, r)
		apiError(w, http.StatusTooManyRequests, "blocked", s.msg(r, "Too many failed attempts. Try again later."))
		return
	}
	ok, how, err := s.checkSecondFactor(r.Context(), u, q.Code)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.guard.fail(r.Context(), ip, u.Email, "second factor")
		s.auditAs(r, u.Email, "login.failed", "user:"+u.Email, "wrong second-factor code")
		apiError(w, http.StatusUnauthorized, "wrong", s.msg(r, "The code is wrong or was already used."))
		return
	}
	if s.finishLogin(w, r, x, u, how) {
		writeJSON(w, http.StatusOK, loginResp{Next: "done"})
	}
}

// checkSecondFactor accepts an authenticator code or a recovery code.
func (s *Server) checkSecondFactor(ctx context.Context, u *store.User, code string) (bool, string, error) {
	code = strings.TrimSpace(code)
	if len(strings.ReplaceAll(code, " ", "")) == 6 {
		tf, err := s.store.GetTwoFactor(ctx, u.ID)
		if err != nil {
			return false, "", err
		}
		if step, good := auth.TOTPVerify(tf.Secret, code, s.now(), tf.LastStep); good {
			ok, err := s.store.UseTOTPStep(ctx, u.ID, step)
			return ok, "authenticator code", err
		}
		return false, "", nil
	}
	if code == "" {
		return false, "", nil
	}
	ok, err := s.store.UseRecoveryCode(ctx, u.ID, code)
	return ok, "recovery code", err
}

type enrollResp struct {
	Secret string   `json:"secret"`
	URI    string   `json:"uri"`
	QR     *auth.QR `json:"qr"`
}

// apiEnrollStart begins the mandatory authenticator setup.
func (s *Server) apiEnrollStart(w http.ResponseWriter, r *http.Request) {
	_, u := s.mfaUser(r)
	if u == nil {
		apiError(w, http.StatusUnauthorized, "signed_out", s.msg(r, "The sign-in took too long. Start again."))
		return
	}
	if u.TOTPEnabled {
		apiError(w, http.StatusConflict, "enrolled", "Two-factor sign-in is already set up.")
		return
	}
	tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if tf.Secret == "" {
		tf.Secret = auth.NewTOTPSecret()
		if err := s.store.SetPendingTOTP(r.Context(), u.ID, tf.Secret); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	uri := auth.TOTPURI(tf.Secret, u.Email)
	qr, _ := auth.QRFor(uri)
	writeJSON(w, http.StatusOK, enrollResp{Secret: tf.Secret, URI: uri, QR: qr})
}

type enrollDone struct {
	Next  string   `json:"next"`
	Codes []string `json:"codes"`
}

func (s *Server) apiEnrollFinish(w http.ResponseWriter, r *http.Request) {
	x, u := s.mfaUser(r)
	if u == nil {
		apiError(w, http.StatusUnauthorized, "signed_out", s.msg(r, "The sign-in took too long. Start again."))
		return
	}
	var q codeReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := auth.TOTPVerify(tf.Secret, q.Code, s.now(), 0)
	if tf.Secret == "" || !ok {
		s.guard.fail(r.Context(), clientIP(r), u.Email, "second factor setup")
		apiError(w, http.StatusBadRequest, "wrong", s.msg(r, "The code is wrong. Check that the time of your phone is correct and try again."))
		return
	}
	plain, hashed := auth.NewRecoveryCodes()
	if err := s.store.EnableTOTP(r.Context(), u.ID, step, hashed); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.auditAs(r, u.Email, "2fa.enable", "user:"+u.Email, "authenticator app set up")
	if s.finishLogin(w, r, x, u, "new authenticator") {
		writeJSON(w, http.StatusOK, enrollDone{Next: "done", Codes: plain})
	}
}

// ---- account creation: first-run setup and invitations

type setupReq struct {
	Token string `json:"token"`
	store.NewAccount
}

// apiSetup creates the first administrator. It works only while there are
// no users and asks for the one-time token from the server's data
// directory, so nobody else on the network can claim a fresh server.
func (s *Server) apiSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.UserCount(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n > 0 {
		apiError(w, http.StatusConflict, "done", s.msg(r, "PassZit is already set up."))
		return
	}
	var q setupReq
	if !readJSON(w, r, 8<<10, &q) {
		return
	}
	if !s.guardOK(w, r, "") {
		return
	}
	if s.setupToken != "" && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(q.Token)), []byte(s.setupToken)) != 1 {
		s.guard.fail(r.Context(), clientIP(r), "", "setup token")
		apiError(w, http.StatusForbidden, "token", s.msg(r, "The setup token is wrong. It is in the file setup-token.txt in the server's data directory."))
		return
	}
	q.Role = store.RoleAdmin
	u, err := s.store.CreateAccount(r.Context(), q.NewAccount)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, storeErr(err)))
		return
	}
	s.setupToken = ""
	if s.SetupTokenFile != "" {
		_ = os.Remove(s.SetupTokenFile)
	}
	s.auditAs(r, u.Email, "setup", "user:"+u.Email, "first administrator created")
	s.log.Info("first administrator created", "user", u.Email, "ip", clientIP(r))
	s.afterAccount(w, r, u)
}

// afterAccount continues a new account with the second factor (or, on a
// test server without it, signs in).
func (s *Server) afterAccount(w http.ResponseWriter, r *http.Request, u *store.User) {
	x := &store.Session{UserID: u.ID, IP: clientIP(r), UserAgent: r.UserAgent()}
	if s.DevNo2FA {
		if s.finishLogin(w, r, x, u, "new account, test mode") {
			writeJSON(w, http.StatusOK, loginResp{Next: "done"})
		}
		return
	}
	tok, _, err := s.store.CreateSession(r.Context(), u.ID, store.StageMFA, 15*time.Minute, x.IP, x.UserAgent)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, tok, 15*time.Minute)
	writeJSON(w, http.StatusOK, loginResp{Next: "enroll"})
}

type inviteReq struct {
	Invite string `json:"invite"`
	store.NewAccount
}

// apiInvite creates an account from an invitation.
func (s *Server) apiInvite(w http.ResponseWriter, r *http.Request) {
	var q inviteReq
	if !readJSON(w, r, 8<<10, &q) {
		return
	}
	if !s.guardOK(w, r, "") {
		return
	}
	inv, err := s.store.InviteByToken(r.Context(), q.Invite)
	if err != nil {
		s.guard.fail(r.Context(), clientIP(r), "", "invitation")
		apiError(w, http.StatusNotFound, "invite", s.msg(r, "This invitation link does not work any more. Ask your administrator for a new one."))
		return
	}
	if !strings.EqualFold(strings.TrimSpace(q.Email), inv.Email) {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, "The invitation is for another e-mail address."))
		return
	}
	q.Role, q.InviteID = inv.Role, inv.ID
	u, err := s.store.CreateAccount(r.Context(), q.NewAccount)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			err = uiMsg("This invitation link does not work any more. Ask your administrator for a new one.")
		}
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, storeErr(err)))
		return
	}
	s.auditAs(r, u.Email, "user.create", "user:"+u.Email, "account created from the invitation of %s", inv.CreatedBy)
	s.afterAccount(w, r, u)
}

// ---- account recovery with the recovery key

type recoverStartReq struct {
	Email        string `json:"email"`
	RecoveryAuth string `json:"recovery_auth"`
	Code         string `json:"code"`
}

type recoverStartResp struct {
	Ticket             string          `json:"ticket"`
	RecoveryWrappedKey string          `json:"recovery_wrapped_key"`
	KDF                vaultcrypto.KDF `json:"kdf"`
}

// recoveryTickets are short-lived proofs that a recovery key (and the
// second factor) were checked; finishing needs one.
type recoveryTicket struct {
	user  int64
	until time.Time
}

var (
	ticketsMu sync.Mutex
	tickets   = map[string]recoveryTicket{}
)

func (s *Server) apiRecoverStart(w http.ResponseWriter, r *http.Request) {
	var q recoverStartReq
	if !readJSON(w, r, 2<<10, &q) {
		return
	}
	if !s.guardOK(w, r, q.Email) {
		return
	}
	fail := func() {
		s.guard.fail(r.Context(), clientIP(r), q.Email, "recovery key")
		s.auditAs(r, q.Email, "recover.failed", "user:"+q.Email, "wrong recovery key or code")
		apiError(w, http.StatusUnauthorized, "wrong", s.msg(r, "The e-mail address, the recovery key or the code is wrong."))
	}
	if store.B64Len(q.RecoveryAuth) != 32 {
		fail()
		return
	}
	u, err := s.store.CheckRecovery(r.Context(), q.Email, q.RecoveryAuth)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		fail()
		return
	}
	if !s.DevNo2FA && u.TOTPEnabled {
		ok, _, err := s.checkSecondFactor(r.Context(), u, q.Code)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if !ok {
			fail()
			return
		}
	}
	k, err := s.store.AccountKeysOf(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	t := auth.RandomToken(24)
	ticketsMu.Lock()
	for id, x := range tickets {
		if s.now().After(x.until) {
			delete(tickets, id)
		}
	}
	tickets[t] = recoveryTicket{user: u.ID, until: s.now().Add(10 * time.Minute)}
	ticketsMu.Unlock()
	writeJSON(w, http.StatusOK, recoverStartResp{Ticket: t, RecoveryWrappedKey: k.RecoveryWrappedKey, KDF: s.policy(r.Context()).KDF})
}

type recoverFinishReq struct {
	Ticket string `json:"ticket"`
	store.Keys
}

func (s *Server) apiRecoverFinish(w http.ResponseWriter, r *http.Request) {
	var q recoverFinishReq
	if !readJSON(w, r, 4<<10, &q) {
		return
	}
	ticketsMu.Lock()
	t, ok := tickets[q.Ticket]
	delete(tickets, q.Ticket)
	ticketsMu.Unlock()
	if !ok || s.now().After(t.until) {
		apiError(w, http.StatusUnauthorized, "expired", s.msg(r, "The recovery took too long. Start again."))
		return
	}
	u, err := s.store.UserByID(r.Context(), t.user)
	if err != nil {
		apiError(w, http.StatusUnauthorized, "expired", s.msg(r, "The recovery took too long. Start again."))
		return
	}
	if err := s.store.SetMasterKeys(r.Context(), u.ID, q.Keys, ""); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, storeErr(err)))
		return
	}
	s.auditAs(r, u.Email, "recover", "user:"+u.Email, "new master password set with the recovery key; all sessions ended")
	writeJSON(w, http.StatusOK, loginResp{Next: "login"})
}

// ---- sign-out and language

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if x := sessionFrom(r); x != nil {
		_ = s.store.DeleteSession(r.Context(), x.Hash)
		if u := userFrom(r); u != nil {
			s.audit(r, "logout", "user:"+u.Email, "signed out")
		}
	}
	s.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleLang(w http.ResponseWriter, r *http.Request) {
	l := r.FormValue("lang")
	if !validLang(l) {
		http.Error(w, "unknown language", http.StatusBadRequest)
		return
	}
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: "lang", Value: l, Path: "/", MaxAge: 365 * 86400, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, HttpOnly: true})
	if u := userFrom(r); u != nil {
		_ = s.store.SetLang(r.Context(), u.ID, l)
	}
	back := "/vault"
	if ref, err := urlPath(r.Referer()); err == nil {
		back = safeNext(ref)
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---- brute-force protection

// loginGuard counts failed sign-ins per address and per account in
// memory. An address that reaches the limit is blocked in the database
// (so a restart does not release it), each repeated block within a day
// twice as long. An account that fails too often from many addresses is
// only throttled for the window, so a guesser cannot lock a user out for
// long. Loopback is never blocked: the server's own console must always work.
type loginGuard struct {
	store *store.Store
	now   func() time.Time
	cfg   func(ctx context.Context) SecuritySettings

	mu    sync.Mutex
	ips   map[string][]time.Time
	users map[string][]time.Time
}

const maxBlock = 7 * 24 * time.Hour

func newLoginGuard(st *store.Store, now func() time.Time) *loginGuard {
	return &loginGuard{store: st, now: now, ips: map[string][]time.Time{}, users: map[string][]time.Time{}}
}

func (g *loginGuard) settings(ctx context.Context) SecuritySettings {
	if g.cfg != nil {
		return g.cfg(ctx)
	}
	x := DefaultSecurity
	if err := g.store.GetSetting(ctx, settingSecurity, &x); err != nil || x.Validate() != nil {
		return DefaultSecurity
	}
	return x
}

func isLoopback(ip string) bool {
	a, ok := netacl.AddrOf(ip)
	return ok && a.IsLoopback()
}

func prune(list []time.Time, since time.Time) []time.Time {
	out := list[:0]
	for _, t := range list {
		if t.After(since) {
			out = append(out, t)
		}
	}
	return out
}

func (g *loginGuard) blocked(ctx context.Context, ip string) time.Time {
	if isLoopback(ip) {
		return time.Time{}
	}
	until, err := g.store.BlockedUntil(ctx, ip)
	if err != nil {
		return time.Time{}
	}
	return until
}

func (g *loginGuard) userThrottled(username string) bool {
	if username == "" {
		return false
	}
	cfg := g.settings(context.Background())
	g.mu.Lock()
	defer g.mu.Unlock()
	k := strings.ToLower(username)
	g.users[k] = prune(g.users[k], g.now().Add(-time.Duration(cfg.WindowMinutes)*time.Minute))
	return len(g.users[k]) >= 4*cfg.MaxAttempts
}

func (g *loginGuard) fail(ctx context.Context, ip, username, reason string) {
	cfg := g.settings(ctx)
	since := g.now().Add(-time.Duration(cfg.WindowMinutes) * time.Minute)
	g.mu.Lock()
	if username != "" {
		k := strings.ToLower(username)
		g.users[k] = append(prune(g.users[k], since), g.now())
	}
	var block bool
	if !isLoopback(ip) {
		g.ips[ip] = append(prune(g.ips[ip], since), g.now())
		if len(g.ips[ip]) >= cfg.MaxAttempts {
			block = true
			delete(g.ips, ip)
		}
	}
	g.mu.Unlock()
	if block {
		d := func(strikes int) time.Duration {
			b := time.Duration(cfg.BlockMinutes) * time.Minute
			for i := 1; i < strikes && b < maxBlock; i++ {
				b *= 2
			}
			return min(b, maxBlock)
		}
		_, _ = g.store.BlockIP(ctx, ip, d, reason)
		_ = g.store.Audit(ctx, "-", ip, "login.blocked", "ip:"+ip, "address blocked after failed sign-ins ("+reason+")")
	}
}

func (g *loginGuard) success(ip, username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.ips, ip)
	delete(g.users, strings.ToLower(username))
}

// urlPath returns the path and query of a same-site URL (the Referer).
func urlPath(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery, nil
	}
	return u.Path, nil
}
