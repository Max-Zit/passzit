package web

import (
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/webauthn"
)

// ---- security keys and passkeys as a second factor (WebAuthn)

// challenges are kept per session for a few minutes; each is used once.
type challengeStore struct {
	mu sync.Mutex
	m  map[string]challenge
}

type challenge struct {
	value   []byte
	purpose string
	expires time.Time
}

func (c *challengeStore) put(session, purpose string, now time.Time) []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]challenge{}
	}
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[session] = challenge{value: b, purpose: purpose, expires: now.Add(5 * time.Minute)}
	return b
}

func (c *challengeStore) take(session, purpose string, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[session]
	delete(c.m, session)
	if !ok || v.purpose != purpose || now.After(v.expires) {
		return nil
	}
	return v.value
}

// relyingParty is the site name keys are bound to (the host) and the
// origins a browser may report.
func (s *Server) relyingParty(r *http.Request) (string, []string) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http" // the loopback development console
	}
	origins := []string{scheme + "://" + r.Host}
	if n, err := s.Network(r.Context()); err == nil && n.PublicURL != "" {
		if u, err := url.Parse(n.PublicURL); err == nil {
			origins = append(origins, u.Scheme+"://"+u.Host)
			if u.Hostname() != host {
				// Signed in through the public address: keys belong to it.
				host = u.Hostname()
				origins = []string{u.Scheme + "://" + u.Host}
			}
		}
	}
	return host, origins
}

type credDesc struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type createOptions struct {
	Challenge string     `json:"challenge"`
	RPID      string     `json:"rp_id"`
	RPName    string     `json:"rp_name"`
	UserID    string     `json:"user_id"`
	UserName  string     `json:"user_name"`
	Algs      []int      `json:"algs"`
	Exclude   []credDesc `json:"exclude"`
}

func (s *Server) apiKeyRegisterStart(w http.ResponseWriter, r *http.Request) {
	u, x := userFrom(r), sessionFrom(r)
	if x.Kind != store.KindWeb {
		apiError(w, http.StatusForbidden, "forbidden", s.msg(r, "Add security keys in the web vault."))
		return
	}
	keys, err := s.store.SecurityKeys(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rp, _ := s.relyingParty(r)
	o := createOptions{Challenge: webauthn.B64.EncodeToString(s.challenges.put(x.Hash, "register", s.now())), RPID: rp, RPName: "PassZit",
		UserName: u.Email, Algs: webauthn.Algorithms, Exclude: []credDesc{}}
	h := make([]byte, 16)
	_, _ = rand.Read(h)
	o.UserID = webauthn.B64.EncodeToString(h)
	for _, k := range keys {
		o.Exclude = append(o.Exclude, credDesc{Type: "public-key", ID: k.ID})
	}
	writeJSON(w, http.StatusOK, o)
}

type keyRegisterReq struct {
	Name string                `json:"name"`
	Reg  webauthn.Registration `json:"registration"`
}

func (s *Server) apiKeyRegister(w http.ResponseWriter, r *http.Request) {
	u, x := userFrom(r), sessionFrom(r)
	var q keyRegisterReq
	if !readJSON(w, r, 64<<10, &q) {
		return
	}
	ch := s.challenges.take(x.Hash, "register", s.now())
	rp, origins := s.relyingParty(r)
	cred, err := webauthn.VerifyRegistration(q.Reg, ch, rp, origins)
	if err != nil {
		s.log.Info("security key registration refused", "user", u.Email, "err", err)
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, "The security key could not be registered. Try again."))
		return
	}
	k := store.SecurityKey{ID: webauthn.B64.EncodeToString(cred.ID), Name: q.Name, PublicKey: cred.PublicKey, Alg: cred.Alg, SignCount: cred.SignCount}
	if err := s.store.AddSecurityKey(r.Context(), u.ID, k); err != nil {
		if errors.Is(err, store.ErrConflict) {
			apiError(w, http.StatusConflict, "exists", s.msg(r, "This security key is registered already."))
			return
		}
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, err.Error()))
		return
	}
	s.audit(r, "2fa.key.add", "user:"+u.Email, "security key %q registered", q.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type getOptions struct {
	Challenge string     `json:"challenge"`
	RPID      string     `json:"rp_id"`
	Allow     []credDesc `json:"allow"`
}

// apiKeyLoginStart offers the second step with a security key (after the
// master password).
func (s *Server) apiKeyLoginStart(w http.ResponseWriter, r *http.Request) {
	x, u := s.mfaUser(r)
	if u == nil {
		apiError(w, http.StatusUnauthorized, "signed_out", s.msg(r, "The sign-in took too long. Start again."))
		return
	}
	keys, err := s.store.SecurityKeys(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(keys) == 0 {
		apiError(w, http.StatusNotFound, "none", s.msg(r, "You have no security key. Use the code of your authenticator app."))
		return
	}
	rp, _ := s.relyingParty(r)
	o := getOptions{Challenge: webauthn.B64.EncodeToString(s.challenges.put(x.Hash, "login", s.now())), RPID: rp}
	for _, k := range keys {
		o.Allow = append(o.Allow, credDesc{Type: "public-key", ID: k.ID})
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) apiKeyLogin(w http.ResponseWriter, r *http.Request) {
	x, u := s.mfaUser(r)
	if u == nil {
		apiError(w, http.StatusUnauthorized, "signed_out", s.msg(r, "The sign-in took too long. Start again."))
		return
	}
	var q webauthn.Assertion
	if !readJSON(w, r, 64<<10, &q) {
		return
	}
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() || s.guard.userThrottled(u.Email) {
		apiError(w, http.StatusTooManyRequests, "blocked", s.msg(r, "Too many failed attempts. Try again later."))
		return
	}
	ch := s.challenges.take(x.Hash, "login", s.now())
	keys, err := s.store.SecurityKeys(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rp, origins := s.relyingParty(r)
	for _, k := range keys {
		if k.ID != q.ID {
			continue
		}
		n, err := webauthn.VerifyAssertion(q, webauthn.Credential{PublicKey: k.PublicKey, Alg: k.Alg, SignCount: k.SignCount}, ch, rp, origins)
		if err != nil {
			s.log.Info("security key sign-in refused", "user", u.Email, "err", err)
			break
		}
		if err := s.store.UseSecurityKey(r.Context(), u.ID, k.ID, n); err != nil {
			s.serverError(w, r, err)
			return
		}
		if s.finishLogin(w, r, x, u, "security key "+k.Name) {
			writeJSON(w, http.StatusOK, loginResp{Next: "done"})
		}
		return
	}
	s.guard.fail(r.Context(), ip, u.Email, "security key")
	s.auditAs(r, u.Email, "login.failed", "user:"+u.Email, "security key refused")
	apiError(w, http.StatusUnauthorized, "wrong", s.msg(r, "The security key was not accepted."))
}

func (s *Server) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if err := s.store.DeleteSecurityKey(r.Context(), u.ID, r.FormValue("id")); err != nil {
		s.redirectErr(w, r, "/account", "Not found.")
		return
	}
	s.audit(r, "2fa.key.remove", "user:"+u.Email, "security key removed")
	s.redirect(w, r, "/account", "The security key is removed.")
}
