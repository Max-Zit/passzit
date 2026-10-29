// Package web is the PassZit server's web side: the console pages, the web
// vault (its JavaScript does all the cryptography in the browser) and the
// JSON API the vault clients use. The server only ever handles ciphertext
// and the auth key's hash.
package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/netacl"
	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// Server serves the console and the vault API.
type Server struct {
	store      *store.Store
	log        *slog.Logger
	tmpl       map[string]*template.Template
	now        func() time.Time
	guard      *loginGuard
	challenges challengeStore
	sso        ssoCache

	// MgmtACL guards the console listener.
	MgmtACL *netacl.List
	// RunningMgmt is the listen address the server actually uses.
	RunningMgmt string
	// ListenOverride: the address comes from a command-line option.
	ListenOverride bool
	Version        string
	// SetupTokenFile holds the one-time token the first-run setup asks for.
	SetupTokenFile string
	// DevNo2FA skips the second factor (development and demo servers only).
	DevNo2FA   bool
	setupToken string
	// DataDir is the server's data directory.
	DataDir string
	// HelperAvailable replaces the check for the root helper (tests).
	HelperAvailable func() bool
	upd             updateState
	backups         backupRunner
}

// New creates the server; settings are loaded from the database.
func New(ctx context.Context, st *store.Store, log *slog.Logger) (*Server, error) {
	t, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{store: st, log: log, tmpl: t, now: time.Now, Version: "dev"}
	s.guard = newLoginGuard(st, func() time.Time { return s.now() })
	n, err := s.Network(ctx)
	if err != nil {
		return nil, err
	}
	mg, _ := netacl.Parse(n.MgmtAllowed)
	s.MgmtACL = netacl.NewManagement(mg)
	return s, nil
}

// SetClock replaces the clock (tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// SetSetupToken sets the token the first-run setup requires.
func (s *Server) SetSetupToken(tok string) { s.setupToken = tok }

// ---- network settings

const settingNetwork = "network"

// NetworkSettings are the console listener and who may reach it.
type NetworkSettings struct {
	// MgmtListen is the console address, e.g. ":8443" or "192.168.1.10:8443".
	MgmtListen string `json:"mgmt_listen"`
	// MgmtAllowed may reach the console (loopback always may).
	MgmtAllowed []string `json:"mgmt_allowed"`
	// PublicURL is how users and extensions reach the server, e.g.
	// "https://vault.example.com" (used in invitation links). Empty: the
	// address the administrator's browser uses.
	PublicURL string `json:"public_url,omitempty"`
}

// defaultNetwork is used until the settings are saved (a fresh copy each
// time: JSON decoding into it must not change the package defaults).
func defaultNetwork() NetworkSettings {
	return NetworkSettings{MgmtListen: ":8443", MgmtAllowed: append([]string(nil), netacl.DefaultManagement...)}
}

// Validate checks the listen address, the networks and the public address.
func (n *NetworkSettings) Validate() error {
	if _, _, err := splitListen(n.MgmtListen); err != nil {
		return fmt.Errorf("console address: %w", err)
	}
	if _, err := netacl.Parse(n.MgmtAllowed); err != nil {
		return err
	}
	if n.PublicURL != "" {
		u, err := url.Parse(n.PublicURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
			return errors.New("the public address must look like https://vault.example.com")
		}
		n.PublicURL = strings.TrimSuffix(n.PublicURL, "/")
	}
	return nil
}

func splitListen(a string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(a))
	if err != nil {
		return "", 0, errors.New("use host:port or :port, e.g. :8443")
	}
	port, err = strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("the port must be 1–65535")
	}
	if h != "" {
		if _, err := netip.ParseAddr(h); err != nil {
			return "", 0, errors.New("the host must be an IP address of this server (or empty for all)")
		}
	}
	return h, port, nil
}

// Network loads the network settings.
func (s *Server) Network(ctx context.Context) (NetworkSettings, error) {
	n := defaultNetwork()
	if err := s.store.GetSetting(ctx, settingNetwork, &n); err != nil {
		return n, err
	}
	if n.Validate() != nil {
		s.log.Warn("invalid network settings in the database; using defaults")
		n = defaultNetwork()
	}
	return n, nil
}

// SaveNetwork stores the settings and applies the allow-list at once.
func (s *Server) SaveNetwork(ctx context.Context, n NetworkSettings) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingNetwork, n); err != nil {
		return err
	}
	mg, _ := netacl.Parse(n.MgmtAllowed)
	s.MgmtACL.Set(mg)
	return nil
}

// ResetMgmtAllowList restores the default console networks (CLI, for an
// administrator who locked themselves out).
func ResetMgmtAllowList(ctx context.Context, st *store.Store) error {
	n := defaultNetwork()
	if err := st.GetSetting(ctx, settingNetwork, &n); err != nil {
		return err
	}
	n.MgmtAllowed = append([]string(nil), netacl.DefaultManagement...)
	if n.Validate() != nil {
		n = defaultNetwork()
	}
	return st.SetSetting(ctx, settingNetwork, n)
}

// ---- security settings

const settingSecurity = "security"

// SecuritySettings control sessions and the brute-force protection.
type SecuritySettings struct {
	SessionHours int `json:"session_hours"`
	IdleMinutes  int `json:"idle_minutes"`
	// MaxAttempts failed sign-ins of one address within WindowMinutes
	// block it for BlockMinutes (doubling for repeated blocks in a day).
	MaxAttempts   int `json:"max_attempts"`
	WindowMinutes int `json:"window_minutes"`
	BlockMinutes  int `json:"block_minutes"`
	// InviteDays is how long an invitation link works.
	InviteDays int `json:"invite_days"`
	// ExtDays is how long a browser extension stays signed in;
	// ExtIdleDays ends it earlier when it is not used.
	ExtDays     int `json:"ext_days"`
	ExtIdleDays int `json:"ext_idle_days"`
}

// DefaultSecurity: a password manager keeps sessions short.
var DefaultSecurity = SecuritySettings{SessionHours: 8, IdleMinutes: 30, MaxAttempts: 5, WindowMinutes: 15, BlockMinutes: 30, InviteDays: 7, ExtDays: 30, ExtIdleDays: 14}

// Validate checks the ranges.
func (x SecuritySettings) Validate() error {
	switch {
	case x.SessionHours < 1 || x.SessionHours > 24:
		return errors.New("the session length must be 1–24 hours")
	case x.IdleMinutes < 5 || x.IdleMinutes > 720:
		return errors.New("the inactivity timeout must be 5–720 minutes")
	case x.MaxAttempts < 3 || x.MaxAttempts > 50:
		return errors.New("failed attempts must be 3–50")
	case x.WindowMinutes < 1 || x.WindowMinutes > 1440:
		return errors.New("the counting period must be 1–1440 minutes")
	case x.BlockMinutes < 1 || x.BlockMinutes > 10080:
		return errors.New("the block must last 1–10080 minutes")
	case x.InviteDays < 1 || x.InviteDays > 30:
		return errors.New("invitations must be valid for 1–30 days")
	case x.ExtDays < 1 || x.ExtDays > 365 || x.ExtIdleDays < 1 || x.ExtIdleDays > x.ExtDays:
		return errors.New("extensions must stay signed in 1–365 days, and the idle limit must not be longer")
	}
	return nil
}

func (s *Server) security(ctx context.Context) SecuritySettings {
	x := DefaultSecurity
	if err := s.store.GetSetting(ctx, settingSecurity, &x); err != nil || x.Validate() != nil {
		return DefaultSecurity
	}
	return x
}

// ---- vault policy

const settingPolicy = "policy"

// Policy are the vault rules for all users. Users may choose shorter
// lock and clipboard times for themselves, not longer ones.
type Policy struct {
	// LockMinutes: the vault locks after this much inactivity.
	LockMinutes int `json:"lock_minutes"`
	// ClipboardSeconds: copied passwords are cleared after this time.
	ClipboardSeconds int `json:"clipboard_seconds"`
	// KDF for new accounts and master-password changes; older accounts
	// are upgraded at their next unlock.
	KDF vaultcrypto.KDF `json:"kdf"`
	// MinPasswordLength of master passwords.
	MinPasswordLength int `json:"min_password_length"`
	// TrashDays: items in the trash are deleted after this time.
	TrashDays int `json:"trash_days"`
	// MaxFileMB limits one attached file, StorageMB all files of a user.
	MaxFileMB int `json:"max_file_mb"`
	StorageMB int `json:"storage_mb"`
	// BreachCheck lets browsers check passwords against the Have I Been
	// Pwned list (k-anonymity: only 5 characters of a hash leave the server).
	BreachCheck bool `json:"breach_check"`
	// SharedAdminsOnly: only administrators create shared vaults.
	SharedAdminsOnly bool `json:"shared_admins_only,omitempty"`
	// NoExport: users may not export their vaults (the web vault and the
	// extension refuse it; a member who can read items can still copy them).
	NoExport bool `json:"no_export,omitempty"`
}

// DefaultPolicy: lock after 15 minutes, clear the clipboard after 30 s,
// Argon2id with 64 MiB, 3 passes, 4 lanes.
var DefaultPolicy = Policy{LockMinutes: 15, ClipboardSeconds: 30, KDF: vaultcrypto.DefaultKDF, MinPasswordLength: 12, TrashDays: 30, MaxFileMB: 10, StorageMB: 500}

// Validate checks the ranges.
func (p Policy) Validate() error {
	switch {
	case p.LockMinutes < 1 || p.LockMinutes > 480:
		return errors.New("the vault must lock after 1–480 minutes")
	case p.ClipboardSeconds < 5 || p.ClipboardSeconds > 600:
		return errors.New("the clipboard must be cleared after 5–600 seconds")
	case p.MinPasswordLength < 10 || p.MinPasswordLength > 64:
		return errors.New("the minimum master password length must be 10–64")
	case p.TrashDays < 1 || p.TrashDays > 365:
		return errors.New("the trash must keep items for 1–365 days")
	case p.MaxFileMB < 1 || p.MaxFileMB > 100 || p.StorageMB < p.MaxFileMB || p.StorageMB > 100000:
		return errors.New("files may be 1–100 MB, the storage of a user at least one file and at most 100000 MB")
	}
	return p.KDF.Validate()
}

func (s *Server) policy(ctx context.Context) Policy {
	p := DefaultPolicy
	if err := s.store.GetSetting(ctx, settingPolicy, &p); err != nil || p.Validate() != nil {
		return DefaultPolicy
	}
	return p
}

// clientPrefs are the effective lock and clipboard times of a user.
func (s *Server) clientPrefs(ctx context.Context, u *store.User) (lock, clip int) {
	p := s.policy(ctx)
	lock, clip = p.LockMinutes, p.ClipboardSeconds
	if u.Prefs.LockMinutes > 0 && u.Prefs.LockMinutes < lock {
		lock = u.Prefs.LockMinutes
	}
	if u.Prefs.ClipboardSeconds > 0 && u.Prefs.ClipboardSeconds < clip {
		clip = u.Prefs.ClipboardSeconds
	}
	return lock, clip
}

// ---- handlers

// Handler is the console with the vault and its API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(gzipStatic(sub, http.FileServer(http.FS(sub))))))
	mux.HandleFunc("GET /sw.js", func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(sub, "sw.js")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /i18n/{lang}", s.handleI18n)

	// Pages without a session: the JavaScript on them talks to /api/….
	mux.HandleFunc("GET /setup", s.handleSetupPage)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /invite/{token}", s.handleInvitePage)
	mux.HandleFunc("GET /recover", s.handleRecoverPage)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("POST /lang", s.handleLang)
	mux.HandleFunc("POST /api/prelogin", s.apiPrelogin)
	mux.HandleFunc("POST /api/setup", s.apiSetup)
	mux.HandleFunc("POST /api/invite", s.apiInvite)
	mux.HandleFunc("POST /api/login", s.apiLogin)
	mux.HandleFunc("POST /api/login/2fa", s.apiLogin2FA)
	mux.HandleFunc("POST /api/login/key/start", s.apiKeyLoginStart)
	mux.HandleFunc("POST /api/login/key", s.apiKeyLogin)
	mux.HandleFunc("GET /login/sso", s.handleSSOStart)
	mux.HandleFunc("GET /login/sso/callback", s.handleOIDCCallback)
	mux.HandleFunc("POST /login/sso/saml", s.handleSAMLACS)
	mux.HandleFunc("GET /login/sso/metadata", s.handleSAMLMetadata)
	mux.HandleFunc("GET /api/login/enroll", s.apiEnrollStart)
	mux.HandleFunc("POST /api/login/enroll", s.apiEnrollFinish)
	mux.HandleFunc("POST /api/recover/start", s.apiRecoverStart)
	mux.HandleFunc("POST /api/recover/finish", s.apiRecoverFinish)
	mux.HandleFunc("POST /api/ext/prelogin", s.apiPrelogin)
	mux.HandleFunc("POST /api/ext/login", s.apiExtLogin)
	mux.HandleFunc("POST /api/ext/login/2fa", s.apiExtLogin2FA)

	app := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(h)) }
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireAdmin(h))) }
	api := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireAPIUser(h)) }

	app("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/vault", http.StatusFound) })
	app("GET /vault", s.handleVault)
	app("GET /generator", s.handleGenerator)
	app("GET /account", s.handleAccount)
	app("POST /account/profile", s.handleAccountProfile)
	app("POST /account/codes", s.handleAccountCodes)
	app("POST /account/sessions/signout", s.handleAccountSignout)
	app("POST /account/keys/delete", s.handleKeyDelete)
	app("POST /account/sessions/{id}/signout", s.handleSessionSignout)
	app("GET /docs", s.handleDocs)
	app("GET /docs/search", s.handleDocsSearch)
	app("GET /docs/{page}", s.handleDocs)

	api("GET /api/account", s.apiAccount)
	api("POST /api/ext/logout", s.apiExtLogout)
	api("GET /api/session/key", s.apiSessionKey)
	api("POST /api/session/lock", s.apiSessionLock)
	api("POST /api/account/password", s.apiChangePassword)
	api("POST /api/account/kdf", s.apiUpgradeKDF)
	api("POST /api/account/recovery", s.apiSetRecovery)
	api("POST /api/account/verify", s.apiVerify)
	api("POST /api/account/event", s.apiEvent)
	api("GET /api/sync", s.apiSync)
	api("GET /api/revision", s.apiRevision)
	api("POST /api/items", s.apiPutItems)
	api("PUT /api/items/{item}/files/{id}", s.apiPutAttachment)
	api("GET /api/files/{id}", s.apiGetAttachment)
	api("DELETE /api/files/{id}", s.apiDeleteAttachment)
	api("GET /api/storage", s.apiStorage)
	api("GET /api/breach/{prefix}", s.apiBreach)
	api("PUT /api/items/{id}", s.apiPutItem)
	api("POST /api/items/{id}/trash", s.apiTrashItem)
	api("POST /api/items/{id}/restore", s.apiRestoreItem)
	api("DELETE /api/items/{id}", s.apiPurgeItem)
	api("POST /api/account/keys/start", s.apiKeyRegisterStart)
	api("POST /api/account/keys", s.apiKeyRegister)
	api("GET /api/directory", s.apiDirectory)
	api("GET /api/groups", s.apiGroups)
	api("POST /api/vaults", s.apiCreateVault)
	api("GET /api/vaults/pending", s.apiPendingAccess)
	api("PUT /api/vaults/{id}", s.apiRenameVault)
	api("DELETE /api/vaults/{id}", s.apiDeleteVault)
	api("GET /api/vaults/{id}/members", s.apiVaultMembers)
	api("PUT /api/vaults/{id}/members", s.apiPutMember)
	api("DELETE /api/vaults/{id}/members/{user}", s.apiRemoveMember)
	api("POST /api/vaults/{id}/rotate", s.apiRotateVault)
	api("PUT /api/vaults/{id}/groups", s.apiPutVaultGroup)
	api("DELETE /api/vaults/{id}/groups/{group}", s.apiRemoveVaultGroup)
	api("POST /api/items/{id}/move", s.apiMoveItem)
	api("GET /api/account/known-keys", s.apiKnownKeys)
	api("PUT /api/account/known-keys", s.apiSetKnownKeys)
	api("PUT /api/folders/{id}", s.apiPutFolder)
	api("DELETE /api/folders/{id}", s.apiDeleteFolder)

	admin("GET /users", s.handleUsers)
	admin("POST /users/invite", s.handleInviteCreate)
	admin("POST /users/invites/{id}/delete", s.handleInviteDelete)
	admin("GET /users/{id}", s.handleUser)
	admin("POST /users/{id}", s.handleUserUpdate)
	admin("POST /users/{id}/reset-2fa", s.handleUserReset2FA)
	admin("POST /users/{id}/delete", s.handleUserDelete)
	admin("GET /groups", s.handleGroups)
	admin("GET /groups/{id}", s.handleGroup)
	admin("POST /groups/{id}", s.handleGroupSave)
	admin("POST /groups/{id}/delete", s.handleGroupDelete)
	admin("GET /audit", s.handleAudit)
	admin("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/policy", http.StatusFound)
	})
	admin("GET /settings/policy", s.handlePolicy)
	admin("POST /settings/policy", s.handlePolicySave)
	admin("GET /settings/network", s.handleNetwork)
	admin("POST /settings/network", s.handleNetworkSave)
	admin("GET /settings/version", s.handleVersion)
	admin("POST /settings/version/check", s.handleVersionCheck)
	admin("POST /settings/version/install", s.handleVersionInstall)
	admin("POST /settings/version/settings", s.handleVersionSettings)
	admin("POST /settings/timezone", s.handleTimeZone)
	admin("POST /settings/restart", s.handleRestart)
	admin("POST /settings/server-network", s.handleServerNetwork)
	admin("GET /settings/directory", s.handleDirectory)
	admin("POST /settings/directory/sso", s.handleSSOSave)
	admin("POST /settings/directory/ldap", s.handleLDAPSave)
	admin("POST /settings/directory/ldap/test", s.handleLDAPTest)
	admin("GET /settings/backup", s.handleBackupSettings)
	admin("POST /settings/backup", s.handleBackupSave)
	admin("POST /settings/backup/run", s.handleBackupRun)
	admin("POST /settings/backup/test", s.handleBackupTest)
	admin("POST /settings/backup/delete", s.handleBackupDelete)
	admin("GET /settings/backup/file/{name}", s.handleBackupDownload)
	admin("GET /settings/security", s.handleSecurity)
	admin("POST /settings/security", s.handleSecuritySave)
	admin("POST /settings/security/unblock", s.handleUnblock)

	return s.secure(s.aclCheck(s.MgmtACL, s.csrf(s.loadSession(mux))))
}

// cacheStatic: files requested with the asset version (?v=…) never change
// under that address; the scripts import each other without it, so those
// are checked again on every load.
func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// csp allows only the server's own files; 'wasm-unsafe-eval' lets the page
// compile the Argon2id WebAssembly module (it does not allow eval).
const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// secure sets the security headers of every response.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin (not no-referrer): browsers then still send a real
		// Origin header on form posts, which the CSRF check needs.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp") // everything the console loads is its own
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// aclCheck repeats the listener's address check per request (defense in
// depth, and the dev HTTP listener has no listener check).
func (s *Server) aclCheck(l *netacl.List, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.AllowsAddr(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrf refuses state-changing requests that do not come from a page of
// this server: the Origin (or, without it, the Referer) must match the
// Host, and Sec-Fetch-Site, where sent, must be same-origin. Extensions
// sign in and call the API with a bearer token instead of a cookie, from
// their own origin: those requests carry no ambient credentials, so they
// are not checked.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if extRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			s.log.Warn("cross-site request refused", "ip", clientIP(r), "path", r.URL.Path, "origin", r.Header.Get("Origin"))
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	want := scheme + "://" + r.Host
	if o := r.Header.Get("Origin"); o != "" {
		return o == want
	}
	ref := r.Header.Get("Referer")
	return ref != "" && (ref == want || strings.HasPrefix(ref, want+"/"))
}

// clientIP is the address of the direct peer (no proxy support yet).
func clientIP(r *http.Request) string {
	if a, ok := netacl.AddrOf(r.RemoteAddr); ok {
		return a.String()
	}
	return r.RemoteAddr
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "notfound", &Page{Title: "Not found"})
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusForbidden, "forbidden", &Page{Title: "Not allowed"})
}

func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

// audit records an action of the signed-in user.
func (s *Server) audit(r *http.Request, action, target, format string, args ...any) {
	name := "-"
	if u := userFrom(r); u != nil {
		name = u.Email
	}
	s.auditAs(r, name, action, target, format, args...)
}

func (s *Server) auditAs(r *http.Request, user, action, target, format string, args ...any) {
	detail := format
	if len(args) > 0 {
		detail = fmt.Sprintf(format, args...)
	}
	if err := s.store.Audit(r.Context(), user, clientIP(r), action, target, detail); err != nil {
		s.log.Error("audit log write failed", "action", action, "err", err)
	}
}

// storeErr turns a store error into a message for the user.
func storeErr(err error) string {
	switch {
	case errors.Is(err, store.ErrConflict):
		return "The address is already used."
	case errors.Is(err, store.ErrNotFound):
		return "Not found."
	}
	return err.Error()
}

// RunHousekeeping empties old trash, forgets old removals and starts the
// scheduled console backup.
func (s *Server) RunHousekeeping(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	// Backups are checked every 5 minutes, the trash and sessions hourly
	// (and at the start).
	for first := true; ; first = false {
		s.RunBackups(ctx)
		if n, err := s.store.ExpireMemberships(ctx); err != nil {
			s.log.Warn("ending time-limited access failed", "err", err)
		} else if n > 0 {
			_ = s.store.Audit(ctx, "-", "local", "vault.member.expire", "vaults", fmt.Sprintf("time-limited access ended for %d membership(s)", n))
		}
		if !first && s.now().Minute() >= 5 {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			continue
		}
		days := s.policy(ctx).TrashDays
		if n, err := s.store.Housekeeping(ctx, s.now().AddDate(0, 0, -days)); err != nil {
			s.log.Warn("housekeeping failed", "err", err)
		} else if n > 0 {
			s.log.Info("emptied the trash", "items", n, "days", days)
		}
		_ = s.store.PurgeSessions(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// uiMsg is an error whose text is a sentence for the user (translated when shown).
type uiMsg string

func (m uiMsg) Error() string { return string(m) }

func init() {
	// Not in Go's built-in list; browsers want it for the app manifest.
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
}
