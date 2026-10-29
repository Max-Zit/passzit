package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/oauth2"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/store"
)

// Company sign-in (Settings → Company sign-in). PassZit cannot hand out a
// vault without the master password — it is the key — so a directory or
// an identity provider adds to the sign-in, it never replaces the master
// password:
//
//   - Single sign-on (OpenID Connect or SAML): the identity provider
//     confirms who signs in; with its own second factor it can stand in
//     for PassZit's authenticator code. It can be required, so that people
//     who left the company (disabled there) cannot sign in any more.
//   - LDAP / Active Directory: at every sign-in PassZit checks that the
//     account exists and is enabled in the directory.
//
// Both can keep PassZit's groups in step with the company groups.

const (
	settingSSO  = "sso"
	settingLDAP = "ldap"
	ssoCookie   = "pzsso"
)

// SSOSettings configure single sign-on.
type SSOSettings struct {
	Protocol string `json:"protocol"` // "", oidc, saml
	Label    string `json:"label,omitempty"`
	// OpenID Connect.
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"` // sealed
	// SAML: the identity provider's metadata, by URL or pasted.
	MetadataURL string `json:"metadata_url,omitempty"`
	MetadataXML string `json:"metadata_xml,omitempty"`
	CACert      string `json:"ca_cert,omitempty"`
	SPKey       string `json:"sp_key,omitempty"` // sealed
	SPCert      string `json:"sp_cert,omitempty"`
	// Claims or attributes with the e-mail address and the groups.
	EmailClaim  string `json:"email_claim,omitempty"`
	GroupsClaim string `json:"groups_claim,omitempty"`
	// RequireTOTP: PassZit's own second factor after the identity provider.
	RequireTOTP bool `json:"require_totp,omitempty"`
	// Required: users (not administrators) sign in only through it.
	Required bool `json:"required,omitempty"`
	// SyncGroups: PassZit groups follow the identity provider's groups of
	// the same name at every sign-in.
	SyncGroups bool `json:"sync_groups,omitempty"`
}

func (c SSOSettings) label() string {
	if c.Label != "" {
		return c.Label
	}
	return "single sign-on"
}

// Validate checks the settings.
func (c *SSOSettings) Validate() error {
	if c.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CACert)) {
		return uiMsg("The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).")
	}
	switch c.Protocol {
	case "":
		return nil
	case "oidc":
		u, err := url.Parse(c.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return uiMsg("The issuer must be an https:// address, e.g. https://login.microsoftonline.com/<tenant>/v2.0.")
		}
		if c.ClientID == "" || c.ClientSecret == "" {
			return uiMsg("Enter the client ID and the client secret of the application registered at the identity provider.")
		}
	case "saml":
		if c.MetadataURL == "" && c.MetadataXML == "" {
			return uiMsg("Enter the identity provider's metadata URL or paste its metadata XML.")
		}
		if c.MetadataURL != "" {
			if u, err := url.Parse(c.MetadataURL); err != nil || u.Scheme != "https" || u.Host == "" {
				return uiMsg("The metadata URL must be an https:// address.")
			}
		}
	default:
		return uiMsg("Unknown single sign-on protocol.")
	}
	return nil
}

// SSO loads the settings.
func (s *Server) SSO(ctx context.Context) SSOSettings {
	var c SSOSettings
	_ = s.store.GetSetting(ctx, settingSSO, &c)
	return c
}

func (s *Server) openSealed(sealed, purpose string) string {
	if sealed == "" {
		return ""
	}
	v, _ := s.store.OpenSecret(purpose, sealed)
	return v
}

func baseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http" // only the loopback development listener
	}
	return scheme + "://" + r.Host
}

// ---- signed state (cookies that only this server process can make)

var ssoKey = func() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}()

func signState(life time.Duration, values ...string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(append(values, strconv.FormatInt(time.Now().Add(life).Unix(), 10)), "\x00")))
	m := hmac.New(sha256.New, ssoKey)
	m.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func parseState(tok string) ([]string, bool) {
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return nil, false
	}
	m := hmac.New(sha256.New, ssoKey)
	m.Write([]byte(payload))
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, m.Sum(nil)) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	v := strings.Split(string(b), "\x00")
	if len(v) < 2 {
		return nil, false
	}
	exp, err := strconv.ParseInt(v[len(v)-1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil, false
	}
	return v[:len(v)-1], true
}

// The SAML response is a cross-site POST, so the state cookie is
// SameSite=None; it holds only signed state, nothing that grants access.
func setStateCookie(w http.ResponseWriter, r *http.Request, v string, maxAge int) {
	// #nosec G124 -- Secure whenever the request came over TLS (only the loopback dev listener is plain)
	http.SetCookie(w, &http.Cookie{Name: "pzssostate", Value: v, Path: "/login/sso", MaxAge: maxAge, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteNoneMode})
}

// The confirmation of the identity provider waits for the master password
// in a cookie for a few minutes.
func setConfirmedCookie(w http.ResponseWriter, r *http.Request, v string, maxAge int) {
	// #nosec G124 -- Secure whenever the request came over TLS (only the loopback dev listener is plain)
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: v, Path: "/", MaxAge: maxAge, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
}

// ssoConfirmed reports whether the identity provider confirmed this user
// in this browser a moment ago.
func ssoConfirmed(r *http.Request, u *store.User) bool {
	ck, err := r.Cookie(ssoCookie)
	if err != nil {
		return false
	}
	v, ok := parseState(ck.Value)
	return ok && len(v) == 2 && v[0] == strconv.FormatInt(u.ID, 10) && strings.EqualFold(v[1], u.Email)
}

// ---- providers (cached per configuration)

type ssoCache struct {
	mu   sync.Mutex
	key  string
	at   time.Time
	oidc *oidc.Provider
	idp  *saml.EntityDescriptor
}

func (c SSOSettings) cacheKey() string {
	return c.Protocol + "|" + c.Issuer + "|" + c.MetadataURL + "|" + strconv.Itoa(len(c.MetadataXML)) + "|" + c.CACert
}

func tlsClient(caPEM string) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM != "" {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(caPEM))
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}
}

func (s *Server) oidcFor(ctx context.Context, c SSOSettings, r *http.Request) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	s.sso.mu.Lock()
	defer s.sso.mu.Unlock()
	if s.sso.key != c.cacheKey() || s.sso.oidc == nil || time.Since(s.sso.at) > time.Hour {
		p, err := oidc.NewProvider(oidc.ClientContext(ctx, tlsClient(c.CACert)), c.Issuer)
		if err != nil {
			return nil, nil, fmt.Errorf("the identity provider cannot be reached: %w", err)
		}
		s.sso.key, s.sso.at, s.sso.oidc = c.cacheKey(), time.Now(), p
	}
	cfg := &oauth2.Config{ClientID: c.ClientID, ClientSecret: s.openSealed(c.ClientSecret, "settings.sso.client"), Endpoint: s.sso.oidc.Endpoint(),
		RedirectURL: baseURL(r) + "/login/sso/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	return cfg, s.sso.oidc.Verifier(&oidc.Config{ClientID: c.ClientID}), nil
}

func (s *Server) serviceProvider(ctx context.Context, c SSOSettings, r *http.Request) (*saml.ServiceProvider, error) {
	s.sso.mu.Lock()
	if s.sso.key != c.cacheKey() || s.sso.idp == nil || time.Since(s.sso.at) > time.Hour {
		var md *saml.EntityDescriptor
		var err error
		if c.MetadataXML != "" {
			md, err = parseIDPMetadata([]byte(c.MetadataXML))
		} else {
			md, err = fetchIDPMetadata(ctx, tlsClient(c.CACert), c.MetadataURL)
		}
		if err != nil {
			s.sso.mu.Unlock()
			return nil, fmt.Errorf("the metadata of the identity provider cannot be read: %w", err)
		}
		s.sso.key, s.sso.at, s.sso.idp = c.cacheKey(), time.Now(), md
	}
	idp := s.sso.idp
	s.sso.mu.Unlock()
	blk, _ := pem.Decode([]byte(s.openSealed(c.SPKey, "settings.sso.spkey")))
	cblk, _ := pem.Decode([]byte(c.SPCert))
	if blk == nil || cblk == nil {
		return nil, errors.New("the server's SAML key is missing; save the settings again")
	}
	key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	base := baseURL(r)
	md, _ := url.Parse(base + "/login/sso/metadata")
	acs, _ := url.Parse(base + "/login/sso/saml")
	return &saml.ServiceProvider{EntityID: md.String(), Key: key, Certificate: cert, MetadataURL: *md, AcsURL: *acs, IDPMetadata: idp,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat, HTTPClient: tlsClient(c.CACert)}, nil
}

func newSPKey() (keyPEM, certPEM string, err error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "PassZit server (SAML)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(20, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// ---- the sign-in through the identity provider

func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := s.SSO(ctx)
	switch c.Protocol {
	case "oidc":
		cfg, _, err := s.oidcFor(ctx, c, r)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		state, nonce, verifier := auth.RandomToken(16), auth.RandomToken(16), oauth2.GenerateVerifier()
		setStateCookie(w, r, signState(10*time.Minute, "oidc", state, nonce, verifier), 600)
		http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusSeeOther)
	case "saml":
		sp, err := s.serviceProvider(ctx, c, r)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		relay := auth.RandomToken(12)
		u, err := req.Redirect(relay, sp)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		setStateCookie(w, r, signState(10*time.Minute, "saml", req.ID, relay), 600)
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func stateOf(r *http.Request, kind string, n int) ([]string, bool) {
	ck, err := r.Cookie("pzssostate")
	if err != nil {
		return nil, false
	}
	v, ok := parseState(ck.Value)
	return v, ok && len(v) == n && v[0] == kind
}

var errSSOState = uiMsg("The sign-in took too long or was started elsewhere. Try again.")

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := s.SSO(ctx)
	v, ok := stateOf(r, "oidc", 4)
	if !ok || c.Protocol != "oidc" || r.FormValue("state") != v[1] {
		s.ssoFailed(w, r, errSSOState)
		return
	}
	if e := r.FormValue("error"); e != "" {
		s.ssoFailed(w, r, fmt.Errorf("the identity provider refused the sign-in: %s", clip(e+" "+r.FormValue("error_description"), 200)))
		return
	}
	cfg, verifier, err := s.oidcFor(ctx, c, r)
	if err != nil {
		s.ssoFailed(w, r, err)
		return
	}
	tok, err := cfg.Exchange(oidc.ClientContext(ctx, tlsClient(c.CACert)), r.FormValue("code"), oauth2.VerifierOption(v[3]))
	if err != nil {
		s.ssoFailed(w, r, fmt.Errorf("the identity provider did not confirm the sign-in: %w", err))
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := verifier.Verify(ctx, raw)
	if err != nil || idt.Nonce != v[2] {
		s.ssoFailed(w, r, fmt.Errorf("the identity token is not valid: %v", err))
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		s.ssoFailed(w, r, err)
		return
	}
	email := claimString(claims, orDefault(c.EmailClaim, "email"), "email", "preferred_username", "upn")
	s.ssoDone(w, r, c, email, claimStrings(claims[orDefault(c.GroupsClaim, "groups")]))
}

func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := s.SSO(ctx)
	v, ok := stateOf(r, "saml", 3)
	if !ok || c.Protocol != "saml" {
		s.ssoFailed(w, r, errSSOState)
		return
	}
	sp, err := s.serviceProvider(ctx, c, r)
	if err != nil {
		s.ssoFailed(w, r, err)
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("RelayState") != v[2] {
		s.ssoFailed(w, r, errSSOState)
		return
	}
	// Signed by the identity provider and the answer to our own request.
	a, err := sp.ParseResponse(r, []string{v[1]})
	if err != nil {
		detail := err.Error()
		var ie *saml.InvalidResponseError
		if errors.As(err, &ie) {
			detail = ie.PrivateErr.Error()
		}
		s.log.Warn("SAML response refused", "err", detail)
		s.ssoFailed(w, r, uiMsg("The response of the identity provider is not valid."))
		return
	}
	attrs := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, val := range at.Values {
				attrs[at.Name] = append(attrs[at.Name], val.Value)
				if at.FriendlyName != "" {
					attrs[at.FriendlyName] = append(attrs[at.FriendlyName], val.Value)
				}
			}
		}
	}
	email := ""
	for _, k := range []string{c.EmailClaim, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email", "mail"} {
		if vs := attrs[k]; k != "" && len(vs) > 0 && vs[0] != "" {
			email = vs[0]
			break
		}
	}
	if email == "" && a.Subject != nil && a.Subject.NameID != nil && strings.Contains(a.Subject.NameID.Value, "@") {
		email = a.Subject.NameID.Value
	}
	groups := attrs[orDefault(c.GroupsClaim, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")]
	if len(groups) == 0 {
		groups = append(attrs["groups"], attrs["Group"]...)
	}
	s.ssoDone(w, r, c, email, groups)
}

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	c := s.SSO(r.Context())
	if c.Protocol != "saml" {
		http.NotFound(w, r)
		return
	}
	sp, err := s.serviceProvider(r.Context(), c, r)
	if err != nil {
		http.Error(w, "SAML is not ready: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	b, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(append([]byte(xml.Header), b...))
}

// ssoDone: the identity provider confirmed an address. The account must
// exist (accounts come only by invitation); the master password follows on
// the sign-in page.
func (s *Server) ssoDone(w http.ResponseWriter, r *http.Request, c SSOSettings, email string, groups []string) {
	ctx := r.Context()
	email = strings.TrimSpace(email)
	u, err := s.store.UserByEmail(ctx, email)
	if err != nil || u.Disabled {
		s.auditAs(r, clip(email, 100), "login.failed", "user:"+clip(email, 100), "single sign-on for an address without an active PassZit account")
		s.ssoFailed(w, r, fmt.Errorf("there is no active PassZit account for %q; ask your administrator for an invitation", clip(email, 100)))
		return
	}
	if c.SyncGroups {
		if err := s.store.SetUserGroups(ctx, u.ID, groupNames(groups)); err != nil {
			s.log.Warn("group sync failed", "user", u.Email, "err", err)
		}
	}
	setStateCookie(w, r, "", -1)
	setConfirmedCookie(w, r, signState(10*time.Minute, strconv.FormatInt(u.ID, 10), u.Email), 600)
	s.auditAs(r, u.Email, "login.sso", "user:"+u.Email, "identity confirmed by %s", c.label())
	http.Redirect(w, r, "/login?sso="+url.QueryEscape(u.Email), http.StatusSeeOther)
}

func (s *Server) ssoFailed(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Warn("single sign-on failed", "err", err, "ip", clientIP(r))
	msg := err.Error()
	var m uiMsg
	if errors.As(err, &m) {
		msg = translate(s.lang(r, nil), string(m))
	}
	s.flash(w, r, "!"+translate(s.lang(r, nil), "Single sign-on failed:")+" "+msg)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// groupNames turns group values (names or LDAP DNs) into names.
func groupNames(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if dn, err := ldap.ParseDN(g); err == nil && len(dn.RDNs) > 0 && len(dn.RDNs[0].Attributes) > 0 && strings.Contains(g, "=") {
			out = append(out, dn.RDNs[0].Attributes[0].Value)
			continue
		}
		out = append(out, g)
	}
	return out
}

func orDefault(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func claimString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func claimStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

func parseIDPMetadata(b []byte) (*saml.EntityDescriptor, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err == nil && len(ed.IDPSSODescriptors) > 0 {
		return &ed, nil
	}
	var eds saml.EntitiesDescriptor
	if err := xml.Unmarshal(b, &eds); err != nil {
		return nil, err
	}
	for i := range eds.EntityDescriptors {
		if len(eds.EntityDescriptors[i].IDPSSODescriptors) > 0 {
			return &eds.EntityDescriptors[i], nil
		}
	}
	return nil, errors.New("no identity provider in the metadata")
}

func fetchIDPMetadata(ctx context.Context, hc *http.Client, u string) (*saml.EntityDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) // #nosec G704 -- the administrator's metadata address (https only)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	return parseIDPMetadata(b)
}

// ---- LDAP / Active Directory: is the account still active?

// LDAPSettings configure the directory check.
type LDAPSettings struct {
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url"`
	StartTLS     bool   `json:"starttls"`
	CACert       string `json:"ca_cert,omitempty"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password,omitempty"` // sealed
	BaseDN       string `json:"base_dn"`
	// UserFilter finds the user by e-mail address; {email} is replaced.
	UserFilter   string `json:"user_filter"`
	NestedGroups bool   `json:"nested_groups"`
	SyncGroups   bool   `json:"sync_groups"`
}

const defaultUserFilter = "(&(|(objectClass=user)(objectClass=inetOrgPerson))(|(mail={email})(userPrincipalName={email})))"

// Validate checks the settings.
func (c *LDAPSettings) Validate() error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" {
		return uiMsg("The server address must look like ldaps://dc1.example.local (or ldap://dc1.example.local with StartTLS).")
	}
	if u.Scheme == "ldap" && !c.StartTLS {
		return uiMsg("An ldap:// address needs StartTLS: the directory must not be read unencrypted.")
	}
	if c.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CACert)) {
		return uiMsg("The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).")
	}
	if c.BindDN == "" || c.BaseDN == "" || c.BindPassword == "" {
		return uiMsg("Enter the service account with its password and the base DN.")
	}
	if !strings.Contains(c.UserFilter, "{email}") {
		return uiMsg("The user filter must contain {email}.")
	}
	return nil
}

// LDAP loads the settings.
func (s *Server) LDAP(ctx context.Context) LDAPSettings {
	c := LDAPSettings{UserFilter: defaultUserFilter, NestedGroups: true}
	_ = s.store.GetSetting(ctx, settingLDAP, &c)
	return c
}

type ldapAccount struct {
	DN       string
	Disabled bool
	Groups   []string
}

var errNotInDirectory = errors.New("not found in the directory")

// ldapLookup finds an account by e-mail address with the service account.
func ldapLookup(c LDAPSettings, bindPassword, email string) (*ldapAccount, error) {
	u, _ := url.Parse(c.URL)
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.CACert != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(c.CACert))
		tc.RootCAs = pool
	}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithTLSConfig(tc), ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetTimeout(15 * time.Second)
	if u.Scheme == "ldap" {
		if err := conn.StartTLS(tc); err != nil {
			return nil, err
		}
	}
	if err := conn.Bind(c.BindDN, bindPassword); err != nil {
		return nil, fmt.Errorf("the service account cannot sign in to the directory: %w", err)
	}
	filter := strings.ReplaceAll(c.UserFilter, "{email}", ldap.EscapeFilter(email))
	res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 15, false, filter,
		[]string{"memberOf", "userAccountControl", "nsAccountLock", "pwdAccountLockedTime"}, nil))
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, errNotInDirectory
	}
	e := res.Entries[0]
	a := &ldapAccount{DN: e.DN, Groups: e.GetAttributeValues("memberOf")}
	if uac, err := strconv.Atoi(e.GetAttributeValue("userAccountControl")); err == nil && uac&2 != 0 {
		a.Disabled = true // Active Directory: ACCOUNTDISABLE
	}
	if strings.EqualFold(e.GetAttributeValue("nsAccountLock"), "true") || e.GetAttributeValue("pwdAccountLockedTime") != "" {
		a.Disabled = true // 389 Directory Server, OpenLDAP ppolicy
	}
	if c.NestedGroups {
		res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 15, false,
			"(member:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(e.DN)+")", []string{"dn"}, nil))
		if err == nil {
			seen := map[string]bool{}
			for _, g := range a.Groups {
				seen[strings.ToLower(g)] = true
			}
			for _, g := range res.Entries {
				if !seen[strings.ToLower(g.DN)] {
					a.Groups = append(a.Groups, g.DN)
				}
			}
		}
	}
	return a, nil
}

// directoryCheck is called after the master password was right. It
// returns a message for the user when the sign-in must stop.
func (s *Server) directoryCheck(r *http.Request, u *store.User, web bool) string {
	ctx := r.Context()
	if c := s.SSO(ctx); web && c.Protocol != "" && c.Required && u.Role != store.RoleAdmin && !ssoConfirmed(r, u) {
		return translate(s.lang(r, nil), "Sign in with %s first.", c.label())
	}
	c := s.LDAP(ctx)
	if !c.Enabled {
		return ""
	}
	a, err := ldapLookup(c, s.openSealed(c.BindPassword, "settings.ldap.bind"), u.Email)
	switch {
	case errors.Is(err, errNotInDirectory):
		s.auditAs(r, u.Email, "login.failed", "user:"+u.Email, "account not found in the directory")
		return translate(s.lang(r, nil), "Your account is not active in the company directory.")
	case err != nil:
		// The directory cannot be reached: administrators may still sign in.
		s.log.Warn("directory check failed", "user", u.Email, "err", err)
		if u.Role == store.RoleAdmin {
			return ""
		}
		return translate(s.lang(r, nil), "The company directory cannot be reached. Try again later or ask your administrator.")
	case a.Disabled:
		s.auditAs(r, u.Email, "login.failed", "user:"+u.Email, "account disabled in the directory")
		return translate(s.lang(r, nil), "Your account is not active in the company directory.")
	}
	if c.SyncGroups {
		if err := s.store.SetUserGroups(ctx, u.ID, groupNames(a.Groups)); err != nil {
			s.log.Warn("group sync failed", "user", u.Email, "err", err)
		}
	}
	return ""
}

// ---- Settings → Company sign-in

type directoryData struct {
	SSO        SSOSettings
	LDAP       LDAPSettings
	HasSecret  bool
	HasBindPW  bool
	Base       string
	TestResult string
	TestOK     bool
}

func (s *Server) showDirectory(w http.ResponseWriter, r *http.Request, test string, ok bool) {
	c, l := s.SSO(r.Context()), s.LDAP(r.Context())
	d := &directoryData{SSO: c, LDAP: l, HasSecret: c.ClientSecret != "", HasBindPW: l.BindPassword != "", Base: baseURL(r), TestResult: test, TestOK: ok}
	d.SSO.ClientSecret, d.SSO.SPKey, d.LDAP.BindPassword = "", "", ""
	s.render(w, r, http.StatusOK, "directory", &Page{Title: "Company sign-in", Nav: "settings", Data: d})
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	s.showDirectory(w, r, "", false)
}

func (s *Server) handleSSOSave(w http.ResponseWriter, r *http.Request) {
	if s.holdForApproval(w, r, "settings.sso", "change single sign-on", "/settings/directory") {
		return
	}
	old := s.SSO(r.Context())
	c := SSOSettings{Protocol: r.FormValue("protocol"), Label: strings.TrimSpace(r.FormValue("label")), Issuer: strings.TrimSpace(r.FormValue("issuer")),
		ClientID: strings.TrimSpace(r.FormValue("client_id")), ClientSecret: old.ClientSecret, MetadataURL: strings.TrimSpace(r.FormValue("metadata_url")),
		MetadataXML: strings.TrimSpace(r.FormValue("metadata_xml")), CACert: strings.TrimSpace(r.FormValue("ca_cert")), SPKey: old.SPKey, SPCert: old.SPCert,
		EmailClaim: strings.TrimSpace(r.FormValue("email_claim")), GroupsClaim: strings.TrimSpace(r.FormValue("groups_claim")),
		RequireTOTP: r.FormValue("require_totp") == "1", Required: r.FormValue("required") == "1", SyncGroups: r.FormValue("sync_groups") == "1"}
	if v := r.FormValue("client_secret"); v != "" {
		c.ClientSecret = s.store.SealSecret("settings.sso.client", v)
	}
	if len(c.Label) > 40 {
		c.Label = c.Label[:40]
	}
	if err := c.Validate(); err != nil {
		s.redirectErr(w, r, "/settings/directory", err.Error())
		return
	}
	if c.Protocol == "saml" && c.SPKey == "" {
		k, cert, err := newSPKey()
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		c.SPKey, c.SPCert = s.store.SealSecret("settings.sso.spkey", k), cert
	}
	if err := s.store.SetSetting(r.Context(), settingSSO, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sso.mu.Lock()
	s.sso.key = ""
	s.sso.mu.Unlock()
	s.audit(r, "settings.sso", "settings", "single sign-on: %q %s%s, required %v, own second factor %v, group sync %v",
		c.Protocol, c.Issuer, c.MetadataURL, c.Required, c.RequireTOTP, c.SyncGroups)
	s.redirect(w, r, "/settings/directory", "Saved.")
}

func (s *Server) ldapFromForm(r *http.Request) LDAPSettings {
	old := s.LDAP(r.Context())
	c := LDAPSettings{Enabled: r.FormValue("enabled") == "1", URL: strings.TrimSpace(r.FormValue("url")), StartTLS: r.FormValue("starttls") == "1",
		CACert: strings.TrimSpace(r.FormValue("ca_cert")), BindDN: strings.TrimSpace(r.FormValue("bind_dn")), BindPassword: old.BindPassword,
		BaseDN: strings.TrimSpace(r.FormValue("base_dn")), UserFilter: strings.TrimSpace(r.FormValue("user_filter")),
		NestedGroups: r.FormValue("nested_groups") == "1", SyncGroups: r.FormValue("sync_groups") == "1"}
	if c.UserFilter == "" {
		c.UserFilter = defaultUserFilter
	}
	if v := r.FormValue("bind_password"); v != "" {
		c.BindPassword = s.store.SealSecret("settings.ldap.bind", v)
	}
	return c
}

func (s *Server) handleLDAPSave(w http.ResponseWriter, r *http.Request) {
	if s.holdForApproval(w, r, "settings.ldap", "change the directory check", "/settings/directory") {
		return
	}
	c := s.ldapFromForm(r)
	if err := c.Validate(); err != nil {
		s.redirectErr(w, r, "/settings/directory", err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingLDAP, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.ldap", "settings", "directory check: enabled %v, %s, base %s, group sync %v", c.Enabled, c.URL, c.BaseDN, c.SyncGroups)
	s.redirect(w, r, "/settings/directory", "Saved.")
}

// handleLDAPTest looks up an address with the saved settings.
func (s *Server) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	c := s.LDAP(r.Context())
	email := strings.TrimSpace(r.FormValue("email"))
	if c.URL == "" || email == "" {
		s.redirectErr(w, r, "/settings/directory", "Save the directory settings first, then enter an address to look up.")
		return
	}
	a, err := ldapLookup(c, s.openSealed(c.BindPassword, "settings.ldap.bind"), email)
	lang := s.lang(r, userFrom(r))
	switch {
	case err != nil:
		s.showDirectory(w, r, translate(lang, "Lookup failed:")+" "+err.Error(), false)
	case a.Disabled:
		s.showDirectory(w, r, translate(lang, "Found, but disabled: %s", a.DN), false)
	default:
		s.showDirectory(w, r, translate(lang, "Found and active: %s (groups: %s)", a.DN, strings.Join(groupNames(a.Groups), ", ")), true)
	}
}
