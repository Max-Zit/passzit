package web

// The console certificate (Settings → Certificate). By default the console
// serves its own self-signed certificate; browsers warn once and the
// browser extensions cannot reach such a server at all. An administrator
// can upload a certificate (company CA or bought) or let PassZit get one
// from Let's Encrypt — through port 80 (HTTP challenge) or a DNS record at
// Cloudflare (works for servers that are not reachable from the internet).
// The trusted certificate is served on the console port in place of the
// self-signed one, without a restart; port 80 can redirect to it.
//
// Adapted from BackupZit (MaxZit's own code, internal/server/webcert.go and
// acme.go).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	settingCert        = "certificate"
	letsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	// renewBefore is when a Let's Encrypt certificate is renewed.
	renewBefore = 30 * 24 * time.Hour
	// cfPurpose binds the sealed Cloudflare token to its place.
	cfPurpose = "settings.certificate.cloudflare"
)

// CertSettings configure the console certificate.
type CertSettings struct {
	// Mode is "self" (the console's own certificate), "upload" or "acme".
	Mode string `json:"mode"`
	// Hostname is the name browsers use, e.g. vault.example.com (an IP
	// address only for uploaded certificates).
	Hostname string `json:"hostname,omitempty"`
	// RedirectHTTP serves port 80: redirects to the console and answers the
	// Let's Encrypt HTTP challenge.
	RedirectHTTP bool   `json:"redirect_http,omitempty"`
	ACMEEmail    string `json:"acme_email,omitempty"`
	// Challenge is "http" or "cloudflare".
	Challenge string `json:"challenge,omitempty"`
	// CloudflareToken is sealed with the server's secret key.
	CloudflareToken string `json:"cloudflare_token,omitempty"`
	// ACMEDirectory overrides Let's Encrypt (staging, tests).
	ACMEDirectory string `json:"acme_directory,omitempty"`
}

var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// certMsg is a message of the settings page, a key of the catalogs.
type certMsg string

func (m certMsg) Error() string { return string(m) }

// Validate checks the settings (messages are catalog keys).
func (c CertSettings) Validate() error {
	switch c.Mode {
	case "self", "":
		return nil
	case "upload", "acme":
	default:
		return certMsg("Unknown certificate choice.")
	}
	isIP := net.ParseIP(c.Hostname) != nil
	if c.Mode == "upload" && !isIP && !hostnameRe.MatchString(c.Hostname) {
		return certMsg("Enter the name or IP address browsers use for the console, e.g. vault.example.com.")
	}
	if c.Mode == "acme" {
		if !hostnameRe.MatchString(c.Hostname) {
			return certMsg("Let's Encrypt needs a public DNS name, e.g. vault.example.com.")
		}
		if !strings.Contains(c.ACMEEmail, "@") || len(c.ACMEEmail) > 200 {
			return certMsg("Let's Encrypt needs an e-mail address for expiry notices.")
		}
		switch c.Challenge {
		case "http":
			if !c.RedirectHTTP {
				return certMsg("The HTTP check needs port 80: switch on \"Serve port 80\".")
			}
		case "cloudflare":
			if c.CloudflareToken == "" {
				return certMsg("Enter a Cloudflare API token that may edit the DNS of the zone.")
			}
		default:
			return certMsg("Choose how Let's Encrypt checks the name.")
		}
	}
	return nil
}

func (c CertSettings) directory() string {
	if c.ACMEDirectory != "" {
		return c.ACMEDirectory
	}
	return letsEncrypt
}

// CertInfo describes a certificate for the settings page.
type CertInfo struct {
	Subject, Issuer string
	Names           []string
	NotAfter        time.Time
	Fingerprint     string
	SelfSigned      bool
}

// DaysLeft until the certificate expires.
func (c CertInfo) DaysLeft() int { return int(time.Until(c.NotAfter).Hours() / 24) }

func certInfo(c *tls.Certificate) *CertInfo {
	if c == nil || len(c.Certificate) == 0 {
		return nil
	}
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil
	}
	names := append([]string(nil), x.DNSNames...)
	for _, ip := range x.IPAddresses {
		names = append(names, ip.String())
	}
	sum := sha256.Sum256(c.Certificate[0])
	return &CertInfo{Subject: x.Subject.CommonName, Issuer: x.Issuer.CommonName, Names: names, NotAfter: x.NotAfter,
		Fingerprint: hex.EncodeToString(sum[:]), SelfSigned: x.Issuer.String() == x.Subject.String()}
}

// parseKeyPair checks an uploaded certificate chain and key.
func parseKeyPair(certPEM, keyPEM []byte, hostname string, now time.Time) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the certificate and the key do not fit together or are not PEM: %v", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("the certificate is valid only from %s", leaf.NotBefore.Format("2006-01-02"))
	}
	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			covers := append([]string(nil), leaf.DNSNames...)
			for _, ip := range leaf.IPAddresses {
				covers = append(covers, ip.String())
			}
			return nil, fmt.Errorf("the certificate is not valid for %s (it covers %s)", hostname, strings.Join(covers, ", "))
		}
	}
	c.Leaf = leaf
	return &c, nil
}

// Certs holds the console's certificates: the self-signed one and, when
// set, the trusted one that browsers get instead.
type Certs struct {
	dir  string // data directory/tls
	self *tls.Certificate
	log  *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate // trusted, nil for "self"
	cfg      CertSettings
	http     *http.Server // port 80
	port     string       // console port, for the redirect
	lastErr  string
	acmeKeys map[string]string // HTTP-01 token → key authorization
	listen   func(network, addr string) (net.Listener, error)
	// tests: Cloudflare API address and the wait for DNS
	cfBase   string
	dnsDelay time.Duration
}

// NewCerts prepares the certificates; self is the console's own one.
func NewCerts(dataDir string, self tls.Certificate, log *slog.Logger) *Certs {
	return &Certs{dir: filepath.Join(dataDir, "tls"), self: &self, log: log}
}

func (c *Certs) certFile() string { return filepath.Join(c.dir, "trusted.crt") }
func (c *Certs) keyFile() string  { return filepath.Join(c.dir, "trusted.key") }

// GetCertificate serves the trusted certificate when there is one.
func (c *Certs) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil {
		return c.cert, nil
	}
	return c.self, nil
}

func (c *Certs) loadCert() *tls.Certificate {
	k, err := tls.LoadX509KeyPair(c.certFile(), c.keyFile())
	if err != nil {
		return nil
	}
	k.Leaf, _ = x509.ParseCertificate(k.Certificate[0])
	return &k
}

// saveCert writes a chain and its key (the key readable only by the service).
func (c *Certs) saveCert(certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
	}{{c.keyFile(), keyPEM}, {c.certFile(), certPEM}} {
		tmp := f.path + ".new"
		if err := os.WriteFile(tmp, f.data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, f.path); err != nil {
			return err
		}
	}
	return nil
}

// apply uses cfg: the trusted certificate and port 80.
func (c *Certs) apply(cfg CertSettings) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	c.cert = nil
	if cfg.Mode == "upload" || cfg.Mode == "acme" {
		c.cert = c.loadCert()
	}
	want := cfg.RedirectHTTP && cfg.Mode != "self" && cfg.Mode != ""
	if c.http != nil && !want {
		closeServer(c.http)
		c.http = nil
	}
	if want && c.http == nil {
		listen := c.listen
		if listen == nil {
			listen = net.Listen
		}
		ln, err := listen("tcp", ":80")
		if err != nil {
			return fmt.Errorf("port 80: %v", err)
		}
		hs := &http.Server{Handler: http.HandlerFunc(c.serveHTTP), ReadHeaderTimeout: 15 * time.Second, ReadTimeout: time.Minute}
		c.http = hs
		go func() { _ = hs.Serve(ln) }()
	}
	return nil
}

func closeServer(hs *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
}

// serveHTTP answers Let's Encrypt and redirects everything else to the
// console.
func (c *Certs) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if tok, ok := strings.CutPrefix(r.URL.Path, "/.well-known/acme-challenge/"); ok {
		c.mu.Lock()
		ka, found := c.acmeKeys[tok]
		c.mu.Unlock()
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(ka))
		return
	}
	c.mu.Lock()
	target := "https://" + c.cfg.Hostname
	if c.port != "" && c.port != "443" {
		target += ":" + c.port
	}
	c.mu.Unlock()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "use HTTPS: "+target, http.StatusBadRequest)
		return
	}
	// #nosec G710 -- the host is the console name the administrator set; only the path comes from the request
	http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
}

func (c *Certs) status() (trusted, self *CertInfo, lastErr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return certInfo(c.cert), certInfo(c.self), c.lastErr
}

func (c *Certs) setErr(msg string) {
	c.mu.Lock()
	c.lastErr = msg
	c.mu.Unlock()
}

func pemEncode(der [][]byte) []byte {
	var b []byte
	for _, d := range der {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return b
}

// ---- Let's Encrypt

func (c *Certs) accountKey() (crypto.Signer, error) {
	p := filepath.Join(c.dir, "acme-account.key")
	if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- the server's own data directory
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("invalid ACME account key")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// obtainACME gets a certificate for cfg.Hostname and stores it; token is
// the opened Cloudflare token.
func (c *Certs) obtainACME(ctx context.Context, cfg CertSettings, token string, hc *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	key, err := c.accountKey()
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: key, DirectoryURL: cfg.directory(), UserAgent: "passzit"}
	if hc != nil {
		cl.HTTPClient = hc
	}
	if _, err := cl.Register(ctx, &acme.Account{Contact: []string{"mailto:" + cfg.ACMEEmail}}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("the account at Let's Encrypt: %w", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(cfg.Hostname))
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		if err := c.solve(ctx, cl, cfg, token, z, hc); err != nil {
			return err
		}
	}
	finalize, orderURI := order.FinalizeURL, order.URI
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("order: %w", err)
	}
	if order.FinalizeURL != "" {
		finalize = order.FinalizeURL
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cfg.Hostname}, DNSNames: []string{cfg.Hostname}}, certKey)
	if err != nil {
		return err
	}
	der, _, err := cl.CreateOrderCert(ctx, finalize, csr, true)
	if err != nil && orderURI != "" {
		// some ACME servers answer the finalize request without the
		// order's address; follow the order by its first address
		if o, werr := cl.WaitOrder(ctx, orderURI); werr == nil && o.CertURL != "" {
			der, err = cl.FetchCert(ctx, o.CertURL, true)
		}
	}
	if err != nil {
		return fmt.Errorf("issue the certificate: %w", err)
	}
	kb, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	certPEM := pemEncode(der)
	if _, err := parseKeyPair(certPEM, keyPEM, cfg.Hostname, time.Now()); err != nil {
		return err
	}
	return c.saveCert(certPEM, keyPEM)
}

func (c *Certs) solve(ctx context.Context, cl *acme.Client, cfg CertSettings, token string, z *acme.Authorization, hc *http.Client) error {
	want := "http-01"
	if cfg.Challenge == "cloudflare" {
		want = "dns-01"
	}
	var ch *acme.Challenge
	for _, x := range z.Challenges {
		if x.Type == want {
			ch = x
		}
	}
	if ch == nil {
		return fmt.Errorf("no %s check offered by Let's Encrypt for %s", want, z.Identifier.Value)
	}
	switch want {
	case "http-01":
		ka, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			return err
		}
		c.mu.Lock()
		if c.acmeKeys == nil {
			c.acmeKeys = map[string]string{}
		}
		c.acmeKeys[ch.Token] = ka
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			delete(c.acmeKeys, ch.Token)
			c.mu.Unlock()
		}()
	case "dns-01":
		val, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return err
		}
		cf := cloudflare{token: token, http: hc, base: c.cfBase}
		zone, rec, err := cf.addTXT(ctx, "_acme-challenge."+z.Identifier.Value, val)
		if err != nil {
			return fmt.Errorf("the Cloudflare API: %w", err)
		}
		defer func() { _ = cf.delete(context.Background(), zone, rec) }()
		wait := c.dnsDelay
		if wait == 0 {
			wait = 20 * time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	if _, err := cl.Accept(ctx, ch); err != nil {
		return fmt.Errorf("check: %w", err)
	}
	if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
		hint := "is port 80 of this server reachable from the internet under " + z.Identifier.Value + "?"
		if want == "dns-01" {
			hint = "may the Cloudflare token edit the DNS zone of " + z.Identifier.Value + "?"
		}
		return fmt.Errorf("the check of %s by Let's Encrypt failed (%s): %w", z.Identifier.Value, hint, err)
	}
	return nil
}

// cloudflare manages DNS TXT records through the Cloudflare API.
type cloudflare struct {
	token string
	http  *http.Client
	base  string
}

func (c cloudflare) do(ctx context.Context, method, path string, body, out any) error {
	base := c.base
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.http
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req) // #nosec G704 -- the Cloudflare API (or a test server)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			msgs = append(msgs, e.Message)
		}
		return errors.New(strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (c cloudflare) zoneFor(ctx context.Context, name string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		zone := strings.Join(labels[i:], ".")
		var zs []struct{ ID string }
		if err := c.do(ctx, "GET", "/zones?name="+url.QueryEscape(zone), nil, &zs); err != nil {
			return "", err
		}
		if len(zs) > 0 {
			return zs[0].ID, nil
		}
	}
	return "", fmt.Errorf("no Cloudflare zone for %s is open to this token", name)
}

func (c cloudflare) addTXT(ctx context.Context, name, value string) (zone, id string, err error) {
	if zone, err = c.zoneFor(ctx, name); err != nil {
		return "", "", err
	}
	var rec struct{ ID string }
	err = c.do(ctx, "POST", "/zones/"+zone+"/dns_records", map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60}, &rec)
	return zone, rec.ID, err
}

func (c cloudflare) delete(ctx context.Context, zone, id string) error {
	if zone == "" || id == "" {
		return nil
	}
	return c.do(ctx, "DELETE", "/zones/"+zone+"/dns_records/"+id, nil, nil)
}
