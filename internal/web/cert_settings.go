package web

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/store"
)

// StartCerts uses the saved certificate settings and renews Let's Encrypt
// certificates in the background (checked twice a day).
func (s *Server) StartCerts(ctx context.Context) {
	if s.Certs == nil {
		return
	}
	if _, port, err := net.SplitHostPort(s.RunningMgmt); err == nil {
		s.Certs.mu.Lock()
		s.Certs.port = port
		s.Certs.mu.Unlock()
	}
	if err := s.Certs.apply(s.certSettings(ctx)); err != nil {
		s.log.Error("console certificate", "err", err)
		s.Certs.setErr(err.Error())
	}
	go func() {
		for {
			s.warnCertExpiry(ctx)
			if err := s.renewCert(ctx); err != nil {
				s.log.Error("renew the Let's Encrypt certificate", "err", err)
				s.notifyAdmins(ctx, mailText{Subject: "The certificate was not renewed",
					Lines: [][]any{{"PassZit could not renew the Let's Encrypt certificate of the console: %s", err.Error()}, {"The current certificate stays in use until it expires."}}}, "/settings/certificate")
				_ = s.store.Audit(ctx, "-", "local", "settings.certificate", "server", "Let's Encrypt renewal failed: "+err.Error())
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(12 * time.Hour):
			}
		}
	}()
}

func (s *Server) certSettings(ctx context.Context) CertSettings {
	c := CertSettings{Mode: "self", Challenge: "http", RedirectHTTP: true}
	if err := s.store.GetSetting(ctx, settingCert, &c); err != nil {
		s.log.Error("certificate settings", "err", err)
	}
	return c
}

func (s *Server) cloudflareToken(c CertSettings) string {
	if c.CloudflareToken == "" {
		return ""
	}
	t, err := s.store.OpenSecret(cfPurpose, c.CloudflareToken)
	if err != nil {
		return ""
	}
	return t
}

// renewCert renews a Let's Encrypt certificate that expires soon.
func (s *Server) renewCert(ctx context.Context) error {
	cfg := s.certSettings(ctx)
	if cfg.Mode != "acme" {
		return nil
	}
	if cur := s.Certs.loadCert(); cur != nil && cur.Leaf != nil && time.Until(cur.Leaf.NotAfter) > renewBefore {
		return nil
	}
	if err := s.Certs.obtainACME(ctx, cfg, s.cloudflareToken(cfg), nil); err != nil {
		s.Certs.setErr(err.Error())
		return err
	}
	s.Certs.setErr("")
	return s.Certs.apply(cfg)
}

type certData struct {
	C        CertSettings
	HasToken bool
	Staging  bool
	Trusted  *CertInfo
	Self     *CertInfo
	LastErr  string
	Port     string
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	s.showCertificate(w, r, http.StatusOK, s.certSettings(r.Context()), "")
}

func (s *Server) showCertificate(w http.ResponseWriter, r *http.Request, status int, c CertSettings, errMsg string) {
	d := &certData{C: c, HasToken: c.CloudflareToken != "", Staging: c.ACMEDirectory == letsEncryptStaging}
	d.C.CloudflareToken = ""
	if s.Certs != nil {
		d.Trusted, d.Self, d.LastErr = s.Certs.status()
		d.Port = s.Certs.port
	}
	p := &Page{Title: "Certificate", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "certificate", p)
}

// readPEM reads an uploaded file or a pasted text field.
func readPEM(r *http.Request, name string) []byte {
	if f, _, err := r.FormFile(name + "_file"); err == nil {
		defer f.Close()
		if b, err := io.ReadAll(io.LimitReader(f, 1<<20)); err == nil && len(b) > 0 {
			return b
		}
	}
	return []byte(strings.TrimSpace(r.FormValue(name)))
}

func (s *Server) handleCertificateSave(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/certificate"
	if s.Certs == nil {
		s.redirectErr(w, r, back, "The certificate cannot be changed in this mode.")
		return
	}
	if err := r.ParseMultipartForm(4 << 20); err != nil && err != http.ErrNotMultipart {
		s.redirectErr(w, r, back, "The upload is too large.")
		return
	}
	if s.holdForApproval(w, r, "settings.certificate", "change the console certificate", back) {
		return
	}
	old := s.certSettings(r.Context())
	c := CertSettings{
		Mode:         r.FormValue("mode"),
		Hostname:     strings.ToLower(strings.TrimSpace(r.FormValue("hostname"))),
		RedirectHTTP: r.FormValue("redirect_http") == "on",
		ACMEEmail:    strings.TrimSpace(r.FormValue("acme_email")),
		Challenge:    r.FormValue("challenge"),
	}
	token := strings.TrimSpace(r.FormValue("cloudflare_token"))
	if token != "" {
		c.CloudflareToken = s.store.SealSecret(cfPurpose, token)
	} else {
		c.CloudflareToken, token = old.CloudflareToken, s.cloudflareToken(old)
	}
	if r.FormValue("staging") == "on" {
		c.ACMEDirectory = letsEncryptStaging
	}
	if err := c.Validate(); err != nil {
		s.showCertificate(w, r, http.StatusBadRequest, c, err.Error())
		return
	}
	switch c.Mode {
	case "upload":
		certPEM, keyPEM := readPEM(r, "cert_pem"), readPEM(r, "key_pem")
		if len(certPEM) == 0 && len(keyPEM) == 0 && old.Mode == "upload" {
			// keep the uploaded certificate, only other settings change
			cur := s.Certs.loadCert()
			if cur == nil || cur.Leaf == nil || cur.Leaf.VerifyHostname(c.Hostname) != nil {
				s.showCertificate(w, r, http.StatusBadRequest, c, "Upload a certificate that is valid for this name.")
				return
			}
			break
		}
		cert, err := parseKeyPair(certPEM, keyPEM, c.Hostname, s.now())
		if err != nil {
			s.showCertificate(w, r, http.StatusBadRequest, c, err.Error())
			return
		}
		if err := s.Certs.saveCert(certPEM, keyPEM); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "settings.certificate", "settings", "uploaded certificate for %s (%s, valid until %s)", c.Hostname, cert.Leaf.Issuer.CommonName, cert.Leaf.NotAfter.Format("2006-01-02"))
	case "acme":
		// port 80 must answer already for the HTTP check
		if c.Challenge == "http" {
			if err := s.Certs.apply(CertSettings{Mode: "acme", Hostname: c.Hostname, RedirectHTTP: true}); err != nil {
				_ = s.Certs.apply(old)
				s.showCertificate(w, r, http.StatusBadRequest, c, err.Error())
				return
			}
		}
		if err := s.Certs.obtainACME(r.Context(), c, token, nil); err != nil {
			_ = s.Certs.apply(old)
			s.Certs.setErr(err.Error())
			s.showCertificate(w, r, http.StatusBadRequest, c, err.Error())
			return
		}
		s.audit(r, "settings.certificate", "settings", "Let's Encrypt certificate for %s (%s check)", c.Hostname, c.Challenge)
	default:
		c = CertSettings{Mode: "self", Challenge: "http", RedirectHTTP: true}
		s.audit(r, "settings.certificate", "settings", "the console's own certificate")
	}
	if err := s.store.SetSetting(r.Context(), settingCert, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Certs.setErr("")
	if err := s.Certs.apply(c); err != nil {
		s.Certs.setErr(err.Error())
		s.redirectErr(w, r, back, "Saved, but port 80 could not be opened: "+err.Error())
		return
	}
	if c.Mode == "self" {
		s.redirect(w, r, back, "The console uses its own certificate.")
		return
	}
	s.redirect(w, r, back, "The certificate is installed. Open the console under its name now.")
}

func (s *Server) handleCertificateRenew(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/certificate"
	c := s.certSettings(r.Context())
	if c.Mode != "acme" || s.Certs == nil {
		s.redirectErr(w, r, back, "No Let's Encrypt certificate is set up.")
		return
	}
	if err := s.Certs.obtainACME(r.Context(), c, s.cloudflareToken(c), nil); err != nil {
		s.Certs.setErr(err.Error())
		s.redirectErr(w, r, back, err.Error())
		return
	}
	s.Certs.setErr("")
	_ = s.Certs.apply(c)
	s.audit(r, "settings.certificate", "settings", "renewed the Let's Encrypt certificate for %s", c.Hostname)
	s.redirect(w, r, back, "The certificate is renewed.")
}

// CertificateCommand serves `passzit-server --certificate info|self` (the
// appliance's setup menu): it shows which certificate browsers get, or goes
// back to the self-signed one. The trusted files stay on disk.
func CertificateCommand(ctx context.Context, st *store.Store, dataDir, cmd string) (string, error) {
	var c CertSettings
	if err := st.GetSetting(ctx, settingCert, &c); err != nil {
		return "", err
	}
	switch cmd {
	case "info":
		if c.Mode != "upload" && c.Mode != "acme" {
			return "The console uses its own self-signed certificate. Set a trusted one in the web console under Settings → Certificate.", nil
		}
		certs := &Certs{dir: filepath.Join(dataDir, "tls")}
		k := certs.loadCert()
		if k == nil || k.Leaf == nil {
			return "Certificate setting: " + c.Mode + " for " + c.Hostname + ", but its files are missing; browsers get the self-signed certificate.", nil
		}
		how := "uploaded"
		if c.Mode == "acme" {
			how = "Let's Encrypt (" + c.Challenge + " check), renewed by itself"
		}
		return fmt.Sprintf("Certificate for %s: %s, issued by %s, valid until %s (%d days).", c.Hostname, how, k.Leaf.Issuer.CommonName,
			k.Leaf.NotAfter.Format("2006-01-02"), int(time.Until(k.Leaf.NotAfter).Hours()/24)), nil
	case "self":
		if err := st.SetSetting(ctx, settingCert, CertSettings{Mode: "self", Challenge: "http", RedirectHTTP: true}); err != nil {
			return "", err
		}
		_ = st.Audit(ctx, "-", "local", "settings.certificate", "settings", "back to the self-signed certificate from the command line")
		return "The console uses its self-signed certificate again. Restart the service if it is running.", nil
	}
	return "", fmt.Errorf("--certificate takes info or self")
}
