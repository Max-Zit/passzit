package web

// E-mail notifications (Settings → E-mail). Administrators get mail about
// the server (certificate renewal, console backups, four-eyes requests);
// users get mail about what concerns them (invitations, emergency access).
// Messages never contain secrets, only what happened and where to look.
//
// The SMTP sender is adapted from BackupZit (MaxZit's own code,
// internal/server/notify.go).

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/store"
)

const (
	settingEmail = "email"
	// mailPurpose binds the sealed SMTP password to its place.
	mailPurpose = "settings.email.password"
)

// EmailSettings configure the SMTP server and the administrators' address.
type EmailSettings struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // starttls, tls or none
	Username string `json:"username,omitempty"`
	// Password is sealed with the server's secret key.
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	// To are the administrators' addresses for server notices.
	To []string `json:"to"`
	// Language of the administrators' mail (a console language; empty: English).
	Language string `json:"language,omitempty"`
}

// Validate checks the settings (messages are catalog keys).
func (e *EmailSettings) Validate() error {
	if !e.Enabled {
		return nil
	}
	e.Host, e.From = strings.TrimSpace(e.Host), strings.TrimSpace(e.From)
	if e.Host == "" || e.From == "" {
		return mailMsg("Enter the SMTP server and the sender address.")
	}
	if e.Port <= 0 || e.Port > 65535 {
		return mailMsg("Invalid SMTP port.")
	}
	switch e.Security {
	case "starttls", "tls", "none":
	default:
		return mailMsg("Choose how the connection to the SMTP server is protected.")
	}
	if e.Username != "" && e.Security == "none" {
		return mailMsg("Sign-in needs STARTTLS or TLS: the password must not travel unencrypted.")
	}
	for _, a := range append([]string{e.From}, e.To...) {
		if !validAddress(a) {
			return mailMsg("Invalid e-mail address.")
		}
	}
	return nil
}

type mailMsg string

func (m mailMsg) Error() string { return string(m) }

// validAddress accepts a plain address without line breaks or lists (it
// goes into message headers).
func validAddress(a string) bool {
	if _, err := mail.ParseAddress(a); err != nil {
		return false
	}
	return strings.Contains(a, "@") && !strings.ContainsAny(a, "\r\n<>,; ")
}

func (s *Server) emailSettings(ctx context.Context) EmailSettings {
	e := EmailSettings{Port: 587, Security: "starttls"}
	if err := s.store.GetSetting(ctx, settingEmail, &e); err != nil {
		s.log.Error("e-mail settings", "err", err)
	}
	return e
}

// sendMail delivers a plain text message to one or more addresses.
// MailSender replaces it in tests.
func (s *Server) sendMail(ctx context.Context, e EmailSettings, to []string, subject, body string) error {
	if s.MailSender != nil {
		return s.MailSender(to, subject, body)
	}
	pass := ""
	if e.Password != "" {
		p, err := s.store.OpenSecret(mailPurpose, e.Password)
		if err != nil {
			return err
		}
		pass = p
	}
	for _, a := range append([]string{e.From}, to...) {
		if !validAddress(a) {
			return fmt.Errorf("invalid e-mail address %q", a)
		}
	}
	if e.Username != "" && e.Security == "none" {
		return errors.New("the password is sent only over an encrypted connection: choose STARTTLS or TLS")
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	d := net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	var err error
	if e.Security == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if e.Security == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, pass, e.Host)); err != nil {
			return fmt.Errorf("sign-in: %w", err)
		}
	}
	if err := c.Mail(e.From); err != nil {
		return fmt.Errorf("sender refused: %w", err)
	}
	for _, a := range to {
		if err := c.Rcpt(a); err != nil {
			return fmt.Errorf("recipient %s refused: %w", a, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	text := strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	msg := fmt.Sprintf("From: PassZit <%s>\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@passzit>\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n%s",
		e.From, strings.Join(to, ", "), mime.QEncoding.Encode("utf-8", subject), time.Now().Format(time.RFC1123Z), hex.EncodeToString(id[:]), text)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// mailText is one message: catalog keys for the subject and the lines of
// the body, with their arguments, translated for the reader.
type mailText struct {
	Subject string
	SubArgs []any
	Lines   [][]any // each: key, args…
}

func (m mailText) render(lang, link string) (string, string) {
	var b strings.Builder
	for _, l := range m.Lines {
		key, _ := l[0].(string)
		b.WriteString(translate(lang, key, l[1:]...) + "\n\n")
	}
	if link != "" {
		b.WriteString(link + "\n\n")
	}
	b.WriteString("— PassZit\n")
	return "[PassZit] " + translate(lang, m.Subject, m.SubArgs...), b.String()
}

// notifyAdmins mails the administrators' addresses; failures only reach
// the log and the audit log (a notice must never break the action).
func (s *Server) notifyAdmins(ctx context.Context, m mailText, path string) {
	e := s.emailSettings(ctx)
	if !e.Enabled || len(e.To) == 0 {
		return
	}
	subject, body := m.render(e.Language, s.linkTo(ctx, path))
	go s.deliver(e, e.To, subject, body) // #nosec G118 -- the mail outlives the request on purpose (own timeout in deliver)
}

// notifyUser mails one user in the user's language.
func (s *Server) notifyUser(ctx context.Context, email, lang string, m mailText, path string) {
	e := s.emailSettings(ctx)
	if !e.Enabled || email == "" {
		return
	}
	link := path
	if !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "http://") {
		link = s.linkTo(ctx, path)
	}
	subject, body := m.render(lang, link)
	go s.deliver(e, []string{email}, subject, body) // #nosec G118 -- the mail outlives the request on purpose (own timeout in deliver)
}

func (s *Server) deliver(e EmailSettings, to []string, subject, body string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.sendMail(ctx, e, to, subject, body); err != nil {
		s.log.Error("e-mail", "to", strings.Join(to, ","), "subject", subject, "err", err)
		_ = s.store.Audit(ctx, "-", "local", "email.failed", "settings", clip("e-mail to "+strings.Join(to, ", ")+" failed: "+err.Error(), 500))
	}
}

// linkTo is the address of a console page for mail: the public address
// when one is set.
func (s *Server) linkTo(ctx context.Context, path string) string {
	if path == "" {
		return ""
	}
	if n, err := s.Network(ctx); err == nil && n.PublicURL != "" {
		return strings.TrimRight(n.PublicURL, "/") + path
	}
	if s.Certs != nil {
		s.Certs.mu.Lock()
		host, port := s.Certs.cfg.Hostname, s.Certs.port
		trusted := s.Certs.cert != nil
		s.Certs.mu.Unlock()
		if trusted && host != "" {
			if port != "" && port != "443" {
				host += ":" + port
			}
			return "https://" + host + path
		}
	}
	return ""
}

// notifyEmergency tells the other side of an emergency contact what
// happened.
func (s *Server) notifyEmergency(r *http.Request, u *store.User, id int64, action string) {
	ctx := r.Context()
	var e *store.Emergency
	var list []store.Emergency
	var err error
	if action == "request" {
		list, err = s.store.EmergencyGrants(ctx, u.ID)
	} else {
		list, err = s.store.EmergencyContacts(ctx, u.ID)
	}
	if err != nil {
		return
	}
	for i := range list {
		if list[i].ID == id {
			e = &list[i]
		}
	}
	if e == nil {
		return
	}
	to, other := e.GrantorID, e.Grantor
	if action != "request" {
		to, other = e.GranteeID, e.Grantor
	}
	rcpt, err := s.store.UserByID(ctx, to)
	if err != nil {
		return
	}
	var m mailText
	switch action {
	case "request":
		m = mailText{Subject: "Emergency access to your vault was requested",
			Lines: [][]any{{"%s asks for emergency access to your vault.", e.Grantee},
				{"The access opens after %d days unless you reject it. Approve or reject it in the web vault under My account → Emergency access.", e.WaitDays}}}
	case "approve":
		m = mailText{Subject: "Emergency access was approved", Lines: [][]any{{"%s approved your emergency access. You can open the vault now in the web vault under Emergency access.", other}}}
	case "reject":
		m = mailText{Subject: "Emergency access was rejected", Lines: [][]any{{"%s rejected your request for emergency access.", other}}}
	default:
		return
	}
	s.notifyUser(ctx, rcpt.Email, rcpt.Lang, m, "/account")
}

// warnCertExpiry mails the administrators once a day when an uploaded
// certificate expires within 21 days (Let's Encrypt renews by itself).
func (s *Server) warnCertExpiry(ctx context.Context) {
	if s.Certs == nil || s.certSettings(ctx).Mode != "upload" {
		return
	}
	c := s.Certs.loadCert()
	if c == nil || c.Leaf == nil {
		return
	}
	days := int(time.Until(c.Leaf.NotAfter).Hours() / 24)
	today := s.now().Format("2006-01-02")
	if days >= 21 || s.certWarned == today {
		return
	}
	s.certWarned = today
	s.notifyAdmins(ctx, mailText{Subject: "The console certificate expires in %d days", SubArgs: []any{days},
		Lines: [][]any{{"The certificate of %s (issued by %s) expires on %s.", c.Leaf.Subject.CommonName, c.Leaf.Issuer.CommonName, c.Leaf.NotAfter.Format("2006-01-02")},
			{"Upload a new one under Settings → Certificate."}}}, "/settings/certificate")
}
