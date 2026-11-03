package web

import (
	"net/http"
	"strconv"
	"strings"
)

type emailData struct {
	E       EmailSettings
	HasPass bool
	ToText  string
}

func (s *Server) handleEmail(w http.ResponseWriter, r *http.Request) {
	s.showEmail(w, r, http.StatusOK, s.emailSettings(r.Context()), "")
}

func (s *Server) showEmail(w http.ResponseWriter, r *http.Request, status int, e EmailSettings, errMsg string) {
	d := &emailData{E: e, HasPass: e.Password != "", ToText: strings.Join(e.To, "\n")}
	d.E.Password = ""
	p := &Page{Title: "E-mail", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "email", p)
}

func (s *Server) handleEmailSave(w http.ResponseWriter, r *http.Request) {
	old := s.emailSettings(r.Context())
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	e := EmailSettings{
		Enabled:  r.FormValue("enabled") == "on",
		Host:     strings.TrimSpace(r.FormValue("host")),
		Port:     port,
		Security: r.FormValue("security"),
		Username: strings.TrimSpace(r.FormValue("username")),
		From:     strings.TrimSpace(r.FormValue("from")),
		Language: r.FormValue("language"),
	}
	for _, a := range strings.FieldsFunc(r.FormValue("to"), func(c rune) bool { return c == '\n' || c == ',' || c == ';' || c == '\r' }) {
		if a = strings.TrimSpace(a); a != "" {
			e.To = append(e.To, a)
		}
	}
	if len(e.To) > 20 {
		e.To = e.To[:20]
	}
	if _, ok := catalogs[e.Language]; !ok && e.Language != "en" {
		e.Language = ""
	}
	if pw := r.FormValue("password"); pw != "" {
		e.Password = s.store.SealSecret(mailPurpose, pw)
	} else if e.Username != "" {
		e.Password = old.Password
	}
	if err := e.Validate(); err != nil {
		s.showEmail(w, r, http.StatusBadRequest, e, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingEmail, e); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.email", "settings", "e-mail %s (server %s, %d administrator addresses)", map[bool]string{true: "on", false: "off"}[e.Enabled], e.Host, len(e.To))
	s.redirect(w, r, "/settings/email", "Saved.")
}

// handleEmailTest sends a test message to the signed-in administrator.
func (s *Server) handleEmailTest(w http.ResponseWriter, r *http.Request) {
	e := s.emailSettings(r.Context())
	u := userFrom(r)
	if !e.Enabled {
		s.redirectErr(w, r, "/settings/email", "Switch on e-mail and save first.")
		return
	}
	subject, body := mailText{Subject: "Test message", Lines: [][]any{{"This is a test message from PassZit. E-mail notifications work."}}}.render(s.lang(r, u), s.linkTo(r.Context(), "/settings/email"))
	if err := s.sendMail(r.Context(), e, []string{u.Email}, subject, body); err != nil {
		s.redirectErr(w, r, "/settings/email", "The test message could not be sent: "+err.Error())
		return
	}
	s.audit(r, "settings.email", "settings", "test message sent to %s", u.Email)
	s.redirect(w, r, "/settings/email", "The test message is sent to "+u.Email+".")
}
