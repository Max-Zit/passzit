package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

//go:embed i18n/*.json
var i18nFS embed.FS

// Language is a console language.
type Language struct{ Code, Name string }

// Languages the console offers, by their own names; English is the source
// language.
var Languages = []Language{
	{"en", "English"}, {"de", "Deutsch"}, {"fr", "Français"}, {"es", "Español"}, {"it", "Italiano"},
	{"pt", "Português"}, {"nl", "Nederlands"}, {"pl", "Polski"}, {"cs", "Čeština"}, {"sr", "Srpski"},
	{"tr", "Türkçe"}, {"ru", "Русский"}, {"zh", "中文（简体）"}, {"ja", "日本語"},
}

// catalogs maps language → English text → translation.
var catalogs = map[string]map[string]string{}

func init() {
	for _, l := range Languages[1:] {
		raw, err := i18nFS.ReadFile("i18n/" + l.Code + ".json")
		if err != nil {
			panic(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			panic(fmt.Sprintf("i18n/%s.json: %v", l.Code, err))
		}
		catalogs[l.Code] = m
	}
}

func validLang(code string) bool {
	for _, l := range Languages {
		if l.Code == code {
			return true
		}
	}
	return false
}

// translate returns the text in lang; with args it is a format string.
func translate(lang, key string, args ...any) string {
	if t, ok := catalogs[lang][key]; ok && t != "" {
		key = t
	}
	if len(args) > 0 {
		return fmt.Sprintf(key, args...)
	}
	return key
}

// jsTextRE finds the texts the browser scripts translate: t("…").
var jsTextRE = regexp.MustCompile(`\bt\("((?:[^"\\]|\\.)+)"`)

// jsTexts are the English texts used by static/**/*.js.
var jsTexts = func() []string {
	seen := map[string]bool{}
	_ = fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") {
			return err
		}
		b, _ := staticFS.ReadFile(p)
		for _, m := range jsTextRE.FindAllStringSubmatch(string(b), -1) {
			var s string
			if json.Unmarshal([]byte(`"`+m[1]+`"`), &s) == nil {
				seen[s] = true
			}
		}
		return nil
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}()

// handleI18n serves the translations of the browser scripts.
func (s *Server) handleI18n(w http.ResponseWriter, r *http.Request) {
	lang := strings.TrimSuffix(r.PathValue("lang"), ".json")
	if !validLang(lang) {
		http.NotFound(w, r)
		return
	}
	m := map[string]string{}
	for _, k := range jsTexts {
		if t := catalogs[lang][k]; t != "" {
			m[k] = t
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(m)
}

// Page is what every template gets.
type Page struct {
	Title    string
	Nav      string
	Lang     string
	User     *store.User
	Flash    string
	FlashErr bool // the flash message reports a failure
	Error    string
	Version  string
	DevNo2FA bool
	Asset    string
	Path     string
	Host     string // the server's host as the browser sees it
	// LockMinutes and ClipboardSeconds are the user's effective vault
	// times (for the scripts).
	LockMinutes      int
	ClipboardSeconds int
	Data             any
}

// T translates a text for the page language.
func (p *Page) T(key string, args ...any) string { return translate(p.Lang, key, args...) }

// Languages lists the console languages (for the language menu).
func (p *Page) Languages() []Language { return Languages }

// Time formats a time in the server's zone.
func (p *Page) Time(t any) string {
	switch v := t.(type) {
	case time.Time:
		if v.IsZero() {
			return "—"
		}
		return v.Local().Format("2006-01-02 15:04")
	case *time.Time:
		if v == nil || v.IsZero() {
			return "—"
		}
		return v.Local().Format("2006-01-02 15:04")
	}
	return ""
}

// Ago is a short relative time ("5 min ago").
func (p *Page) Ago(t any) string {
	var tt time.Time
	switch v := t.(type) {
	case time.Time:
		tt = v
	case *time.Time:
		if v == nil {
			return "—"
		}
		tt = *v
	}
	if tt.IsZero() {
		return "—"
	}
	d := time.Since(tt)
	switch {
	case d < time.Minute:
		return p.T("just now")
	case d < time.Hour:
		return p.T("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return p.T("%d h ago", int(d.Hours()))
	}
	return p.T("%d days ago", int(d.Hours()/24))
}

// RoleName is the display name of a role.
func (p *Page) RoleName(r string) string {
	switch r {
	case store.RoleAdmin:
		return p.T("Administrator")
	case store.RoleUser:
		return p.T("User")
	}
	return r
}

// Zone names the server's time zone, e.g. "CEST, UTC+02:00".
func (p *Page) Zone() string { return time.Now().Format("MST, UTC-07:00") }

var funcs = template.FuncMap{
	"initial": func(s string) string {
		for _, r := range s {
			return strings.ToUpper(string(r))
		}
		return "?"
	},
	"join": strings.Join,
	"div":  func(a, b int) int { return a / b },
}

// loadTemplates parses each page together with the layout.
func loadTemplates() (map[string]*template.Template, error) {
	base, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/_*.html")
	if err != nil {
		return nil, err
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.Must(base.Clone()).ParseFS(templateFS, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out[name] = t
	}
	return out, nil
}

// render writes a page; the layout is chosen by the page itself
// ({{template "app" .}} or {{template "guest" .}}).
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p *Page) {
	t, ok := s.tmpl[name]
	if !ok {
		s.serverError(w, r, fmt.Errorf("no template %q", name))
		return
	}
	if p.User == nil {
		p.User = userFrom(r)
	}
	if p.Lang == "" {
		p.Lang = s.lang(r, p.User) // the user's own language first
	}
	p.Version = s.Version
	p.DevNo2FA = s.DevNo2FA
	p.Asset = assetVersion
	p.Path = r.URL.RequestURI()
	p.Host = r.Host
	if p.User != nil {
		p.LockMinutes, p.ClipboardSeconds = s.clientPrefs(r.Context(), p.User)
	}
	if f := s.takeFlash(w, r); f != "" && p.Flash == "" {
		// An error message (redirectErr) starts with "!".
		p.Flash, p.FlashErr = strings.TrimPrefix(f, "!"), strings.HasPrefix(f, "!")
	}
	var b strings.Builder
	if err := t.ExecuteTemplate(&b, name+".html", p); err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

// lang picks the console language: the user's choice, the lang cookie,
// then the browser's preference.
func (s *Server) lang(r *http.Request, u *store.User) string {
	if u != nil && validLang(u.Lang) {
		return u.Lang
	}
	if c, err := r.Cookie("lang"); err == nil && validLang(c.Value) {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		code := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		code = strings.SplitN(code, "-", 2)[0]
		if code == "sr" || code == "hr" || code == "bs" || code == "sh" {
			return "sr"
		}
		if validLang(code) {
			return code
		}
	}
	return "en"
}

// ---- flash messages: a short-lived cookie carries the message (in
// English, translated when shown) across the redirect after a POST.

const flashCookie = "pzflash"

func (s *Server) flash(w http.ResponseWriter, r *http.Request, msg string) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: url.QueryEscape(msg), Path: "/", MaxAge: 60,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return ""
	}
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	msg, _ := url.QueryUnescape(c.Value)
	if len(msg) > 300 {
		return ""
	}
	if strings.HasPrefix(msg, "!") {
		return msg // an error, translated when it was set
	}
	return translate(s.lang(r, userFrom(r)), msg)
}

// redirect answers a POST with 303 See Other and an optional message.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to, msg string) {
	if msg != "" {
		s.flash(w, r, msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// redirectErr answers a POST with an error message shown on the next page.
func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, to, msg string) {
	s.flash(w, r, "!"+translate(s.lang(r, userFrom(r)), msg))
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// assetVersion changes with the static files, so browsers do not keep an
// old script from their cache after an update.
var assetVersion = func() string {
	h := sha256.New()
	_ = fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".wasm") {
			return err
		}
		b, _ := staticFS.ReadFile(p)
		h.Write([]byte(p))
		h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

// rowCtx is a value of a shared template together with its page.
type rowCtx struct {
	P   *Page
	Row string
}

func init() {
	funcs["rowOf"] = func(p *Page, v string) rowCtx { return rowCtx{P: p, Row: v} }
}
