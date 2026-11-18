package web

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/update"
)

// The update notice: administrators (who may install updates) see a newer
// PassZit at the top of every console page, except on the Updates page
// itself. The version comes only from the signature-checked release check
// the server makes anyway (CheckUpdate); nothing else is fetched. The ×
// hides it for that administrator for five days, stored in the database so
// it holds in every browser; a version newer than the hidden one shows it
// again at once. Vault users never see it.

const (
	updateNoticePause = 5 * 24 * time.Hour
	updatesPage       = "/settings/version"
)

// updateNotice is what the layout shows.
type updateNotice struct {
	Version   string // the newer release
	Installed string
	// NoHelper: this installation cannot install from the console (no
	// root helper); the text points to install.sh or the package instead.
	NoHelper bool
	NotesURL string
}

// showUpdateNotice decides whether a release is shown to a user who hid
// the notice for hiddenVersion until hiddenUntil.
func showUpdateNotice(available, hiddenVersion string, hiddenUntil *time.Time, now time.Time) bool {
	switch {
	case available == "":
		return false
	case hiddenVersion == "" || hiddenUntil == nil:
		return true
	case update.Newer(available, hiddenVersion):
		return true
	default:
		return !now.Before(*hiddenUntil)
	}
}

// availableRelease is the newer release the last check found, or "".
func (s *Server) availableRelease() string {
	s.upd.mu.Lock()
	m := s.upd.latest
	s.upd.mu.Unlock()
	if m == nil || !update.Newer(m.Version, s.Version) {
		return ""
	}
	return m.Version
}

// releaseNotesURL is the page of a release: the GitHub release for the
// official source, else the Updates page (which shows the signed notes).
func (s *Server) releaseNotesURL(version string) string {
	if s.updateSource() != update.DefaultSource {
		return updatesPage
	}
	return "https://github.com/Max-Zit/passzit/releases/tag/v" + url.PathEscape(version)
}

// updateNoticeFor returns the notice for u on the page at path, or nil.
func (s *Server) updateNoticeFor(ctx context.Context, u *store.User, path string) *updateNotice {
	if !u.IsAdmin() || path == updatesPage {
		return nil
	}
	v := s.availableRelease()
	if v == "" {
		return nil
	}
	hv, until, err := s.store.UpdateNoticeHidden(ctx, u.ID)
	if err != nil {
		s.log.Warn("update notice", "err", err)
		hv, until = "", nil
	}
	if !showUpdateNotice(v, hv, until, s.now()) {
		return nil
	}
	return &updateNotice{Version: v, Installed: s.Version, NoHelper: !s.helperOK(), NotesURL: s.releaseNotesURL(v)}
}

// handleUpdateNoticeHide serves POST /settings/version/hide-notice and
// goes back to the page the notice was on.
func (s *Server) handleUpdateNoticeHide(w http.ResponseWriter, r *http.Request) {
	if u, v := userFrom(r), s.availableRelease(); u != nil && v != "" {
		if err := s.store.HideUpdateNotice(r.Context(), u.ID, v, s.now().Add(updateNoticePause)); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	http.Redirect(w, r, refererPath(r), http.StatusSeeOther)
}

// refererPath is the local page a form was sent from (path and query of a
// Referer on this host), for going back to it; anything else gives the
// vault. Never a redirect to another site.
func refererPath(r *http.Request) string {
	ref, err := url.Parse(r.Referer())
	if err != nil || ref.Host != r.Host || (ref.Scheme != "https" && ref.Scheme != "http") {
		return "/vault"
	}
	p := ref.EscapedPath()
	if ref.RawQuery != "" {
		p += "?" + ref.RawQuery
	}
	return safeNext(p)
}
