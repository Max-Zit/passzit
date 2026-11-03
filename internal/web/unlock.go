package web

import (
	"errors"
	"net/http"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/webauthn"
)

// Quick unlock: a passkey of the device (Windows Hello, Touch ID …) with the
// WebAuthn PRF extension gives the browser a secret that never leaves the
// authenticator. The browser seals the account key with it; the server
// only stores that sealed copy and the PRF input, so it can open nothing.

type unlockKeyJSON struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Salt    string `json:"salt"`
	Wrapped string `json:"wrapped"`
}

// webOnly refuses sessions of the extension and other clients: unlock keys
// belong to the web vault of this server.
func (s *Server) webOnly(w http.ResponseWriter, r *http.Request) bool {
	if sessionFrom(r).Kind != store.KindWeb {
		apiError(w, http.StatusForbidden, "forbidden", s.msg(r, "Set up Windows Hello in the web vault."))
		return false
	}
	return true
}

func (s *Server) apiUnlockKeys(w http.ResponseWriter, r *http.Request) {
	if !s.webOnly(w, r) {
		return
	}
	keys, err := s.store.UnlockKeys(r.Context(), userFrom(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := []unlockKeyJSON{}
	for _, k := range keys {
		out = append(out, unlockKeyJSON{ID: k.ID, Name: k.Name, Salt: k.Salt, Wrapped: k.Wrapped})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// b64Len reports whether v is base64url of min..max bytes.
func b64Len(v string, min, max int) bool {
	b, err := webauthn.B64.DecodeString(v)
	return err == nil && len(b) >= min && len(b) <= max
}

func (s *Server) apiAddUnlockKey(w http.ResponseWriter, r *http.Request) {
	if !s.webOnly(w, r) {
		return
	}
	u := userFrom(r)
	var q unlockKeyJSON
	if !readJSON(w, r, 16<<10, &q) {
		return
	}
	if !b64Len(q.ID, 16, 1023) || !b64Len(q.Salt, 32, 32) || !b64Len(q.Wrapped, 32, 256) {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, "invalid key material"))
		return
	}
	if err := s.store.AddUnlockKey(r.Context(), u.ID, store.UnlockKey{ID: q.ID, Name: q.Name, Salt: q.Salt, Wrapped: q.Wrapped}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			apiError(w, http.StatusConflict, "exists", s.msg(r, "This device unlocks the vault already."))
			return
		}
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, err.Error()))
		return
	}
	s.audit(r, "unlock.key.add", "user:"+u.Email, "quick unlock %q set up", q.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// apiUsedUnlockKey records an unlock with a device passkey (for the list and
// the audit log; the server cannot check the unlock itself).
func (s *Server) apiUsedUnlockKey(w http.ResponseWriter, r *http.Request) {
	if !s.webOnly(w, r) {
		return
	}
	u := userFrom(r)
	if err := s.store.UseUnlockKey(r.Context(), u.ID, r.PathValue("id")); err != nil {
		apiError(w, http.StatusNotFound, "not_found", s.msg(r, "Not found."))
		return
	}
	s.audit(r, "unlock.key.use", "user:"+u.Email, "vault unlocked with a device passkey")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUnlockKeyDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if err := s.store.DeleteUnlockKey(r.Context(), u.ID, r.FormValue("id")); err != nil {
		s.redirectErr(w, r, "/account", "Not found.")
		return
	}
	s.audit(r, "unlock.key.remove", "user:"+u.Email, "quick unlock removed")
	s.redirect(w, r, "/account", "Windows Hello no longer unlocks the vault on that device.")
}
