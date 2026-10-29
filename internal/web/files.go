package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/max-zit/passzit/internal/store"
)

// ---- encrypted attachments: the browser seals each file with its own key
// (kept inside the encrypted item); the server stores bytes it cannot read.

func (s *Server) apiPutAttachment(w http.ResponseWriter, r *http.Request) {
	p := s.policy(r.Context())
	max := int64(p.MaxFileMB)<<20 + 64
	data, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "The request could not be read.")
		return
	}
	err = s.store.PutAttachment(r.Context(), userFrom(r).ID, r.PathValue("item"), r.PathValue("id"), data, max, int64(p.StorageMB)<<20)
	switch {
	case errors.Is(err, store.ErrQuota):
		apiError(w, http.StatusRequestEntityTooLarge, "quota", s.msg(r, "Your storage for files is full (%d MB).", p.StorageMB))
		return
	case err != nil:
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"size": len(data)})
}

func (s *Server) apiGetAttachment(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.Attachment(r.Context(), userFrom(r).ID, r.PathValue("id"))
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (s *Server) apiDeleteAttachment(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAttachment(r.Context(), userFrom(r).ID, r.PathValue("id")); err != nil {
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiStorage(w http.ResponseWriter, r *http.Request) {
	used, err := s.store.StorageUsed(r.Context(), userFrom(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p := s.policy(r.Context())
	writeJSON(w, http.StatusOK, map[string]int64{"used": used, "quota": int64(p.StorageMB) << 20, "max_file": int64(p.MaxFileMB) << 20})
}

// ---- breach check: k-anonymity range queries of the Have I Been Pwned
// password list. The browser sends only the first five hex characters of a
// password's SHA-1; the server asks the service with padding switched on,
// so neither the server nor the service learns the password.

var hashPrefixRE = regexp.MustCompile(`^[0-9A-F]{5}$`)

// BreachURL is the range API (tests point it to a local server).
var BreachURL = "https://api.pwnedpasswords.com/range/"

var breachClient = &http.Client{Timeout: 15 * time.Second}

func (s *Server) apiBreach(w http.ResponseWriter, r *http.Request) {
	if !s.policy(r.Context()).BreachCheck {
		apiError(w, http.StatusForbidden, "off", s.msg(r, "The breach check is switched off by your administrator."))
		return
	}
	prefix := r.PathValue("prefix")
	if !hashPrefixRE.MatchString(prefix) {
		apiError(w, http.StatusBadRequest, "bad_request", "Five upper-case hex characters expected.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, BreachURL+prefix, nil)
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "PassZit/"+s.Version)
	resp, err := breachClient.Do(req) // #nosec G704 -- a fixed service address, the path is checked above
	if err != nil {
		s.log.Warn("breach check failed", "err", err)
		apiError(w, http.StatusBadGateway, "unreachable", s.msg(r, "The breach check service cannot be reached."))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		apiError(w, http.StatusBadGateway, "unreachable", s.msg(r, "The breach check service cannot be reached."))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}
