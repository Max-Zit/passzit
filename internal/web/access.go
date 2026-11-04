package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// ---- secret links (Send): sealed in the browser, the key in the link's
// #fragment, which browsers never send to a server.

type createSendReq struct {
	ID       string `json:"id"`
	Data     string `json:"data"` // base64url of the sealed bytes
	Auth     string `json:"auth,omitempty"`
	MaxViews int    `json:"max_views"`
	Hours    int    `json:"hours"`
}

func (s *Server) apiCreateSend(w http.ResponseWriter, r *http.Request) {
	p := s.policy(r.Context())
	if p.NoSends {
		apiError(w, http.StatusForbidden, "forbidden", s.msg(r, "Your administrator does not allow secret links."))
		return
	}
	var q createSendReq
	limit := int64(p.MaxFileMB)<<20*4/3 + 4096
	if !readJSON(w, r, limit, &q) {
		return
	}
	data, err := b64Decode(q.Data)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid", "Invalid link data.")
		return
	}
	if q.Hours < 1 || q.Hours > 30*24 {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, "A link may work for at most 30 days."))
		return
	}
	hash := ""
	if q.Auth != "" {
		if store.B64Len(q.Auth) != 32 {
			apiError(w, http.StatusBadRequest, "invalid", "Invalid password data.")
			return
		}
		if hash, err = auth.HashPassword(q.Auth); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	u := userFrom(r)
	if err := s.store.CreateSend(r.Context(), u.ID, q.ID, data, hash, q.MaxViews, s.now().Add(time.Duration(q.Hours)*time.Hour), int64(p.StorageMB)<<20); err != nil {
		if errors.Is(err, store.ErrQuota) {
			apiError(w, http.StatusRequestEntityTooLarge, "quota", s.msg(r, "Your storage is full (%d MB). Delete files or secret links you no longer need.", p.StorageMB))
			return
		}
		s.vaultErr(w, r, err)
		return
	}
	s.audit(r, "send.create", "send:"+q.ID, "secret link made (%d bytes, opens %d times, %d hours, password %v)", len(data), q.MaxViews, q.Hours, hash != "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiSends(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Sends(r.Context(), userFrom(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if list == nil {
		list = []store.Send{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) apiDeleteSend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSend(r.Context(), userFrom(r).ID, id); err != nil {
		s.vaultErr(w, r, err)
		return
	}
	s.audit(r, "send.delete", "send:"+id, "secret link deleted")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSendPage is the page a recipient opens (no account needed).
func (s *Server) handleSendPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.render(w, r, http.StatusOK, "send", &Page{Title: "Secret link"})
}

func (s *Server) apiSendState(w http.ResponseWriter, r *http.Request) {
	protected, err := s.store.SendState(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, http.StatusGone, "gone", s.msg(r, "This link does not work any more: it was opened already, ran out or was deleted."))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"protected": protected})
}

type openSendReq struct {
	Auth string `json:"auth,omitempty"`
}

func (s *Server) apiOpenSend(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		apiError(w, http.StatusTooManyRequests, "blocked", s.msg(r, "Too many failed attempts. Try again later."))
		return
	}
	var q openSendReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	id := r.PathValue("id")
	data, left, err := s.store.OpenSend(r.Context(), id, func(hash string) bool {
		ok, _ := auth.VerifyPassword(hash, q.Auth)
		return ok
	})
	switch {
	case errors.Is(err, store.ErrForbidden):
		s.guard.fail(r.Context(), ip, "send:"+id, "secret link password")
		apiError(w, http.StatusForbidden, "wrong", s.msg(r, "The password is wrong."))
		return
	case errors.Is(err, store.ErrGone):
		apiError(w, http.StatusGone, "gone", s.msg(r, "This link does not work any more: it was opened already, ran out or was deleted."))
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.auditAs(r, "-", "send.open", "send:"+id, "secret link opened (%d openings left)", left)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"data": b64Encode(data), "left": left})
}

// ---- emergency access

func (s *Server) apiEmergency(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	contacts, err := s.store.EmergencyContacts(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	grants, err := s.store.EmergencyGrants(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if contacts == nil {
		contacts = []store.Emergency{}
	}
	if grants == nil {
		grants = []store.Emergency{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"contacts": contacts, "grants": grants})
}

type addEmergencyReq struct {
	GranteeID int64  `json:"grantee_id"`
	SealedKey string `json:"sealed_key"`
	WaitDays  int    `json:"wait_days"`
}

func (s *Server) apiAddEmergency(w http.ResponseWriter, r *http.Request) {
	var q addEmergencyReq
	if !readJSON(w, r, 4<<10, &q) {
		return
	}
	if err := s.store.AddEmergency(r.Context(), userFrom(r).ID, q.GranteeID, q.SealedKey, q.WaitDays); err != nil {
		if errors.Is(err, store.ErrConflict) {
			apiError(w, http.StatusConflict, "exists", s.msg(r, "This person is your emergency contact already."))
			return
		}
		s.vaultErr(w, r, err)
		return
	}
	s.audit(r, "emergency.add", fmt.Sprintf("user:%d", q.GranteeID), "emergency contact added (waiting time %d days)", q.WaitDays)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiEmergencyAction(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var err error
	var what string
	switch r.PathValue("action") {
	case "request":
		err, what = s.store.RequestEmergency(r.Context(), u.ID, id), "emergency access requested; the waiting time runs"
	case "approve":
		err, what = s.store.ApproveEmergency(r.Context(), u.ID, id), "emergency access approved early"
	case "reject":
		err, what = s.store.RejectEmergency(r.Context(), u.ID, id), "emergency access request rejected"
	default:
		err = store.ErrNotFound
	}
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	s.audit(r, "emergency."+r.PathValue("action"), fmt.Sprintf("emergency:%d", id), "%s", what)
	s.notifyEmergency(r, u, id, r.PathValue("action"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiDeleteEmergency(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.store.DeleteEmergency(r.Context(), userFrom(r).ID, id); err != nil {
		s.vaultErr(w, r, err)
		return
	}
	s.audit(r, "emergency.remove", fmt.Sprintf("emergency:%d", id), "emergency contact removed")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiEmergencyVault(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	v, err := s.store.EmergencyOpen(r.Context(), userFrom(r).ID, id)
	if errors.Is(err, store.ErrForbidden) {
		apiError(w, http.StatusForbidden, "waiting", s.msg(r, "The access is not open yet."))
		return
	}
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	s.audit(r, "emergency.open", fmt.Sprintf("emergency:%d", id), "emergency access used: vault of %s opened", v.Grantor)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, v)
}

// ---- who used an item of a shared vault

type accessReq struct {
	Action string `json:"action"`
	// Via: "extension", "console" (opened from a MaxZit console such as
	// WatchZit) or "cli" for device tokens; web sessions are always "web".
	Via string `json:"via"`
}

func (s *Server) apiItemAccess(w http.ResponseWriter, r *http.Request) {
	var q accessReq
	if !readJSON(w, r, 256, &q) {
		return
	}
	u := userFrom(r)
	device, via := "", "web"
	if sess := sessionFrom(r); sess != nil {
		if sess.Kind == store.KindExt {
			device, via = sess.Device, "extension"
			if q.Via == "console" || q.Via == "cli" {
				via = q.Via
			}
		} else {
			device = browserOf(sess.UserAgent)
		}
	}
	// Items of personal vaults are not logged; the answer does not tell.
	// Beyond the limit per user and hour, reports are dropped silently.
	if s.accessReports.allow(u.ID, s.now()) {
		_ = s.store.LogItemAccess(r.Context(), u.ID, u.Email, r.PathValue("id"), q.Action, clientIP(r), device, via)
	}
	w.WriteHeader(http.StatusNoContent)
}

// maxAccessReports is how many uses of items one user may report per hour.
const maxAccessReports = 600

// rateCounter counts events per user in fixed windows of an hour.
type rateCounter struct {
	mu sync.Mutex
	m  map[int64]rateWindow
}

type rateWindow struct {
	start time.Time
	n     int
}

func (c *rateCounter) allow(user int64, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[int64]rateWindow{}
	}
	w := c.m[user]
	if now.Sub(w.start) >= time.Hour || now.Before(w.start) {
		if len(c.m) > 10000 {
			for k, x := range c.m { // forget old windows now and then
				if now.Sub(x.start) >= time.Hour {
					delete(c.m, k)
				}
			}
		}
		w = rateWindow{start: now}
	}
	if w.n >= maxAccessReports {
		return false
	}
	w.n++
	c.m[user] = w
	return true
}

// browserOf names a browser and system from a User-Agent ("Edge · Windows").
func browserOf(ua string) string {
	b := ""
	for _, c := range []struct{ mark, name string }{{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Vivaldi", "Vivaldi"}, {"Firefox/", "Firefox"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}} {
		if strings.Contains(ua, c.mark) {
			b = c.name
			break
		}
	}
	os := ""
	for _, c := range []struct{ mark, name string }{{"Windows", "Windows"}, {"Android", "Android"}, {"iPhone", "iOS"}, {"iPad", "iOS"}, {"Mac OS X", "macOS"}, {"Linux", "Linux"}} {
		if strings.Contains(ua, c.mark) {
			os = c.name
			break
		}
	}
	switch {
	case b != "" && os != "":
		return b + " · " + os
	case b != "":
		return b
	}
	return os
}

func (s *Server) apiItemAccessLog(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ItemAccessLog(r.Context(), userFrom(r).ID, r.PathValue("id"))
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	if list == nil {
		list = []store.AccessEntry{}
	}
	writeJSON(w, http.StatusOK, list)
}

// ---- four-eyes approval of sensitive administrator actions

type approvedKey struct{}

// needsApproval tells whether an action must wait for a second
// administrator (the policy is on and there is another active one).
func (s *Server) needsApproval(r *http.Request) bool {
	if r.Context().Value(approvedKey{}) != nil || !s.policy(r.Context()).FourEyes {
		return false
	}
	users, err := s.store.Users(r.Context())
	if err != nil {
		return true
	}
	admins := 0
	for _, u := range users {
		if u.Role == store.RoleAdmin && !u.Disabled {
			admins++
		}
	}
	return admins >= 2
}

// holdForApproval stores the request when it needs a second
// administrator; true means it was held (the handler stops).
func (s *Server) holdForApproval(w http.ResponseWriter, r *http.Request, action, summary, back string) bool {
	if !s.needsApproval(r) {
		return false
	}
	if err := r.ParseForm(); err != nil {
		s.redirectErr(w, r, back, "The request could not be read.")
		return true
	}
	// The form may hold secrets (a client secret, a bind password): it is
	// kept sealed with the server key until it runs.
	raw, _ := json.Marshal(r.PostForm)
	form := map[string][]string{"sealed": {s.store.SealSecret("approval.form", string(raw))}}
	id, err := s.store.CreateApproval(r.Context(), store.Approval{Action: action, Summary: summary, Path: r.URL.Path, Form: form, RequestedBy: userFrom(r).Email})
	if err != nil {
		s.serverError(w, r, err)
		return true
	}
	s.audit(r, "approval.request", fmt.Sprintf("approval:%d", id), "%s — waits for a second administrator", summary)
	s.notifyAdmins(r.Context(), mailText{Subject: "A change waits for a second administrator",
		Lines: [][]any{{"%s asks: %s.", userFrom(r).Email, summary}, {"It runs only after a second administrator approves it under Approvals."}}}, "/approvals")
	s.redirect(w, r, back, "A second administrator must approve this under Approvals (within 24 hours).")
	return true
}

type approvalsData struct {
	List []store.Approval
	Me   string
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Approvals(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "approvals", &Page{Title: "Approvals", Nav: "approvals", Data: &approvalsData{List: list, Me: userFrom(r).Email}})
}

func (s *Server) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	const back = "/approvals"
	me := userFrom(r).Email
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if r.PathValue("decision") == "reject" {
		a, err := s.store.TakeApproval(r.Context(), id, me, "rejected")
		if err != nil {
			s.redirectErr(w, r, back, "This request is no longer waiting.")
			return
		}
		s.audit(r, "approval.reject", fmt.Sprintf("approval:%d", id), "rejected: %s (requested by %s)", a.Summary, a.RequestedBy)
		s.redirect(w, r, back, "Rejected.")
		return
	}
	if r.PathValue("decision") != "approve" {
		s.notFound(w, r)
		return
	}
	// the store refuses the requester's own approval (whatever the list shows)
	a, err := s.store.TakeApproval(r.Context(), id, me, "approved")
	if errors.Is(err, store.ErrOwnApproval) {
		s.redirectErr(w, r, back, "You cannot approve your own request.")
		return
	}
	if err != nil {
		s.redirectErr(w, r, back, "This request is no longer waiting.")
		return
	}
	ok, result := s.replayApproved(r, a)
	_ = s.store.FinishApproval(r.Context(), id, ok, result)
	s.audit(r, "approval.approve", fmt.Sprintf("approval:%d", id), "approved: %s (requested by %s) — %s", a.Summary, a.RequestedBy, result)
	if !ok {
		s.redirectErr(w, r, back, "Approved, but the action failed: "+result)
		return
	}
	s.redirect(w, r, back, "Approved and done.")
}

// replayApproved runs the stored request as the approving administrator.
func (s *Server) replayApproved(r *http.Request, a *store.Approval) (bool, string) {
	if s.mux == nil {
		return false, "not available"
	}
	var form url.Values
	plain, err := s.store.OpenSecret("approval.form", strings.Join(a.Form["sealed"], ""))
	if err != nil || json.Unmarshal([]byte(plain), &form) != nil {
		return false, "the stored request cannot be read"
	}
	body := form.Encode()
	ctx := context.WithValue(r.Context(), approvedKey{}, a.ID)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, a.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = r.RemoteAddr
	for _, c := range r.Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	msg := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == flashCookie {
			msg, _ = url.QueryUnescape(c.Value)
		}
	}
	if rec.Code >= 400 || strings.HasPrefix(msg, "!") {
		return false, strings.TrimPrefix(msg, "!")
	}
	if msg == "" {
		msg = "done"
	}
	return true, msg
}

func b64Encode(b []byte) string          { return vaultcrypto.B64.EncodeToString(b) }
func b64Decode(s string) ([]byte, error) { return vaultcrypto.B64.DecodeString(s) }
