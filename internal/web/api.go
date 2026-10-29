package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// accountResp is what a client needs to unlock and to follow the policy.
type accountResp struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	HasRecovery bool   `json:"has_recovery"`
	*store.AccountKeys
	// Policy: lock and clipboard times in effect for this user, the key
	// derivation new keys should use, the minimum master-password length.
	LockMinutes      int             `json:"lock_minutes"`
	ClipboardSeconds int             `json:"clipboard_seconds"`
	PolicyKDF        vaultcrypto.KDF `json:"policy_kdf"`
	MinLength        int             `json:"min_length"`
	TrashDays        int             `json:"trash_days"`
	BreachCheck      bool            `json:"breach_check"`
	NoExport         bool            `json:"no_export"`
	SharedAdminsOnly bool            `json:"shared_admins_only"`
	NoSends          bool            `json:"no_sends"`
}

func (s *Server) apiAccount(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	k, err := s.store.AccountKeysOf(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p := s.policy(r.Context())
	lock, clip := s.clientPrefs(r.Context(), u)
	writeJSON(w, http.StatusOK, accountResp{Email: u.Email, Name: u.DisplayName, Role: u.Role, HasRecovery: u.HasRecovery, AccountKeys: k,
		LockMinutes: lock, ClipboardSeconds: clip, PolicyKDF: p.KDF, MinLength: p.MinPasswordLength, TrashDays: p.TrashDays, BreachCheck: p.BreachCheck,
		NoExport: p.NoExport, SharedAdminsOnly: p.SharedAdminsOnly, NoSends: p.NoSends})
}

// apiSessionKey hands the browser the key it encrypts its unlocked keys
// with in its session storage (the key lives only in this session).
func (s *Server) apiSessionKey(w http.ResponseWriter, r *http.Request) {
	k, err := s.store.UnlockKey(r.Context(), sessionFrom(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": k})
}

// apiSessionLock makes the keys the browser kept useless.
func (s *Server) apiSessionLock(w http.ResponseWriter, r *http.Request) {
	if err := s.store.LockSession(r.Context(), sessionFrom(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type changePasswordReq struct {
	CurrentAuth string `json:"current_auth"`
	store.Keys
}

// checkCurrent verifies the current master password (its auth key).
func (s *Server) checkCurrent(w http.ResponseWriter, r *http.Request, authKey string) bool {
	u := userFrom(r)
	if !s.guardOK(w, r, u.Email) {
		return false
	}
	ok, err := false, error(nil)
	if store.B64Len(authKey) == 32 {
		ok, err = s.store.VerifyAuth(r.Context(), u.ID, authKey)
	}
	if err != nil {
		s.serverError(w, r, err)
		return false
	}
	if !ok {
		s.guard.fail(r.Context(), clientIP(r), u.Email, "master password check")
		s.audit(r, "password.failed", "user:"+u.Email, "wrong current master password")
		apiError(w, http.StatusForbidden, "wrong", s.msg(r, "The current master password is wrong."))
		return false
	}
	return true
}

func (s *Server) apiChangePassword(w http.ResponseWriter, r *http.Request) {
	var q changePasswordReq
	if !readJSON(w, r, 4<<10, &q) {
		return
	}
	if !s.checkCurrent(w, r, q.CurrentAuth) {
		return
	}
	u := userFrom(r)
	if err := s.store.SetMasterKeys(r.Context(), u.ID, q.Keys, sessionFrom(r).Hash); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, storeErr(err)))
		return
	}
	s.audit(r, "password.change", "user:"+u.Email, "master password changed; other sessions ended")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// apiUpgradeKDF re-keys an account to the policy's stronger key
// derivation (the client does it right after an unlock).
func (s *Server) apiUpgradeKDF(w http.ResponseWriter, r *http.Request) {
	var q changePasswordReq
	if !readJSON(w, r, 4<<10, &q) {
		return
	}
	p := s.policy(r.Context())
	if q.KDF != p.KDF {
		apiError(w, http.StatusBadRequest, "invalid", "Only the key derivation of the policy is accepted.")
		return
	}
	if !s.checkCurrent(w, r, q.CurrentAuth) {
		return
	}
	u := userFrom(r)
	if err := s.store.SetMasterKeys(r.Context(), u.ID, q.Keys, sessionFrom(r).Hash); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, storeErr(err)))
		return
	}
	s.audit(r, "password.kdf", "user:"+u.Email, "key derivation upgraded to %s m=%d t=%d p=%d", p.KDF.Alg, p.KDF.M, p.KDF.T, p.KDF.P)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type recoveryReq struct {
	CurrentAuth        string `json:"current_auth"`
	RecoveryAuth       string `json:"recovery_auth"`
	RecoveryWrappedKey string `json:"recovery_wrapped_key"`
}

// apiSetRecovery creates, replaces or (empty values) removes the recovery key.
func (s *Server) apiSetRecovery(w http.ResponseWriter, r *http.Request) {
	var q recoveryReq
	if !readJSON(w, r, 2<<10, &q) {
		return
	}
	if !s.checkCurrent(w, r, q.CurrentAuth) {
		return
	}
	u := userFrom(r)
	if err := s.store.SetRecovery(r.Context(), u.ID, q.RecoveryAuth, q.RecoveryWrappedKey); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, storeErr(err)))
		return
	}
	if q.RecoveryAuth == "" {
		s.audit(r, "recovery.remove", "user:"+u.Email, "recovery key removed")
	} else {
		s.audit(r, "recovery.set", "user:"+u.Email, "new recovery key created")
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type verifyReq struct {
	CurrentAuth string `json:"current_auth"`
}

// apiVerify checks the master password again before a sensitive step in
// the client (export).
func (s *Server) apiVerify(w http.ResponseWriter, r *http.Request) {
	var q verifyReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	if s.checkCurrent(w, r, q.CurrentAuth) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

type eventReq struct {
	Event string `json:"event"`
	Count int    `json:"count"`
}

// events clients report for the audit log (only what happened, never data).
var events = map[string]string{
	"export":       "vault exported (%d items)",
	"export.plain": "vault exported UNENCRYPTED (%d items)",
	"import":       "items imported (%d items)",
}

func (s *Server) apiEvent(w http.ResponseWriter, r *http.Request) {
	var q eventReq
	if !readJSON(w, r, 1<<10, &q) {
		return
	}
	f, ok := events[q.Event]
	if !ok || q.Count < 0 {
		apiError(w, http.StatusBadRequest, "invalid", "Unknown event.")
		return
	}
	if strings.HasPrefix(q.Event, "export") && s.policy(r.Context()).NoExport {
		apiError(w, http.StatusForbidden, "forbidden", s.msg(r, "Your administrator does not allow exports."))
		return
	}
	u := userFrom(r)
	s.audit(r, "vault."+q.Event, "user:"+u.Email, f, q.Count)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- vault data

func (s *Server) apiSync(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	d, err := s.store.SyncData(r.Context(), userFrom(r).ID, max(since, 0))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) apiRevision(w http.ResponseWriter, r *http.Request) {
	rev, err := s.store.CurrentRevision(r.Context(), userFrom(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"revision": rev})
}

type putItemReq struct {
	VaultID  string `json:"vault_id"`
	Data     string `json:"data"`
	Revision int64  `json:"revision"` // the revision the change is based on; 0 for a new item
}

type revResp struct {
	Revision int64 `json:"revision"`
}

// vaultErr answers a store error of a vault change.
func (s *Server) vaultErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrStale):
		apiError(w, http.StatusConflict, "stale", s.msg(r, "This was changed on another device in the meantime. Reload and try again."))
	case errors.Is(err, store.ErrForbidden):
		apiError(w, http.StatusForbidden, "forbidden", s.msg(r, "You may not change this vault."))
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, "not_found", s.msg(r, "Not found."))
	default:
		apiError(w, http.StatusBadRequest, "invalid", s.msg(r, err.Error()))
	}
}

func (s *Server) apiPutItem(w http.ResponseWriter, r *http.Request) {
	var q putItemReq
	if !readJSON(w, r, store.MaxItemData+1024, &q) {
		return
	}
	rev, err := s.store.PutItem(r.Context(), userFrom(r).ID, r.PathValue("id"), q.VaultID, q.Data, q.Revision)
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, revResp{Revision: rev})
}

func (s *Server) itemOp(w http.ResponseWriter, r *http.Request, op func(*Server, *http.Request, int64, string) (int64, error)) {
	rev, err := op(s, r, userFrom(r).ID, r.PathValue("id"))
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, revResp{Revision: rev})
}

func (s *Server) apiTrashItem(w http.ResponseWriter, r *http.Request) {
	s.itemOp(w, r, func(s *Server, r *http.Request, u int64, id string) (int64, error) {
		return s.store.TrashItem(r.Context(), u, id)
	})
}

func (s *Server) apiRestoreItem(w http.ResponseWriter, r *http.Request) {
	s.itemOp(w, r, func(s *Server, r *http.Request, u int64, id string) (int64, error) {
		return s.store.RestoreItem(r.Context(), u, id)
	})
}

func (s *Server) apiPurgeItem(w http.ResponseWriter, r *http.Request) {
	s.itemOp(w, r, func(s *Server, r *http.Request, u int64, id string) (int64, error) {
		return s.store.PurgeItem(r.Context(), u, id)
	})
}

type putFolderReq struct {
	Data     string `json:"data"`
	Revision int64  `json:"revision"`
}

func (s *Server) apiPutFolder(w http.ResponseWriter, r *http.Request) {
	var q putFolderReq
	if !readJSON(w, r, store.MaxFolderData+256, &q) {
		return
	}
	rev, err := s.store.PutFolder(r.Context(), userFrom(r).ID, r.PathValue("id"), q.Data, q.Revision)
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, revResp{Revision: rev})
}

func (s *Server) apiDeleteFolder(w http.ResponseWriter, r *http.Request) {
	s.itemOp(w, r, func(s *Server, r *http.Request, u int64, id string) (int64, error) {
		return s.store.DeleteFolder(r.Context(), u, id)
	})
}

type batchReq struct {
	Items []store.NewItem `json:"items"`
}

// apiPutItems creates many items at once (import).
func (s *Server) apiPutItems(w http.ResponseWriter, r *http.Request) {
	var q batchReq
	if !readJSON(w, r, 16<<20, &q) {
		return
	}
	rev, err := s.store.PutItems(r.Context(), userFrom(r).ID, q.Items)
	if err != nil {
		s.vaultErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, revResp{Revision: rev})
}
