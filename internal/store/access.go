package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- secret links (Send)

var sendIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// ValidSendID checks the form of a link id (16 random bytes, base64url).
func ValidSendID(id string) bool { return sendIDRE.MatchString(id) }

// ErrGone is returned for a link that ran out or was deleted.
var ErrGone = errors.New("the link does not work any more")

// Send is a secret link as its owner sees it.
type Send struct {
	ID         string     `json:"id"`
	Size       int        `json:"size"`
	Protected  bool       `json:"protected"`
	MaxViews   int        `json:"max_views"`
	Views      int        `json:"views"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastViewed *time.Time `json:"last_viewed,omitempty"`
}

// CreateSend stores a sealed secret.
func (s *Store) CreateSend(ctx context.Context, owner int64, id string, data []byte, authHash string, maxViews int, expires time.Time) error {
	if !ValidSendID(id) || len(data) < 1+12+16 || data[0] != 1 {
		return errors.New("invalid link")
	}
	if maxViews < 1 || maxViews > 100 || !expires.After(s.now()) {
		return errors.New("a link opens 1–100 times and ends in the future")
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM sends WHERE owner_id=$1`, owner).Scan(&n); err != nil {
		return err
	}
	if n >= 200 {
		return errors.New("too many links; delete old ones")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO sends(id, owner_id, data, auth_hash, max_views, expires_at, created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		id, owner, data, authHash, maxViews, expires, s.now())
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// Sends lists the links of a user, newest first.
func (s *Store) Sends(ctx context.Context, owner int64) ([]Send, error) {
	rows, err := s.db.Query(ctx, `SELECT id, length(data), auth_hash<>'', max_views, views, expires_at, created_at, last_viewed FROM sends WHERE owner_id=$1 ORDER BY created_at DESC`, owner)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Send, error) {
		var x Send
		err := r.Scan(&x.ID, &x.Size, &x.Protected, &x.MaxViews, &x.Views, &x.ExpiresAt, &x.CreatedAt, &x.LastViewed)
		return x, err
	})
}

// DeleteSend removes a link of its owner.
func (s *Store) DeleteSend(ctx context.Context, owner int64, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM sends WHERE id=$1 AND owner_id=$2`, id, owner)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// SendState tells whether a link still works and needs a password (it
// does not count an opening).
func (s *Store) SendState(ctx context.Context, id string) (protected bool, err error) {
	if !ValidSendID(id) {
		return false, ErrGone
	}
	var views, max int
	var exp time.Time
	err = s.db.QueryRow(ctx, `SELECT auth_hash<>'', views, max_views, expires_at FROM sends WHERE id=$1`, id).Scan(&protected, &views, &max, &exp)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (views >= max || !exp.After(s.now()))) {
		return false, ErrGone
	}
	return protected, err
}

// OpenSend counts an opening and returns the sealed data. check decides
// about the password (given the stored hash); a wrong one does not count.
// The data is removed with the last allowed opening.
func (s *Store) OpenSend(ctx context.Context, id string, check func(hash string) bool) ([]byte, int, error) {
	if !ValidSendID(id) {
		return nil, 0, ErrGone
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback(ctx)
	var data []byte
	var hash string
	var views, max int
	var exp time.Time
	err = tx.QueryRow(ctx, `SELECT data, auth_hash, views, max_views, expires_at FROM sends WHERE id=$1 FOR UPDATE`, id).Scan(&data, &hash, &views, &max, &exp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, ErrGone
	}
	if err != nil {
		return nil, 0, err
	}
	if views >= max || !exp.After(s.now()) {
		return nil, 0, ErrGone
	}
	if hash != "" && !check(hash) {
		return nil, 0, ErrForbidden
	}
	views++
	if views >= max {
		// The last opening: nothing stays on the server.
		_, err = tx.Exec(ctx, `UPDATE sends SET views=$2, last_viewed=$3, data='\x00'::bytea WHERE id=$1`, id, views, s.now())
	} else {
		_, err = tx.Exec(ctx, `UPDATE sends SET views=$2, last_viewed=$3 WHERE id=$1`, id, views, s.now())
	}
	if err != nil {
		return nil, 0, err
	}
	return data, max - views, tx.Commit(ctx)
}

// PurgeSends removes links that ended a week ago (the owners still see
// them for a while).
func (s *Store) PurgeSends(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sends WHERE expires_at < $1 OR (views >= max_views AND last_viewed < $1)`, s.now().Add(-7*24*time.Hour))
	if err == nil {
		_, err = s.db.Exec(ctx, `UPDATE sends SET data='\x00'::bytea WHERE expires_at < $1 AND length(data) > 1`, s.now())
	}
	return err
}

// ---- emergency access

// Emergency is an emergency-access link between two users.
type Emergency struct {
	ID          int64      `json:"id"`
	GrantorID   int64      `json:"grantor_id"`
	Grantor     string     `json:"grantor"`
	GranteeID   int64      `json:"grantee_id"`
	Grantee     string     `json:"grantee"`
	WaitDays    int        `json:"wait_days"`
	RequestedAt *time.Time `json:"requested_at,omitempty"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	// ReadyAt is when the access opens (requested + waiting time).
	ReadyAt *time.Time `json:"ready_at,omitempty"`
	Open    bool       `json:"open"`
}

func (s *Store) emergencyList(ctx context.Context, where string, id int64) ([]Emergency, error) {
	rows, err := s.db.Query(ctx, `SELECT e.id, e.grantor_id, g.email, e.grantee_id, t.email, e.wait_days, e.requested_at, e.approved_at, e.created_at
		FROM emergency_contacts e JOIN users g ON g.id=e.grantor_id JOIN users t ON t.id=e.grantee_id WHERE `+where+`=$1 ORDER BY e.created_at`, id)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Emergency, error) {
		var x Emergency
		err := r.Scan(&x.ID, &x.GrantorID, &x.Grantor, &x.GranteeID, &x.Grantee, &x.WaitDays, &x.RequestedAt, &x.ApprovedAt, &x.CreatedAt)
		return x, err
	})
	for i := range list {
		if t := list[i].RequestedAt; t != nil {
			ready := t.Add(time.Duration(list[i].WaitDays) * 24 * time.Hour)
			list[i].ReadyAt = &ready
			list[i].Open = list[i].ApprovedAt != nil || !s.now().Before(ready)
		}
	}
	return list, err
}

// EmergencyContacts lists the people a user trusts.
func (s *Store) EmergencyContacts(ctx context.Context, grantor int64) ([]Emergency, error) {
	return s.emergencyList(ctx, "e.grantor_id", grantor)
}

// EmergencyGrants lists the people who trust a user.
func (s *Store) EmergencyGrants(ctx context.Context, grantee int64) ([]Emergency, error) {
	return s.emergencyList(ctx, "e.grantee_id", grantee)
}

// AddEmergency makes a user an emergency contact (the account key sealed
// to the contact's public key).
func (s *Store) AddEmergency(ctx context.Context, grantor, grantee int64, sealed string, waitDays int) error {
	if grantor == grantee {
		return errors.New("you cannot be your own emergency contact")
	}
	if !SealedToOK(sealed, 512) || waitDays < 0 || waitDays > 90 {
		return errors.New("invalid emergency contact")
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM emergency_contacts WHERE grantor_id=$1`, grantor).Scan(&n); err != nil {
		return err
	}
	if n >= 5 {
		return errors.New("at most 5 emergency contacts")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO emergency_contacts(grantor_id, grantee_id, sealed_key, wait_days, created_at) SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM users WHERE id=$2 AND NOT disabled)`,
		grantor, grantee, sealed, waitDays, s.now())
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// emergencyAct changes a link the user is part of (as grantor or grantee).
func (s *Store) emergencyAct(ctx context.Context, q string, id, user int64) error {
	tag, err := s.db.Exec(ctx, q, id, user, s.now())
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// RequestEmergency starts the waiting time (by the contact).
func (s *Store) RequestEmergency(ctx context.Context, grantee, id int64) error {
	return s.emergencyAct(ctx, `UPDATE emergency_contacts SET requested_at=$3 WHERE id=$1 AND grantee_id=$2 AND requested_at IS NULL`, id, grantee)
}

// ApproveEmergency opens a requested access at once (by the grantor).
func (s *Store) ApproveEmergency(ctx context.Context, grantor, id int64) error {
	return s.emergencyAct(ctx, `UPDATE emergency_contacts SET approved_at=$3 WHERE id=$1 AND grantor_id=$2 AND requested_at IS NOT NULL`, id, grantor)
}

// RejectEmergency ends a request (by the grantor); the contact stays.
func (s *Store) RejectEmergency(ctx context.Context, grantor, id int64) error {
	return s.emergencyAct(ctx, `UPDATE emergency_contacts SET requested_at=NULL, approved_at=NULL WHERE id=$1 AND grantor_id=$2 AND $3::timestamptz IS NOT NULL`, id, grantor)
}

// DeleteEmergency removes a link (by either side).
func (s *Store) DeleteEmergency(ctx context.Context, user, id int64) error {
	return s.emergencyAct(ctx, `DELETE FROM emergency_contacts WHERE id=$1 AND (grantor_id=$2 OR grantee_id=$2) AND $3::timestamptz IS NOT NULL`, id, user)
}

// EmergencyVault is what an emergency contact gets once the access is
// open: the sealed account key, the grantor's personal vault key wrapped
// by it, and the vault's items (all still encrypted).
type EmergencyVault struct {
	Grantor    string `json:"grantor"`
	SealedKey  string `json:"sealed_key"`
	VaultID    string `json:"vault_id"`
	WrappedKey string `json:"wrapped_key"`
	Items      []Item `json:"items"`
}

// EmergencyOpen returns the grantor's vault for an open access.
func (s *Store) EmergencyOpen(ctx context.Context, grantee, id int64) (*EmergencyVault, error) {
	list, err := s.EmergencyGrants(ctx, grantee)
	if err != nil {
		return nil, err
	}
	var e *Emergency
	for i := range list {
		if list[i].ID == id {
			e = &list[i]
		}
	}
	if e == nil {
		return nil, ErrNotFound
	}
	if !e.Open {
		return nil, ErrForbidden
	}
	out := &EmergencyVault{Grantor: e.Grantor, Items: []Item{}}
	if err := s.db.QueryRow(ctx, `SELECT e.sealed_key, v.id::text, m.wrapped_key FROM emergency_contacts e
		JOIN vaults v ON v.owner_id=e.grantor_id AND v.kind='personal' JOIN vault_members m ON m.vault_id=v.id AND m.user_id=e.grantor_id
		WHERE e.id=$1`, id).Scan(&out.SealedKey, &out.VaultID, &out.WrappedKey); err != nil {
		return nil, notFound(err)
	}
	rows, err := s.db.Query(ctx, `SELECT id::text, vault_id::text, data, revision, created_at, updated_at, deleted_at FROM items WHERE vault_id=$1 AND deleted_at IS NULL`, out.VaultID)
	if err != nil {
		return nil, err
	}
	out.Items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Item, error) {
		var it Item
		err := r.Scan(&it.ID, &it.VaultID, &it.Data, &it.Revision, &it.CreatedAt, &it.UpdatedAt, &it.DeletedAt)
		return it, err
	})
	return out, err
}

// ---- who used an item of a shared vault

// AccessEntry is one use of an item.
type AccessEntry struct {
	Email  string    `json:"email"`
	Action string    `json:"action"`
	IP     string    `json:"ip"`
	At     time.Time `json:"at"`
}

// ItemActions are the uses clients report.
var ItemActions = map[string]bool{"show": true, "copy": true, "fill": true, "view": true}

// LogItemAccess records a use of an item in a shared vault (items of
// personal vaults are not logged).
func (s *Store) LogItemAccess(ctx context.Context, userID int64, email, itemID, action, ip string) error {
	if !ValidID(itemID) || !ItemActions[action] {
		return ErrNotFound
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO item_access(item_id, vault_id, user_id, email, action, ip, at)
		SELECT i.id, i.vault_id, $2, $3, $4, $5, $6 FROM items i JOIN vaults v ON v.id=i.vault_id AND v.kind='shared'
		JOIN vault_members m ON m.vault_id=i.vault_id AND m.user_id=$2 WHERE i.id=$1`, itemID, userID, email, action, ip, s.now())
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// ItemAccessLog returns the last uses of an item (for the vault's managers).
func (s *Store) ItemAccessLog(ctx context.Context, userID int64, itemID string) ([]AccessEntry, error) {
	if !ValidID(itemID) {
		return nil, ErrNotFound
	}
	var rights string
	err := s.db.QueryRow(ctx, `SELECT m.rights FROM items i JOIN vault_members m ON m.vault_id=i.vault_id AND m.user_id=$2 WHERE i.id=$1`, itemID, userID).Scan(&rights)
	if err != nil {
		return nil, notFound(err)
	}
	if rights != "manage" {
		return nil, ErrForbidden
	}
	rows, err := s.db.Query(ctx, `SELECT email, action, ip, at FROM item_access WHERE item_id=$1 ORDER BY at DESC LIMIT 200`, itemID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AccessEntry, error) {
		var a AccessEntry
		err := r.Scan(&a.Email, &a.Action, &a.IP, &a.At)
		return a, err
	})
}

// PurgeItemAccess forgets uses older than a year.
func (s *Store) PurgeItemAccess(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM item_access WHERE at < $1`, s.now().AddDate(-1, 0, 0))
	return err
}

// ---- four-eyes approvals

// Approval is a sensitive action waiting for a second administrator.
type Approval struct {
	ID          int64               `json:"id"`
	Action      string              `json:"action"`
	Summary     string              `json:"summary"`
	Path        string              `json:"path"`
	Form        map[string][]string `json:"form"`
	RequestedBy string              `json:"requested_by"`
	RequestedAt time.Time           `json:"requested_at"`
	DecidedBy   string              `json:"decided_by"`
	DecidedAt   *time.Time          `json:"decided_at,omitempty"`
	Status      string              `json:"status"`
	Result      string              `json:"result"`
}

// CreateApproval stores a request (the form of the action as it was sent).
func (s *Store) CreateApproval(ctx context.Context, a Approval) (int64, error) {
	raw, _ := json.Marshal(a.Form)
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO approvals(action, summary, path, form, requested_by, requested_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
		a.Action, a.Summary, a.Path, raw, a.RequestedBy, s.now()).Scan(&id)
	return id, err
}

// Approvals lists the pending requests and the last decisions.
func (s *Store) Approvals(ctx context.Context) ([]Approval, error) {
	if _, err := s.db.Exec(ctx, `UPDATE approvals SET status='expired', decided_at=$1 WHERE status='pending' AND requested_at < $2`, s.now(), s.now().Add(-24*time.Hour)); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT id, action, summary, path, form, requested_by, requested_at, decided_by, decided_at, status, result FROM approvals
		WHERE status='pending' OR requested_at > $1 ORDER BY status='pending' DESC, requested_at DESC LIMIT 100`, s.now().AddDate(0, 0, -30))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Approval, error) {
		var a Approval
		var raw []byte
		err := r.Scan(&a.ID, &a.Action, &a.Summary, &a.Path, &raw, &a.RequestedBy, &a.RequestedAt, &a.DecidedBy, &a.DecidedAt, &a.Status, &a.Result)
		if err == nil {
			err = json.Unmarshal(raw, &a.Form)
		}
		return a, err
	})
}

// TakeApproval marks a pending request as decided (once) and returns it.
func (s *Store) TakeApproval(ctx context.Context, id int64, by, status string) (*Approval, error) {
	var a Approval
	var raw []byte
	err := s.db.QueryRow(ctx, `UPDATE approvals SET status=$3, decided_by=$2, decided_at=$4 WHERE id=$1 AND status='pending' AND requested_at > $5
		RETURNING id, action, summary, path, form, requested_by, requested_at, status`, id, by, status, s.now(), s.now().Add(-24*time.Hour)).
		Scan(&a.ID, &a.Action, &a.Summary, &a.Path, &raw, &a.RequestedBy, &a.RequestedAt, &a.Status)
	if err != nil {
		return nil, notFound(err)
	}
	return &a, json.Unmarshal(raw, &a.Form)
}

// FinishApproval records how the approved action went.
func (s *Store) FinishApproval(ctx context.Context, id int64, ok bool, result string) error {
	status := "approved"
	if !ok {
		status = "failed"
	}
	_, err := s.db.Exec(ctx, `UPDATE approvals SET status=$2, result=$3 WHERE id=$1`, id, status, result)
	return err
}

// PendingApprovals counts the requests waiting (for the menu).
func (s *Store) PendingApprovals(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE status='pending' AND requested_at > $1`, s.now().Add(-24*time.Hour)).Scan(&n)
	return n, err
}
