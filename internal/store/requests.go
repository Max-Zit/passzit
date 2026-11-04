package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Requests for access. A member asks the managers of a shared vault for
// more rights for some hours; approved, the rights go up and come back by
// themselves. A user who is not in a vault asks a person (a manager or an
// administrator) instead: that person gives the access in the vault (only
// a manager's browser can seal the vault key) with an end time.

// AccessRequest is one request, as the requester and the deciders see it.
type AccessRequest struct {
	ID            int64      `json:"id"`
	UserID        int64      `json:"user_id"`
	Email         string     `json:"email"`
	PublicKey     string     `json:"public_key,omitempty"`
	VaultID       string     `json:"vault_id,omitempty"`
	AskedEmail    string     `json:"asked_email,omitempty"`
	Rights        string     `json:"rights"`
	CurrentRights string     `json:"current_rights,omitempty"`
	Hours         int        `json:"hours"`
	Reason        string     `json:"reason"`
	Status        string     `json:"status"`
	DecidedBy     string     `json:"decided_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	// Mine: made by the user who asks for the list; Decide: the user may
	// approve or reject it.
	Mine   bool `json:"mine"`
	Decide bool `json:"decide"`
}

// NewAccessRequest is what a user asks for.
type NewAccessRequest struct {
	VaultID string `json:"vault_id"`
	AskedID int64  `json:"asked_id"`
	Rights  string `json:"rights"`
	Hours   int    `json:"hours"`
	Reason  string `json:"reason"`
}

// Errors of requests (sentences for the user).
var (
	ErrRequestOpen   = errors.New("a request of yours for this is open already")
	ErrRightsHeld    = errors.New("you have these rights already")
	ErrRequestClosed = errors.New("the request is not open any more")
	ErrTooManyOpen   = errors.New("you have 10 open requests already; wait for an answer or withdraw one")
)

// MaxOpenRequests is how many requests of one user may wait at a time.
const MaxOpenRequests = 10

func rightsRank(r string) int {
	for i, x := range Rights {
		if x == r {
			return i
		}
	}
	return -1
}

// CreateAccessRequest stores a request and returns its id.
func (s *Store) CreateAccessRequest(ctx context.Context, userID int64, n NewAccessRequest) (int64, error) {
	n.Reason = strings.TrimSpace(n.Reason)
	switch {
	case !ValidRights(n.Rights):
		return 0, errors.New("unknown rights")
	case n.Hours < 1 || n.Hours > 720:
		return 0, errors.New("the access may last 1–720 hours")
	case n.Reason == "" || len(n.Reason) > 500:
		return 0, errors.New("say in a few words why you need the access")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var vault *string
	var asked *int64
	if n.VaultID != "" {
		// more rights in a shared vault the user is in
		if !ValidID(n.VaultID) {
			return 0, ErrNotFound
		}
		var kind string
		if err := tx.QueryRow(ctx, `SELECT kind FROM vaults WHERE id=$1`, n.VaultID).Scan(&kind); err != nil || kind != "shared" {
			return 0, ErrNotFound
		}
		cur, err := memberRights(ctx, tx, n.VaultID, userID, s.now())
		if errors.Is(err, ErrForbidden) {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		if rightsRank(n.Rights) <= rightsRank(cur) {
			return 0, ErrRightsHeld
		}
		vault = &n.VaultID
	} else {
		// access through a person
		var ok bool
		err := tx.QueryRow(ctx, `SELECT NOT disabled FROM users WHERE id=$1 AND id<>$2`, n.AskedID, userID).Scan(&ok)
		if err != nil || !ok {
			return 0, ErrNotFound
		}
		asked = &n.AskedID
	}
	var open int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM access_requests WHERE user_id=$1 AND status='pending' AND vault_id IS NOT DISTINCT FROM $2 AND asked_id IS NOT DISTINCT FROM $3`, userID, vault, asked).Scan(&open); err != nil {
		return 0, err
	}
	if open > 0 {
		return 0, ErrRequestOpen
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM access_requests WHERE user_id=$1 AND status='pending'`, userID).Scan(&open); err != nil {
		return 0, err
	}
	if open >= MaxOpenRequests {
		return 0, ErrTooManyOpen
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO access_requests(user_id, vault_id, asked_id, rights, hours, reason, created_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		userID, vault, asked, n.Rights, n.Hours, n.Reason, s.now()).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, tx.Commit(ctx)
}

// requestCols lists a request; $2 is the time the current rights are taken at.
const requestCols = `r.id, r.user_id, u.email, u.public_key, COALESCE(r.vault_id::text, ''), COALESCE(a.email, ''), r.rights,
	COALESCE(CASE WHEN m.rights_until <= $2 THEN COALESCE(m.base_rights, m.rights) ELSE m.rights END, ''), r.hours, r.reason, r.status, r.decided_by, r.created_at, r.decided_at`

// requestJoins: the requester, the person asked and the requester's
// membership valid at $2.
const requestJoins = ` FROM access_requests r JOIN users u ON u.id=r.user_id LEFT JOIN users a ON a.id=r.asked_id
	LEFT JOIN vault_members m ON m.vault_id=r.vault_id AND m.user_id=r.user_id AND (m.expires_at IS NULL OR m.expires_at > $2)`

// managesAt: user $1 manages the vault of request r at $2.
const managesAt = `EXISTS (SELECT 1 FROM vault_members x WHERE x.vault_id=r.vault_id AND x.user_id=$1 AND (x.expires_at IS NULL OR x.expires_at > $2)
	AND (CASE WHEN x.rights_until <= $2 THEN COALESCE(x.base_rights, x.rights) ELSE x.rights END)='manage')`

func scanRequest(row pgx.Row) (AccessRequest, error) {
	var q AccessRequest
	err := row.Scan(&q.ID, &q.UserID, &q.Email, &q.PublicKey, &q.VaultID, &q.AskedEmail, &q.Rights, &q.CurrentRights, &q.Hours, &q.Reason, &q.Status, &q.DecidedBy, &q.CreatedAt, &q.DecidedAt)
	return q, err
}

// AccessRequests lists the user's own requests of the last 30 days and the
// open requests the user may decide (managers of the vault, the person
// asked).
func (s *Store) AccessRequests(ctx context.Context, userID int64) ([]AccessRequest, error) {
	now := s.now()
	rows, err := s.db.Query(ctx, `SELECT `+requestCols+`, r.user_id=$1,
		r.status='pending' AND r.user_id<>$1 AND (r.asked_id=$1 OR `+managesAt+`)`+requestJoins+`
		WHERE (r.user_id=$1 AND r.created_at > $3)
		   OR (r.status='pending' AND r.user_id<>$1 AND (r.asked_id=$1 OR `+managesAt+`))
		ORDER BY r.created_at DESC LIMIT 200`, userID, now, now.AddDate(0, 0, -30))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AccessRequest, error) {
		var q AccessRequest
		err := r.Scan(&q.ID, &q.UserID, &q.Email, &q.PublicKey, &q.VaultID, &q.AskedEmail, &q.Rights, &q.CurrentRights, &q.Hours, &q.Reason, &q.Status, &q.DecidedBy, &q.CreatedAt, &q.DecidedAt, &q.Mine, &q.Decide)
		if !q.Decide {
			q.PublicKey = ""
		}
		return q, err
	})
}

// AccessRequest returns one request.
func (s *Store) AccessRequest(ctx context.Context, id int64) (AccessRequest, error) {
	q, err := scanRequest(s.db.QueryRow(ctx, `SELECT `+requestCols+requestJoins+` WHERE r.id=$1`, id, s.now()))
	return q, notFound(err)
}

// RequestDeciders are the users who may decide a request (for notices).
func (s *Store) RequestDeciders(ctx context.Context, id int64) ([]User, error) {
	rows, err := s.db.Query(ctx, `SELECT `+userCols+` FROM users WHERE NOT disabled AND id IN (
		SELECT r.asked_id FROM access_requests r WHERE r.id=$1 AND r.asked_id IS NOT NULL
		UNION SELECT x.user_id FROM access_requests r JOIN vault_members x ON x.vault_id=r.vault_id AND (x.expires_at IS NULL OR x.expires_at > $2)
			AND (CASE WHEN x.rights_until <= $2 THEN COALESCE(x.base_rights, x.rights) ELSE x.rights END)='manage'
		WHERE r.id=$1 AND x.user_id<>r.user_id)`, id, s.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// DecideAccessRequest approves or rejects a request. Approving a request
// for more rights raises them until the end; approving a request to a
// person needs the vault the person gave the access in (the requester
// must be a member there now, which the person's browser did).
func (s *Store) DecideAccessRequest(ctx context.Context, actor *User, id int64, approve bool, vaultID string) (AccessRequest, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return AccessRequest{}, err
	}
	defer tx.Rollback(ctx)
	var q struct {
		user   int64
		vault  *string
		asked  *int64
		rights string
		hours  int
		status string
	}
	err = tx.QueryRow(ctx, `SELECT user_id, vault_id::text, asked_id, rights, hours, status FROM access_requests WHERE id=$1 FOR UPDATE`, id).Scan(&q.user, &q.vault, &q.asked, &q.rights, &q.hours, &q.status)
	if err != nil {
		return AccessRequest{}, notFound(err)
	}
	if q.status != "pending" {
		return AccessRequest{}, ErrRequestClosed
	}
	if q.user == actor.ID {
		return AccessRequest{}, ErrForbidden
	}
	now := s.now()
	until := now.Add(time.Duration(q.hours) * time.Hour)
	switch {
	case q.vault != nil:
		if err := requireManage(ctx, tx, *q.vault, actor.ID, now); err != nil {
			return AccessRequest{}, err
		}
		if approve {
			cur, err := memberRights(ctx, tx, *q.vault, q.user, now)
			if errors.Is(err, ErrForbidden) {
				return AccessRequest{}, ErrNotFound // not a member any more
			}
			if err != nil {
				return AccessRequest{}, err
			}
			// Only ever up: a requester who has the asked rights (or more)
			// by now keeps them as they are, and the request is closed as
			// approved, since they have what they asked for.
			if rightsRank(q.rights) > rightsRank(cur) {
				if _, err := tx.Exec(ctx, `UPDATE vault_members SET base_rights=COALESCE(base_rights, rights), rights=$3, rights_until=$4, revision=nextval('revisions') WHERE vault_id=$1 AND user_id=$2`,
					*q.vault, q.user, q.rights, until); err != nil {
					return AccessRequest{}, err
				}
			}
		}
	case q.asked != nil && *q.asked == actor.ID:
		if approve {
			if err := requireManage(ctx, tx, vaultID, actor.ID, now); err != nil {
				return AccessRequest{}, err
			}
			var ends *time.Time
			if err := tx.QueryRow(ctx, `SELECT expires_at FROM vault_members WHERE vault_id=$1 AND user_id=$2`, vaultID, q.user).Scan(&ends); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return AccessRequest{}, err
			}
			cur, err := memberRights(ctx, tx, vaultID, q.user, now)
			if errors.Is(err, ErrForbidden) {
				return AccessRequest{}, errors.New("give the access in the vault first")
			} else if err != nil {
				return AccessRequest{}, err
			}
			// a member of the vault already: the rights go up for the time
			// (a member just given access has the end time already)
			if ends == nil && rightsRank(q.rights) > rightsRank(cur) {
				if _, err := tx.Exec(ctx, `UPDATE vault_members SET base_rights=COALESCE(base_rights, rights), rights=$3, rights_until=$4, revision=nextval('revisions') WHERE vault_id=$1 AND user_id=$2`,
					vaultID, q.user, q.rights, until); err != nil {
					return AccessRequest{}, err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE access_requests SET vault_id=$2 WHERE id=$1`, id, vaultID); err != nil {
				return AccessRequest{}, err
			}
		}
	default:
		return AccessRequest{}, ErrForbidden
	}
	status := "rejected"
	if approve {
		status = "approved"
	}
	if _, err := tx.Exec(ctx, `UPDATE access_requests SET status=$2, decided_by=$3, decided_at=$4 WHERE id=$1`, id, status, actor.Email, s.now()); err != nil {
		return AccessRequest{}, err
	}
	if err := touchUsers(ctx, tx, []int64{q.user}); err != nil {
		return AccessRequest{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AccessRequest{}, err
	}
	return s.AccessRequest(ctx, id)
}

// CancelAccessRequest withdraws the user's own open request.
func (s *Store) CancelAccessRequest(ctx context.Context, userID, id int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE access_requests SET status='cancelled', decided_at=$3 WHERE id=$1 AND user_id=$2 AND status='pending'`, id, userID, s.now())
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrRequestClosed
	}
	return err
}

// ExpireRights takes temporary rights back when their time is over and
// closes requests nobody decided within 7 days. It returns how many rights
// went back.
func (s *Store) ExpireRights(ctx context.Context) (int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `UPDATE vault_members SET rights=base_rights, base_rights=NULL, rights_until=NULL, revision=nextval('revisions')
		WHERE rights_until IS NOT NULL AND rights_until <= $1 AND base_rights IS NOT NULL RETURNING user_id`, s.now())
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return 0, err
	}
	if err := touchUsers(ctx, tx, ids); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE access_requests SET status='expired', decided_at=$1 WHERE status='pending' AND created_at < $2`, s.now(), s.now().AddDate(0, 0, -7)); err != nil {
		return 0, err
	}
	return len(ids), tx.Commit(ctx)
}
