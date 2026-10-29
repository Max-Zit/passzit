package store

import (
	"context"
	"errors"
	"time"

	"github.com/max-zit/passzit/internal/auth"
)

// Invite is an invitation to create an account.
type Invite struct {
	ID        int64
	Email     string
	Role      string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// Expired reports an unused invitation that can no longer be used.
func (i *Invite) Expired(now time.Time) bool { return i.UsedAt == nil && now.After(i.ExpiresAt) }

// CreateInvite makes an invitation and returns its token (shown once).
// A new invitation for the same address replaces an unused older one.
func (s *Store) CreateInvite(ctx context.Context, email, role, by string, life time.Duration) (string, *Invite, error) {
	e, err := NormEmail(email)
	if err != nil {
		return "", nil, err
	}
	if !ValidRole(role) {
		return "", nil, errors.New("unknown role")
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE lower(email)=$1`, e).Scan(&n); err != nil {
		return "", nil, err
	}
	if n > 0 {
		return "", nil, ErrConflict
	}
	tok := "pzi_" + auth.RandomToken(24)
	now := s.now()
	inv := &Invite{Email: e, Role: role, CreatedBy: by, CreatedAt: now, ExpiresAt: now.Add(life)}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM invites WHERE lower(email)=$1 AND used_at IS NULL`, e); err != nil {
		return "", nil, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO invites(token_hash, email, role, created_by, created_at, expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
		auth.HashToken("invite", tok), e, role, by, now, inv.ExpiresAt).Scan(&inv.ID)
	if err != nil {
		return "", nil, err
	}
	return tok, inv, tx.Commit(ctx)
}

const inviteCols = `id, email, role, created_by, created_at, expires_at, used_at`

func scanInvite(row interface{ Scan(...any) error }) (*Invite, error) {
	i := &Invite{}
	err := row.Scan(&i.ID, &i.Email, &i.Role, &i.CreatedBy, &i.CreatedAt, &i.ExpiresAt, &i.UsedAt)
	return i, err
}

// InviteByToken loads a usable invitation (unused, not expired).
func (s *Store) InviteByToken(ctx context.Context, tok string) (*Invite, error) {
	i, err := scanInvite(s.db.QueryRow(ctx, `SELECT `+inviteCols+` FROM invites WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2`,
		auth.HashToken("invite", tok), s.now()))
	if err != nil {
		return nil, notFound(err)
	}
	return i, nil
}

// Invites lists the invitations of the last 30 days and all open ones.
func (s *Store) Invites(ctx context.Context) ([]*Invite, error) {
	rows, err := s.db.Query(ctx, `SELECT `+inviteCols+` FROM invites WHERE used_at IS NULL OR used_at > $1 ORDER BY created_at DESC`, s.now().AddDate(0, 0, -30))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Invite
	for rows.Next() {
		i, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// DeleteInvite withdraws an unused invitation.
func (s *Store) DeleteInvite(ctx context.Context, id int64) (*Invite, error) {
	i, err := scanInvite(s.db.QueryRow(ctx, `DELETE FROM invites WHERE id=$1 AND used_at IS NULL RETURNING `+inviteCols, id))
	if err != nil {
		return nil, notFound(err)
	}
	return i, nil
}
