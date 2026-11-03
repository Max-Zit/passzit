package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// UnlockKey is a passkey of a device that unlocks the vault: the account
// key sealed under a key derived from the authenticator's PRF output.
type UnlockKey struct {
	ID         string // WebAuthn credential id (base64url)
	Name       string
	Salt       string // PRF input (base64url)
	Wrapped    string // sealed account key
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// UnlockKeys lists the unlock keys of a user.
func (s *Store) UnlockKeys(ctx context.Context, userID int64) ([]UnlockKey, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, salt, wrapped, created_at, last_used_at FROM unlock_keys WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (UnlockKey, error) {
		var k UnlockKey
		err := r.Scan(&k.ID, &k.Name, &k.Salt, &k.Wrapped, &k.CreatedAt, &k.LastUsedAt)
		return k, err
	})
}

// AddUnlockKey stores an unlock key (at most 10 per user).
func (s *Store) AddUnlockKey(ctx context.Context, userID int64, k UnlockKey) error {
	k.Name = strings.TrimSpace(k.Name)
	if k.Name == "" {
		k.Name = "This device"
	}
	if len(k.Name) > 60 {
		k.Name = k.Name[:60]
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM unlock_keys WHERE user_id=$1`, userID).Scan(&n); err != nil {
		return err
	}
	if n >= 10 {
		return errors.New("at most 10 unlock keys")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO unlock_keys(id, user_id, name, salt, wrapped, created_at) VALUES($1,$2,$3,$4,$5,$6)`,
		k.ID, userID, k.Name, k.Salt, k.Wrapped, s.now())
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// UseUnlockKey records an unlock.
func (s *Store) UseUnlockKey(ctx context.Context, userID int64, id string) error {
	tag, err := s.db.Exec(ctx, `UPDATE unlock_keys SET last_used_at=$3 WHERE id=$1 AND user_id=$2`, id, userID, s.now())
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// DeleteUnlockKey removes an unlock key of a user.
func (s *Store) DeleteUnlockKey(ctx context.Context, userID int64, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM unlock_keys WHERE id=$1 AND user_id=$2`, id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}
