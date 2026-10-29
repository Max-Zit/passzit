package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SecurityKey is a registered security key or passkey of a user.
type SecurityKey struct {
	ID         string
	Name       string
	PublicKey  []byte
	Alg        int
	SignCount  uint32
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// SecurityKeys lists the keys of a user.
func (s *Store) SecurityKeys(ctx context.Context, userID int64) ([]SecurityKey, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, public_key, alg, sign_count, created_at, last_used_at FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SecurityKey, error) {
		var k SecurityKey
		var n int64
		err := r.Scan(&k.ID, &k.Name, &k.PublicKey, &k.Alg, &n, &k.CreatedAt, &k.LastUsedAt)
		k.SignCount = uint32(n) // #nosec G115 -- stored from a uint32
		return k, err
	})
}

// AddSecurityKey registers a key (at most 10 per user).
func (s *Store) AddSecurityKey(ctx context.Context, userID int64, k SecurityKey) error {
	k.Name = strings.TrimSpace(k.Name)
	if k.Name == "" {
		k.Name = "Security key"
	}
	if len(k.Name) > 60 {
		k.Name = k.Name[:60]
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id=$1`, userID).Scan(&n); err != nil {
		return err
	}
	if n >= 10 {
		return errors.New("at most 10 security keys")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO webauthn_credentials(id, user_id, name, public_key, alg, sign_count, created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		k.ID, userID, k.Name, k.PublicKey, k.Alg, int64(k.SignCount), s.now())
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// UseSecurityKey stores the new signature counter after a sign-in.
func (s *Store) UseSecurityKey(ctx context.Context, userID int64, id string, count uint32) error {
	_, err := s.db.Exec(ctx, `UPDATE webauthn_credentials SET sign_count=$3, last_used_at=$4 WHERE id=$1 AND user_id=$2`, id, userID, int64(count), s.now())
	return err
}

// DeleteSecurityKey removes a key of a user.
func (s *Store) DeleteSecurityKey(ctx context.Context, userID int64, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM webauthn_credentials WHERE id=$1 AND user_id=$2`, id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}
