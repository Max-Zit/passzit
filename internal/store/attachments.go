package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrQuota is returned when a file would exceed the storage of a user.
var ErrQuota = errors.New("no space left for files")

// itemAccess checks that the user may open an item and reports whether
// the user may change it.
func (s *Store) itemAccess(ctx context.Context, userID int64, itemID string) (bool, error) {
	if !ValidID(itemID) {
		return false, ErrNotFound
	}
	var rights string
	err := s.db.QueryRow(ctx, `SELECT (CASE WHEN m.rights_until <= $3 THEN COALESCE(m.base_rights, m.rights) ELSE m.rights END)
		FROM items i JOIN vault_members m ON m.vault_id=i.vault_id AND m.user_id=$2 AND (m.expires_at IS NULL OR m.expires_at > $3) WHERE i.id=$1`, itemID, userID, s.now()).Scan(&rights)
	if err != nil {
		return false, notFound(err)
	}
	return canEdit(rights), nil
}

// storageUsedSQL is what a user stores: files of items and secret links.
const storageUsedSQL = `SELECT COALESCE((SELECT sum(size) FROM attachments WHERE owner_id=$1), 0) + COALESCE((SELECT sum(length(data)) FROM sends WHERE owner_id=$1), 0)`

// lockStorage serialises the changes of one user's storage (the check of
// the limit and the insert), so parallel uploads cannot pass it together.
func lockStorage(ctx context.Context, tx pgx.Tx, userID int64) (int64, error) {
	var id int64
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&id); err != nil {
		return 0, notFound(err)
	}
	var used int64
	err := tx.QueryRow(ctx, storageUsedSQL, userID).Scan(&used)
	return used, err
}

// PutAttachment stores a sealed file of an item. maxSize limits one file,
// quota all files (and secret links) of the user.
func (s *Store) PutAttachment(ctx context.Context, userID int64, itemID, id string, data []byte, maxSize, quota int64) error {
	if !ValidID(id) {
		return errors.New("invalid id")
	}
	if len(data) < 1+12+16 || data[0] != 1 {
		return errors.New("invalid file")
	}
	if int64(len(data)) > maxSize {
		return errors.New("the file is too large")
	}
	edit, err := s.itemAccess(ctx, userID, itemID)
	if err != nil {
		return err
	}
	if !edit {
		return ErrForbidden
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	used, err := lockStorage(ctx, tx, userID)
	if err != nil {
		return err
	}
	if used+int64(len(data)) > quota {
		return ErrQuota
	}
	_, err = tx.Exec(ctx, `INSERT INTO attachments(id, item_id, owner_id, size, data) VALUES($1,$2,$3,$4,$5)`, id, itemID, userID, len(data), data)
	if isUnique(err) {
		return ErrStale
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Attachment returns a sealed file the user may read.
func (s *Store) Attachment(ctx context.Context, userID int64, id string) ([]byte, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	var data []byte
	err := s.db.QueryRow(ctx, `SELECT a.data FROM attachments a JOIN items i ON i.id=a.item_id
		JOIN vault_members m ON m.vault_id=i.vault_id AND m.user_id=$2 AND (m.expires_at IS NULL OR m.expires_at > $3) WHERE a.id=$1`, id, userID, s.now()).Scan(&data)
	return data, notFound(err)
}

// DeleteAttachment removes a file of an item the user may change.
func (s *Store) DeleteAttachment(ctx context.Context, userID int64, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM attachments a USING items i, vault_members m
		WHERE a.id=$1 AND i.id=a.item_id AND m.vault_id=i.vault_id AND m.user_id=$2 AND (m.expires_at IS NULL OR m.expires_at > $3)
		AND (CASE WHEN m.rights_until <= $3 THEN COALESCE(m.base_rights, m.rights) ELSE m.rights END) IN ('edit','manage')`, id, userID, s.now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// StorageUsed is the size of all files and secret links of a user.
func (s *Store) StorageUsed(ctx context.Context, userID int64) (int64, error) {
	var used int64
	err := s.db.QueryRow(ctx, storageUsedSQL, userID).Scan(&used)
	return used, err
}
