package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Limits of vault data (sealed sizes).
const (
	MaxItemData   = 96 << 10 // one item (notes, fields, history)
	MaxFolderData = 1 << 10
	MaxItems      = 50_000 // per vault
	MaxFolders    = 1_000  // per user
)

// ErrStale is returned when a change is based on an older revision.
var ErrStale = errors.New("changed in the meantime")

// ErrForbidden is returned for vaults the user is not a member of (or may
// not change).
var ErrForbidden = errors.New("not allowed")

// VaultRef is a vault as one member sees it.
type VaultRef struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	WrappedKey string `json:"wrapped_key"`
	Rights     string `json:"rights"`
}

// Item is a sealed item.
type Item struct {
	ID        string     `json:"id"`
	VaultID   string     `json:"vault_id"`
	Data      string     `json:"data"`
	Revision  int64      `json:"revision"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Folder is a sealed folder name.
type Folder struct {
	ID       string `json:"id"`
	Data     string `json:"data"`
	Revision int64  `json:"revision"`
}

// Sync is everything a client needs (or, with since > 0, what changed).
type Sync struct {
	Revision int64      `json:"revision"`
	Full     bool       `json:"full"`
	Vaults   []VaultRef `json:"vaults"`
	Items    []Item     `json:"items"`
	Folders  []Folder   `json:"folders"`
	// Removed lists ids of items and folders removed since the given revision.
	Removed []string `json:"removed"`
}

// tombstoneLife is how long removals are remembered; older clients sync in full.
const tombstoneLife = 90 * 24 * time.Hour

// SyncData returns the vault data of a user, all of it (since 0) or what
// changed after revision since.
func (s *Store) SyncData(ctx context.Context, userID, since int64) (*Sync, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	out := &Sync{Vaults: []VaultRef{}, Items: []Item{}, Folders: []Folder{}, Removed: []string{}}
	if err := tx.QueryRow(ctx, `SELECT last_value FROM revisions`).Scan(&out.Revision); err != nil {
		return nil, err
	}
	if since > 0 {
		// Removals older than what is remembered may be missing: full sync.
		var purgedBefore int64
		_ = s.GetSettingTx(ctx, tx, "tombstones_purged_upto", &purgedBefore)
		if since < purgedBefore {
			since = 0
		}
	}
	out.Full = since == 0
	rows, err := tx.Query(ctx, `SELECT v.id::text, v.kind, m.wrapped_key, m.rights FROM vault_members m JOIN vaults v ON v.id=m.vault_id WHERE m.user_id=$1 ORDER BY v.created_at`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v VaultRef
		if err := rows.Scan(&v.ID, &v.Kind, &v.WrappedKey, &v.Rights); err != nil {
			rows.Close()
			return nil, err
		}
		out.Vaults = append(out.Vaults, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT i.id::text, i.vault_id::text, i.data, i.revision, i.created_at, i.updated_at, i.deleted_at
		FROM items i JOIN vault_members m ON m.vault_id=i.vault_id AND m.user_id=$1 WHERE i.revision>$2 ORDER BY i.revision`, userID, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.VaultID, &it.Data, &it.Revision, &it.CreatedAt, &it.UpdatedAt, &it.DeletedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Items = append(out.Items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT id::text, data, revision FROM folders WHERE user_id=$1 AND revision>$2 ORDER BY revision`, userID, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f Folder
		if err := rows.Scan(&f.ID, &f.Data, &f.Revision); err != nil {
			rows.Close()
			return nil, err
		}
		out.Folders = append(out.Folders, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if since > 0 {
		rows, err = tx.Query(ctx, `SELECT id::text FROM tombstones WHERE revision>$2 AND (user_id=$1 OR vault_id IN (SELECT vault_id FROM vault_members WHERE user_id=$1))`, userID, since)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			out.Removed = append(out.Removed, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetSettingTx is GetSetting inside a transaction.
func (s *Store) GetSettingTx(ctx context.Context, tx pgx.Tx, key string, v any) error {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// memberRights returns the rights of a user in a vault (ErrForbidden if none).
func memberRights(ctx context.Context, tx pgx.Tx, vaultID string, userID int64) (string, error) {
	var r string
	err := tx.QueryRow(ctx, `SELECT rights FROM vault_members WHERE vault_id=$1 AND user_id=$2`, vaultID, userID).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrForbidden
	}
	return r, err
}

func canEdit(rights string) bool { return rights == "edit" || rights == "manage" }

// PutItem creates (base 0) or replaces (base = the revision the client
// changed) an item and returns its new revision.
func (s *Store) PutItem(ctx context.Context, userID int64, id, vaultID, data string, base int64) (int64, error) {
	if !ValidID(id) || !ValidID(vaultID) {
		return 0, errors.New("invalid id")
	}
	if !SealedOK(data, MaxItemData) {
		return 0, errors.New("invalid or too large item")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	r, err := memberRights(ctx, tx, vaultID, userID)
	if err != nil {
		return 0, err
	}
	if !canEdit(r) {
		return 0, ErrForbidden
	}
	now := s.now()
	var rev int64
	if base == 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM items WHERE vault_id=$1`, vaultID).Scan(&n); err != nil {
			return 0, err
		}
		if n >= MaxItems {
			return 0, errors.New("the vault is full")
		}
		err = tx.QueryRow(ctx, `INSERT INTO items(id, vault_id, data, revision, created_at, updated_at) VALUES($1,$2,$3,nextval('revisions'),$4,$4) RETURNING revision`,
			id, vaultID, data, now).Scan(&rev)
		if isUnique(err) {
			return 0, ErrStale
		}
	} else {
		// The item stays in its vault (moving between vaults re-encrypts: later).
		err = tx.QueryRow(ctx, `UPDATE items SET data=$3, revision=nextval('revisions'), updated_at=$4 WHERE id=$1 AND vault_id=$2 AND revision=$5 RETURNING revision`,
			id, vaultID, data, now, base).Scan(&rev)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrStale
		}
	}
	if err != nil {
		return 0, err
	}
	return rev, tx.Commit(ctx)
}

// itemAction runs a change on one item the user may edit.
func (s *Store) itemAction(ctx context.Context, userID int64, id, q string, args ...any) (int64, error) {
	if !ValidID(id) {
		return 0, ErrNotFound
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var vaultID string
	if err := tx.QueryRow(ctx, `SELECT vault_id::text FROM items WHERE id=$1 FOR UPDATE`, id).Scan(&vaultID); err != nil {
		return 0, notFound(err)
	}
	r, err := memberRights(ctx, tx, vaultID, userID)
	if errors.Is(err, ErrForbidden) {
		return 0, ErrNotFound // do not tell that the item exists
	}
	if err != nil {
		return 0, err
	}
	if !canEdit(r) {
		return 0, ErrForbidden
	}
	var rev int64
	err = tx.QueryRow(ctx, q, append([]any{id, s.now()}, args...)...).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrStale
	}
	if err != nil {
		return 0, err
	}
	return rev, tx.Commit(ctx)
}

// TrashItem moves an item to the trash.
func (s *Store) TrashItem(ctx context.Context, userID int64, id string) (int64, error) {
	return s.itemAction(ctx, userID, id, `UPDATE items SET deleted_at=$2, revision=nextval('revisions') WHERE id=$1 AND deleted_at IS NULL RETURNING revision`)
}

// RestoreItem takes an item back from the trash.
func (s *Store) RestoreItem(ctx context.Context, userID int64, id string) (int64, error) {
	return s.itemAction(ctx, userID, id, `UPDATE items SET deleted_at=NULL, updated_at=$2, revision=nextval('revisions') WHERE id=$1 AND deleted_at IS NOT NULL RETURNING revision`)
}

// PurgeItem deletes an item from the trash for good.
func (s *Store) PurgeItem(ctx context.Context, userID int64, id string) (int64, error) {
	return s.itemAction(ctx, userID, id, `WITH d AS (DELETE FROM items WHERE id=$1 AND deleted_at IS NOT NULL AND $2::timestamptz IS NOT NULL RETURNING id, vault_id)
		INSERT INTO tombstones(id, kind, vault_id, revision) SELECT id, 'item', vault_id, nextval('revisions') FROM d RETURNING revision`)
}

// PutFolder creates or renames a folder.
func (s *Store) PutFolder(ctx context.Context, userID int64, id, data string, base int64) (int64, error) {
	if !ValidID(id) {
		return 0, errors.New("invalid id")
	}
	if !SealedOK(data, MaxFolderData) {
		return 0, errors.New("invalid or too large folder")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if base == 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM folders WHERE user_id=$1`, userID).Scan(&n); err != nil {
			return 0, err
		}
		if n >= MaxFolders {
			return 0, errors.New("too many folders")
		}
		err = tx.QueryRow(ctx, `INSERT INTO folders(id, user_id, data, revision, updated_at) VALUES($1,$2,$3,nextval('revisions'),$4) RETURNING revision`,
			id, userID, data, s.now()).Scan(&rev)
		if isUnique(err) {
			return 0, ErrStale
		}
	} else {
		err = tx.QueryRow(ctx, `UPDATE folders SET data=$3, revision=nextval('revisions'), updated_at=$4 WHERE id=$1 AND user_id=$2 AND revision=$5 RETURNING revision`,
			id, userID, data, s.now(), base).Scan(&rev)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrStale
		}
	}
	if err != nil {
		return 0, err
	}
	return rev, tx.Commit(ctx)
}

// DeleteFolder removes a folder (its items stay; clients show them without folder).
func (s *Store) DeleteFolder(ctx context.Context, userID int64, id string) (int64, error) {
	if !ValidID(id) {
		return 0, ErrNotFound
	}
	var rev int64
	err := s.db.QueryRow(ctx, `WITH d AS (DELETE FROM folders WHERE id=$1 AND user_id=$2 RETURNING id)
		INSERT INTO tombstones(id, kind, user_id, revision) SELECT id, 'folder', $2, nextval('revisions') FROM d RETURNING revision`, id, userID).Scan(&rev)
	return rev, notFound(err)
}

// CurrentRevision is the newest revision visible to a user (cheap check
// whether a client must sync).
func (s *Store) CurrentRevision(ctx context.Context, userID int64) (int64, error) {
	var rev int64
	err := s.db.QueryRow(ctx, `SELECT GREATEST(
		(SELECT revision FROM users WHERE id=$1),
		COALESCE((SELECT max(i.revision) FROM items i JOIN vault_members m ON m.vault_id=i.vault_id AND m.user_id=$1), 0),
		COALESCE((SELECT max(revision) FROM folders WHERE user_id=$1), 0),
		COALESCE((SELECT max(revision) FROM tombstones WHERE user_id=$1 OR vault_id IN (SELECT vault_id FROM vault_members WHERE user_id=$1)), 0))`, userID).Scan(&rev)
	return rev, err
}

// Housekeeping empties the trash (items deleted before trashBefore) and
// forgets old removals.
func (s *Store) Housekeeping(ctx context.Context, trashBefore time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `WITH d AS (DELETE FROM items WHERE deleted_at < $1 RETURNING id, vault_id)
		INSERT INTO tombstones(id, kind, vault_id, revision) SELECT id, 'item', vault_id, nextval('revisions') FROM d`, trashBefore)
	if err != nil {
		return 0, err
	}
	var upto *int64
	err = s.db.QueryRow(ctx, `WITH d AS (DELETE FROM tombstones WHERE at < $1 RETURNING revision) SELECT max(revision) FROM d`, s.now().Add(-tombstoneLife)).Scan(&upto)
	if err != nil {
		return 0, err
	}
	if upto != nil {
		var cur int64
		_ = s.GetSetting(ctx, "tombstones_purged_upto", &cur)
		if *upto > cur {
			if err := s.SetSetting(ctx, "tombstones_purged_upto", *upto); err != nil {
				return 0, err
			}
		}
	}
	return tag.RowsAffected(), nil
}

// VaultStats counts items for the admin overview (no contents, of course).
type VaultStats struct {
	Users, Items, Trash int
}

// Stats counts users and items.
func (s *Store) Stats(ctx context.Context) (VaultStats, error) {
	var v VaultStats
	err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM items WHERE deleted_at IS NULL), (SELECT count(*) FROM items WHERE deleted_at IS NOT NULL)`).
		Scan(&v.Users, &v.Items, &v.Trash)
	return v, err
}
