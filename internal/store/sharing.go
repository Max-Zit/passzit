package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// Shared vaults. The server never sees a vault key: a manager's client
// seals it to the public key of every member. The server keeps who may do
// what (rights) and refuses changes without the right, but it cannot give
// anyone access by itself — a member always needs a key sealed by a
// manager.

// Rights in a vault, from least to most.
var Rights = []string{"use", "view", "edit", "manage"}

// ValidRights reports whether r is one of Rights.
func ValidRights(r string) bool {
	for _, x := range Rights {
		if x == r {
			return true
		}
	}
	return false
}

// MaxVaultName is the sealed size of a vault name.
const MaxVaultName = 1 << 10

// SealedToOK checks the format of a value sealed to a public key
// (ephemeral X25519 key ‖ sealed value).
func SealedToOK(s string, maxLen int) bool {
	if len(s) > maxLen || !b64urlRE.MatchString(s) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) >= 32+1+12+16 && raw[32] == vaultcrypto.Version
}

// ErrLastManager is returned when a change would leave a vault without a
// manager.
var ErrLastManager = errors.New("a vault needs at least one manager")

// touchUsers makes the clients of these users sync in full (they gained or
// lost a vault, or its key changed).
func touchUsers(ctx context.Context, tx pgx.Tx, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE users SET revision=nextval('revisions') WHERE id = ANY($1)`, ids)
	return err
}

func vaultMemberIDs(ctx context.Context, tx pgx.Tx, vaultID string) ([]int64, error) {
	rows, err := tx.Query(ctx, `SELECT user_id FROM vault_members WHERE vault_id=$1`, vaultID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// requireManage checks that a user manages a shared vault.
func requireManage(ctx context.Context, tx pgx.Tx, vaultID string, userID int64) error {
	if !ValidID(vaultID) {
		return ErrNotFound
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM vaults WHERE id=$1 FOR UPDATE`, vaultID).Scan(&kind); err != nil {
		return notFound(err)
	}
	r, err := memberRights(ctx, tx, vaultID, userID)
	if errors.Is(err, ErrForbidden) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if kind != "shared" || r != "manage" {
		return ErrForbidden
	}
	return nil
}

// managersLeft counts the managers of a vault.
func managersLeft(ctx context.Context, tx pgx.Tx, vaultID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM vault_members m JOIN users u ON u.id=m.user_id AND NOT u.disabled WHERE m.vault_id=$1 AND m.rights='manage'`, vaultID).Scan(&n)
	return n, err
}

// CreateVault makes a shared vault with its creator as manager.
func (s *Store) CreateVault(ctx context.Context, userID int64, id, data, wrappedKey string) error {
	if !ValidID(id) {
		return errors.New("invalid id")
	}
	if !SealedOK(data, MaxVaultName) || !SealedToOK(wrappedKey, 512) {
		return errors.New("invalid vault data")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM vault_members WHERE user_id=$1`, userID).Scan(&n); err != nil {
		return err
	}
	if n >= 500 {
		return errors.New("too many vaults")
	}
	_, err = tx.Exec(ctx, `INSERT INTO vaults(id, kind, data, created_by) VALUES($1,'shared',$2,$3)`, id, data, userID)
	if isUnique(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO vault_members(vault_id, user_id, wrapped_key, rights, added_by) VALUES($1,$2,$3,'manage','creator')`, id, userID, wrappedKey); err != nil {
		return err
	}
	if err := touchUsers(ctx, tx, []int64{userID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RenameVault replaces the sealed name of a shared vault.
func (s *Store) RenameVault(ctx context.Context, userID int64, id, data string) error {
	if !SealedOK(data, MaxVaultName) {
		return errors.New("invalid vault data")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireManage(ctx, tx, id, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE vaults SET data=$2, revision=nextval('revisions') WHERE id=$1`, id, data); err != nil {
		return err
	}
	ids, err := vaultMemberIDs(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := touchUsers(ctx, tx, ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteVault removes a shared vault with all its items and files.
func (s *Store) DeleteVault(ctx context.Context, userID int64, id string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireManage(ctx, tx, id, userID); err != nil {
		return err
	}
	ids, err := vaultMemberIDs(ctx, tx, id)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vaults WHERE id=$1`, id); err != nil {
		return err
	}
	if err := touchUsers(ctx, tx, ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Member is a member of a shared vault as the vault's page shows it.
type Member struct {
	UserID      int64      `json:"user_id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Rights      string     `json:"rights"`
	GroupID     *int64     `json:"group_id,omitempty"`
	GroupName   string     `json:"group_name,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	PublicKey   string     `json:"public_key"`
	Disabled    bool       `json:"disabled"`
}

// VaultMembers lists the members of a shared vault (for its members).
func (s *Store) VaultMembers(ctx context.Context, userID int64, vaultID string) ([]Member, error) {
	if !ValidID(vaultID) {
		return nil, ErrNotFound
	}
	var ok bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vault_members WHERE vault_id=$1 AND user_id=$2)`, vaultID, userID).Scan(&ok); err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.db.Query(ctx, `SELECT u.id, u.email, u.display_name, m.rights, m.group_id, COALESCE(g.name, ''), m.expires_at, u.public_key, u.disabled
		FROM vault_members m JOIN users u ON u.id=m.user_id LEFT JOIN groups g ON g.id=m.group_id
		WHERE m.vault_id=$1 ORDER BY lower(u.email)`, vaultID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Member, error) {
		var m Member
		err := r.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Rights, &m.GroupID, &m.GroupName, &m.ExpiresAt, &m.PublicKey, &m.Disabled)
		return m, err
	})
}

// MemberChange adds a member or changes one. WrappedKey is needed for a
// new member (the vault key sealed to the member's public key).
type MemberChange struct {
	UserID     int64      `json:"user_id"`
	WrappedKey string     `json:"wrapped_key,omitempty"`
	Rights     string     `json:"rights"`
	GroupID    *int64     `json:"group_id,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// PutMember adds a member to a shared vault or changes the rights or end
// of a membership. Through a group, the rights come from the group's grant.
func (s *Store) PutMember(ctx context.Context, actor int64, actorName, vaultID string, c MemberChange) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if err := requireManage(ctx, tx, vaultID, actor); err != nil {
		return false, err
	}
	var disabled bool
	if err := tx.QueryRow(ctx, `SELECT disabled FROM users WHERE id=$1`, c.UserID).Scan(&disabled); err != nil {
		return false, notFound(err)
	}
	if c.GroupID != nil {
		err := tx.QueryRow(ctx, `SELECT vg.rights FROM vault_groups vg JOIN group_members gm ON gm.group_id=vg.group_id AND gm.user_id=$3
			WHERE vg.vault_id=$1 AND vg.group_id=$2`, vaultID, *c.GroupID, c.UserID).Scan(&c.Rights)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, errors.New("the user is not in a group of this vault")
		}
		if err != nil {
			return false, err
		}
	}
	if !ValidRights(c.Rights) {
		return false, errors.New("unknown rights")
	}
	if c.ExpiresAt != nil && !c.ExpiresAt.After(s.now()) {
		return false, errors.New("the end of the access must be in the future")
	}
	var cur string
	err = tx.QueryRow(ctx, `SELECT rights FROM vault_members WHERE vault_id=$1 AND user_id=$2`, vaultID, c.UserID).Scan(&cur)
	added := false
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if disabled {
			return false, errors.New("the user is disabled")
		}
		if !SealedToOK(c.WrappedKey, 512) {
			return false, errors.New("the vault key for the new member is missing")
		}
		_, err = tx.Exec(ctx, `INSERT INTO vault_members(vault_id, user_id, wrapped_key, rights, group_id, expires_at, added_by) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			vaultID, c.UserID, c.WrappedKey, c.Rights, c.GroupID, c.ExpiresAt, actorName)
		added = true
	case err != nil:
		return false, err
	default:
		_, err = tx.Exec(ctx, `UPDATE vault_members SET rights=$3, expires_at=$4, revision=nextval('revisions') WHERE vault_id=$1 AND user_id=$2`,
			vaultID, c.UserID, c.Rights, c.ExpiresAt)
	}
	if err != nil {
		return false, err
	}
	if cur == "manage" && c.Rights != "manage" {
		if n, err := managersLeft(ctx, tx, vaultID); err != nil {
			return false, err
		} else if n == 0 {
			return false, ErrLastManager
		}
	}
	if err := touchUsers(ctx, tx, []int64{c.UserID}); err != nil {
		return false, err
	}
	return added, tx.Commit(ctx)
}

// RemoveMember takes a member out of a shared vault (a member may also
// leave). The vault is marked for a new key: the member knew the old one.
func (s *Store) RemoveMember(ctx context.Context, actor int64, vaultID string, userID int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if actor != userID {
		if err := requireManage(ctx, tx, vaultID, actor); err != nil {
			return err
		}
	} else if !ValidID(vaultID) {
		return ErrNotFound
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM vaults WHERE id=$1`, vaultID).Scan(&kind); err != nil {
		return notFound(err)
	}
	if kind != "shared" {
		return ErrForbidden
	}
	tag, err := tx.Exec(ctx, `DELETE FROM vault_members WHERE vault_id=$1 AND user_id=$2`, vaultID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	var left int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM vault_members WHERE vault_id=$1`, vaultID).Scan(&left); err != nil {
		return err
	}
	if left > 0 {
		if n, err := managersLeft(ctx, tx, vaultID); err != nil {
			return err
		} else if n == 0 {
			return ErrLastManager
		}
		if _, err := tx.Exec(ctx, `UPDATE vaults SET needs_rotation=true, revision=nextval('revisions') WHERE id=$1`, vaultID); err != nil {
			return err
		}
		ids, err := vaultMemberIDs(ctx, tx, vaultID)
		if err != nil {
			return err
		}
		if err := touchUsers(ctx, tx, ids); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `DELETE FROM vaults WHERE id=$1`, vaultID); err != nil {
		return err
	}
	if err := touchUsers(ctx, tx, []int64{userID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RotatedItem is an item sealed again with the new vault key.
type RotatedItem struct {
	ID   string `json:"id"`
	Data string `json:"data"`
}

// Rotation replaces the key of a shared vault: the name and every item
// sealed with the new key, the new key sealed to every member.
type Rotation struct {
	KeyVersion int              `json:"key_version"`
	Data       string           `json:"data"`
	Members    map[int64]string `json:"members"`
	Items      []RotatedItem    `json:"items"`
}

// RotateVault applies a rotation in one transaction. It must cover all
// members and all items exactly; a concurrent change makes it stale.
func (s *Store) RotateVault(ctx context.Context, actor int64, vaultID string, r Rotation) (int64, error) {
	if !SealedOK(r.Data, MaxVaultName) {
		return 0, errors.New("invalid vault data")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if err := requireManage(ctx, tx, vaultID, actor); err != nil {
		return 0, err
	}
	var ver int
	if err := tx.QueryRow(ctx, `SELECT key_version FROM vaults WHERE id=$1`, vaultID).Scan(&ver); err != nil {
		return 0, err
	}
	if ver != r.KeyVersion {
		return 0, ErrStale
	}
	members, err := vaultMemberIDs(ctx, tx, vaultID)
	if err != nil {
		return 0, err
	}
	if len(members) != len(r.Members) {
		return 0, ErrStale
	}
	for _, id := range members {
		k, ok := r.Members[id]
		if !ok {
			return 0, ErrStale
		}
		if !SealedToOK(k, 512) {
			return 0, errors.New("invalid member key")
		}
		if _, err := tx.Exec(ctx, `UPDATE vault_members SET wrapped_key=$3, revision=nextval('revisions') WHERE vault_id=$1 AND user_id=$2`, vaultID, id, k); err != nil {
			return 0, err
		}
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM items WHERE vault_id=$1`, vaultID).Scan(&n); err != nil {
		return 0, err
	}
	if n != len(r.Items) {
		return 0, ErrStale
	}
	seen := map[string]bool{}
	for _, it := range r.Items {
		if seen[it.ID] || !ValidID(it.ID) || !SealedOK(it.Data, MaxItemData) {
			return 0, errors.New("invalid item")
		}
		seen[it.ID] = true
		tag, err := tx.Exec(ctx, `UPDATE items SET data=$3, revision=nextval('revisions') WHERE id=$1 AND vault_id=$2`, it.ID, vaultID, it.Data)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() != 1 {
			return 0, ErrStale
		}
	}
	var rev int64
	if err := tx.QueryRow(ctx, `UPDATE vaults SET data=$2, key_version=key_version+1, needs_rotation=false, revision=nextval('revisions') WHERE id=$1 RETURNING revision`, vaultID, r.Data).Scan(&rev); err != nil {
		return 0, err
	}
	if err := touchUsers(ctx, tx, members); err != nil {
		return 0, err
	}
	return rev, tx.Commit(ctx)
}

// Pending is access a group grants that no manager has sealed yet.
type Pending struct {
	VaultID   string `json:"vault_id"`
	UserID    int64  `json:"user_id"`
	Email     string `json:"email"`
	PublicKey string `json:"public_key"`
	Rights    string `json:"rights"`
	GroupID   int64  `json:"group_id"`
}

// PendingAccess lists the pending access of the vaults a user manages.
func (s *Store) PendingAccess(ctx context.Context, userID int64) ([]Pending, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (vg.vault_id, gm.user_id) vg.vault_id::text, u.id, u.email, u.public_key, vg.rights, vg.group_id
		FROM vault_groups vg
		JOIN vault_members me ON me.vault_id=vg.vault_id AND me.user_id=$1 AND me.rights='manage'
		JOIN group_members gm ON gm.group_id=vg.group_id
		JOIN users u ON u.id=gm.user_id AND NOT u.disabled
		WHERE NOT EXISTS (SELECT 1 FROM vault_members x WHERE x.vault_id=vg.vault_id AND x.user_id=gm.user_id)
		ORDER BY vg.vault_id, gm.user_id, array_position(ARRAY['manage','edit','view','use'], vg.rights)`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Pending, error) {
		var p Pending
		err := r.Scan(&p.VaultID, &p.UserID, &p.Email, &p.PublicKey, &p.Rights, &p.GroupID)
		return p, err
	})
}

// DirectoryEntry is a user others can share with.
type DirectoryEntry struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	PublicKey   string `json:"public_key"`
}

// Directory lists the active users with their public keys.
func (s *Store) Directory(ctx context.Context) ([]DirectoryEntry, error) {
	rows, err := s.db.Query(ctx, `SELECT id, email, display_name, public_key FROM users WHERE NOT disabled ORDER BY lower(email)`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (DirectoryEntry, error) {
		var d DirectoryEntry
		err := r.Scan(&d.ID, &d.Email, &d.DisplayName, &d.PublicKey)
		return d, err
	})
}

// ---- groups

// Group is a group of users.
type Group struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []int64  `json:"members"`
	Emails      []string `json:"emails"`
	Vaults      int      `json:"vaults"`
}

// Groups lists the groups with their members.
func (s *Store) Groups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.Query(ctx, `SELECT g.id, g.name, g.description,
		COALESCE(array_agg(u.id ORDER BY lower(u.email)) FILTER (WHERE u.id IS NOT NULL), '{}'),
		COALESCE(array_agg(u.email ORDER BY lower(u.email)) FILTER (WHERE u.id IS NOT NULL), '{}'),
		(SELECT count(*) FROM vault_groups vg WHERE vg.group_id=g.id)
		FROM groups g LEFT JOIN group_members gm ON gm.group_id=g.id LEFT JOIN users u ON u.id=gm.user_id
		GROUP BY g.id ORDER BY lower(g.name)`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Group, error) {
		var g Group
		err := r.Scan(&g.ID, &g.Name, &g.Description, &g.Members, &g.Emails, &g.Vaults)
		return g, err
	})
}

// Group returns one group.
func (s *Store) Group(ctx context.Context, id int64) (*Group, error) {
	all, err := s.Groups(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, ErrNotFound
}

func cleanGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 || strings.ContainsAny(name, "\r\n\x00") {
		return "", errors.New("a group name has 1–80 characters")
	}
	return name, nil
}

// SaveGroup creates (id 0) or renames a group.
func (s *Store) SaveGroup(ctx context.Context, id int64, name, desc string) (int64, error) {
	name, err := cleanGroupName(name)
	if err != nil {
		return 0, err
	}
	if len(desc) > 300 {
		desc = desc[:300]
	}
	if id == 0 {
		err = s.db.QueryRow(ctx, `INSERT INTO groups(name, description) VALUES($1,$2) RETURNING id`, name, desc).Scan(&id)
	} else {
		var tag interface{ RowsAffected() int64 }
		tag, err = s.db.Exec(ctx, `UPDATE groups SET name=$2, description=$3 WHERE id=$1`, id, name, desc)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
	}
	if isUnique(err) {
		return 0, ErrConflict
	}
	return id, err
}

// dropGroupAccess removes the memberships that came through a group (all
// of them, or of some users or one vault) and marks those vaults for a new
// key.
func dropGroupAccess(ctx context.Context, tx pgx.Tx, groupID int64, users []int64, vaultID string) error {
	q := `DELETE FROM vault_members WHERE group_id=$1`
	args := []any{groupID}
	if users != nil {
		q += ` AND user_id = ANY($2)`
		args = append(args, users)
	}
	if vaultID != "" {
		q += fmt.Sprintf(` AND vault_id=$%d`, len(args)+1)
		args = append(args, vaultID)
	}
	rows, err := tx.Query(ctx, q+` RETURNING vault_id::text, user_id`, args...)
	if err != nil {
		return err
	}
	type pair struct {
		v string
		u int64
	}
	gone, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pair, error) {
		var p pair
		err := r.Scan(&p.v, &p.u)
		return p, err
	})
	if err != nil {
		return err
	}
	vaults := map[string]bool{}
	var touched []int64
	for _, p := range gone {
		vaults[p.v] = true
		touched = append(touched, p.u)
	}
	for v := range vaults {
		if _, err := tx.Exec(ctx, `UPDATE vaults SET needs_rotation=true, revision=nextval('revisions') WHERE id=$1`, v); err != nil {
			return err
		}
		ids, err := vaultMemberIDs(ctx, tx, v)
		if err != nil {
			return err
		}
		touched = append(touched, ids...)
	}
	return touchUsers(ctx, tx, touched)
}

// DeleteGroup removes a group and the access it gave.
func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := dropGroupAccess(ctx, tx, id, nil, ""); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM groups WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// SetGroupMembers replaces the members of a group; users who left lose the
// access the group gave them.
func (s *Store) SetGroupMembers(ctx context.Context, id int64, users []int64) error {
	if users == nil {
		users = []int64{}
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1)`, id).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	rows, err := tx.Query(ctx, `DELETE FROM group_members WHERE group_id=$1 AND NOT (user_id = ANY($2)) RETURNING user_id`, id, users)
	if err != nil {
		return err
	}
	left, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return err
	}
	if len(left) > 0 {
		if err := dropGroupAccess(ctx, tx, id, left, ""); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO group_members(group_id, user_id) SELECT $1, u FROM unnest($2::bigint[]) u WHERE EXISTS(SELECT 1 FROM users WHERE id=u) ON CONFLICT DO NOTHING`, id, users); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// VaultGroup is a group's grant on a vault.
type VaultGroup struct {
	GroupID int64  `json:"group_id"`
	Name    string `json:"name"`
	Rights  string `json:"rights"`
	Members int    `json:"members"`
}

// VaultGroups lists the groups of a vault (for its members).
func (s *Store) VaultGroups(ctx context.Context, userID int64, vaultID string) ([]VaultGroup, error) {
	if _, err := s.VaultMembers(ctx, userID, vaultID); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT g.id, g.name, vg.rights, (SELECT count(*) FROM group_members gm WHERE gm.group_id=g.id)
		FROM vault_groups vg JOIN groups g ON g.id=vg.group_id WHERE vg.vault_id=$1 ORDER BY lower(g.name)`, vaultID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (VaultGroup, error) {
		var v VaultGroup
		err := r.Scan(&v.GroupID, &v.Name, &v.Rights, &v.Members)
		return v, err
	})
}

// PutVaultGroup gives a group access to a vault or changes its rights
// (the memberships through the group follow).
func (s *Store) PutVaultGroup(ctx context.Context, actor int64, vaultID string, groupID int64, rights string) error {
	if !ValidRights(rights) {
		return errors.New("unknown rights")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireManage(ctx, tx, vaultID, actor); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO vault_groups(vault_id, group_id, rights) VALUES($1,$2,$3) ON CONFLICT (vault_id, group_id) DO UPDATE SET rights=EXCLUDED.rights`, vaultID, groupID, rights)
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			return ErrNotFound
		}
		return err
	}
	rows, err := tx.Query(ctx, `UPDATE vault_members SET rights=$3, revision=nextval('revisions') WHERE vault_id=$1 AND group_id=$2 RETURNING user_id`, vaultID, groupID, rights)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return err
	}
	if n, err := managersLeft(ctx, tx, vaultID); err != nil {
		return err
	} else if n == 0 {
		return ErrLastManager
	}
	if err := touchUsers(ctx, tx, ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RemoveVaultGroup takes a group's access to a vault away.
func (s *Store) RemoveVaultGroup(ctx context.Context, actor int64, vaultID string, groupID int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireManage(ctx, tx, vaultID, actor); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM vault_groups WHERE vault_id=$1 AND group_id=$2`, vaultID, groupID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := dropGroupAccess(ctx, tx, groupID, nil, vaultID); err != nil {
		return err
	}
	if n, err := managersLeft(ctx, tx, vaultID); err != nil {
		return err
	} else if n == 0 {
		return ErrLastManager
	}
	return tx.Commit(ctx)
}

// MoveItem moves an item to another vault, sealed again with that vault's
// key; its files go with it. The user needs edit rights in both vaults.
func (s *Store) MoveItem(ctx context.Context, userID int64, id, toVault, data string, base int64) (int64, error) {
	if !ValidID(id) || !ValidID(toVault) {
		return 0, ErrNotFound
	}
	if !SealedOK(data, MaxItemData) {
		return 0, errors.New("invalid or too large item")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var from string
	if err := tx.QueryRow(ctx, `SELECT vault_id::text FROM items WHERE id=$1 FOR UPDATE`, id).Scan(&from); err != nil {
		return 0, notFound(err)
	}
	for _, v := range []string{from, toVault} {
		r, err := memberRights(ctx, tx, v, userID)
		if errors.Is(err, ErrForbidden) && v == from {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		if !canEdit(r) {
			return 0, ErrForbidden
		}
	}
	// Members of the old vault learn that the item is gone from it. The
	// removal comes before the moved item (a smaller revision), so members
	// of both vaults remove it and get it back in the same sync.
	if _, err := tx.Exec(ctx, `INSERT INTO tombstones(id, kind, vault_id, revision) VALUES($1,'item',$2,nextval('revisions')) ON CONFLICT (id) DO UPDATE SET vault_id=EXCLUDED.vault_id, revision=EXCLUDED.revision, at=now()`, id, from); err != nil {
		return 0, err
	}
	var rev int64
	err = tx.QueryRow(ctx, `UPDATE items SET vault_id=$2, data=$3, revision=nextval('revisions'), updated_at=$4 WHERE id=$1 AND revision=$5 RETURNING revision`,
		id, toVault, data, s.now(), base).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrStale
	}
	if err != nil {
		return 0, err
	}
	return rev, tx.Commit(ctx)
}

// KnownKeys returns the sealed list of confirmed member keys.
func (s *Store) KnownKeys(ctx context.Context, userID int64) (string, error) {
	var k string
	err := s.db.QueryRow(ctx, `SELECT known_keys FROM users WHERE id=$1`, userID).Scan(&k)
	return k, notFound(err)
}

// SetKnownKeys replaces the sealed list of confirmed member keys.
func (s *Store) SetKnownKeys(ctx context.Context, userID int64, data string) error {
	if data != "" && !SealedOK(data, 256<<10) {
		return errors.New("invalid data")
	}
	_, err := s.db.Exec(ctx, `UPDATE users SET known_keys=$2 WHERE id=$1`, userID, data)
	return err
}

// ExpireMemberships ends time-limited access that ran out; those vaults
// need a new key.
func (s *Store) ExpireMemberships(ctx context.Context) (int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `DELETE FROM vault_members WHERE expires_at IS NOT NULL AND expires_at <= $1 RETURNING vault_id::text, user_id`, s.now())
	if err != nil {
		return 0, err
	}
	type pair struct {
		v string
		u int64
	}
	gone, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pair, error) {
		var p pair
		err := r.Scan(&p.v, &p.u)
		return p, err
	})
	if err != nil || len(gone) == 0 {
		return 0, err
	}
	var touched []int64
	vaults := map[string]bool{}
	for _, p := range gone {
		touched = append(touched, p.u)
		vaults[p.v] = true
	}
	for v := range vaults {
		if _, err := tx.Exec(ctx, `UPDATE vaults SET needs_rotation=true, revision=nextval('revisions') WHERE id=$1`, v); err != nil {
			return 0, err
		}
		ids, err := vaultMemberIDs(ctx, tx, v)
		if err != nil {
			return 0, err
		}
		touched = append(touched, ids...)
	}
	if err := touchUsers(ctx, tx, touched); err != nil {
		return 0, err
	}
	return len(gone), tx.Commit(ctx)
}

// SetUserGroups puts a user into exactly the groups with these names
// (from the directory or the identity provider; names compared without
// case). Leaving a group ends the access it gave.
func (s *Store) SetUserGroups(ctx context.Context, userID int64, names []string) error {
	lower := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			lower = append(lower, n)
		}
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `DELETE FROM group_members gm USING groups g WHERE gm.group_id=g.id AND gm.user_id=$1 AND NOT (lower(g.name) = ANY($2)) RETURNING gm.group_id`, userID, lower)
	if err != nil {
		return err
	}
	left, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return err
	}
	for _, g := range left {
		if err := dropGroupAccess(ctx, tx, g, []int64{userID}, ""); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO group_members(group_id, user_id) SELECT id, $1 FROM groups WHERE lower(name) = ANY($2) ON CONFLICT DO NOTHING`, userID, lower); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
