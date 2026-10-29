package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// Roles.
const (
	RoleAdmin = "admin" // users, settings and the audit log, plus an own vault
	RoleUser  = "user"  // an own vault
)

// ValidRole reports a known role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleUser }

// User is an account.
type User struct {
	ID          int64
	Email       string
	DisplayName string
	Role        string
	TOTPEnabled bool
	Disabled    bool
	Lang        string
	Prefs       Prefs
	HasRecovery bool
	Revision    int64
	CreatedAt   time.Time
	PasswordAt  time.Time
	LastLoginAt *time.Time
}

// Prefs are a user's own choices for the vault clients (not secret).
type Prefs struct {
	// LockMinutes locks the vault after this much inactivity (0 = the default).
	LockMinutes int `json:"lock_minutes,omitempty"`
	// ClipboardSeconds clears copied passwords (0 = the default).
	ClipboardSeconds int `json:"clipboard_seconds,omitempty"`
}

// IsAdmin reports the admin role.
func (u *User) IsAdmin() bool { return u != nil && u.Role == RoleAdmin }

// Name is the display name or, without one, the e-mail address.
func (u *User) Name() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

// NormEmail checks and normalises an e-mail address (the sign-in name).
func NormEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || len(s) > 254 || strings.ContainsAny(s, " \t\r\n<>\"") {
		return "", errors.New("enter a valid e-mail address")
	}
	return strings.ToLower(s), nil
}

const userCols = `id, email, display_name, role, totp_enabled, disabled, lang, prefs, recovery_auth_hash<>'', revision, created_at, password_changed_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var prefs []byte
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.TOTPEnabled, &u.Disabled, &u.Lang, &prefs, &u.HasRecovery,
		&u.Revision, &u.CreatedAt, &u.PasswordAt, &u.LastLoginAt)
	if err == nil {
		_ = json.Unmarshal(prefs, &u.Prefs)
	}
	return u, err
}

// UserCount is the number of accounts (0 = setup not done).
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// Keys are what a client sends to create or re-key an account: the auth
// key (only hashed here) and keys wrapped by keys the server never sees.
type Keys struct {
	KDF               vaultcrypto.KDF `json:"kdf"`
	Salt              string          `json:"salt"`
	Auth              string          `json:"auth"`
	WrappedAccountKey string          `json:"wrapped_account_key"`
}

var b64urlRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// SealedOK checks the shape of a sealed value (version, nonce, tag, size).
func SealedOK(s string, maxLen int) bool {
	if len(s) > maxLen || !b64urlRE.MatchString(s) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) >= 1+12+16 && raw[0] == vaultcrypto.Version
}

// B64Len is the decoded length of a base64url value, -1 if it is not one.
func B64Len(s string) int {
	if !b64urlRE.MatchString(s) {
		return -1
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return -1
	}
	return len(raw)
}

// Validate checks the shapes (the server cannot check the contents).
func (k *Keys) Validate() error {
	if err := k.KDF.Validate(); err != nil {
		return err
	}
	if B64Len(k.Salt) != 16 || B64Len(k.Auth) != 32 || !SealedOK(k.WrappedAccountKey, 200) {
		return errors.New("invalid key material")
	}
	return nil
}

// NewAccount is a new user with the keys the client made.
type NewAccount struct {
	Email       string `json:"email"`
	DisplayName string `json:"name"`
	Role        string `json:"-"`
	Keys
	PublicKey         string `json:"public_key"`
	WrappedPrivateKey string `json:"wrapped_private_key"`
	Vault             struct {
		ID         string `json:"id"`
		WrappedKey string `json:"wrapped_key"`
	} `json:"vault"`
	// InviteID is the invitation used up by this account (0 for the setup).
	InviteID int64 `json:"-"`
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ValidID reports a client-made id (a lower-case version 4 UUID).
func ValidID(id string) bool { return uuidRE.MatchString(id) }

// CreateAccount adds a user with the personal vault; with an invitation
// the invitation is used up in the same transaction.
func (s *Store) CreateAccount(ctx context.Context, n NewAccount) (*User, error) {
	email, err := NormEmail(n.Email)
	if err != nil {
		return nil, err
	}
	if !ValidRole(n.Role) {
		return nil, errors.New("unknown role")
	}
	if err := n.Keys.Validate(); err != nil {
		return nil, err
	}
	if B64Len(n.PublicKey) != 32 || !SealedOK(n.WrappedPrivateKey, 400) || !ValidID(n.Vault.ID) || !SealedOK(n.Vault.WrappedKey, 200) {
		return nil, errors.New("invalid key material")
	}
	if len([]rune(n.DisplayName)) > 100 {
		return nil, errors.New("the name is too long")
	}
	h, err := auth.HashPassword(n.Auth)
	if err != nil {
		return nil, err
	}
	kdf, _ := json.Marshal(n.KDF)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if n.InviteID != 0 {
		tag, err := tx.Exec(ctx, `UPDATE invites SET used_at=$2 WHERE id=$1 AND used_at IS NULL AND expires_at>$2`, n.InviteID, s.now())
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return nil, ErrNotFound
		}
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO users(email, display_name, role, kdf, salt, auth_hash, wrapped_account_key, public_key, wrapped_private_key)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, email, strings.TrimSpace(n.DisplayName), n.Role, kdf, n.Salt, h,
		n.WrappedAccountKey, n.PublicKey, n.WrappedPrivateKey).Scan(&id)
	if isUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO vaults(id, kind, owner_id) VALUES($1,'personal',$2)`, n.Vault.ID, id); err != nil {
		if isUnique(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO vault_members(vault_id, user_id, wrapped_key, rights) VALUES($1,$2,$3,'manage')`, n.Vault.ID, id, n.Vault.WrappedKey); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.UserByID(ctx, id)
}

// UserByID loads an account.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		return nil, notFound(err)
	}
	return u, nil
}

// UserByEmail loads an account by its sign-in address.
func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)))
	if err != nil {
		return nil, notFound(err)
	}
	return u, nil
}

// Users lists all accounts.
func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.db.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY lower(email)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Prelogin returns the key-derivation settings and salt of an address.
// Unknown addresses get settings and a salt that look real and stay the
// same (derived from the address with the server's key), so the answer
// does not tell whether an account exists.
func (s *Store) Prelogin(ctx context.Context, email string, def vaultcrypto.KDF) (vaultcrypto.KDF, string, error) {
	var raw []byte
	var salt string
	err := s.db.QueryRow(ctx, `SELECT kdf, salt FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).Scan(&raw, &salt)
	if errors.Is(err, pgx.ErrNoRows) {
		fake := s.box.sum("prelogin|" + strings.ToLower(strings.TrimSpace(email)))
		return def, base64.RawURLEncoding.EncodeToString(fake[:16]), nil
	}
	if err != nil {
		return def, "", err
	}
	var k vaultcrypto.KDF
	err = json.Unmarshal(raw, &k)
	return k, salt, err
}

// CheckAuth verifies a sign-in with the auth key. It returns ErrNotFound
// for unknown or disabled users and a wrong key, in about the same time.
func (s *Store) CheckAuth(ctx context.Context, email, authKey string) (*User, error) {
	var id int64
	var hash string
	var disabled bool
	err := s.db.QueryRow(ctx, `SELECT id, auth_hash, disabled FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).
		Scan(&id, &hash, &disabled)
	if err != nil {
		auth.BurnTime(authKey)
		return nil, notFound(err)
	}
	ok, err := auth.VerifyPassword(hash, authKey)
	if err != nil {
		return nil, err
	}
	if !ok || disabled {
		return nil, ErrNotFound
	}
	return s.UserByID(ctx, id)
}

// VerifyAuth checks the auth key of a signed-in user (before changes that
// need the master password again).
func (s *Store) VerifyAuth(ctx context.Context, userID int64, authKey string) (bool, error) {
	var hash string
	if err := s.db.QueryRow(ctx, `SELECT auth_hash FROM users WHERE id=$1`, userID).Scan(&hash); err != nil {
		return false, notFound(err)
	}
	return auth.VerifyPassword(hash, authKey)
}

// AccountKeys is what a client needs to unlock: all wrapped.
type AccountKeys struct {
	KDF               vaultcrypto.KDF `json:"kdf"`
	Salt              string          `json:"salt"`
	WrappedAccountKey string          `json:"wrapped_account_key"`
	PublicKey         string          `json:"public_key"`
	WrappedPrivateKey string          `json:"wrapped_private_key"`
	// RecoveryWrappedKey is handed out only after a recovery key was proven.
	RecoveryWrappedKey string `json:"-"`
}

// AccountKeysOf loads the wrapped keys of a user.
func (s *Store) AccountKeysOf(ctx context.Context, userID int64) (*AccountKeys, error) {
	k := &AccountKeys{}
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT kdf, salt, wrapped_account_key, public_key, wrapped_private_key, recovery_wrapped_key FROM users WHERE id=$1`, userID).
		Scan(&raw, &k.Salt, &k.WrappedAccountKey, &k.PublicKey, &k.WrappedPrivateKey, &k.RecoveryWrappedKey)
	if err != nil {
		return nil, notFound(err)
	}
	return k, json.Unmarshal(raw, &k.KDF)
}

// SetMasterKeys replaces the auth hash and the wrapped account key (new
// master password, stronger key derivation, recovery) and signs the user
// out everywhere except keepSession ("" = everywhere).
func (s *Store) SetMasterKeys(ctx context.Context, userID int64, k Keys, keepSession string) error {
	if err := k.Validate(); err != nil {
		return err
	}
	h, err := auth.HashPassword(k.Auth)
	if err != nil {
		return err
	}
	kdf, _ := json.Marshal(k.KDF)
	tag, err := s.db.Exec(ctx, `UPDATE users SET kdf=$2, salt=$3, auth_hash=$4, wrapped_account_key=$5, password_changed_at=$6, revision=nextval('revisions') WHERE id=$1`,
		userID, kdf, k.Salt, h, k.WrappedAccountKey, s.now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND token_hash<>$2`, userID, keepSession)
	return err
}

// SetRecovery stores (or, with empty values, removes) a recovery key.
func (s *Store) SetRecovery(ctx context.Context, userID int64, recoveryAuth, wrapped string) error {
	h := ""
	if recoveryAuth != "" || wrapped != "" {
		if B64Len(recoveryAuth) != 32 || !SealedOK(wrapped, 200) {
			return errors.New("invalid key material")
		}
		var err error
		if h, err = auth.HashPassword(recoveryAuth); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(ctx, `UPDATE users SET recovery_auth_hash=$2, recovery_wrapped_key=$3 WHERE id=$1`, userID, h, wrapped)
	return err
}

// CheckRecovery verifies a recovery key's auth part; ErrNotFound for
// unknown or disabled users, accounts without a recovery key and a wrong key.
func (s *Store) CheckRecovery(ctx context.Context, email, recoveryAuth string) (*User, error) {
	var id int64
	var hash string
	var disabled bool
	err := s.db.QueryRow(ctx, `SELECT id, recovery_auth_hash, disabled FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).
		Scan(&id, &hash, &disabled)
	if err == nil && hash == "" {
		err = pgx.ErrNoRows
	}
	if err != nil {
		auth.BurnTime(recoveryAuth)
		return nil, notFound(err)
	}
	ok, err := auth.VerifyPassword(hash, recoveryAuth)
	if err != nil {
		return nil, err
	}
	if !ok || disabled {
		return nil, ErrNotFound
	}
	return s.UserByID(ctx, id)
}

// UpdateUser changes the name, role and state of an account.
func (s *Store) UpdateUser(ctx context.Context, id int64, displayName, role string, disabled bool) error {
	if !ValidRole(role) {
		return errors.New("unknown role")
	}
	if len([]rune(displayName)) > 100 {
		return errors.New("the name is too long")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users SET display_name=$2, role=$3, disabled=$4 WHERE id=$1`,
		id, strings.TrimSpace(displayName), role, disabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := lastAdminGuard(ctx, tx); err != nil {
		return err
	}
	if disabled {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// lastAdminGuard refuses to remove the last way in.
func lastAdminGuard(ctx context.Context, tx pgx.Tx) error {
	var admins int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled`).Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		return errors.New("at least one enabled administrator must remain")
	}
	return nil
}

// DeleteUser removes an account with its personal vault and items. It
// cannot be undone: nobody else can open that vault.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Shared vaults the user was in need a new key; those only the user
	// was in go away.
	if _, err := tx.Exec(ctx, `DELETE FROM vaults v WHERE v.kind='shared' AND EXISTS(SELECT 1 FROM vault_members m WHERE m.vault_id=v.id AND m.user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM vault_members m WHERE m.vault_id=v.id AND m.user_id<>$1)`, id); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `UPDATE vaults v SET needs_rotation=true, revision=nextval('revisions') WHERE v.kind='shared'
		AND EXISTS(SELECT 1 FROM vault_members m WHERE m.vault_id=v.id AND m.user_id=$1) RETURNING v.id::text`, id)
	if err != nil {
		return err
	}
	shared, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	for _, v := range shared {
		ids, err := vaultMemberIDs(ctx, tx, v)
		if err != nil {
			return err
		}
		if err := touchUsers(ctx, tx, ids); err != nil {
			return err
		}
	}
	// the personal vault and its items go with the user (ON DELETE CASCADE)
	if err := lastAdminGuard(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetLang stores the console language of a user.
func (s *Store) SetLang(ctx context.Context, userID int64, lang string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET lang=$2 WHERE id=$1`, userID, lang)
	return err
}

// SetPrefs stores a user's vault preferences.
func (s *Store) SetPrefs(ctx context.Context, userID int64, p Prefs) error {
	raw, _ := json.Marshal(p)
	_, err := s.db.Exec(ctx, `UPDATE users SET prefs=$2, revision=nextval('revisions') WHERE id=$1`, userID, raw)
	return err
}

// MarkLogin records a successful sign-in.
func (s *Store) MarkLogin(ctx context.Context, userID int64) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET last_login_at=$2 WHERE id=$1`, userID, s.now())
	return err
}

// ---- second factor

// TwoFactor is a user's second factor state.
type TwoFactor struct {
	Enabled  bool
	Secret   string // decrypted
	LastStep int64
	Codes    []string // hashes of unused recovery codes
}

// GetTwoFactor loads and decrypts the TOTP state.
func (s *Store) GetTwoFactor(ctx context.Context, userID int64) (TwoFactor, error) {
	var t TwoFactor
	var sealed string
	err := s.db.QueryRow(ctx, `SELECT totp_enabled, totp_secret, totp_last_step, recovery_codes FROM users WHERE id=$1`, userID).
		Scan(&t.Enabled, &sealed, &t.LastStep, &t.Codes)
	if err != nil {
		return t, notFound(err)
	}
	t.Secret, err = s.box.open("users.totp_secret", sealed)
	return t, err
}

// SetPendingTOTP stores a new secret that is not confirmed yet. It refuses
// to replace an enabled factor (use ResetTwoFactor first).
func (s *Store) SetPendingTOTP(ctx context.Context, userID int64, secret string) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_secret=$2, totp_last_step=0 WHERE id=$1 AND NOT totp_enabled`,
		userID, s.box.seal("users.totp_secret", secret))
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("two-factor sign-in is already set up")
	}
	return err
}

// EnableTOTP confirms the pending secret with a valid code and stores the
// hashes of new recovery codes.
func (s *Store) EnableTOTP(ctx context.Context, userID, step int64, recoveryHashes []string) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_enabled=true, totp_last_step=$2, recovery_codes=$3 WHERE id=$1 AND NOT totp_enabled AND totp_secret<>''`,
		userID, step, recoveryHashes)
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("no pending two-factor setup")
	}
	return err
}

// UseTOTPStep records the last accepted step; it fails when another
// request used the same or a later step in the meantime (no replay).
func (s *Store) UseTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_last_step=$2 WHERE id=$1 AND totp_last_step<$2`, userID, step)
	return err == nil && tag.RowsAffected() == 1, err
}

// UseRecoveryCode consumes a recovery code.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int64, code string) (bool, error) {
	h := auth.HashRecoveryCode(code)
	tag, err := s.db.Exec(ctx, `UPDATE users SET recovery_codes=array_remove(recovery_codes,$2) WHERE id=$1 AND $2=ANY(recovery_codes)`, userID, h)
	return err == nil && tag.RowsAffected() == 1, err
}

// SetRecoveryCodes replaces the recovery codes.
func (s *Store) SetRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET recovery_codes=$2 WHERE id=$1 AND totp_enabled`, userID, hashes)
	return err
}

// ResetTwoFactor removes the second factor (an administrator does this for
// a user who lost the phone); the user sets it up again at the next sign-in.
func (s *Store) ResetTwoFactor(ctx context.Context, userID int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_enabled=false, totp_secret='', totp_last_step=0, recovery_codes='{}' WHERE id=$1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	return err
}
