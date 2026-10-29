package store

import (
	"context"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/auth"
)

// Session stages.
const (
	StageMFA  = "mfa"  // password verified, second factor pending
	StageFull = "full" // signed in
)

// Session kinds.
const (
	KindWeb = "web" // the web vault (cookie)
	KindExt = "ext" // a browser extension (bearer token)
)

// MFATimeout is how long a password-verified sign-in waits for the code.
const MFATimeout = 5 * time.Minute

// Session is a sign-in.
type Session struct {
	Hash      string
	UserID    int64
	Stage     string
	Kind      string
	Device    string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

// ID is a short handle of the session for its owner (part of the hash).
func (x *Session) ID() string { return x.Hash[:16] }

// NewSession describes a session to start.
type NewSession struct {
	UserID        int64
	Stage, Kind   string
	Device        string
	Life          time.Duration
	IP, UserAgent string
}

// CreateSession starts a web session and returns the cookie value.
func (s *Store) CreateSession(ctx context.Context, userID int64, stage string, life time.Duration, ip, ua string) (string, *Session, error) {
	return s.StartSession(ctx, NewSession{UserID: userID, Stage: stage, Kind: KindWeb, Life: life, IP: ip, UserAgent: ua})
}

// StartSession starts a session of any kind and returns its token.
func (s *Store) StartSession(ctx context.Context, n NewSession) (string, *Session, error) {
	tok := auth.RandomToken(32)
	if n.Kind == KindExt {
		tok = "pzd_" + tok
	}
	now := s.now()
	ua := n.UserAgent
	if len(ua) > 300 {
		ua = ua[:300]
	}
	dev := strings.TrimSpace(n.Device)
	if len([]rune(dev)) > 60 {
		dev = string([]rune(dev)[:60])
	}
	if n.Kind == "" {
		n.Kind = KindWeb
	}
	x := &Session{Hash: auth.HashToken("session", tok), UserID: n.UserID, Stage: n.Stage, Kind: n.Kind, Device: dev, CreatedAt: now, LastSeen: now,
		ExpiresAt: now.Add(n.Life), IP: n.IP, UserAgent: ua}
	_, err := s.db.Exec(ctx, `INSERT INTO sessions(token_hash, user_id, stage, kind, device, created_at, last_seen, expires_at, ip, user_agent) VALUES($1,$2,$3,$4,$5,$6,$6,$7,$8,$9)`,
		x.Hash, x.UserID, x.Stage, x.Kind, x.Device, now, x.ExpiresAt, x.IP, ua)
	return tok, x, err
}

const sessionCols = `token_hash, user_id, stage, kind, device, created_at, last_seen, expires_at, ip, user_agent`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	x := &Session{}
	err := row.Scan(&x.Hash, &x.UserID, &x.Stage, &x.Kind, &x.Device, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt, &x.IP, &x.UserAgent)
	return x, err
}

// SessionByToken loads a session by its token; expired or idle sessions
// are deleted and reported as ErrNotFound. idle gives the inactivity limit
// of a kind (0 disables the check).
func (s *Store) SessionByToken(ctx context.Context, tok string, idle func(kind string) time.Duration) (*Session, error) {
	if tok == "" {
		return nil, ErrNotFound
	}
	x, err := scanSession(s.db.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE token_hash=$1`, auth.HashToken("session", tok)))
	if err != nil {
		return nil, notFound(err)
	}
	now := s.now()
	limit := time.Duration(0)
	if idle != nil {
		limit = idle(x.Kind)
	}
	if now.After(x.ExpiresAt) || (limit > 0 && x.Stage == StageFull && now.Sub(x.LastSeen) > limit) {
		_ = s.DeleteSession(ctx, x.Hash)
		return nil, ErrNotFound
	}
	return x, nil
}

// TouchSession updates the last activity (at most once a minute).
func (s *Store) TouchSession(ctx context.Context, x *Session, ip string) error {
	now := s.now()
	if now.Sub(x.LastSeen) < time.Minute {
		return nil
	}
	x.LastSeen = now
	_, err := s.db.Exec(ctx, `UPDATE sessions SET last_seen=$2, ip=$3 WHERE token_hash=$1`, x.Hash, now, ip)
	return err
}

// PromoteSession turns a second-factor-pending sign-in into a full session
// under a NEW token (the pre-auth token must not become a session token).
func (s *Store) PromoteSession(ctx context.Context, x *Session, life time.Duration) (string, error) {
	if err := s.DeleteSession(ctx, x.Hash); err != nil {
		return "", err
	}
	tok, _, err := s.StartSession(ctx, NewSession{UserID: x.UserID, Stage: StageFull, Kind: x.Kind, Device: x.Device, Life: life, IP: x.IP, UserAgent: x.UserAgent})
	return tok, err
}

// DeleteSession signs a session out.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, hash)
	return err
}

// DeleteUserSession signs out one session of a user by its ID.
func (s *Store) DeleteUserSession(ctx context.Context, userID int64, id string) (*Session, error) {
	if len(id) != 16 {
		return nil, ErrNotFound
	}
	x, err := scanSession(s.db.QueryRow(ctx, `DELETE FROM sessions WHERE user_id=$1 AND left(token_hash,16)=$2 RETURNING `+sessionCols, userID, id))
	if err != nil {
		return nil, notFound(err)
	}
	return x, nil
}

// UserSessions lists the sessions of a user.
func (s *Store) UserSessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := s.db.Query(ctx, `SELECT `+sessionCols+` FROM sessions WHERE user_id=$1 AND stage='full' ORDER BY last_seen DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

// PurgeSessions deletes expired sessions.
func (s *Store) PurgeSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, s.now())
	return err
}

// UnlockKey returns the session's key for the browser's locally stored
// unlocked keys, making one when there is none (after a lock).
func (s *Store) UnlockKey(ctx context.Context, x *Session) (string, error) {
	var sealed string
	if err := s.db.QueryRow(ctx, `SELECT unlock_key FROM sessions WHERE token_hash=$1 AND stage='full'`, x.Hash).Scan(&sealed); err != nil {
		return "", notFound(err)
	}
	if sealed != "" {
		return s.box.open("sessions.unlock_key", sealed)
	}
	k := auth.RandomToken(32)
	_, err := s.db.Exec(ctx, `UPDATE sessions SET unlock_key=$2 WHERE token_hash=$1`, x.Hash, s.box.seal("sessions.unlock_key", k))
	return k, err
}

// LockSession forgets the unlock key: what the browser kept is useless.
func (s *Store) LockSession(ctx context.Context, x *Session) error {
	_, err := s.db.Exec(ctx, `UPDATE sessions SET unlock_key='' WHERE token_hash=$1`, x.Hash)
	return err
}
