package models

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MagicLinkPrefix is the literal prefix every magic-link plaintext token
// carries. Visible in logs and emails so it's recognizable as a magic-link
// token (vs. a PAT "ink_" or a session JWT).
const MagicLinkPrefix = "mlnk_"

// MagicLink is a stored, hashed passwordless login token.
type MagicLink struct {
	ID         uuid.UUID
	Email      string
	TokenHash  string
	ReturnTo   string
	ExpiresAt  time.Time
	ConsumedAt sql.NullTime
	CreatedAt  time.Time
}

// ErrMagicLinkNotFound is returned when a hash lookup yields no rows OR the
// row is expired/consumed. Callers should NEVER distinguish between those
// cases in their response — return a generic "invalid or expired link"
// message either way.
var ErrMagicLinkNotFound = errors.New("magic link not found, expired, or already used")

// GenerateMagicLinkPlaintext returns a fresh plaintext token in the canonical
// "mlnk_<base64url>" form. 32 random bytes → ~43 base64 chars → tokens ~48
// chars total. The caller is expected to hash it with HashMagicLink and pass
// only the hash to CreateMagicLink.
func GenerateMagicLinkPlaintext() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read: %w", err)
	}
	return MagicLinkPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashMagicLink returns the storage form of a plaintext magic-link token.
// SHA-256 is constant-time on fixed-length input.
func HashMagicLink(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// CreateMagicLink inserts a new row. The plaintext is hashed; only the hash
// is persisted. ttl is added to now() to derive expires_at.
//
// The inserted row lands with email_send_status='pending' (migration 041
// default). Callers must transition it to 'sent' or 'send_failed' via the
// MarkMagicLink* helpers below once the email provider has resolved.
// A row stuck at 'pending' inside the TTL window is what the worker's
// reconciler treats as "in flight" — see worker's magic_link_reconciler.go.
func CreateMagicLink(ctx context.Context, db *sql.DB, email, plaintext, returnTo string, ttl time.Duration) (*MagicLink, error) {
	hash := HashMagicLink(plaintext)
	expiresAt := time.Now().UTC().Add(ttl)

	m := &MagicLink{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO magic_links (email, token_hash, return_to, expires_at, email_send_status)
		VALUES ($1, $2, $3, $4, 'pending')
		RETURNING id, email, token_hash, return_to, expires_at, consumed_at, created_at
	`, email, hash, returnTo, expiresAt).Scan(
		&m.ID, &m.Email, &m.TokenHash, &m.ReturnTo, &m.ExpiresAt, &m.ConsumedAt, &m.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreateMagicLink: %w", err)
	}
	return m, nil
}

// Magic-link send-status constants — mirror the migration-041 DEFAULT and
// the worker's enum. The handler only writes pending/sent/send_failed; the
// worker is the only writer that flips a row to send_abandoned (after the
// 3rd failed attempt). Kept as string constants because the column is TEXT —
// a single source of truth here prevents typo drift across handler + worker.
const (
	MagicLinkSendStatusPending   = "pending"
	MagicLinkSendStatusSent      = "sent"
	MagicLinkSendStatusFailed    = "send_failed"
	MagicLinkSendStatusAbandoned = "send_abandoned"
)

// MagicLinkReconcileRow is the projection ListMagicLinksForReconcile returns.
// The worker only needs the id + the addr to re-send, plus the attempt
// counter to short-circuit at the 3-attempt cap.
type MagicLinkReconcileRow struct {
	ID                uuid.UUID
	Email             string
	TokenHash         string
	ReturnTo          string
	EmailSendStatus   string
	EmailSendAttempts int
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// MarkMagicLinkSent flips the row to email_send_status='sent', increments
// the attempt counter, and records the attempt timestamp. We intentionally
// do NOT gate on the previous status — a successful resend from the
// worker's reconciler should win over a stale 'send_failed' marker (the
// email got there, that's what matters for the user).
func MarkMagicLinkSent(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE magic_links
		SET email_send_status = $1,
		    email_send_attempts = email_send_attempts + 1,
		    email_send_last_error = NULL,
		    email_send_last_attempted_at = now()
		WHERE id = $2
	`, MagicLinkSendStatusSent, id)
	if err != nil {
		return fmt.Errorf("models.MarkMagicLinkSent: %w", err)
	}
	return nil
}

// MarkMagicLinkSendFailed increments the attempts counter and records the
// error string in email_send_last_error. Bounded to the last 512 chars so
// a verbose stack-trace from a misbehaving provider doesn't bloat the
// platform DB. The worker uses email_send_attempts to enforce the 3-attempt
// cap; once it reaches 3 the worker writes status='send_abandoned' via
// MarkMagicLinkSendAbandoned (separate write path so the cap policy lives
// in one place — the worker — not split across handler + worker).
func MarkMagicLinkSendFailed(ctx context.Context, db *sql.DB, id uuid.UUID, sendErr error) error {
	errStr := ""
	if sendErr != nil {
		errStr = sendErr.Error()
		if len(errStr) > 512 {
			errStr = errStr[:512]
		}
	}
	_, err := db.ExecContext(ctx, `
		UPDATE magic_links
		SET email_send_status = $1,
		    email_send_attempts = email_send_attempts + 1,
		    email_send_last_error = $2,
		    email_send_last_attempted_at = now()
		WHERE id = $3
	`, MagicLinkSendStatusFailed, errStr, id)
	if err != nil {
		return fmt.Errorf("models.MarkMagicLinkSendFailed: %w", err)
	}
	return nil
}

// MarkMagicLinkSendAbandoned flips a row to email_send_status='send_abandoned'.
// Only the worker calls this — after the 3rd failed reconcile attempt.
// Kept separate from MarkMagicLinkSendFailed because abandonment is a
// terminal policy decision (no more retries, operator alert fires) rather
// than a transient outcome.
func MarkMagicLinkSendAbandoned(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE magic_links
		SET email_send_status = $1,
		    email_send_last_attempted_at = now()
		WHERE id = $2
	`, MagicLinkSendStatusAbandoned, id)
	if err != nil {
		return fmt.Errorf("models.MarkMagicLinkSendAbandoned: %w", err)
	}
	return nil
}

// ListMagicLinksForReconcile returns up to `limit` rows that the worker
// should re-drive. Selection criteria:
//
//   - email_send_status IN ('pending', 'send_failed')
//   - created_at > before              (TTL gate; caller passes now() - 15min)
//   - email_send_attempts < 3          (3-attempt cap)
//
// Returns oldest-first so the worker prioritises rows closest to expiry —
// the user is more likely to give up and retry by hand if their first send
// vanished. The partial index from migration 041 backs this query.
func ListMagicLinksForReconcile(ctx context.Context, db *sql.DB, before time.Time, limit int) ([]MagicLinkReconcileRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, email, token_hash, return_to, email_send_status, email_send_attempts, created_at, expires_at
		FROM magic_links
		WHERE email_send_status IN ($1, $2)
		  AND created_at > $3
		  AND email_send_attempts < 3
		ORDER BY created_at ASC
		LIMIT $4
	`, MagicLinkSendStatusPending, MagicLinkSendStatusFailed, before, limit)
	if err != nil {
		return nil, fmt.Errorf("models.ListMagicLinksForReconcile: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []MagicLinkReconcileRow
	for rows.Next() {
		var r MagicLinkReconcileRow
		if err := rows.Scan(&r.ID, &r.Email, &r.TokenHash, &r.ReturnTo, &r.EmailSendStatus, &r.EmailSendAttempts, &r.CreatedAt, &r.ExpiresAt); err != nil {
			return nil, fmt.Errorf("models.ListMagicLinksForReconcile scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListMagicLinksForReconcile rows: %w", err)
	}
	return out, nil
}

// UpdateMagicLinkTokenHash rotates the token_hash on an existing row. Used
// by the /internal/email/resend-magic-link handler when the worker drives
// a resend: the original plaintext is gone (we only ever stored the hash)
// so the resend has to ship a fresh plaintext, and the row must match.
// The previous hash is overwritten — the original first-attempt link (if
// the user somehow obtained it) is invalidated at that moment, which is
// the right outcome because by definition that first attempt didn't get
// to the user (otherwise the reconciler wouldn't have picked it up).
func UpdateMagicLinkTokenHash(ctx context.Context, db *sql.DB, id uuid.UUID, newHash string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE magic_links
		SET token_hash = $1
		WHERE id = $2 AND consumed_at IS NULL
	`, newHash, id)
	if err != nil {
		return fmt.Errorf("models.UpdateMagicLinkTokenHash: %w", err)
	}
	return nil
}

// GetMagicLinkByID returns the row matching id (whatever its status). Used
// by the /internal/email/resend-magic-link handler so the worker can
// re-drive a specific row by ID rather than re-sending by email address.
func GetMagicLinkByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*MagicLink, error) {
	m := &MagicLink{}
	err := db.QueryRowContext(ctx, `
		SELECT id, email, token_hash, return_to, expires_at, consumed_at, created_at
		FROM magic_links
		WHERE id = $1
	`, id).Scan(
		&m.ID, &m.Email, &m.TokenHash, &m.ReturnTo, &m.ExpiresAt, &m.ConsumedAt, &m.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrMagicLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetMagicLinkByID: %w", err)
	}
	return m, nil
}

// GetMagicLinkForConsumption looks up an unconsumed, non-expired link by its
// hash. Returns ErrMagicLinkNotFound when the hash doesn't exist, the link is
// already consumed, or it's past expires_at.
func GetMagicLinkForConsumption(ctx context.Context, db *sql.DB, hash string) (*MagicLink, error) {
	m := &MagicLink{}
	err := db.QueryRowContext(ctx, `
		SELECT id, email, token_hash, return_to, expires_at, consumed_at, created_at
		FROM magic_links
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
	`, hash).Scan(
		&m.ID, &m.Email, &m.TokenHash, &m.ReturnTo, &m.ExpiresAt, &m.ConsumedAt, &m.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrMagicLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetMagicLinkForConsumption: %w", err)
	}
	return m, nil
}

// ConsumeMagicLink atomically marks a link as consumed. Returns true on the
// first call, false on every subsequent call (single-use). Callers should
// treat false as ErrMagicLinkNotFound — somebody beat us to the row.
func ConsumeMagicLink(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE magic_links SET consumed_at = now()
		WHERE id = $1 AND consumed_at IS NULL
	`, id)
	if err != nil {
		return false, fmt.Errorf("models.ConsumeMagicLink: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("models.ConsumeMagicLink rows: %w", err)
	}
	return n == 1, nil
}
