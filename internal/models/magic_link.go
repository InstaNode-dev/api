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
func CreateMagicLink(ctx context.Context, db *sql.DB, email, plaintext, returnTo string, ttl time.Duration) (*MagicLink, error) {
	hash := HashMagicLink(plaintext)
	expiresAt := time.Now().UTC().Add(ttl)

	m := &MagicLink{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO magic_links (email, token_hash, return_to, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, email, token_hash, return_to, expires_at, consumed_at, created_at
	`, email, hash, returnTo, expiresAt).Scan(
		&m.ID, &m.Email, &m.TokenHash, &m.ReturnTo, &m.ExpiresAt, &m.ConsumedAt, &m.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreateMagicLink: %w", err)
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
