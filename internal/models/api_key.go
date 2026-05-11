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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// APIKeyPrefix is the literal prefix every Personal Access Token carries.
// The auth middleware uses it to distinguish a PAT from a JWT without
// parsing the token shape.
const APIKeyPrefix = "ink_"

// APIKey is a stored, hashed Personal Access Token.
type APIKey struct {
	ID         uuid.UUID
	TeamID     uuid.UUID
	CreatedBy  uuid.NullUUID
	Name       string
	KeyHash    string
	Scopes     []string
	LastUsedAt sql.NullTime
	RevokedAt  sql.NullTime
	CreatedAt  time.Time
}

// ErrAPIKeyNotFound — handlers map to 404. Never 401 to avoid distinguishing
// "key revoked" from "key never existed."
var ErrAPIKeyNotFound = errors.New("api key not found")

// GenerateAPIKeyPlaintext returns a fresh plaintext key in the canonical
// "ink_<base64url>" form. 32 random bytes → ~43 base64 chars → tokens ~47
// chars total. Caller stores SHA-256(plaintext) via CreateAPIKey.
func GenerateAPIKeyPlaintext() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read: %w", err)
	}
	return APIKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashAPIKey returns the storage form of a plaintext PAT. Constant-time
// safe: SHA-256 fixed-time on fixed-length input.
func HashAPIKey(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// CreateAPIKey inserts a new key row. Returns the created row (without
// plaintext — caller already has it).
func CreateAPIKey(ctx context.Context, db *sql.DB, teamID uuid.UUID, createdBy uuid.NullUUID, name, keyHash string, scopes []string) (*APIKey, error) {
	if len(scopes) == 0 {
		scopes = []string{"read", "write"}
	}
	row := db.QueryRowContext(ctx, `
		INSERT INTO api_keys (team_id, created_by, name, key_hash, scopes)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, team_id, created_by, name, key_hash, scopes, last_used_at, revoked_at, created_at
	`, teamID, createdBy, name, keyHash, pq.Array(scopes))

	k := &APIKey{}
	if err := row.Scan(
		&k.ID, &k.TeamID, &k.CreatedBy, &k.Name, &k.KeyHash,
		pq.Array(&k.Scopes), &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("models.CreateAPIKey: %w", err)
	}
	return k, nil
}

// GetAPIKeyByHash looks up an active (non-revoked) key by its SHA-256.
// Returns ErrAPIKeyNotFound when the key doesn't exist OR is revoked.
func GetAPIKeyByHash(ctx context.Context, db *sql.DB, keyHash string) (*APIKey, error) {
	k := &APIKey{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, created_by, name, key_hash, scopes, last_used_at, revoked_at, created_at
		FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL
	`, keyHash).Scan(
		&k.ID, &k.TeamID, &k.CreatedBy, &k.Name, &k.KeyHash,
		pq.Array(&k.Scopes), &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrAPIKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetAPIKeyByHash: %w", err)
	}
	return k, nil
}

// TouchAPIKey best-effort updates last_used_at to now. Failures are logged
// by callers; never block a request.
func TouchAPIKey(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
	return err
}

// ListAPIKeysByTeam returns active and revoked keys, newest first.
// key_hash is included; plaintext is never recoverable.
func ListAPIKeysByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*APIKey, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, created_by, name, key_hash, scopes, last_used_at, revoked_at, created_at
		FROM api_keys WHERE team_id = $1 ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListAPIKeysByTeam: %w", err)
	}
	defer rows.Close()

	keys := make([]*APIKey, 0)
	for rows.Next() {
		k := &APIKey{}
		if err := rows.Scan(
			&k.ID, &k.TeamID, &k.CreatedBy, &k.Name, &k.KeyHash,
			pq.Array(&k.Scopes), &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("models.ListAPIKeysByTeam scan: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// RevokeAPIKey sets revoked_at = now() for (team_id, id). Returns
// ErrAPIKeyNotFound when the key doesn't exist for that team or is already
// revoked. Idempotent on subsequent calls.
func RevokeAPIKey(ctx context.Context, db *sql.DB, teamID, id uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE api_keys SET revoked_at = now()
		WHERE id = $1 AND team_id = $2 AND revoked_at IS NULL
	`, id, teamID)
	if err != nil {
		return fmt.Errorf("models.RevokeAPIKey: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("models.RevokeAPIKey rows: %w", err)
	}
	if n == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

// HasScope reports whether the key carries the given scope (or a higher one).
// Hierarchy: admin > write > read.
func (k *APIKey) HasScope(want string) bool {
	rank := map[string]int{"read": 1, "write": 2, "admin": 3}
	wantRank, ok := rank[want]
	if !ok {
		return false
	}
	for _, s := range k.Scopes {
		if r, ok := rank[strings.ToLower(s)]; ok && r >= wantRank {
			return true
		}
	}
	return false
}
