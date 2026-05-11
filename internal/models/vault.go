package models

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// VaultSecret is one versioned row in vault_secrets.
//
// EncryptedValue stores AES-256-GCM ciphertext as raw bytes. The base64 string
// produced by crypto.Encrypt is decoded before insertion and re-encoded on read,
// so the at-rest format is opaque binary.
type VaultSecret struct {
	ID             uuid.UUID
	TeamID         uuid.UUID
	Env            string
	Key            string
	EncryptedValue []byte
	Version        int
	CreatedBy      uuid.NullUUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// VaultAuditEntry is one row in vault_audit_log.
type VaultAuditEntry struct {
	ID        int64
	TeamID    uuid.UUID
	UserID    uuid.NullUUID
	Action    string
	Env       string
	SecretKey string
	IP        sql.NullString
	TS        time.Time
}

// ErrVaultSecretNotFound is returned when a vault secret cannot be located for
// the given (team, env, key[, version]). Handlers translate this to 404, never
// 403, to avoid leaking the existence of secrets owned by other teams.
var ErrVaultSecretNotFound = errors.New("vault secret not found")

// CreateVaultSecret inserts a new row at version=nextVersion(team,env,key).
// Returns the created row. A unique-constraint violation on (team_id,env,key,version)
// is treated as a transient race and returned as-is.
func CreateVaultSecret(ctx context.Context, db *sql.DB, teamID uuid.UUID, env, key string, ciphertext []byte, createdBy uuid.NullUUID) (*VaultSecret, error) {
	// Determine next version atomically using SELECT … FROM vault_secrets
	// inside the INSERT (subselect avoids a separate round trip).
	row := db.QueryRowContext(ctx, `
		INSERT INTO vault_secrets (team_id, env, key, encrypted_value, version, created_by)
		VALUES (
			$1, $2, $3, $4,
			COALESCE((SELECT MAX(version) FROM vault_secrets WHERE team_id = $1 AND env = $2 AND key = $3), 0) + 1,
			$5
		)
		RETURNING id, team_id, env, key, encrypted_value, version, created_by, created_at, updated_at
	`, teamID, env, key, ciphertext, createdBy)

	s := &VaultSecret{}
	if err := row.Scan(&s.ID, &s.TeamID, &s.Env, &s.Key, &s.EncryptedValue, &s.Version, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, fmt.Errorf("models.CreateVaultSecret: %w", err)
	}
	return s, nil
}

// GetVaultSecretLatest returns the highest-version row scoped to (team,env,key).
// Returns ErrVaultSecretNotFound when the secret does not exist OR when team_id
// does not match (cross-team isolation: never leak existence).
func GetVaultSecretLatest(ctx context.Context, db *sql.DB, teamID uuid.UUID, env, key string) (*VaultSecret, error) {
	s := &VaultSecret{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, env, key, encrypted_value, version, created_by, created_at, updated_at
		FROM vault_secrets
		WHERE team_id = $1 AND env = $2 AND key = $3
		ORDER BY version DESC
		LIMIT 1
	`, teamID, env, key).Scan(
		&s.ID, &s.TeamID, &s.Env, &s.Key, &s.EncryptedValue, &s.Version, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrVaultSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetVaultSecretLatest: %w", err)
	}
	return s, nil
}

// GetVaultSecretVersion returns a specific version of (team,env,key).
// Returns ErrVaultSecretNotFound when no row matches.
func GetVaultSecretVersion(ctx context.Context, db *sql.DB, teamID uuid.UUID, env, key string, version int) (*VaultSecret, error) {
	s := &VaultSecret{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, env, key, encrypted_value, version, created_by, created_at, updated_at
		FROM vault_secrets
		WHERE team_id = $1 AND env = $2 AND key = $3 AND version = $4
	`, teamID, env, key, version).Scan(
		&s.ID, &s.TeamID, &s.Env, &s.Key, &s.EncryptedValue, &s.Version, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrVaultSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetVaultSecretVersion: %w", err)
	}
	return s, nil
}

// ListVaultKeys returns the distinct keys for (team,env). Values are never returned —
// handlers must never expose a list endpoint that includes ciphertext.
func ListVaultKeys(ctx context.Context, db *sql.DB, teamID uuid.UUID, env string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT key FROM vault_secrets
		WHERE team_id = $1 AND env = $2
		ORDER BY key ASC
	`, teamID, env)
	if err != nil {
		return nil, fmt.Errorf("models.ListVaultKeys: %w", err)
	}
	defer rows.Close()

	keys := make([]string, 0)
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("models.ListVaultKeys scan: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListVaultKeys rows: %w", err)
	}
	return keys, nil
}

// DeleteVaultSecret performs a HARD delete of every version for (team,env,key).
//
// Semantics chosen for MVP: hard delete simplifies access control (no "deleted but
// still readable" state to enforce) and keeps the table small. Audit history is
// preserved separately in vault_audit_log so the deletion event itself is durable.
//
// Returns (rowsDeleted, error). rowsDeleted == 0 when the secret does not exist
// for this team — handlers turn that into 404 (idempotent delete, no leak).
func DeleteVaultSecret(ctx context.Context, db *sql.DB, teamID uuid.UUID, env, key string) (int64, error) {
	res, err := db.ExecContext(ctx, `
		DELETE FROM vault_secrets
		WHERE team_id = $1 AND env = $2 AND key = $3
	`, teamID, env, key)
	if err != nil {
		return 0, fmt.Errorf("models.DeleteVaultSecret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("models.DeleteVaultSecret rows: %w", err)
	}
	return n, nil
}

// AppendVaultAudit inserts one audit row. Errors are logged by callers; auditing
// must never block a request from completing (best-effort).
func AppendVaultAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, userID uuid.NullUUID, action, env, key, ip string) error {
	var ipNS sql.NullString
	if ip != "" {
		ipNS = sql.NullString{String: ip, Valid: true}
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO vault_audit_log (team_id, user_id, action, env, secret_key, ip)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, teamID, userID, action, env, key, ipNS)
	if err != nil {
		return fmt.Errorf("models.AppendVaultAudit: %w", err)
	}
	return nil
}

// CountVaultKeysByTeam returns the number of distinct keys in the vault
// for a team. Used by handlers to enforce per-tier quotas.
func CountVaultKeysByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT key) FROM vault_secrets WHERE team_id = $1
	`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountVaultKeysByTeam: %w", err)
	}
	return n, nil
}

// CountVaultAudit returns the number of audit rows for (team, action, env, key).
// Used by tests to verify audit logging without exposing the full log surface.
func CountVaultAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, action, env, key string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vault_audit_log
		WHERE team_id = $1 AND action = $2 AND env = $3 AND secret_key = $4
	`, teamID, action, env, key).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountVaultAudit: %w", err)
	}
	return n, nil
}
