package models

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// EnvProduction is the default environment used when callers omit one.
// All migration-backfilled rows start at this value.
const EnvProduction = "production"

// envPattern restricts the env name to lowercase alphanumerics + dashes,
// 1–32 chars. Enforced at the model boundary so every caller (handlers,
// background jobs, internal endpoints) gets the same guarantee.
var envPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// NormalizeEnv coerces an empty env to EnvProduction (backwards compat) and
// validates the format. Returns (env, true) when valid, ("", false) otherwise.
func NormalizeEnv(env string) (string, bool) {
	if env == "" {
		return EnvProduction, true
	}
	if !envPattern.MatchString(env) {
		return "", false
	}
	return env, true
}

// Resource represents any provisioned resource (postgres, redis, mongodb, queue, webhook, storage).
type Resource struct {
	ID                 uuid.UUID
	TeamID             uuid.NullUUID
	Token              uuid.UUID
	ResourceType       string
	Name               sql.NullString
	ConnectionURL      sql.NullString // AES-256-GCM encrypted
	KeyPrefix          sql.NullString // provisioner key prefix (e.g. "pool_abc:") for Redis
	Tier               string
	Env                string // dev | staging | production | <custom>; defaults to "production"
	Fingerprint        sql.NullString
	CloudVendor        sql.NullString
	CountryCode        sql.NullString
	Status             string
	MigrationStatus    sql.NullString
	ExpiresAt          sql.NullTime
	StorageBytes       int64
	ProviderResourceID sql.NullString
	CreatedRequestID   sql.NullString
	CreatedAt          time.Time
}

// ErrResourceNotFound is returned when a resource lookup yields no rows.
type ErrResourceNotFound struct {
	Token string
}

func (e *ErrResourceNotFound) Error() string {
	return fmt.Sprintf("resource not found: %s", e.Token)
}

// CreateResourceParams holds fields for inserting a new resource.
type CreateResourceParams struct {
	TeamID           *uuid.UUID
	ResourceType     string
	Name             string
	Tier             string
	Env              string // empty string is normalised to EnvProduction
	Fingerprint      string
	CloudVendor      string
	CountryCode      string
	ExpiresAt        *time.Time
	CreatedRequestID string
}

// resourceColumns is the canonical list of columns selected by every read query.
// Centralising the column list (and the matching scan order in scanResource)
// makes it easy to add a new column without touching half a dozen functions.
const resourceColumns = `id, team_id, token, resource_type, name, connection_url, key_prefix, tier,
       env, fingerprint, cloud_vendor, country_code, status, migration_status,
       expires_at, storage_bytes, provider_resource_id, created_request_id, created_at`

// scanResource reads a single resources row in the order defined by resourceColumns.
func scanResource(row interface {
	Scan(dest ...any) error
}) (*Resource, error) {
	r := &Resource{}
	if err := row.Scan(
		&r.ID, &r.TeamID, &r.Token, &r.ResourceType, &r.Name, &r.ConnectionURL, &r.KeyPrefix,
		&r.Tier, &r.Env, &r.Fingerprint, &r.CloudVendor, &r.CountryCode, &r.Status,
		&r.MigrationStatus, &r.ExpiresAt, &r.StorageBytes, &r.ProviderResourceID, &r.CreatedRequestID, &r.CreatedAt,
	); err != nil {
		return nil, err
	}
	return r, nil
}

// CreateResource inserts a new resource row and returns it.
func CreateResource(ctx context.Context, db *sql.DB, p CreateResourceParams) (*Resource, error) {
	var teamID interface{}
	if p.TeamID != nil {
		teamID = *p.TeamID
	}
	var expiresAt interface{}
	if p.ExpiresAt != nil {
		expiresAt = *p.ExpiresAt
	}

	env := p.Env
	if env == "" {
		env = EnvProduction
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO resources
			(team_id, resource_type, name, tier, env, fingerprint, cloud_vendor, country_code, expires_at, created_request_id)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), $9, NULLIF($10,''))
		RETURNING `+resourceColumns,
		teamID, p.ResourceType, p.Name, p.Tier, env, p.Fingerprint, p.CloudVendor, p.CountryCode,
		expiresAt, p.CreatedRequestID,
	)

	r, err := scanResource(row)
	if err != nil {
		return nil, fmt.Errorf("models.CreateResource: %w", err)
	}
	return r, nil
}

// CountActiveResourcesByTeamAndType returns the number of active (non-deleted)
// resources of the given type owned by a team. Used for plan limit enforcement.
// Counts across ALL environments — plan limits apply per team, not per env.
func CountActiveResourcesByTeamAndType(ctx context.Context, db *sql.DB, teamID uuid.UUID, resourceType string) (int, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM resources WHERE team_id = $1 AND resource_type = $2 AND status = 'active'`,
		teamID, resourceType,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("models.CountActiveResourcesByTeamAndType: %w", err)
	}
	return count, nil
}

// GetResourceByToken fetches a resource by its public token UUID.
func GetResourceByToken(ctx context.Context, db *sql.DB, token uuid.UUID) (*Resource, error) {
	row := db.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM resources WHERE token = $1`, token)
	r, err := scanResource(row)
	if err == sql.ErrNoRows {
		return nil, &ErrResourceNotFound{Token: token.String()}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetResourceByToken: %w", err)
	}
	return r, nil
}

// GetActiveResourceByFingerprintType finds the most recent active anonymous resource
// of a specific type (e.g. "postgres", "redis", "mongodb") for a fingerprint.
// Used by Phase 2+ handlers when the rate-limit is hit to return the existing resource.
// Anonymous resources are always env=production — there is no env switch on the
// dedup path, since anonymous callers don't pick an env.
func GetActiveResourceByFingerprintType(ctx context.Context, db *sql.DB, fingerprint, resourceType string) (*Resource, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE fingerprint = $1
		  AND team_id IS NULL
		  AND resource_type = $2
		  AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`, fingerprint, resourceType)

	r, err := scanResource(row)
	if err == sql.ErrNoRows {
		return nil, &ErrResourceNotFound{Token: fingerprint}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetActiveResourceByFingerprintType: %w", err)
	}
	return r, nil
}

// GetAllActiveResourcesByFingerprint returns all active anonymous resources for a fingerprint.
// Used when issuing an onboarding JWT to include all services provisioned in one session.
func GetAllActiveResourcesByFingerprint(ctx context.Context, db *sql.DB, fingerprint string) ([]*Resource, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE fingerprint = $1
		  AND team_id IS NULL
		  AND status = 'active'
		ORDER BY created_at DESC
	`, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("models.GetAllActiveResourcesByFingerprint: %w", err)
	}
	defer rows.Close()

	var resources []*Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetAllActiveResourcesByFingerprint: scan: %w", err)
		}
		resources = append(resources, r)
	}
	return resources, rows.Err()
}

// SoftDeleteResource marks a resource status as 'deleted'.
func SoftDeleteResource(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE resources SET status = 'deleted' WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("models.SoftDeleteResource: %w", err)
	}
	return nil
}

// ListResourcesByTeam returns all active resources for a team across every environment.
// Equivalent to ListResourcesByTeamAndEnv with env="" — kept as the dashboard's
// "give me everything I own" entry point.
func ListResourcesByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*Resource, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE team_id = $1 AND status != 'deleted'
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListResourcesByTeam: %w", err)
	}
	defer rows.Close()

	var results []*Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("models.ListResourcesByTeam scan: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListResourcesByTeam rows: %w", err)
	}
	return results, nil
}

// ListResourcesByTeamAndEnv returns all active resources for a team filtered to
// a single environment. Empty env is normalised to "production" so callers that
// omit the param see prod resources by default.
func ListResourcesByTeamAndEnv(ctx context.Context, db *sql.DB, teamID uuid.UUID, env string) ([]*Resource, error) {
	if env == "" {
		env = EnvProduction
	}
	rows, err := db.QueryContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE team_id = $1 AND env = $2 AND status != 'deleted'
		ORDER BY created_at DESC
	`, teamID, env)
	if err != nil {
		return nil, fmt.Errorf("models.ListResourcesByTeamAndEnv: %w", err)
	}
	defer rows.Close()

	var results []*Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("models.ListResourcesByTeamAndEnv scan: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListResourcesByTeamAndEnv rows: %w", err)
	}
	return results, nil
}

// UpdateConnectionURL replaces the encrypted connection_url for a resource.
// Used exclusively by the credential rotation endpoint.
func UpdateConnectionURL(ctx context.Context, db *sql.DB, resourceID uuid.UUID, encryptedURL string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE resources SET connection_url = $1 WHERE id = $2
	`, encryptedURL, resourceID)
	if err != nil {
		return fmt.Errorf("models.UpdateConnectionURL: %w", err)
	}
	return nil
}

// UpdateKeyPrefix stores the provisioner-returned key prefix for a resource.
// For Redis resources this is the ACL-enforced key namespace (e.g. "pool_abc:").
// Called immediately after successful provisioning; used by the dedup path to
// return the correct prefix instead of guessing from the platform token.
func UpdateKeyPrefix(ctx context.Context, db *sql.DB, resourceID uuid.UUID, keyPrefix string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE resources SET key_prefix = $1 WHERE id = $2
	`, keyPrefix, resourceID)
	if err != nil {
		return fmt.Errorf("models.UpdateKeyPrefix: %w", err)
	}
	return nil
}

// UpdateProviderResourceID stores the backend-specific resource identifier (e.g. Neon project ID)
// for a resource. For local backend this will be an empty string (stored as NULL).
func UpdateProviderResourceID(ctx context.Context, db *sql.DB, resourceID uuid.UUID, providerResourceID string) error {
	var val interface{}
	if providerResourceID != "" {
		val = providerResourceID
	}
	_, err := db.ExecContext(ctx, `
		UPDATE resources SET provider_resource_id = $1 WHERE id = $2
	`, val, resourceID)
	if err != nil {
		return fmt.Errorf("models.UpdateProviderResourceID: %w", err)
	}
	return nil
}

// ElevateResourceTiersByTeam sets the tier of all active, permanent resources for a
// team to newTier. Called from the Razorpay upgrade webhook so that existing resources
// benefit from higher limits immediately — not just resources provisioned after the upgrade.
// Only affects permanent resources (expires_at IS NULL); anonymous TTL resources are excluded.
// Applies across ALL environments — an upgrade lifts dev, staging, and prod alike.
func ElevateResourceTiersByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID, newTier string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE resources
		SET tier = $1
		WHERE team_id = $2
		  AND status = 'active'
		  AND expires_at IS NULL
	`, newTier, teamID)
	if err != nil {
		return fmt.Errorf("models.ElevateResourceTiersByTeam: %w", err)
	}
	return nil
}

// SumStorageBytesByTeamAndType returns total storage_bytes for active resources of a given type for a team.
// Sums across ALL environments — storage quotas are per-team, not per-env.
func SumStorageBytesByTeamAndType(ctx context.Context, db *sql.DB, teamID uuid.UUID, resourceType string) (int64, error) {
	var total int64
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(storage_bytes), 0) FROM resources WHERE team_id = $1 AND resource_type = $2 AND status = 'active'`,
		teamID, resourceType,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("models.SumStorageBytesByTeamAndType: %w", err)
	}
	return total, nil
}

// ExpireAnonymousResources marks anonymous resources past their expires_at as 'deleted'.
// Returns the count of affected rows.
func ExpireAnonymousResources(ctx context.Context, db *sql.DB) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE resources
		SET status = 'deleted'
		WHERE team_id IS NULL
		  AND status = 'active'
		  AND expires_at IS NOT NULL
		  AND expires_at < now()
	`)
	if err != nil {
		return 0, fmt.Errorf("models.ExpireAnonymousResources: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
