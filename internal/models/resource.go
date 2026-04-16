package models

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

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
	Fingerprint      string
	CloudVendor      string
	CountryCode      string
	ExpiresAt        *time.Time
	CreatedRequestID string
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

	r := &Resource{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO resources
			(team_id, resource_type, name, tier, fingerprint, cloud_vendor, country_code, expires_at, created_request_id)
		VALUES ($1, $2, NULLIF($3,''), $4, NULLIF($5,''), NULLIF($6,''), NULLIF($7,''), $8, NULLIF($9,''))
		RETURNING id, team_id, token, resource_type, name, connection_url, key_prefix, tier,
		          fingerprint, cloud_vendor, country_code, status, migration_status,
		          expires_at, storage_bytes, created_request_id, created_at
	`, teamID, p.ResourceType, p.Name, p.Tier, p.Fingerprint, p.CloudVendor, p.CountryCode,
		expiresAt, p.CreatedRequestID,
	).Scan(
		&r.ID, &r.TeamID, &r.Token, &r.ResourceType, &r.Name, &r.ConnectionURL, &r.KeyPrefix,
		&r.Tier, &r.Fingerprint, &r.CloudVendor, &r.CountryCode, &r.Status,
		&r.MigrationStatus, &r.ExpiresAt, &r.StorageBytes, &r.CreatedRequestID, &r.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreateResource: %w", err)
	}
	return r, nil
}

// CountActiveResourcesByTeamAndType returns the number of active (non-deleted)
// resources of the given type owned by a team. Used for plan limit enforcement.
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
	r := &Resource{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, token, resource_type, name, connection_url, key_prefix, tier,
		       fingerprint, cloud_vendor, country_code, status, migration_status,
		       expires_at, storage_bytes, provider_resource_id, created_request_id, created_at
		FROM resources WHERE token = $1
	`, token).Scan(
		&r.ID, &r.TeamID, &r.Token, &r.ResourceType, &r.Name, &r.ConnectionURL, &r.KeyPrefix,
		&r.Tier, &r.Fingerprint, &r.CloudVendor, &r.CountryCode, &r.Status,
		&r.MigrationStatus, &r.ExpiresAt, &r.StorageBytes, &r.ProviderResourceID, &r.CreatedRequestID, &r.CreatedAt,
	)
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
func GetActiveResourceByFingerprintType(ctx context.Context, db *sql.DB, fingerprint, resourceType string) (*Resource, error) {
	r := &Resource{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, token, resource_type, name, connection_url, key_prefix, tier,
		       fingerprint, cloud_vendor, country_code, status, migration_status,
		       expires_at, storage_bytes, created_request_id, created_at
		FROM resources
		WHERE fingerprint = $1
		  AND team_id IS NULL
		  AND resource_type = $2
		  AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`, fingerprint, resourceType).Scan(
		&r.ID, &r.TeamID, &r.Token, &r.ResourceType, &r.Name, &r.ConnectionURL, &r.KeyPrefix,
		&r.Tier, &r.Fingerprint, &r.CloudVendor, &r.CountryCode, &r.Status,
		&r.MigrationStatus, &r.ExpiresAt, &r.StorageBytes, &r.CreatedRequestID, &r.CreatedAt,
	)
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
		SELECT id, team_id, token, resource_type, name, connection_url, key_prefix, tier,
		       fingerprint, cloud_vendor, country_code, status, migration_status,
		       expires_at, storage_bytes, created_request_id, created_at
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
		r := &Resource{}
		if err := rows.Scan(
			&r.ID, &r.TeamID, &r.Token, &r.ResourceType, &r.Name, &r.ConnectionURL, &r.KeyPrefix,
			&r.Tier, &r.Fingerprint, &r.CloudVendor, &r.CountryCode, &r.Status,
			&r.MigrationStatus, &r.ExpiresAt, &r.StorageBytes, &r.CreatedRequestID, &r.CreatedAt,
		); err != nil {
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

// ListResourcesByTeam returns all active resources for a team.
func ListResourcesByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*Resource, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, token, resource_type, name, connection_url, key_prefix, tier,
		       fingerprint, cloud_vendor, country_code, status, migration_status,
		       expires_at, storage_bytes, created_request_id, created_at
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
		r := &Resource{}
		if err := rows.Scan(
			&r.ID, &r.TeamID, &r.Token, &r.ResourceType, &r.Name, &r.ConnectionURL, &r.KeyPrefix,
			&r.Tier, &r.Fingerprint, &r.CloudVendor, &r.CountryCode, &r.Status,
			&r.MigrationStatus, &r.ExpiresAt, &r.StorageBytes, &r.CreatedRequestID, &r.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("models.ListResourcesByTeam scan: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListResourcesByTeam rows: %w", err)
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

