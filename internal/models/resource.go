package models

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// EnvProduction names the "production" environment. Kept as a typed constant
// because several listing/promotion code paths still reference it by name.
// NOTE: this is no longer the default — see EnvDevelopment.
const EnvProduction = "production"

// EnvDevelopment is the default environment used when callers omit one.
// Migration 026 flipped the DB column DEFAULT to match.
//
// WHY (product directive, 2026-05-13): accidental no-env provisions should
// land in the lowest-stakes bucket. Defaulting to "production" silently
// merged experimental work with real prod state — the new default sends
// no-env callers to "development" so the mistake is recoverable. Callers
// that explicitly send env="production" continue to work unchanged
// (validated by envPattern; behaviour identical pre/post this change).
const EnvDevelopment = "development"

// EnvDefault is the canonical name for the default env. Use this in new code
// instead of referencing EnvDevelopment directly so a future change to the
// default doesn't ripple through every call site.
const EnvDefault = EnvDevelopment

// Canonical resource_type strings used by the handlers and model layer.
// Keep these in one place so callers performing same-type checks (e.g.
// the family-linking guard) can't drift on string capitalisation.
const (
	ResourceTypePostgres = "postgres"
	ResourceTypeRedis    = "redis"
	ResourceTypeMongoDB  = "mongodb"
	ResourceTypeQueue    = "queue"
	ResourceTypeStorage  = "storage"
	ResourceTypeWebhook  = "webhook"
	// ResourceTypeVector is a pgvector-enabled Postgres database. Same
	// underlying backend as ResourceTypePostgres — the row is just tagged
	// "vector" so audit feeds, the storage scanner, and tier-limit lookups
	// (plans.Registry.StorageLimitMB / ConnectionsLimit) can distinguish
	// vector workloads from plain Postgres without inspecting the schema.
	ResourceTypeVector = "vector"
)

// envPattern restricts the env name to lowercase alphanumerics + dashes,
// 1–32 chars. Enforced at the model boundary so every caller (handlers,
// background jobs, internal endpoints) gets the same guarantee.
var envPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// NormalizeEnv coerces an empty env to EnvDefault (currently "development") and
// validates the format. Returns (env, true) when valid, ("", false) otherwise.
//
// The default flipped from "production" → "development" in migration 026
// (2026-05-13) so accidental no-env provisions land in the lowest-stakes
// bucket. Callers that explicitly pass "production" continue to work
// unchanged.
func NormalizeEnv(env string) (string, bool) {
	if env == "" {
		return EnvDefault, true
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
	Env                string // dev | staging | production | <custom>; defaults to "development" (mig 026)
	Fingerprint        sql.NullString
	CloudVendor        sql.NullString
	CountryCode        sql.NullString
	Status             string
	MigrationStatus    sql.NullString
	ExpiresAt          sql.NullTime
	StorageBytes       int64
	ProviderResourceID sql.NullString
	CreatedRequestID   sql.NullString
	// ParentResourceID is the family root for env-twin resources. Nil for the
	// root row itself (the root's family id is its own ID). Added by
	// migration 018_resource_family.sql for slice 2 of env-aware deployments.
	ParentResourceID *uuid.UUID
	// PausedAt records when status flipped from 'active' to 'paused'. Cleared
	// (NULL) when the resource resumes. Added by migration 024.
	PausedAt sql.NullTime
	// LastSeenAt is stamped by the worker's resource_heartbeat job on a
	// successful probe. NULL means "never probed yet." Added by migration
	// 030_resource_heartbeat.
	LastSeenAt sql.NullTime
	// Degraded is set by the worker's resource_heartbeat job when a probe
	// fails. The dashboard reads this to surface "your Postgres is
	// unreachable" banners. Added by migration 030_resource_heartbeat.
	Degraded bool
	// DegradedReason carries the last probe error string. Cleared when
	// Degraded transitions back to false. Heartbeat truncates to 500 chars.
	// Added by migration 030_resource_heartbeat.
	DegradedReason sql.NullString
	// LastReconciledAt is stamped by the worker's provisioner_reconciler
	// to prevent tight-loop re-sweeping of the same pending row. Added by
	// migration 030_resource_heartbeat.
	LastReconciledAt sql.NullTime
	CreatedAt        time.Time
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
	Env              string // empty string is normalised to EnvDefault ("development")
	Fingerprint      string
	CloudVendor      string
	CountryCode      string
	ExpiresAt        *time.Time
	CreatedRequestID string
	// ParentResourceID links the new row into an existing env-twin family.
	// Nil = standalone (own family root). When non-nil the caller is
	// expected to have already enforced same-team + same-type (handlers
	// do that via ValidateFamilyParent before calling CreateResource).
	ParentResourceID *uuid.UUID
}

// resourceColumns is the canonical list of columns selected by every read query.
// Centralising the column list (and the matching scan order in scanResource)
// makes it easy to add a new column without touching half a dozen functions.
const resourceColumns = `id, team_id, token, resource_type, name, connection_url, key_prefix, tier,
       env, fingerprint, cloud_vendor, country_code, status, migration_status,
       expires_at, storage_bytes, provider_resource_id, created_request_id, parent_resource_id, paused_at,
       last_seen_at, degraded, degraded_reason, last_reconciled_at, created_at`

// scanResource reads a single resources row in the order defined by resourceColumns.
func scanResource(row interface {
	Scan(dest ...any) error
}) (*Resource, error) {
	r := &Resource{}
	var parentID uuid.NullUUID
	if err := row.Scan(
		&r.ID, &r.TeamID, &r.Token, &r.ResourceType, &r.Name, &r.ConnectionURL, &r.KeyPrefix,
		&r.Tier, &r.Env, &r.Fingerprint, &r.CloudVendor, &r.CountryCode, &r.Status,
		&r.MigrationStatus, &r.ExpiresAt, &r.StorageBytes, &r.ProviderResourceID, &r.CreatedRequestID,
		&parentID, &r.PausedAt,
		&r.LastSeenAt, &r.Degraded, &r.DegradedReason, &r.LastReconciledAt,
		&r.CreatedAt,
	); err != nil {
		return nil, err
	}
	if parentID.Valid {
		id := parentID.UUID
		r.ParentResourceID = &id
	}
	return r, nil
}

// StatusPending is the transient status a resource row carries between the
// CreateResource INSERT and the backend provision RPC + connection-URL
// persistence completing. CreateResource inserts this value explicitly (NOT
// the column DEFAULT 'active') so an api crash mid-provision leaves a
// 'pending' row the worker's provisioner_reconciler can sweep and recover or
// abandon. MarkResourceActive flips it to 'active' only after every backend
// + persistence step succeeds. See migration 057 + MR-P0-2 (BugBash 2026-05-20).
const StatusPending = "pending"

// StatusActive is the canonical "provisioned and usable" status.
const StatusActive = "active"

// CreateResource inserts a new resource row and returns it.
//
// MR-P0-2 (BugBash 2026-05-20): the row is inserted with status='pending', NOT
// the column DEFAULT 'active'. The caller MUST call MarkResourceActive after
// the backend provision RPC and all connection-URL / provider-resource-id
// persistence have succeeded. A row left 'pending' by an api crash mid-provision
// is recoverable by the worker's provisioner_reconciler (it sweeps
// WHERE status='pending'); a row stranded 'active' with connection_url=NULL was
// invisible to that sweep — the bug this two-phase lifecycle fixes.
func CreateResource(ctx context.Context, db *sql.DB, p CreateResourceParams) (*Resource, error) {
	var teamID interface{}
	if p.TeamID != nil {
		teamID = *p.TeamID
	}
	var expiresAt interface{}
	if p.ExpiresAt != nil {
		expiresAt = *p.ExpiresAt
	}
	var parentID interface{}
	if p.ParentResourceID != nil {
		parentID = *p.ParentResourceID
	}

	env := p.Env
	if env == "" {
		env = EnvDefault
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO resources
			(team_id, resource_type, name, tier, env, fingerprint, cloud_vendor, country_code, expires_at, created_request_id, parent_resource_id, status)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), $9, NULLIF($10,''), $11, $12)
		RETURNING `+resourceColumns,
		teamID, p.ResourceType, p.Name, p.Tier, env, p.Fingerprint, p.CloudVendor, p.CountryCode,
		expiresAt, p.CreatedRequestID, parentID, StatusPending,
	)

	r, err := scanResource(row)
	if err != nil {
		return nil, fmt.Errorf("models.CreateResource: %w", err)
	}
	return r, nil
}

// MarkResourceActive flips a resource from 'pending' → 'active'. It is the
// second phase of the MR-P0-2 two-phase provision lifecycle: the caller runs
// it ONLY after the backend provision RPC and every connection-URL /
// provider-resource-id persistence step has succeeded.
//
// The atomic `WHERE id=$1 AND status='pending'` guard means: a row already
// flipped (a duplicate call) is a no-op, and a row that some other path moved
// out of 'pending' (e.g. a reconciler abandon, a soft-delete) is NOT silently
// resurrected. Returns ErrResourceNotPending when no 'pending' row matched so
// the caller can treat that as a hard provision failure rather than reporting
// a success for a resource that is not in the expected state.
func MarkResourceActive(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE resources SET status = 'active' WHERE id = $1 AND status = 'pending'
	`, id)
	if err != nil {
		return fmt.Errorf("models.MarkResourceActive: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrResourceNotPending
	}
	return nil
}

// ErrResourceNotPending is returned by MarkResourceActive when the row is
// missing or not in 'pending' status — the caller asked to activate a row
// that is not in the expected mid-provision state.
var ErrResourceNotPending = fmt.Errorf("models: resource is not pending")

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
// of a specific type (e.g. "postgres", "redis", "mongodb") for a fingerprint AND
// environment. Used by Phase 2+ handlers when the rate-limit is hit to return the
// existing resource.
//
// The env filter (added P1-A 2026-05-17) prevents the dedup path from leaking a
// `production` resource to a caller that resolved to `development` — defeats
// migration 026 / CLAUDE.md convention #11 if omitted. Empty env is normalised to
// EnvDefault so callers stay consistent with CreateResource.
func GetActiveResourceByFingerprintType(ctx context.Context, db *sql.DB, fingerprint, resourceType, env string) (*Resource, error) {
	if env == "" {
		env = EnvDefault
	}
	row := db.QueryRowContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE fingerprint = $1
		  AND team_id IS NULL
		  AND resource_type = $2
		  AND env = $3
		  AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`, fingerprint, resourceType, env)

	r, err := scanResource(row)
	if err == sql.ErrNoRows {
		return nil, &ErrResourceNotFound{Token: fingerprint}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetActiveResourceByFingerprintType: %w", err)
	}
	return r, nil
}

// GetActiveResourceByFingerprint finds the most recent active anonymous resource of
// ANY type for a fingerprint+env. This is the cross-service fallback for the
// daily-cap dedup path (P1-A 2026-05-17): when the per-fingerprint provision cap
// (CLAUDE.md convention #6) is hit and no same-type resource exists, returning the
// most recent resource of any type keeps the abuser from minting a fresh resource
// for every new service type. Empty env is normalised to EnvDefault.
func GetActiveResourceByFingerprint(ctx context.Context, db *sql.DB, fingerprint, env string) (*Resource, error) {
	if env == "" {
		env = EnvDefault
	}
	row := db.QueryRowContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE fingerprint = $1
		  AND team_id IS NULL
		  AND env = $2
		  AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`, fingerprint, env)

	r, err := scanResource(row)
	if err == sql.ErrNoRows {
		return nil, &ErrResourceNotFound{Token: fingerprint}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetActiveResourceByFingerprint: %w", err)
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

// GetWebhookHMACSecret returns the optional shared secret used to verify
// X-Hub-Signature-256 on POST /webhook/receive/:token. NULL / empty
// secret = back-compat open receiver (signed traffic not required).
// Migration 042 added the column as nullable; if a stale schema is
// running the missing-column error is wrapped and returned so the
// caller can fail open.
func GetWebhookHMACSecret(ctx context.Context, db *sql.DB, resourceID uuid.UUID) (string, error) {
	var secret sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT hmac_secret FROM resources WHERE id = $1`, resourceID,
	).Scan(&secret)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("models.GetWebhookHMACSecret: %w", err)
	}
	if !secret.Valid {
		return "", nil
	}
	return secret.String, nil
}

// SetWebhookHMACSecret stores (or clears, when secret == "") the shared
// HMAC secret on a webhook resource. Empty string sets the column to
// NULL so the receiver falls back to its back-compat open mode.
//
// Caller is expected to have already authorized the mutation
// (resource ownership / tier gate); this function does no authz of
// its own.
func SetWebhookHMACSecret(ctx context.Context, db *sql.DB, resourceID uuid.UUID, secret string) error {
	var val any
	if secret != "" {
		val = secret
	} else {
		val = nil
	}
	_, err := db.ExecContext(ctx,
		`UPDATE resources SET hmac_secret = $1 WHERE id = $2`, val, resourceID,
	)
	if err != nil {
		return fmt.Errorf("models.SetWebhookHMACSecret: %w", err)
	}
	return nil
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

// ErrResourceNotActive is returned by PauseResource when the row exists but
// status != 'active'. The handler maps this to 409 conflict (already paused
// or terminal). Distinct error type so the handler doesn't have to second-guess
// whether a zero-rows-affected was idempotency or a missing row.
var ErrResourceNotActive = fmt.Errorf("models: resource is not active")

// ErrResourceNotPaused is the resume-side counterpart — caller asked to resume
// a row that isn't currently paused.
var ErrResourceNotPaused = fmt.Errorf("models: resource is not paused")

// PauseResource flips status from 'active' → 'paused' atomically and stamps
// paused_at. Returns ErrResourceNotActive when the row is missing or already
// not active (so the caller can return a typed 409 / 404 without a follow-up
// SELECT). The atomic WHERE status='active' guard makes concurrent pause
// requests idempotent: only the first one writes; the second observes
// ErrResourceNotActive.
//
// Caller is expected to have already verified team ownership and Pro+ tier —
// this function does no authz of its own.
func PauseResource(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE resources
		   SET status = 'paused', paused_at = now()
		 WHERE id = $1 AND status = 'active'
	`, id)
	if err != nil {
		return fmt.Errorf("models.PauseResource: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrResourceNotActive
	}
	return nil
}

// PauseAllTeamResources flips every active resource for a team to
// status='paused' in a single statement. Returns the number of rows
// affected. Idempotent — a second call after every row is already
// paused returns 0.
//
// Used by the internal terminate endpoint after the 7-day payment grace
// window expires. Pausing (not deleting) preserves the on-disk data —
// the customer can still recover if they pay within the retention
// window. Rows already in non-active states (paused, deleted, reaped)
// are left untouched.
//
// Caller is expected to have already established that the team really
// is past its grace window — this function does no policy enforcement.
func PauseAllTeamResources(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE resources
		   SET status = 'paused', paused_at = now()
		 WHERE team_id = $1 AND status = 'active'
	`, teamID)
	if err != nil {
		return 0, fmt.Errorf("models.PauseAllTeamResources: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("models.PauseAllTeamResources rows_affected: %w", err)
	}
	return n, nil
}

// ResumeResource flips status from 'paused' → 'active' and clears paused_at.
// Returns ErrResourceNotPaused when the row is missing or not currently paused
// (mirror of PauseResource). The connection_url is preserved unchanged — the
// caller's credentials remain valid.
func ResumeResource(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE resources
		   SET status = 'active', paused_at = NULL
		 WHERE id = $1 AND status = 'paused'
	`, id)
	if err != nil {
		return fmt.Errorf("models.ResumeResource: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrResourceNotPaused
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
// a single environment. Empty env is normalised to EnvDefault ("development")
// so callers that omit the param see the default env's resources — matches
// the post-migration-026 default for /db/new and friends.
func ListResourcesByTeamAndEnv(ctx context.Context, db *sql.DB, teamID uuid.UUID, env string) ([]*Resource, error) {
	if env == "" {
		env = EnvDefault
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

// ElevateResourceTiersByTeam sets the tier of every active or paused team-owned
// resource to newTier and clears its TTL (expires_at = NULL).
//
// Called from the Razorpay subscription.charged webhook. Picks up two cases:
//   1) Resources that are already permanent (expires_at IS NULL) — a hobby
//      user upgrading to pro: lift their existing resources to the new tier.
//   2) Resources still on anonymous TTL (expires_at > now()) — a freshly
//      claimed user paying for the first time: clear the TTL + set tier.
// This is the second half of "pay from day one": claim transfers team
// ownership but does NOT clear the TTL or change tier. Only payment does.
//
// Paused rows are included so that a terminated-then-reinstated team's paused
// resources are promoted to the new tier. Without this, a team whose resources
// were paused by the payment-grace terminator (tier→free) and who then
// re-subscribed would have their resources stuck at the wrong tier, blocking
// the resume flow which re-derives access rights from the resource tier.
//
// expires_at > now() guards a race with the reaper — we don't resurrect a
// resource whose TTL already elapsed.
// Applies across all environments — one upgrade lifts dev, staging, and prod.
func ElevateResourceTiersByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID, newTier string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE resources
		SET tier = $1, expires_at = NULL
		WHERE team_id = $2
		  AND status IN ('active', 'paused')
		  AND (expires_at IS NULL OR expires_at > now())
	`, newTier, teamID)
	if err != nil {
		return fmt.Errorf("models.ElevateResourceTiersByTeam: %w", err)
	}
	return nil
}

// SumStorageBytesByTeamAndType returns total storage_bytes for active or paused
// resources of a given type for a team. Paused resources STILL count toward
// storage limits — pausing stops billing for the slot but the on-disk data is
// preserved, so the storage cap is what prevents pause-and-bloat. Deleted /
// expired rows are excluded.
//
// Sums across ALL environments — storage quotas are per-team, not per-env.
func SumStorageBytesByTeamAndType(ctx context.Context, db *sql.DB, teamID uuid.UUID, resourceType string) (int64, error) {
	var total int64
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(storage_bytes), 0)
		   FROM resources
		  WHERE team_id = $1
		    AND resource_type = $2
		    AND status IN ('active', 'paused')`,
		teamID, resourceType,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("models.SumStorageBytesByTeamAndType: %w", err)
	}
	return total, nil
}

// SumStorageBytesByFingerprintAndType returns total storage_bytes for active or
// paused anonymous resources (team_id IS NULL) of a given type for a fingerprint.
// This is the anonymous-tier analogue of SumStorageBytesByTeamAndType (P1-B
// 2026-05-17): the anonymous storage byte cap (e.g. 10MB) has to be summed across
// a fingerprint's rows since there is no team to scope to. storage_bytes is
// populated by the worker's object-store scanner; on a brand-new bucket it is 0
// until the first scan, so this cap lags real usage by one worker tick.
func SumStorageBytesByFingerprintAndType(ctx context.Context, db *sql.DB, fingerprint, resourceType string) (int64, error) {
	var total int64
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(storage_bytes), 0)
		   FROM resources
		  WHERE fingerprint = $1
		    AND team_id IS NULL
		    AND resource_type = $2
		    AND status IN ('active', 'paused')`,
		fingerprint, resourceType,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("models.SumStorageBytesByFingerprintAndType: %w", err)
	}
	return total, nil
}

// ExpireAnonymousResources marks resources past their expires_at as 'deleted'.
//
// Despite the name, this covers TWO equivalent TTL policies that share the
// 24h "pay from day one" mechanic:
//
//  1. tier='anonymous': pre-claim (team_id IS NULL). Classic case — the
//     agent never claimed the token, the 24h grace period ran out.
//  2. tier='free': claimed-but-unpaid (team_id IS NOT NULL, no subscription).
//     The user claimed the resource on the dashboard but never paid; same
//     24h fate. The Razorpay subscription.charged webhook clears expires_at
//     before the reaper sees it, so any free row whose expires_at is in the
//     past genuinely failed to convert.
//
// Returns the count of affected rows.
func ExpireAnonymousResources(ctx context.Context, db *sql.DB) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE resources
		SET status = 'deleted'
		WHERE status = 'active'
		  AND expires_at IS NOT NULL
		  AND expires_at < now()
		  AND (
		    (team_id IS NULL AND tier = 'anonymous')
		    OR tier = 'free'
		  )
	`)
	if err != nil {
		return 0, fmt.Errorf("models.ExpireAnonymousResources: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
