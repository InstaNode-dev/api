package models

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Deployment represents a user app hosted on instant.dev infrastructure (Phase 6).
//
// Private / AllowedIPs back the private-deploy feature (migration 020). When
// Private is true, the underlying k8s Ingress carries an
// nginx.ingress.kubernetes.io/whitelist-source-range annotation. AllowedIPs
// is stored as a comma-joined TEXT column (not JSONB) — keeps the model's
// scalar-friendly shape and matches the Ingress annotation format byte-for-byte.
//
// NotifyWebhook / NotifyWebhookSecret / NotifyState / NotifyAttempts back the
// deploy-webhook-notify feature (migration 026). When NotifyWebhook is set,
// the worker POSTs to it once the deploy reaches a terminal state — healthy
// or failed. NotifyWebhookSecret (when supplied) is the HMAC-SHA256 signing
// key for the X-InstaNode-Signature header; it is AES-256-GCM encrypted at
// rest using the platform AES_KEY (same shape as resources.connection_url).
// The model surfaces the ENCRYPTED form — the worker decrypts at dispatch
// time so plaintext never lands in the deployments row.
type Deployment struct {
	ID                  uuid.UUID
	TeamID              uuid.UUID
	ResourceID          uuid.NullUUID
	AppID               string
	ProviderID          string // k8s Deployment name, e.g. "app-{app_id}"
	Status              string // building | deploying | healthy | failed | stopped
	AppURL              string
	EnvVars             map[string]string
	Port                int
	Tier                string
	Env                 string // dev | staging | production | <custom>; defaults to "production"
	Private             bool
	AllowedIPs          []string // parsed from the comma-joined `allowed_ips` column
	NotifyWebhook       string   // user-supplied https:// URL; empty when unset
	NotifyWebhookSecret string   // AES-256-GCM ciphertext of the HMAC key; empty when unset
	NotifyState         string   // 'unset' | 'pending' | 'sent' | 'failed'
	NotifyAttempts      int      // dispatch retry counter (worker bumps on 5xx/network)
	ErrorMessage        string
	// TTL fields (Wave FIX-J — migration 045).
	//
	// ExpiresAt: when the deploy auto-expires. Zero (sql NULL) means
	// permanent. Set by CreateDeployment when ttl_policy='auto_24h' (default)
	// to now()+24h. SetDeploymentTTL and MakeDeploymentPermanent mutate this
	// field after the row is created.
	//
	// TTLPolicy: 'auto_24h' (server default) | 'permanent' (user opted in
	// to keeping it forever) | 'custom' (user set a non-24h TTL via POST
	// /deployments/:id/ttl). The deployment_expirer worker only deletes
	// rows where ttl_policy != 'permanent' AND expires_at < now().
	//
	// RemindersSent: 0..6, count of reminder emails sent so far. The
	// deployment_reminder worker advances one step per 2h tick, starting
	// at T-12h before expires_at.
	//
	// LastReminderAt: wall-clock of the most recent reminder dispatched.
	// Combined with RemindersSent forms the CAS guard that prevents
	// duplicate sends inside the 60s tick window.
	ExpiresAt      sql.NullTime
	TTLPolicy      string
	RemindersSent  int
	LastReminderAt sql.NullTime
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// CreateDeploymentParams holds fields for inserting a new deployment row.
//
// NotifyWebhook (when non-empty) must already be a validated https:// URL
// pointing at a publicly routable hostname (SSRF-checked by the handler
// before this struct is constructed). NotifyWebhookSecret (when non-empty)
// must already be AES-256-GCM ciphertext — this layer does no crypto.
// When NotifyWebhook is empty, NotifyState defaults to 'unset' at the DB
// layer; when non-empty, the INSERT sets it to 'pending' so the worker
// scan picks it up the moment the deploy reaches a terminal state.
type CreateDeploymentParams struct {
	TeamID              uuid.UUID
	ResourceID          *uuid.UUID
	AppID               string
	Port                int
	Tier                string
	Env                 string // empty string is normalised to EnvDefault ("development")
	EnvVars             map[string]string
	Private             bool
	AllowedIPs          []string // each entry must already be a valid IP or CIDR
	NotifyWebhook       string   // empty = no webhook; non-empty = validated https URL
	NotifyWebhookSecret string   // empty = no HMAC; non-empty = AES ciphertext
	// TTLPolicy chooses the lifecycle for this deploy. Valid values are
	// "auto_24h" (default — expires_at set to now()+24h), "permanent"
	// (expires_at = NULL, never auto-expires), or "custom" (caller sets
	// expires_at via the TTLHours field). Empty defaults to "auto_24h".
	//
	// Per-tier override: anonymous tier is FORCED to auto_24h regardless
	// of caller intent; the handler enforces that before populating this
	// struct, so by the time we hit the DB we trust the caller.
	TTLPolicy string
	// TTLHours, when TTLPolicy="custom", sets expires_at = now()+TTLHours.
	// Ignored for auto_24h (always 24h) and permanent (NULL). Range
	// 1..8760 (1h..1y) — the handler enforces the bound BEFORE this struct
	// is constructed; the model trusts the input.
	TTLHours int
}

// DeployTTLPolicyAuto24h is the default TTL policy — auto-expire after 24h.
const DeployTTLPolicyAuto24h = "auto_24h"

// DeployTTLPolicyPermanent disables TTL — the deploy never auto-expires.
const DeployTTLPolicyPermanent = "permanent"

// DeployTTLPolicyCustom is a user-chosen non-24h TTL set via POST /deployments/:id/ttl.
const DeployTTLPolicyCustom = "custom"

// ErrDeploymentNotFound is returned when a deployment lookup yields no rows.
type ErrDeploymentNotFound struct {
	ID string
}

func (e *ErrDeploymentNotFound) Error() string {
	return fmt.Sprintf("deployment not found: %s", e.ID)
}

// deploymentColumns is the canonical column list shared by all deployment SELECTs.
// notify_webhook / notify_webhook_secret / notify_state / notify_attempts
// (migration 026) are appended at the end so existing column-order assumptions
// in this file's scanDeployment continue to compile-fail loudly on drift.
const deploymentColumns = `id, team_id, resource_id, app_id, provider_id, status, app_url,
       env_vars, port, tier, env, private, allowed_ips, error_message, created_at, updated_at,
       notify_webhook, notify_webhook_secret, notify_state, notify_attempts,
       expires_at, ttl_policy, reminders_sent, last_reminder_at`

// scanDeployment reads a single deployments row into a Deployment struct.
// env_vars is stored as JSONB; error_message, provider_id, and app_url are nullable.
// allowed_ips is a comma-joined TEXT column — empty string parses to a nil slice.
func scanDeployment(row interface {
	Scan(dest ...any) error
}) (*Deployment, error) {
	d := &Deployment{}
	var envVarsRaw []byte
	var providerID, appURL, errorMessage sql.NullString
	var resourceID uuid.NullUUID
	var allowedIPsRaw string
	// migration 026: notify_webhook / notify_webhook_secret are nullable
	// (legacy rows have NULL); notify_state defaults to 'unset' (NOT NULL)
	// and notify_attempts defaults to 0 (NOT NULL).
	var notifyWebhook, notifyWebhookSecret sql.NullString

	if err := row.Scan(
		&d.ID, &d.TeamID, &resourceID, &d.AppID,
		&providerID, &d.Status, &appURL,
		&envVarsRaw, &d.Port, &d.Tier, &d.Env,
		&d.Private, &allowedIPsRaw,
		&errorMessage,
		&d.CreatedAt, &d.UpdatedAt,
		&notifyWebhook, &notifyWebhookSecret, &d.NotifyState, &d.NotifyAttempts,
		// migration 045 (Wave FIX-J): nullable expires_at + last_reminder_at,
		// NOT NULL ttl_policy + reminders_sent. Order MUST match the trailing
		// 4 columns appended in deploymentColumns above.
		&d.ExpiresAt, &d.TTLPolicy, &d.RemindersSent, &d.LastReminderAt,
	); err != nil {
		return nil, err
	}

	d.ResourceID = resourceID
	d.ProviderID = providerID.String
	d.AppURL = appURL.String
	d.ErrorMessage = errorMessage.String
	d.AllowedIPs = splitAllowedIPs(allowedIPsRaw)
	d.NotifyWebhook = notifyWebhook.String
	d.NotifyWebhookSecret = notifyWebhookSecret.String

	if len(envVarsRaw) > 0 {
		if err := json.Unmarshal(envVarsRaw, &d.EnvVars); err != nil {
			return nil, fmt.Errorf("unmarshal env_vars: %w", err)
		}
	}
	if d.EnvVars == nil {
		d.EnvVars = make(map[string]string)
	}

	return d, nil
}

// splitAllowedIPs parses the comma-joined `allowed_ips` column into a slice.
// Empty string returns nil so JSON marshalling emits `null`/omits the field
// for legacy rows instead of `[]`. Whitespace around entries is trimmed.
func splitAllowedIPs(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// joinAllowedIPs is the inverse of splitAllowedIPs — produces the canonical
// comma-joined form used by the DB column AND the nginx whitelist-source-range
// annotation. Exported for the k8s compute provider so it doesn't have to
// know the storage convention.
func JoinAllowedIPs(ips []string) string {
	return strings.Join(ips, ",")
}

// CreateDeployment inserts a new deployment row and returns it.
func CreateDeployment(ctx context.Context, db dbExecutor, p CreateDeploymentParams) (*Deployment, error) {
	var resourceID interface{}
	if p.ResourceID != nil {
		resourceID = *p.ResourceID
	}

	port := p.Port
	if port == 0 {
		port = 8080
	}

	envVars := p.EnvVars
	if envVars == nil {
		envVars = make(map[string]string)
	}
	envVarsJSON, err := json.Marshal(envVars)
	if err != nil {
		return nil, fmt.Errorf("models.CreateDeployment: marshal env_vars: %w", err)
	}

	env := p.Env
	if env == "" {
		env = EnvDefault
	}

	// allowed_ips is stored as a comma-joined string — keeps it identical to
	// the form the nginx whitelist-source-range annotation already requires.
	allowedIPs := JoinAllowedIPs(p.AllowedIPs)

	// notify_state lifecycle (migration 026):
	//   no URL supplied  → 'unset'   (column default, but explicit here so
	//                                  the contract is visible in the query)
	//   URL supplied     → 'pending' (worker scan picks it up the moment
	//                                  the deploy reaches a terminal state)
	notifyState := "unset"
	var notifyWebhook, notifyWebhookSecret interface{}
	if p.NotifyWebhook != "" {
		notifyState = "pending"
		notifyWebhook = p.NotifyWebhook
		if p.NotifyWebhookSecret != "" {
			notifyWebhookSecret = p.NotifyWebhookSecret
		}
	}

	// TTL policy resolution (migration 045 — Wave FIX-J). Empty defaults to
	// auto_24h. The handler is responsible for forcing 'auto_24h' on the
	// anonymous tier; this layer trusts the input. We compute expires_at
	// here (rather than letting the DB compute it) so the value round-trips
	// through scanDeployment without an extra refresh query.
	ttlPolicy := p.TTLPolicy
	if ttlPolicy == "" {
		ttlPolicy = DeployTTLPolicyAuto24h
	}
	var expiresAt interface{} // NULL = permanent
	switch ttlPolicy {
	case DeployTTLPolicyAuto24h:
		expiresAt = time.Now().UTC().Add(24 * time.Hour)
	case DeployTTLPolicyCustom:
		hours := p.TTLHours
		if hours < 1 {
			hours = 24
		}
		expiresAt = time.Now().UTC().Add(time.Duration(hours) * time.Hour)
	case DeployTTLPolicyPermanent:
		expiresAt = nil
	default:
		// Unknown policy — fall back to auto_24h (defensive; the handler
		// validates ahead of this so we should never reach this branch).
		ttlPolicy = DeployTTLPolicyAuto24h
		expiresAt = time.Now().UTC().Add(24 * time.Hour)
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO deployments
			(team_id, resource_id, app_id, port, tier, env, env_vars, private, allowed_ips,
			 notify_webhook, notify_webhook_secret, notify_state,
			 expires_at, ttl_policy)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING `+deploymentColumns,
		p.TeamID, resourceID, p.AppID, port, p.Tier, env, envVarsJSON,
		p.Private, allowedIPs,
		notifyWebhook, notifyWebhookSecret, notifyState,
		expiresAt, ttlPolicy)

	d, err := scanDeployment(row)
	if err != nil {
		return nil, fmt.Errorf("models.CreateDeployment: %w", err)
	}
	return d, nil
}

// GetDeploymentByAppID fetches a deployment by its app_id slug (the short public token).
// app_id is unique across all envs — the same app name in dev vs prod must use distinct
// app_ids (the deploy handler generates a fresh one per call).
func GetDeploymentByAppID(ctx context.Context, db *sql.DB, appID string) (*Deployment, error) {
	row := db.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM deployments WHERE app_id = $1`, appID)

	d, err := scanDeployment(row)
	if err == sql.ErrNoRows {
		return nil, &ErrDeploymentNotFound{ID: appID}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentByAppID: %w", err)
	}
	return d, nil
}

// GetDeploymentByID fetches a deployment by primary key UUID.
func GetDeploymentByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*Deployment, error) {
	row := db.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM deployments WHERE id = $1`, id)

	d, err := scanDeployment(row)
	if err == sql.ErrNoRows {
		return nil, &ErrDeploymentNotFound{ID: id.String()}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentByID: %w", err)
	}
	return d, nil
}

// GetDeploymentsByTeam returns the user-visible deployments for a team across
// every environment, ordered by creation time descending. Terminal rows
// (deploymentVisibleClause — 'deleted' / 'expired') are excluded so the list
// reflects only deployments the user can still act on. This is the canonical
// "user-visible deployments" row set; GET /api/v1/billing/usage counts the
// exact same set via CountVisibleDeploymentsByTeam.
func GetDeploymentsByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*Deployment, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE team_id = $1 AND `+deploymentVisibleClause+`
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeam: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetDeploymentsByTeam scan: %w", err)
		}
		results = append(results, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeam rows: %w", err)
	}
	return results, nil
}

// GetDeploymentsByTeamAndEnv returns the user-visible deployments for a team
// scoped to a single environment. Empty env is normalised to EnvDefault
// ("development") to match the post-migration-026 default for POST /deploy/new.
// Terminal rows are excluded via deploymentVisibleClause, the same filter
// GetDeploymentsByTeam applies, so a ?env= filter cannot drift from the
// unfiltered list.
func GetDeploymentsByTeamAndEnv(ctx context.Context, db *sql.DB, teamID uuid.UUID, env string) ([]*Deployment, error) {
	if env == "" {
		env = EnvDefault
	}
	rows, err := db.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE team_id = $1 AND env = $2 AND `+deploymentVisibleClause+`
		ORDER BY created_at DESC
	`, teamID, env)
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeamAndEnv: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetDeploymentsByTeamAndEnv scan: %w", err)
		}
		results = append(results, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeamAndEnv rows: %w", err)
	}
	return results, nil
}

// FindActiveDeploymentByTeamEnvName looks up the most recent non-terminal
// deployment for (team, env, name) — the lookup key for the POST /deploy/new
// `redeploy=true` in-place-update path.
//
// Selection rules:
//   - status filter: includes 'building', 'deploying', 'healthy', 'failed'
//     (the rows a caller can legitimately redeploy in place). 'deleted' and
//     'expired' (the terminal set per terminalDeploymentStatusesSQL) are
//     excluded so a redeploy never resurrects a reaped row. 'stopped' is
//     also excluded: a paused deploy must be explicitly restarted via its
//     own flow, not silently replaced.
//   - the human-readable name is stored in env_vars.JSONB under the
//     "_name" key (see handlers.deployNameEnvKey). We compare the JSONB
//     extraction (env_vars->>'_name') directly so the lookup matches what
//     the dashboard / list endpoint surfaces as `name`.
//   - ORDER BY created_at DESC LIMIT 1: when a name has been reused across
//     multiple deploy rows (e.g. a failed build then a healthy retry), we
//     target the most recent one — same heuristic an operator would apply.
//
// Returns (nil, sql.ErrNoRows) when no matching row exists. The handler
// translates that to a 404 with the canonical agent_action envelope.
func FindActiveDeploymentByTeamEnvName(ctx context.Context, db *sql.DB, teamID uuid.UUID, env, name string) (*Deployment, error) {
	if env == "" {
		env = EnvDefault
	}
	row := db.QueryRowContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE team_id = $1
		  AND env = $2
		  AND env_vars->>'_name' = $3
		  AND status IN ('building', 'deploying', 'healthy', 'failed')
		ORDER BY created_at DESC
		LIMIT 1
	`, teamID, env, name)
	d, err := scanDeployment(row)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("models.FindActiveDeploymentByTeamEnvName: %w", err)
	}
	return d, nil
}

// UpdateDeploymentStatus updates the status and optional error_message for a deployment.
// updated_at is set to now() by the database.
func UpdateDeploymentStatus(ctx context.Context, db *sql.DB, id uuid.UUID, status, errorMessage string) error {
	var errMsg interface{}
	if errorMessage != "" {
		errMsg = errorMessage
	}
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET status = $1, error_message = $2, updated_at = now()
		WHERE id = $3
	`, status, errMsg, id)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentStatus: %w", err)
	}
	return nil
}

// UpdateDeploymentProviderID records the k8s Deployment name and the resolved app URL
// after the k8s Deployment object has been successfully created.
// updated_at is set to now() by the database.
func UpdateDeploymentProviderID(ctx context.Context, db *sql.DB, id uuid.UUID, providerID, appURL string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET provider_id = $1, app_url = $2, updated_at = now()
		WHERE id = $3
	`, providerID, appURL, id)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentProviderID: %w", err)
	}
	return nil
}

// UpdateDeploymentEnvVars replaces the env_vars JSONB blob for a deployment.
// updated_at is set to now() by the database.
func UpdateDeploymentEnvVars(ctx context.Context, db *sql.DB, id uuid.UUID, envVars map[string]string) error {
	if envVars == nil {
		envVars = make(map[string]string)
	}
	envVarsJSON, err := json.Marshal(envVars)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentEnvVars: marshal: %w", err)
	}
	_, err = db.ExecContext(ctx, `
		UPDATE deployments
		SET env_vars = $1, updated_at = now()
		WHERE id = $2
	`, envVarsJSON, id)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentEnvVars: %w", err)
	}
	return nil
}

// UpdateDeploymentAccessControl replaces the private flag and allowed_ips list
// on an existing deployment row. Single-row UPDATE — no aggregation,
// no caching concerns. Backs PATCH /api/v1/deployments/:id.
//
// allowedIPs uses REPLACE semantics (matches the storage column shape — the
// row holds the canonical comma-joined list). Empty allowedIPs slice persists
// as an empty string in the column, which is what splitAllowedIPs reads back
// as nil — symmetric round-trip with CreateDeployment's behaviour.
//
// Caller is responsible for having validated the slice (each entry a valid
// IP or CIDR, len ≤ maxAllowedIPs, non-empty when private=true). This
// function trusts its inputs.
func UpdateDeploymentAccessControl(ctx context.Context, db *sql.DB, id uuid.UUID, private bool, allowedIPs []string) error {
	allowed := JoinAllowedIPs(allowedIPs)
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET private = $1, allowed_ips = $2, updated_at = now()
		WHERE id = $3
	`, private, allowed, id)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentAccessControl: %w", err)
	}
	return nil
}

// DeleteDeployment hard-deletes a deployment row.
// Compute resources are real money — no soft-delete; callers must deprovision
// the k8s Deployment before calling this.
func DeleteDeployment(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM deployments WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("models.DeleteDeployment: %w", err)
	}
	return nil
}

// MakeDeploymentPermanent sets expires_at = NULL and ttl_policy = 'permanent'.
// Backs POST /api/v1/deployments/:id/make-permanent. Idempotent — calling
// twice is a no-op (the second UPDATE still touches updated_at, which is
// fine for auditing the "kept" event).
//
// Wave FIX-J: this is the explicit opt-in that prevents the
// deployment_expirer worker from sweeping the row. Once made permanent the
// row only goes away when the user explicitly DELETEs it.
func MakeDeploymentPermanent(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET expires_at = NULL, ttl_policy = 'permanent', updated_at = now()
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("models.MakeDeploymentPermanent: %w", err)
	}
	return nil
}

// ElevateDeploymentTiersByTeam promotes every non-terminal deployment owned by
// the team to newTier and clears the anonymous 24h TTL. Called from the
// Razorpay subscription.charged webhook (via UpgradeTeamAllTiers) and from the
// dev-only /internal/set-tier endpoint.
//
// The query intentionally avoids filtering on the current tier value — both
// anonymous and free-tier deployments must be lifted on first payment. Terminal
// statuses ('deleted', 'expired') are excluded because they no longer consume
// infrastructure.
//
// reminders_sent / last_reminder_at are reset so the full 6-email warning cycle
// fires again if the newly-permanent deployment is ever given a custom TTL later.
func ElevateDeploymentTiersByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID, newTier string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET tier             = $1,
		    expires_at       = NULL,
		    ttl_policy       = 'permanent',
		    reminders_sent   = 0,
		    last_reminder_at = NULL,
		    updated_at       = now()
		WHERE team_id = $2
		  AND `+deploymentVisibleClause+`
	`, newTier, teamID)
	if err != nil {
		return fmt.Errorf("models.ElevateDeploymentTiersByTeam: %w", err)
	}
	return nil
}

// SetDeploymentTTL sets expires_at = now()+hours and ttl_policy = 'custom'.
// Backs POST /api/v1/deployments/:id/ttl. Callers must validate hours
// (1..8760) BEFORE invoking this — the model trusts its input. Resets
// reminders_sent so a freshly-extended deploy gets the full 6-email
// warning cycle again instead of skipping reminders that fired earlier.
func SetDeploymentTTL(ctx context.Context, db *sql.DB, id uuid.UUID, hours int) error {
	expiresAt := time.Now().UTC().Add(time.Duration(hours) * time.Hour)
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET expires_at = $1,
		    ttl_policy = 'custom',
		    reminders_sent = 0,
		    last_reminder_at = NULL,
		    updated_at = now()
		WHERE id = $2
	`, expiresAt, id)
	if err != nil {
		return fmt.Errorf("models.SetDeploymentTTL: %w", err)
	}
	return nil
}

// GetDeploymentsExpiringSoon returns deployments whose expires_at falls
// within the next `window` from now AND whose last_reminder_at is either
// NULL or older than `reminderCooldown`. Used by the worker's
// deployment_reminder job to dedupe sends across 60s ticks while still
// firing 6 reminders over the final 12h. Caller is responsible for
// stamping last_reminder_at + reminders_sent after dispatch.
//
// Returns rows with ttl_policy != 'permanent' only; permanent deploys
// have NULL expires_at and never match the WHERE clause regardless of
// the policy check, but we filter explicitly for safety in case of a
// future schema drift where a permanent row gets a non-null expires_at.
//
// reminderCooldown is the minimum gap between two reminders for the
// same deployment. Default in the worker is 2h.
func GetDeploymentsExpiringSoon(ctx context.Context, db *sql.DB, window, reminderCooldown time.Duration) ([]*Deployment, error) {
	now := time.Now().UTC()
	cutoff := now.Add(window)
	cooldownBefore := now.Add(-reminderCooldown)
	rows, err := db.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE expires_at IS NOT NULL
		  AND ttl_policy != 'permanent'
		  AND status NOT IN ('deleted', 'expired')
		  AND expires_at > $1
		  AND expires_at <= $2
		  AND reminders_sent < 6
		  AND (last_reminder_at IS NULL OR last_reminder_at <= $3)
		ORDER BY expires_at ASC
		LIMIT 500
	`, now, cutoff, cooldownBefore)
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsExpiringSoon: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var results []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetDeploymentsExpiringSoon scan: %w", err)
		}
		results = append(results, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsExpiringSoon rows: %w", err)
	}
	return results, nil
}

// AdvanceDeploymentReminder atomically increments reminders_sent and stamps
// last_reminder_at = now() — but only when the row still matches the
// "ready to dispatch" predicate. Returns true when the row was advanced
// (caller is responsible for sending the email AFTER this returns true),
// false when another tick already advanced it.
//
// The CAS is on (reminders_sent < 6) AND
// (last_reminder_at IS NULL OR last_reminder_at <= now() - cooldown).
// expectedRemindersSent must match the value the caller read; this
// prevents a race where two workers both read reminders_sent=2, both
// see the cooldown gate satisfied, and both fire — only the first
// CAS succeeds.
func AdvanceDeploymentReminder(ctx context.Context, db *sql.DB, id uuid.UUID, expectedRemindersSent int, cooldown time.Duration) (bool, error) {
	cooldownBefore := time.Now().UTC().Add(-cooldown)
	res, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET reminders_sent = reminders_sent + 1,
		    last_reminder_at = now()
		WHERE id = $1
		  AND reminders_sent = $2
		  AND reminders_sent < 6
		  AND (last_reminder_at IS NULL OR last_reminder_at <= $3)
	`, id, expectedRemindersSent, cooldownBefore)
	if err != nil {
		return false, fmt.Errorf("models.AdvanceDeploymentReminder: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("models.AdvanceDeploymentReminder rows: %w", err)
	}
	return n == 1, nil
}

// GetExpiredDeployments returns deployments whose expires_at < now() and
// whose ttl_policy != 'permanent' and whose status is not already
// 'expired'/'deleted'. Used by the worker's deployment_expirer job to
// drive the actual teardown.
func GetExpiredDeployments(ctx context.Context, db *sql.DB, limit int) ([]*Deployment, error) {
	if limit <= 0 {
		limit = 100
	}
	now := time.Now().UTC()
	rows, err := db.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE expires_at IS NOT NULL
		  AND ttl_policy != 'permanent'
		  AND status NOT IN ('deleted', 'expired')
		  AND expires_at < $1
		ORDER BY expires_at ASC
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("models.GetExpiredDeployments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var results []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetExpiredDeployments scan: %w", err)
		}
		results = append(results, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetExpiredDeployments rows: %w", err)
	}
	return results, nil
}

// MarkDeploymentExpired flips a deploy's status to 'expired'. Distinct
// from DELETE (which removes the row entirely) — expired rows stay
// around so the dashboard can still render them with an "expired" badge
// and the user can read the audit trail of what happened.
func MarkDeploymentExpired(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET status = 'expired', updated_at = now()
		WHERE id = $1 AND status NOT IN ('deleted', 'expired')
	`, id)
	if err != nil {
		return fmt.Errorf("models.MarkDeploymentExpired: %w", err)
	}
	return nil
}

// DeployStatusExpired is the status the worker's DeploymentExpirer sets on a
// deploy whose 24h TTL elapsed. It is NOT terminal at the infra layer — the
// k8s namespace / pod / Ingress / cert are still live. The api's
// teardown reconciler (P3) picks these up, tears down the compute, then
// flips the row to DeployStatusDeleted.
const DeployStatusExpired = "expired"

// DeployStatusDeleted is the terminal status set once the compute backing a
// deployment has actually been torn down. A 'deleted' row consumes no slot
// and is never re-processed by the teardown reconciler.
const DeployStatusDeleted = "deleted"

// DeployStatusStopped is the status of a user-paused deployment — the pod is
// scaled to zero so it consumes no compute and occupies no tier slot.
const DeployStatusStopped = "stopped"

// IsDeploymentTerminal reports whether a deployment status is one a redeploy
// must not resurrect: expired (24h TTL elapsed — teardown reconciler will reap
// it), deleted (compute torn down), or stopped (user-paused). Redeploying any
// of these would resurrect an over-TTL / over-cap workload, so POST
// /deploy/:id/redeploy rejects them with 409.
func IsDeploymentTerminal(status string) bool {
	switch status {
	case DeployStatusExpired, DeployStatusDeleted, DeployStatusStopped:
		return true
	default:
		return false
	}
}

// Live deployment statuses — the only states in which a deployment runs a
// pod and therefore occupies a billable tier slot. Any status NOT in this
// set (failed / stopped / expired / deleted) consumes no compute and frees
// the slot. P1-E (bug hunt 2026-05-17 round 2): the tier-cap counter and the
// dashboard usage counter disagreed because each used a different negative
// filter; both now share activeDeploymentStatusesSQL so they can never drift.
const (
	DeployStatusBuilding  = "building"
	DeployStatusDeploying = "deploying"
	DeployStatusHealthy   = "healthy"
)

// activeDeploymentStatusesSQL is the SQL IN-list of deployment statuses that
// occupy a tier slot. Used verbatim by CountActiveDeploymentsByTeam (the
// POST /deploy/new tier-cap gate) — a slot is only consumed while a pod runs.
const activeDeploymentStatusesSQL = `('building', 'deploying', 'healthy')`

// terminalDeploymentStatusesSQL is the SQL IN-list of deployment statuses that
// are terminal at the user's surface: the row's compute has been reaped and
// the deployment is gone from the user's point of view.
//
//   - deleted — compute torn down (teardown reconciler advanced an expired row,
//     or a hard DELETE that didn't drop the row); nothing left to act on.
//   - expired — 24h TTL elapsed; the teardown reconciler will reap it shortly.
//
// 'failed' and 'stopped' are deliberately NOT terminal here: a failed build
// and a user-paused app are still real, user-visible deployments that the
// dashboard lists. This constant is the single source of truth for the
// "user-visible deployments" row set — see deploymentVisibleClause.
const terminalDeploymentStatusesSQL = `('deleted', 'expired')`

// deploymentVisibleClause is the shared WHERE predicate for "deployments the
// user sees" — i.e. every non-terminal row. GET /api/v1/deployments (the list)
// and GET /api/v1/billing/usage's deployment count MUST use this same clause
// so the list length and the usage count can never drift (S5-F4: the usage
// count once used the narrower activeDeploymentStatusesSQL filter while the
// list applied no status filter at all, so a terminal row reported count=1
// against an empty list).
//
// It is a clause fragment, not a full WHERE — callers prepend their own
// `team_id = $N AND` (and optionally `env = $M AND`) scope.
const deploymentVisibleClause = `status NOT IN ` + terminalDeploymentStatusesSQL

// GetExpiredDeploymentsAwaitingTeardown returns deployments stuck in
// status='expired' that still have a provider_id — i.e. the worker's
// DeploymentExpirer flipped the row but the compute (namespace / pod /
// Ingress / cert) was never destroyed.
//
// P3 (bug-hunt 2026-05-17): DeploymentExpirer only set status='expired';
// its comment claimed "the api reconciler tears down" but no api reconciler
// ever called Teardown — every auto-expired deploy leaked live, billed
// infra forever. This query is the input to the api teardown reconciler
// that closes that gap.
//
// Rows with an empty provider_id are skipped: runDeploy never reached
// UpdateDeploymentProviderID for them, so there is no k8s object to tear
// down. The reconciler marks those terminal directly without a Teardown
// call — this query only returns rows that genuinely need a compute call.
//
// P1-W5-17 (bug-hunt 2026-05-18): the api runs replicas:2 and StartTeardownReconciler
// sweeps in EVERY pod, so a plain SELECT had both pods pick the same rows and
// double-invoke compute.Teardown. The select MUST run inside the same
// transaction the reconciler holds for the sweep and now carries
// `FOR UPDATE SKIP LOCKED`: a row locked by one pod's sweep tx is silently
// skipped by the other pod's sweep, so each expired deployment is claimed
// and torn down by exactly one pod. The lock is held until the sweep tx
// commits — SKIP LOCKED means the loser never blocks, it just no-ops.
func GetExpiredDeploymentsAwaitingTeardown(ctx context.Context, tx *sql.Tx, limit int) ([]*Deployment, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE status = $1
		  AND provider_id IS NOT NULL
		  AND provider_id != ''
		ORDER BY updated_at ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, DeployStatusExpired, limit)
	if err != nil {
		return nil, fmt.Errorf("models.GetExpiredDeploymentsAwaitingTeardown: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var results []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetExpiredDeploymentsAwaitingTeardown scan: %w", err)
		}
		results = append(results, d)
	}
	return results, rows.Err()
}

// MarkDeploymentTornDown flips an expired deployment to the terminal
// 'deleted' status after its compute has been destroyed by the teardown
// reconciler (P3). The guarded WHERE status = 'expired' makes this safe to
// call concurrently / repeatedly: a row already advanced past 'expired'
// (e.g. a DELETE /deploy/:id raced the reconciler) is left untouched and
// RowsAffected reports 0, so the caller can tell a real teardown from a
// no-op.
//
// P1-W5-17: runs on the same transaction as GetExpiredDeploymentsAwaitingTeardown
// so the row claimed by FOR UPDATE SKIP LOCKED is flipped under the lock that
// claimed it — no other pod's sweep can race the status transition.
func MarkDeploymentTornDown(ctx context.Context, tx *sql.Tx, id uuid.UUID) (int64, error) {
	res, err := tx.ExecContext(ctx, `
		UPDATE deployments
		SET status = $1, updated_at = now()
		WHERE id = $2 AND status = $3
	`, DeployStatusDeleted, id, DeployStatusExpired)
	if err != nil {
		return 0, fmt.Errorf("models.MarkDeploymentTornDown: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CountActiveDeploymentsByTeam counts deployments for a team that occupy a
// billable tier slot. Used by POST /deploy/new to enforce the per-tier
// deployments_apps cap from plans.yaml.
//
// "Active" means the deployment is running a pod — status is one of
// building / deploying / healthy (activeDeploymentStatusesSQL). Every other
// status frees the slot:
//   - deleted  — compute torn down (hard DeleteDeployment drops the row too)
//   - expired  — 24h TTL elapsed; teardown reconciler will reap it
//   - failed   — build/rollout failed; runs no pod, no compute consumed
//   - stopped  — user-paused; pod scaled to zero, no compute consumed
//
// P1-E (bug hunt 2026-05-17 round 2): the previous negative filter
// (NOT IN deleted/expired/failed) still counted 'stopped' deployments, so a
// team that stopped a deploy could not create a new one within its tier cap —
// and the count disagreed with the dashboard usage counter. Both now share
// activeDeploymentStatusesSQL.
func CountActiveDeploymentsByTeam(ctx context.Context, db dbExecutor, teamID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM deployments
		WHERE team_id = $1 AND status IN `+activeDeploymentStatusesSQL+`
	`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountActiveDeploymentsByTeam: %w", err)
	}
	return n, nil
}

// CountVisibleDeploymentsByTeam counts the user-visible deployments for a team —
// the exact row set GetDeploymentsByTeam returns. It shares deploymentVisibleClause
// with the list query so the GET /api/v1/billing/usage deployment count and the
// GET /api/v1/deployments list length can never drift.
//
// S5-F4 (bug hunt): the billing/usage panel previously used the narrower
// activeDeploymentStatusesSQL filter (building/deploying/healthy only) while the
// list endpoint applied no status filter at all. The two counted different row
// sets — a stale terminal row could surface as count=1 against an empty list.
// Both now resolve through deploymentVisibleClause.
//
// This is intentionally NOT CountActiveDeploymentsByTeam: that counter answers
// "how many billable compute slots are consumed?" (the POST /deploy/new tier
// gate) and must exclude failed/stopped pods. This counter answers "how many
// deployments does the user see in the dashboard?" and includes them.
func CountVisibleDeploymentsByTeam(ctx context.Context, db dbExecutor, teamID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM deployments
		WHERE team_id = $1 AND `+deploymentVisibleClause+`
	`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountVisibleDeploymentsByTeam: %w", err)
	}
	return n, nil
}
