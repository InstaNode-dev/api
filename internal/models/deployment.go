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
	ID                   uuid.UUID
	TeamID               uuid.UUID
	ResourceID           uuid.NullUUID
	AppID                string
	ProviderID           string // k8s Deployment name, e.g. "app-{app_id}"
	Status               string // building | deploying | healthy | failed | stopped
	AppURL               string
	EnvVars              map[string]string
	Port                 int
	Tier                 string
	Env                  string // dev | staging | production | <custom>; defaults to "production"
	Private              bool
	AllowedIPs           []string // parsed from the comma-joined `allowed_ips` column
	NotifyWebhook        string   // user-supplied https:// URL; empty when unset
	NotifyWebhookSecret  string   // AES-256-GCM ciphertext of the HMAC key; empty when unset
	NotifyState          string   // 'unset' | 'pending' | 'sent' | 'failed'
	NotifyAttempts       int      // dispatch retry counter (worker bumps on 5xx/network)
	ErrorMessage         string
	CreatedAt            time.Time
	UpdatedAt            time.Time
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
}

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
       notify_webhook, notify_webhook_secret, notify_state, notify_attempts`

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
func CreateDeployment(ctx context.Context, db *sql.DB, p CreateDeploymentParams) (*Deployment, error) {
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

	row := db.QueryRowContext(ctx, `
		INSERT INTO deployments
			(team_id, resource_id, app_id, port, tier, env, env_vars, private, allowed_ips,
			 notify_webhook, notify_webhook_secret, notify_state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING `+deploymentColumns,
		p.TeamID, resourceID, p.AppID, port, p.Tier, env, envVarsJSON,
		p.Private, allowedIPs,
		notifyWebhook, notifyWebhookSecret, notifyState)

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

// GetDeploymentsByTeam returns all deployments for a team across every environment,
// ordered by creation time descending.
func GetDeploymentsByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*Deployment, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE team_id = $1
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeam: %w", err)
	}
	defer rows.Close()

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

// GetDeploymentsByTeamAndEnv returns deployments for a team scoped to a single
// environment. Empty env is normalised to EnvDefault ("development") to match
// the post-migration-026 default for POST /deploy/new.
func GetDeploymentsByTeamAndEnv(ctx context.Context, db *sql.DB, teamID uuid.UUID, env string) ([]*Deployment, error) {
	if env == "" {
		env = EnvDefault
	}
	rows, err := db.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployments
		WHERE team_id = $1 AND env = $2
		ORDER BY created_at DESC
	`, teamID, env)
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeamAndEnv: %w", err)
	}
	defer rows.Close()

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

// CountActiveDeploymentsByTeam counts deployments for a team that have not been
// torn down. Used by POST /deploy/new to enforce the per-tier deployments_apps
// cap from plans.yaml.
//
// "Active" here means anything that still consumes a slot — that is, every
// row in the deployments table whose status is not "deleted". Hard-deleted
// rows (via DeleteDeployment) drop out naturally because the row is gone.
// A soft-deleted "deleted" status is treated as freeing the slot, mirroring
// the behaviour callers expect when they DELETE then re-create.
func CountActiveDeploymentsByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM deployments
		WHERE team_id = $1 AND status != 'deleted'
	`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountActiveDeploymentsByTeam: %w", err)
	}
	return n, nil
}
