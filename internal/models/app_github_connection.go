package models

// app_github_connection.go — model layer for the GitHub auto-deploy feature
// (migration 035). One row per (deployment app) that has been wired to a
// GitHub repo + branch. The receive endpoint /webhooks/github/:webhook_id
// looks up the row by id, verifies HMAC, and enqueues a pending_github_deploys
// row for the worker to drain.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AppGitHubConnection represents one connection between a deployment and a
// GitHub repo. WebhookSecret is the AES-256-GCM ciphertext — callers MUST
// decrypt before computing the HMAC; the column never holds plaintext.
type AppGitHubConnection struct {
	ID             uuid.UUID
	AppID          uuid.UUID
	TeamID         uuid.UUID
	GitHubRepo     string // "owner/repo"
	Branch         string
	WebhookSecret  string // AES-256-GCM ciphertext
	InstallationID sql.NullInt64
	CreatedAt      time.Time
	LastDeployAt   sql.NullTime
	LastCommitSHA  sql.NullString
}

// ErrGitHubConnectionNotFound is returned when a lookup yields no rows.
type ErrGitHubConnectionNotFound struct {
	ID string
}

func (e *ErrGitHubConnectionNotFound) Error() string {
	return fmt.Sprintf("github connection not found: %s", e.ID)
}

// CreateGitHubConnectionParams holds the fields needed to insert a new row.
// WebhookSecret MUST already be AES-256-GCM ciphertext — this layer does no
// crypto.
type CreateGitHubConnectionParams struct {
	AppID          uuid.UUID
	TeamID         uuid.UUID
	GitHubRepo     string
	Branch         string
	WebhookSecret  string
	InstallationID *int64
}

const githubConnectionColumns = `id, app_id, team_id, github_repo, branch,
       webhook_secret, installation_id, created_at, last_deploy_at, last_commit_sha`

// scanGitHubConnection reads a single row into an AppGitHubConnection.
func scanGitHubConnection(row interface {
	Scan(dest ...any) error
}) (*AppGitHubConnection, error) {
	c := &AppGitHubConnection{}
	if err := row.Scan(
		&c.ID, &c.AppID, &c.TeamID,
		&c.GitHubRepo, &c.Branch, &c.WebhookSecret,
		&c.InstallationID, &c.CreatedAt,
		&c.LastDeployAt, &c.LastCommitSHA,
	); err != nil {
		return nil, err
	}
	return c, nil
}

// CreateGitHubConnection inserts a new row. Returns ErrGitHubConnectionExists
// (wrapping the raw pq error) when the unique index on app_id rejects the
// insert — the caller surfaces this as 409 Conflict.
func CreateGitHubConnection(ctx context.Context, db *sql.DB, p CreateGitHubConnectionParams) (*AppGitHubConnection, error) {
	var installation sql.NullInt64
	if p.InstallationID != nil {
		installation = sql.NullInt64{Int64: *p.InstallationID, Valid: true}
	}
	branch := p.Branch
	if branch == "" {
		branch = "main"
	}
	row := db.QueryRowContext(ctx, `
		INSERT INTO app_github_connections (app_id, team_id, github_repo, branch, webhook_secret, installation_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+githubConnectionColumns,
		p.AppID, p.TeamID, p.GitHubRepo, branch, p.WebhookSecret, installation,
	)
	return scanGitHubConnection(row)
}

// GetGitHubConnectionByID looks up a connection by its UUID (which doubles
// as the public webhook id in the URL path).
func GetGitHubConnectionByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*AppGitHubConnection, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+githubConnectionColumns+`
		FROM app_github_connections
		WHERE id = $1`, id)
	c, err := scanGitHubConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &ErrGitHubConnectionNotFound{ID: id.String()}
	}
	return c, err
}

// GetGitHubConnectionByAppID looks up the connection (at most one) for a
// deployment. Returns ErrGitHubConnectionNotFound when there is none.
func GetGitHubConnectionByAppID(ctx context.Context, db *sql.DB, appID uuid.UUID) (*AppGitHubConnection, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+githubConnectionColumns+`
		FROM app_github_connections
		WHERE app_id = $1`, appID)
	c, err := scanGitHubConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &ErrGitHubConnectionNotFound{ID: appID.String()}
	}
	return c, err
}

// DeleteGitHubConnection removes the row by id. Returns nil even when no row
// existed — DELETE is idempotent.
func DeleteGitHubConnection(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM app_github_connections WHERE id = $1`, id)
	return err
}

// DeleteGitHubConnectionByAppID is the convenience the handler uses (the
// dashboard / agent identifies the connection by the deployment, not by the
// connection id).
func DeleteGitHubConnectionByAppID(ctx context.Context, db *sql.DB, appID uuid.UUID) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM app_github_connections WHERE app_id = $1`, appID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// UpdateGitHubConnectionLastDeploy marks the most recent enqueued commit on
// the connection. Called after a successful pending_github_deploys insert so
// duplicate push.events for the same SHA can be short-circuited.
func UpdateGitHubConnectionLastDeploy(ctx context.Context, db *sql.DB, id uuid.UUID, commitSHA string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE app_github_connections
		   SET last_deploy_at = now(), last_commit_sha = $2
		 WHERE id = $1`, id, commitSHA)
	return err
}

// ── pending_github_deploys ────────────────────────────────────────────────────

// PendingGitHubDeploy is the worker-side queue row. The api inserts on push
// receive; the worker drains queued rows, downloads the github tarball, and
// triggers a redeploy on the linked deployment.
type PendingGitHubDeploy struct {
	ID           uuid.UUID
	ConnectionID uuid.UUID
	AppID        uuid.UUID
	CommitSHA    string
	PusherLogin  sql.NullString
	Status       string // queued | in_progress | completed | failed
	Attempts     int
	ErrorMessage sql.NullString
	EnqueuedAt   time.Time
	CompletedAt  sql.NullTime
}

// EnqueueGitHubDeployParams describes a new pending row.
type EnqueueGitHubDeployParams struct {
	ConnectionID uuid.UUID
	AppID        uuid.UUID
	CommitSHA    string
	PusherLogin  string
}

// EnqueueGitHubDeploy inserts a new pending_github_deploys row with status
// 'queued'. Returns the row id so the audit log can reference it.
func EnqueueGitHubDeploy(ctx context.Context, db *sql.DB, p EnqueueGitHubDeployParams) (uuid.UUID, error) {
	var pusher sql.NullString
	if p.PusherLogin != "" {
		pusher = sql.NullString{String: p.PusherLogin, Valid: true}
	}
	var id uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO pending_github_deploys (connection_id, app_id, commit_sha, pusher_login)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		p.ConnectionID, p.AppID, p.CommitSHA, pusher,
	).Scan(&id)
	return id, err
}

// CountRecentGitHubDeploys returns the number of rows enqueued for a given
// connection within the supplied window. Powers the rate-limit gate
// (max N deploys/hour/repo) so a noisy PR ladder doesn't burn through quota.
func CountRecentGitHubDeploys(ctx context.Context, db *sql.DB, connectionID uuid.UUID, since time.Time) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM pending_github_deploys
		 WHERE connection_id = $1 AND enqueued_at >= $2`,
		connectionID, since,
	).Scan(&n)
	return n, err
}
