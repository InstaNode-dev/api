package models

// github_push_match.go — query helpers for the GitHub push-to-deploy webhook
// (P4.2). A single push event carries a repo + branch; we need to find all
// AppGitHubConnections that are wired to that repo+branch so each linked
// deployment can be redeployed. We also expose a lookup by installation_id so
// the installation.deleted / installation.suspended events can locate every
// affected connection in one query.

import (
	"context"
	"database/sql"
	"fmt"
)

// FindConnectionsByRepoBranch returns every AppGitHubConnection whose
// github_repo and branch match the supplied values. A single repo+branch pair
// can be wired to multiple deployments (e.g. a monorepo with two apps), so the
// result is always a slice. An empty slice (not an error) is returned when
// there are no matching rows.
func FindConnectionsByRepoBranch(ctx context.Context, db *sql.DB, githubRepo, branch string) ([]*AppGitHubConnection, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+githubConnectionColumns+`
		   FROM app_github_connections
		  WHERE github_repo = $1
		    AND branch = $2`,
		githubRepo, branch)
	if err != nil {
		return nil, fmt.Errorf("models.FindConnectionsByRepoBranch: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*AppGitHubConnection
	for rows.Next() {
		c, err := scanGitHubConnection(rows)
		if err != nil {
			return nil, fmt.Errorf("models.FindConnectionsByRepoBranch scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.FindConnectionsByRepoBranch rows: %w", err)
	}
	return out, nil
}

// FindConnectionsByInstallationID returns every AppGitHubConnection whose
// installation_id matches the supplied value. Used when a GitHub App
// installation is deleted or suspended to locate all affected connections.
// An empty slice (not an error) is returned when there are no matching rows.
func FindConnectionsByInstallationID(ctx context.Context, db *sql.DB, installationID int64) ([]*AppGitHubConnection, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+githubConnectionColumns+`
		   FROM app_github_connections
		  WHERE installation_id = $1`,
		installationID)
	if err != nil {
		return nil, fmt.Errorf("models.FindConnectionsByInstallationID: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*AppGitHubConnection
	for rows.Next() {
		c, err := scanGitHubConnection(rows)
		if err != nil {
			return nil, fmt.Errorf("models.FindConnectionsByInstallationID scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.FindConnectionsByInstallationID rows: %w", err)
	}
	return out, nil
}
