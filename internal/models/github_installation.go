package models

// github_installation.go — model layer for GitHub App installations (migration
// 066, P4.1). One row per (team, installation) — the link the install/callback
// flow persists and the App webhook resolves an incoming installation_id against
// before acting. No access token is stored here; tokens are minted on demand
// (internal/github) from the App private key and cached in Redis.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// GitHubInstallation links a GitHub App installation to a team.
type GitHubInstallation struct {
	InstallationID int64
	TeamID         uuid.UUID
	AccountLogin   string
	SuspendedAt    sql.NullTime // non-NULL → installation suspended; do not act
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ErrGitHubInstallationNotFound is returned when a lookup yields no rows.
type ErrGitHubInstallationNotFound struct {
	InstallationID int64
}

func (e *ErrGitHubInstallationNotFound) Error() string {
	return fmt.Sprintf("github installation not found: %d", e.InstallationID)
}

// ErrGitHubInstallationTeamConflict is returned when an upsert would rebind an
// installation that already belongs to a DIFFERENT team — the install-callback
// hijack guard (review HIGH-2). A re-install by the same team is allowed.
type ErrGitHubInstallationTeamConflict struct {
	InstallationID int64
}

func (e *ErrGitHubInstallationTeamConflict) Error() string {
	return fmt.Sprintf("github installation %d is already linked to another team", e.InstallationID)
}

const githubInstallationColumns = `installation_id, team_id, account_login,
       suspended_at, created_at, updated_at`

func scanGitHubInstallation(row interface {
	Scan(dest ...any) error
}) (*GitHubInstallation, error) {
	i := &GitHubInstallation{}
	if err := row.Scan(
		&i.InstallationID, &i.TeamID, &i.AccountLogin,
		&i.SuspendedAt, &i.CreatedAt, &i.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return i, nil
}

// UpsertGitHubInstallation inserts or updates the installation↔team link. The
// installation_id is GitHub's primary key; a re-install (or a callback replay)
// updates team_id/account_login and clears any prior suspension.
func UpsertGitHubInstallation(ctx context.Context, db *sql.DB, installationID int64, teamID uuid.UUID, accountLogin string) (*GitHubInstallation, error) {
	// The DO UPDATE is guarded by `WHERE team_id = EXCLUDED.team_id` so a
	// re-install by the SAME team refreshes the row, but a request carrying a
	// different team cannot rebind an installation it doesn't own — the update
	// matches no row, RETURNING is empty, and we surface a team conflict instead
	// of silently hijacking the victim's installation (review HIGH-2).
	row := db.QueryRowContext(ctx, `
		INSERT INTO github_installations (installation_id, team_id, account_login)
		VALUES ($1, $2, $3)
		ON CONFLICT (installation_id) DO UPDATE
			SET account_login = EXCLUDED.account_login,
			    suspended_at = NULL,
			    updated_at = now()
			WHERE github_installations.team_id = EXCLUDED.team_id
		RETURNING `+githubInstallationColumns,
		installationID, teamID, accountLogin)
	i, err := scanGitHubInstallation(row)
	if err == sql.ErrNoRows {
		return nil, &ErrGitHubInstallationTeamConflict{InstallationID: installationID}
	}
	if err != nil {
		return nil, fmt.Errorf("models.UpsertGitHubInstallation: %w", err)
	}
	return i, nil
}

// GetGitHubInstallation fetches one installation by its id.
func GetGitHubInstallation(ctx context.Context, db *sql.DB, installationID int64) (*GitHubInstallation, error) {
	row := db.QueryRowContext(ctx,
		`SELECT `+githubInstallationColumns+` FROM github_installations WHERE installation_id = $1`,
		installationID)
	i, err := scanGitHubInstallation(row)
	if err == sql.ErrNoRows {
		return nil, &ErrGitHubInstallationNotFound{InstallationID: installationID}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetGitHubInstallation: %w", err)
	}
	return i, nil
}

// ListGitHubInstallationsByTeam returns all (non-deleted) installations a team
// has, newest first.
func ListGitHubInstallationsByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*GitHubInstallation, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+githubInstallationColumns+` FROM github_installations WHERE team_id = $1 ORDER BY created_at DESC`,
		teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListGitHubInstallationsByTeam: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*GitHubInstallation
	for rows.Next() {
		i, err := scanGitHubInstallation(rows)
		if err != nil {
			return nil, fmt.Errorf("models.ListGitHubInstallationsByTeam scan: %w", err)
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListGitHubInstallationsByTeam rows: %w", err)
	}
	return out, nil
}

// SetGitHubInstallationSuspended toggles the suspended flag (GitHub `suspend` /
// `unsuspend` installation events). Suspended installations are kept (not
// deleted) so an unsuspend restores the link without a re-install.
func SetGitHubInstallationSuspended(ctx context.Context, db *sql.DB, installationID int64, suspended bool) error {
	var suspendedAt interface{}
	if suspended {
		suspendedAt = time.Now().UTC()
	}
	res, err := db.ExecContext(ctx,
		`UPDATE github_installations SET suspended_at = $2, updated_at = now() WHERE installation_id = $1`,
		installationID, suspendedAt)
	if err != nil {
		return fmt.Errorf("models.SetGitHubInstallationSuspended: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return &ErrGitHubInstallationNotFound{InstallationID: installationID}
	}
	return nil
}

// DeleteGitHubInstallation removes the link (GitHub `deleted` installation
// event). Returns the number of rows removed (0 = already gone, not an error).
func DeleteGitHubInstallation(ctx context.Context, db *sql.DB, installationID int64) (int64, error) {
	res, err := db.ExecContext(ctx,
		`DELETE FROM github_installations WHERE installation_id = $1`, installationID)
	if err != nil {
		return 0, fmt.Errorf("models.DeleteGitHubInstallation: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
