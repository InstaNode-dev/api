package models

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// ghConnRow returns a one-row Rows fixture with all columns that
// scanGitHubConnection expects (mirrors githubConnectionColumns order):
//
//	id, app_id, team_id, github_repo, branch,
//	webhook_secret, installation_id, created_at, last_deploy_at, last_commit_sha
func ghConnRow() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "app_id", "team_id", "github_repo", "branch",
		"webhook_secret", "installation_id", "created_at", "last_deploy_at", "last_commit_sha",
	}).AddRow(
		uuid.New(), uuid.New(), uuid.New(),
		"acme/api", "main",
		"secret-cipher", int64(99), time.Now(), nil, nil,
	)
}

// ── FindConnectionsByRepoBranch ───────────────────────────────────────────────

func TestFindConnectionsByRepoBranch(t *testing.T) {
	ctx := context.Background()

	// happy path — two matching rows
	t.Run("two rows", func(t *testing.T) {
		db, mock := newMock(t)
		rows := sqlmock.NewRows([]string{
			"id", "app_id", "team_id", "github_repo", "branch",
			"webhook_secret", "installation_id", "created_at", "last_deploy_at", "last_commit_sha",
		}).
			AddRow(uuid.New(), uuid.New(), uuid.New(), "acme/api", "main", "s1", int64(1), time.Now(), nil, nil).
			AddRow(uuid.New(), uuid.New(), uuid.New(), "acme/api", "main", "s2", int64(2), time.Now(), nil, nil)
		mock.ExpectQuery(`FROM app_github_connections`).
			WithArgs("acme/api", "main").
			WillReturnRows(rows)
		got, err := FindConnectionsByRepoBranch(ctx, db, "acme/api", "main")
		require.NoError(t, err)
		require.Len(t, got, 2)
		require.Equal(t, "acme/api", got[0].GitHubRepo)
		require.Equal(t, "acme/api", got[1].GitHubRepo)
	})

	// happy path — no matching rows → empty slice, not error
	t.Run("no rows", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WithArgs("ghost/repo", "main").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "app_id", "team_id", "github_repo", "branch",
				"webhook_secret", "installation_id", "created_at", "last_deploy_at", "last_commit_sha",
			}))
		got, err := FindConnectionsByRepoBranch(ctx, db, "ghost/repo", "main")
		require.NoError(t, err)
		require.Empty(t, got)
	})

	// query error
	t.Run("query error", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WillReturnError(errors.New("boom"))
		_, err := FindConnectionsByRepoBranch(ctx, db, "acme/api", "main")
		require.ErrorContains(t, err, "boom")
		require.ErrorContains(t, err, "FindConnectionsByRepoBranch")
	})

	// scan error (wrong column count)
	t.Run("scan error", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
		_, err := FindConnectionsByRepoBranch(ctx, db, "acme/api", "main")
		require.ErrorContains(t, err, "scan")
	})

	// rows.Err()
	t.Run("rows err", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WillReturnRows(ghConnRow().RowError(0, errors.New("rowboom")))
		_, err := FindConnectionsByRepoBranch(ctx, db, "acme/api", "main")
		require.ErrorContains(t, err, "rowboom")
		require.ErrorContains(t, err, "rows")
	})
}

// ── FindConnectionsByInstallationID ──────────────────────────────────────────

func TestFindConnectionsByInstallationID(t *testing.T) {
	ctx := context.Background()

	// happy path — one row
	t.Run("one row", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WithArgs(int64(99)).
			WillReturnRows(ghConnRow())
		got, err := FindConnectionsByInstallationID(ctx, db, 99)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.True(t, got[0].InstallationID.Valid)
		require.Equal(t, int64(99), got[0].InstallationID.Int64)
	})

	// happy path — no rows → empty slice
	t.Run("no rows", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WithArgs(int64(404)).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "app_id", "team_id", "github_repo", "branch",
				"webhook_secret", "installation_id", "created_at", "last_deploy_at", "last_commit_sha",
			}))
		got, err := FindConnectionsByInstallationID(ctx, db, 404)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	// query error
	t.Run("query error", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WillReturnError(errors.New("boom"))
		_, err := FindConnectionsByInstallationID(ctx, db, 99)
		require.ErrorContains(t, err, "boom")
		require.ErrorContains(t, err, "FindConnectionsByInstallationID")
	})

	// scan error (wrong column count)
	t.Run("scan error", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
		_, err := FindConnectionsByInstallationID(ctx, db, 99)
		require.ErrorContains(t, err, "scan")
	})

	// rows.Err()
	t.Run("rows err", func(t *testing.T) {
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM app_github_connections`).
			WillReturnRows(ghConnRow().RowError(0, errors.New("rowboom")))
		_, err := FindConnectionsByInstallationID(ctx, db, 99)
		require.ErrorContains(t, err, "rowboom")
		require.ErrorContains(t, err, "rows")
	})
}
