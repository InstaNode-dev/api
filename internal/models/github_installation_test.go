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

func ghInstallRow() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"installation_id", "team_id", "account_login", "suspended_at", "created_at", "updated_at",
	}).AddRow(int64(42), uuid.New(), "acme", nil, time.Now(), time.Now())
}

func TestUpsertGitHubInstallation(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO github_installations`).WillReturnRows(ghInstallRow())
	got, err := UpsertGitHubInstallation(ctx, db, 42, uuid.New(), "acme")
	require.NoError(t, err)
	require.Equal(t, int64(42), got.InstallationID)

	// scan/db error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO github_installations`).WillReturnError(errors.New("boom"))
	_, err = UpsertGitHubInstallation(ctx, db2, 42, uuid.New(), "acme")
	require.ErrorContains(t, err, "boom")

	// team conflict: the WHERE-guarded DO UPDATE matches no row (installation
	// already owned by another team), RETURNING is empty → ErrNoRows →
	// ErrGitHubInstallationTeamConflict (review HIGH-2, anti-hijack).
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`INSERT INTO github_installations`).
		WillReturnRows(sqlmock.NewRows([]string{
			"installation_id", "team_id", "account_login", "suspended_at", "created_at", "updated_at",
		})) // no rows → ErrNoRows
	_, err = UpsertGitHubInstallation(ctx, db3, 42, uuid.New(), "acme")
	var conflict *ErrGitHubInstallationTeamConflict
	require.ErrorAs(t, err, &conflict)
	require.Contains(t, conflict.Error(), "another team")
}

func TestGetGitHubInstallation(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnRows(ghInstallRow())
	got, err := GetGitHubInstallation(ctx, db, 42)
	require.NoError(t, err)
	require.Equal(t, "acme", got.AccountLogin)

	// not found
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnError(errNoRows())
	_, err = GetGitHubInstallation(ctx, db2, 7)
	var nf *ErrGitHubInstallationNotFound
	require.ErrorAs(t, err, &nf)
	require.Contains(t, nf.Error(), "7")

	// other error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnError(errors.New("boom"))
	_, err = GetGitHubInstallation(ctx, db3, 7)
	require.ErrorContains(t, err, "boom")
}

func TestListGitHubInstallationsByTeam(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()

	db, mock := newMock(t)
	rows := sqlmock.NewRows([]string{
		"installation_id", "team_id", "account_login", "suspended_at", "created_at", "updated_at",
	}).AddRow(int64(1), team, "a", nil, time.Now(), time.Now()).
		AddRow(int64(2), team, "b", time.Now(), time.Now(), time.Now())
	mock.ExpectQuery(`FROM github_installations WHERE team_id`).WillReturnRows(rows)
	got, err := ListGitHubInstallationsByTeam(ctx, db, team)
	require.NoError(t, err)
	require.Len(t, got, 2)

	// query error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM github_installations WHERE team_id`).WillReturnError(errors.New("boom"))
	_, err = ListGitHubInstallationsByTeam(ctx, db2, team)
	require.ErrorContains(t, err, "boom")

	// scan error (wrong column count)
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM github_installations WHERE team_id`).
		WillReturnRows(sqlmock.NewRows([]string{"installation_id"}).AddRow(int64(1)))
	_, err = ListGitHubInstallationsByTeam(ctx, db3, team)
	require.ErrorContains(t, err, "scan")

	// rows.Err()
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM github_installations WHERE team_id`).
		WillReturnRows(ghInstallRow().RowError(0, errors.New("rowboom")))
	_, err = ListGitHubInstallationsByTeam(ctx, db4, team)
	require.ErrorContains(t, err, "rowboom")
}

func TestSetGitHubInstallationSuspended(t *testing.T) {
	ctx := context.Background()

	// suspend = true
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE github_installations SET suspended_at`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetGitHubInstallationSuspended(ctx, db, 42, true))

	// unsuspend (suspended=false) — 1 row
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE github_installations SET suspended_at`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetGitHubInstallationSuspended(ctx, db2, 42, false))

	// 0 rows → not found
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE github_installations SET suspended_at`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	var nf *ErrGitHubInstallationNotFound
	require.ErrorAs(t, SetGitHubInstallationSuspended(ctx, db3, 9, true), &nf)

	// exec error
	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE github_installations SET suspended_at`).
		WillReturnError(errors.New("boom"))
	require.ErrorContains(t, SetGitHubInstallationSuspended(ctx, db4, 9, true), "boom")
}

func TestDeleteGitHubInstallation(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM github_installations`).WillReturnResult(sqlmock.NewResult(0, 1))
	n, err := DeleteGitHubInstallation(ctx, db, 42)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	// exec error
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`DELETE FROM github_installations`).WillReturnError(errors.New("boom"))
	_, err = DeleteGitHubInstallation(ctx, db2, 42)
	require.ErrorContains(t, err, "boom")
}
