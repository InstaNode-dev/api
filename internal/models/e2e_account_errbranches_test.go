package models

// e2e_account_errbranches_test.go — white-box (package models) sqlmock coverage
// for the DB-error branches of the CI-only ephemeral-test-account model
// functions. The happy-path / idempotent behaviour is exercised DB-backed in
// e2e_account_models_test.go (package models_test); those paths can't
// deterministically hit the Exec-failed / RowsAffected-failed branches against
// a real working Postgres, so they're covered here via sqlmock to satisfy the
// 100%-patch coverage gate.
//
// Covers:
//   - CreateTestCohortTeam       — INSERT … RETURNING QueryRow error (team.go)
//   - DeleteTeamHard             — Exec error + RowsAffected error (team.go)
//   - MarkTeamResourcesForReaper — Exec error + RowsAffected error (resource.go)

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCreateTestCohortTeam_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO teams .* is_test_cohort`).
		WillReturnError(errors.New("boom"))

	team, err := CreateTestCohortTeam(context.Background(), db, "cohort-mint")
	require.Error(t, err)
	require.Nil(t, team)
	require.Contains(t, err.Error(), "models.CreateTestCohortTeam")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteTeamHard_ExecError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM teams WHERE id`).
		WillReturnError(errors.New("boom"))

	deleted, err := DeleteTeamHard(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.False(t, deleted)
	require.Contains(t, err.Error(), "models.DeleteTeamHard")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteTeamHard_RowsAffectedError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM teams WHERE id`).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))

	deleted, err := DeleteTeamHard(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.False(t, deleted)
	require.Contains(t, err.Error(), "rows_affected")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMarkTeamResourcesForReaper_ExecError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources`).
		WillReturnError(errors.New("boom"))

	n, err := MarkTeamResourcesForReaper(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.Equal(t, int64(0), n)
	require.Contains(t, err.Error(), "models.MarkTeamResourcesForReaper")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMarkTeamResourcesForReaper_RowsAffectedError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources`).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))

	n, err := MarkTeamResourcesForReaper(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.Equal(t, int64(0), n)
	require.Contains(t, err.Error(), "rows_affected")
	require.NoError(t, mock.ExpectationsWereMet())
}
