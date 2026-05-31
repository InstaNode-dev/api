package models

// coverage_promote_ttl_test.go — sqlmock-driven coverage for the six error
// branches in PromoteDeploymentTTLsForTeam that the real-DB integration
// tests in promote_ttl_test.go can't reach (a real Postgres won't reject
// BeginTx/Commit on demand). Each branch maps to a fmt.Errorf wrapper that
// callers grep for in NR alerts — losing one to a silent refactor would
// make on-call's job harder.
//
// White-box (package models) so we can drive a sqlmock-backed *sql.DB
// straight through the function. Mirrors the pattern in
// coverage_deploys_audit_test.go.

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestPromoteDeploymentTTLsForTeam_BeginTxError covers the
// "models.PromoteDeploymentTTLsForTeam: begin tx" wrapper. sqlmock can
// reject BeginTx with a configured error, which a real Postgres test DB
// won't reproduce on demand.
func TestPromoteDeploymentTTLsForTeam_BeginTxError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("simulated begin failure"))

	_, err := PromoteDeploymentTTLsForTeam(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.ErrorContains(t, err, "begin tx")
	require.ErrorContains(t, err, "simulated begin failure")
}

// TestPromoteDeploymentTTLsForTeam_FlipTeamDefaultError covers the
// "flip_team_default" wrapper — the first UPDATE inside the tx failing.
func TestPromoteDeploymentTTLsForTeam_FlipTeamDefaultError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE teams`).WillReturnError(errors.New("simulated team update failure"))
	mock.ExpectRollback()

	_, err := PromoteDeploymentTTLsForTeam(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.ErrorContains(t, err, "flip_team_default")
	require.ErrorContains(t, err, "simulated team update failure")
}

// TestPromoteDeploymentTTLsForTeam_TeamRowsAffectedError covers the
// "team_rows_affected" wrapper. sqlmock.NewErrorResult lets us return a
// sql.Result whose RowsAffected() errors — a state real drivers basically
// never hit but the wrapper exists so future driver swaps surface cleanly.
func TestPromoteDeploymentTTLsForTeam_TeamRowsAffectedError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewErrorResult(errors.New("simulated team rows.Affected failure")))
	mock.ExpectRollback()

	_, err := PromoteDeploymentTTLsForTeam(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.ErrorContains(t, err, "team_rows_affected")
	require.ErrorContains(t, err, "simulated team rows.Affected failure")
}

// TestPromoteDeploymentTTLsForTeam_PromoteDeploysError covers the
// "promote_deploys" wrapper — the second UPDATE inside the tx failing.
func TestPromoteDeploymentTTLsForTeam_PromoteDeploysError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE deployments`).WillReturnError(errors.New("simulated deploys update failure"))
	mock.ExpectRollback()

	_, err := PromoteDeploymentTTLsForTeam(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.ErrorContains(t, err, "promote_deploys")
	require.ErrorContains(t, err, "simulated deploys update failure")
}

// TestPromoteDeploymentTTLsForTeam_DeploysRowsAffectedError covers the
// "deploys_rows_affected" wrapper.
func TestPromoteDeploymentTTLsForTeam_DeploysRowsAffectedError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE deployments`).WillReturnResult(sqlmock.NewErrorResult(errors.New("simulated deploys rows.Affected failure")))
	mock.ExpectRollback()

	_, err := PromoteDeploymentTTLsForTeam(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.ErrorContains(t, err, "deploys_rows_affected")
	require.ErrorContains(t, err, "simulated deploys rows.Affected failure")
}

// TestPromoteDeploymentTTLsForTeam_CommitError covers the "commit"
// wrapper. The two UPDATEs succeed but the commit itself rejects — also
// driver-rare but the wrapper has to exist for the rollback-on-defer to
// be observed in NR.
func TestPromoteDeploymentTTLsForTeam_CommitError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE deployments`).WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit().WillReturnError(errors.New("simulated commit failure"))

	_, err := PromoteDeploymentTTLsForTeam(context.Background(), db, uuid.New())
	require.Error(t, err)
	require.ErrorContains(t, err, "commit")
	require.ErrorContains(t, err, "simulated commit failure")
}
