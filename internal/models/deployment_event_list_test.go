package models

// deployment_event_list_test.go — coverage for GetDeploymentEvents, the
// model-layer DAL behind GET /api/v1/deployments/:id/events. Each branch is
// exercised: limit clamp (default + cap + zero), empty result, happy-path
// ordering, corrupt jsonb fallback, scan error, db error, rows.Err.

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var deploymentEventsCols = []string{
	"id", "deployment_id", "kind", "reason",
	"exit_code", "event", "last_lines", "hint", "created_at",
}

func TestGetDeploymentEvents_LimitClamp(t *testing.T) {
	// limit < 1 → default 50.
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployment_events`).
		WithArgs(sqlmock.AnyArg(), DeploymentEventsListDefaultLimit).
		WillReturnRows(sqlmock.NewRows(deploymentEventsCols))
	_, err := GetDeploymentEvents(context.Background(), db, uuid.New(), 0)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())

	// limit > max → clamped to DeploymentEventsListMaxLimit.
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM deployment_events`).
		WithArgs(sqlmock.AnyArg(), DeploymentEventsListMaxLimit).
		WillReturnRows(sqlmock.NewRows(deploymentEventsCols))
	_, err = GetDeploymentEvents(context.Background(), db2, uuid.New(), DeploymentEventsListMaxLimit+500)
	require.NoError(t, err)
	require.NoError(t, mock2.ExpectationsWereMet())

	// In-range limit passes through verbatim.
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM deployment_events`).
		WithArgs(sqlmock.AnyArg(), 7).
		WillReturnRows(sqlmock.NewRows(deploymentEventsCols))
	_, err = GetDeploymentEvents(context.Background(), db3, uuid.New(), 7)
	require.NoError(t, err)
	require.NoError(t, mock3.ExpectationsWereMet())
}

func TestGetDeploymentEvents_EmptyResult(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployment_events`).
		WillReturnRows(sqlmock.NewRows(deploymentEventsCols))

	out, err := GetDeploymentEvents(context.Background(), db, uuid.New(), 10)
	require.NoError(t, err)
	assert.NotNil(t, out, "must return a non-nil slice so JSON marshals as []")
	assert.Len(t, out, 0)
}

func TestGetDeploymentEvents_HappyPath_OrderingPreserved(t *testing.T) {
	deploymentID := uuid.New()
	id1, id2, id3 := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()

	db, mock := newMock(t)
	// The handler relies on ORDER BY created_at DESC at the SQL layer —
	// the model preserves whatever order the DB returns. We mock 3 rows in
	// DESC order and assert the slice mirrors that order.
	rows := sqlmock.NewRows(deploymentEventsCols).
		AddRow(id1, deploymentID, "failure_autopsy", "kaniko_oom",
			sql.NullInt32{Int32: 137, Valid: true}, "OOMKilled",
			[]byte(`["line1","line2"]`), "Out of memory.", now).
		AddRow(id2, deploymentID, "failure_autopsy", "image_pull_failed",
			sql.NullInt32{}, "ErrImagePull",
			[]byte(`[]`), "Check image name.", now.Add(-1*time.Minute)).
		AddRow(id3, deploymentID, "lifecycle", "deploying",
			sql.NullInt32{}, "",
			nil, "", now.Add(-2*time.Minute))

	mock.ExpectQuery(`FROM deployment_events`).
		WithArgs(deploymentID, 50).
		WillReturnRows(rows)

	out, err := GetDeploymentEvents(context.Background(), db, deploymentID, 50)
	require.NoError(t, err)
	require.Len(t, out, 3)

	// Row 0: full payload, exit_code valid.
	assert.Equal(t, "kaniko_oom", out[0].Reason)
	assert.Equal(t, "failure_autopsy", out[0].Kind)
	require.True(t, out[0].ExitCode.Valid)
	assert.Equal(t, int32(137), out[0].ExitCode.Int32)
	assert.Equal(t, []string{"line1", "line2"}, out[0].LastLines)

	// Row 1: exit_code null, empty last_lines jsonb [].
	assert.Equal(t, "image_pull_failed", out[1].Reason)
	assert.False(t, out[1].ExitCode.Valid)
	assert.Equal(t, []string{}, out[1].LastLines, "empty jsonb [] must surface as empty slice, not nil")

	// Row 2: nil last_lines raw (legacy / pre-default rows) → empty slice.
	assert.Equal(t, "lifecycle", out[2].Kind)
	assert.Equal(t, []string{}, out[2].LastLines, "nil raw must surface as empty slice")
}

func TestGetDeploymentEvents_CorruptJSONB_Recovers(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployment_events`).
		WillReturnRows(sqlmock.NewRows(deploymentEventsCols).
			AddRow(uuid.New(), uuid.New(), "failure_autopsy", "Error",
				sql.NullInt32{}, "boom", []byte(`{not-json`), "hint", time.Now()))

	out, err := GetDeploymentEvents(context.Background(), db, uuid.New(), 5)
	require.NoError(t, err, "corrupt jsonb must NOT 500 the list")
	require.Len(t, out, 1)
	assert.Equal(t, []string{}, out[0].LastLines, "fallback to empty slice")
}

func TestGetDeploymentEvents_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployment_events`).
		WillReturnError(errors.New("connection refused"))

	out, err := GetDeploymentEvents(context.Background(), db, uuid.New(), 10)
	require.ErrorContains(t, err, "connection refused")
	assert.Nil(t, out)
}

func TestGetDeploymentEvents_ScanError(t *testing.T) {
	db, mock := newMock(t)
	// Force scan failure: declare 9 columns but feed only 3 values — sqlmock
	// will reject the AddRow at scan time.
	mock.ExpectQuery(`FROM deployment_events`).
		WillReturnRows(sqlmock.NewRows(deploymentEventsCols).
			AddRow("not-a-uuid", "also-not", "kind", "reason",
				sql.NullInt32{}, "ev", []byte(`[]`), "hint", time.Now()))

	_, err := GetDeploymentEvents(context.Background(), db, uuid.New(), 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan")
}

func TestGetDeploymentEvents_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployment_events`).
		WillReturnRows(sqlmock.NewRows(deploymentEventsCols).
			AddRow(uuid.New(), uuid.New(), "k", "r",
				sql.NullInt32{}, "ev", []byte(`[]`), "h", time.Now()).
			RowError(0, errors.New("driver-row-err")))

	_, err := GetDeploymentEvents(context.Background(), db, uuid.New(), 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "driver-row-err")
}

func TestDeploymentEventsListConstants_AreSane(t *testing.T) {
	// Belt-and-braces guard on the constants the handler + spec advertise.
	// If someone bumps these, the test forces them to update the OpenAPI
	// description (which hard-codes 50 / 200).
	assert.Equal(t, 50, DeploymentEventsListDefaultLimit)
	assert.Equal(t, 200, DeploymentEventsListMaxLimit)
	assert.True(t, DeploymentEventsListDefaultLimit < DeploymentEventsListMaxLimit)
}
