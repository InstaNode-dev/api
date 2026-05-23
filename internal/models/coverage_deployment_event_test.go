package models

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestHintForReason(t *testing.T) {
	require.Equal(t, FailureHint[FailureReasonOOMKilled], HintForReason(FailureReasonOOMKilled))
	require.Equal(t, FailureHint[FailureReasonUnknown], HintForReason("something-unmapped"))
}

func TestGetLatestDeploymentAutopsy_Branches(t *testing.T) {
	ctx := context.Background()
	cols := []string{"reason", "exit_code", "event", "last_lines", "hint", "created_at"}

	// happy with valid json
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployment_events`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow("OOMKilled", sql.NullInt32{Int32: 137, Valid: true}, "ev", []byte(`["a","b"]`), "hint", time.Now()))
	got, err := GetLatestDeploymentAutopsy(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, got.LastLines)

	// no rows
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM deployment_events`).WillReturnError(errNoRows())
	got, err = GetLatestDeploymentAutopsy(ctx, db2, uuid.New())
	require.NoError(t, err)
	require.Nil(t, got)

	// db error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM deployment_events`).WillReturnError(errors.New("boom"))
	_, err = GetLatestDeploymentAutopsy(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")

	// invalid json -> empty slice, no error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM deployment_events`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow("Error", nil, "ev", []byte(`{bad`), "hint", time.Now()))
	got, err = GetLatestDeploymentAutopsy(ctx, db4, uuid.New())
	require.NoError(t, err)
	require.Equal(t, []string{}, got.LastLines)

	// empty last_lines -> empty slice
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM deployment_events`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow("Error", nil, "ev", []byte{}, "hint", time.Now()))
	got, err = GetLatestDeploymentAutopsy(ctx, db5, uuid.New())
	require.NoError(t, err)
	require.Equal(t, []string{}, got.LastLines)
}

func TestUpsertDeploymentAutopsy_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO deployment_events`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpsertDeploymentAutopsy(ctx, db, UpsertAutopsyParams{
		DeploymentID: uuid.New(), Reason: "OOMKilled", ExitCode: sql.NullInt32{Int32: 137, Valid: true}, Event: "e", LastLines: []string{"x"}, Hint: "h",
	}))

	// nil last_lines path + exec error
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`INSERT INTO deployment_events`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpsertDeploymentAutopsy(ctx, db2, UpsertAutopsyParams{DeploymentID: uuid.New(), Reason: "Error"}), "boom")
}
