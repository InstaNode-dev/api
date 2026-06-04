package models

// is_test_cohort_test.go — white-box sqlmock coverage for the cohort-isolation
// helpers added in migration 067 (W0 / PR-1): IsTestCohort + SetTestCohort.
// Every DB-error / no-rows / rows-affected branch is driven here without a real
// Postgres; the DB-backed smoke (default + real scan) lives in
// is_test_cohort_db_test.go (package models_test).

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestIsTestCohort_Branches(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()

	// true value scans through.
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT is_test_cohort FROM teams WHERE id`).
		WillReturnRows(sqlmock.NewRows([]string{"is_test_cohort"}).AddRow(true))
	got, err := IsTestCohort(ctx, db, id)
	require.NoError(t, err)
	require.True(t, got)

	// false value scans through.
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT is_test_cohort FROM teams WHERE id`).
		WillReturnRows(sqlmock.NewRows([]string{"is_test_cohort"}).AddRow(false))
	got, err = IsTestCohort(ctx, db2, id)
	require.NoError(t, err)
	require.False(t, got)

	// no rows → (false, nil) — missing team is not a test cohort.
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT is_test_cohort FROM teams WHERE id`).WillReturnError(errNoRows())
	got, err = IsTestCohort(ctx, db3, id)
	require.NoError(t, err)
	require.False(t, got)

	// query error → wrapped error, false.
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`SELECT is_test_cohort FROM teams WHERE id`).WillReturnError(errors.New("boom"))
	got, err = IsTestCohort(ctx, db4, id)
	require.ErrorContains(t, err, "boom")
	require.False(t, got)
}

func TestSetTestCohort_Branches(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()

	// success — one row updated.
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams SET is_test_cohort`).
		WithArgs(true, id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetTestCohort(ctx, db, id, true))

	// zero rows → ErrTeamNotFound.
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams SET is_test_cohort`).
		WithArgs(false, id).
		WillReturnResult(sqlmock.NewResult(0, 0))
	err := SetTestCohort(ctx, db2, id, false)
	var notFound *ErrTeamNotFound
	require.ErrorAs(t, err, &notFound)

	// exec error → wrapped error.
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE teams SET is_test_cohort`).
		WithArgs(true, id).
		WillReturnError(errors.New("boom"))
	require.ErrorContains(t, SetTestCohort(ctx, db3, id, true), "boom")

	// RowsAffected error → wrapped "rows" error.
	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE teams SET is_test_cohort`).
		WithArgs(true, id).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("ra-boom")))
	require.ErrorContains(t, SetTestCohort(ctx, db4, id, true), "rows")
}
