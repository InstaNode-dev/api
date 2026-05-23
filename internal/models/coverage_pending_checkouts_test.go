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

func TestInsertPendingCheckout_Branches(t *testing.T) {
	ctx := context.Background()

	require.NoError(t, InsertPendingCheckout(ctx, nil, "sub", uuid.New(), "a@b.com", "pro")) // nil db

	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO pending_checkouts`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, InsertPendingCheckout(ctx, db, "sub", uuid.New(), "a@b.com", "pro"))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`INSERT INTO pending_checkouts`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, InsertPendingCheckout(ctx, db2, "sub", uuid.New(), "a@b.com", "pro"), "boom")
}

func TestFindUnresolvedPendingCheckouts_Branches(t *testing.T) {
	ctx := context.Background()
	cols := []string{"subscription_id", "plan_tier", "failure_notified_at"}

	out, err := FindUnresolvedPendingCheckouts(ctx, nil, uuid.New())
	require.NoError(t, err)
	require.Nil(t, out)

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM pending_checkouts`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow("sub", "pro", nil))
	out, err = FindUnresolvedPendingCheckouts(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM pending_checkouts`).WillReturnError(errors.New("qerr"))
	_, err = FindUnresolvedPendingCheckouts(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM pending_checkouts`).WillReturnRows(sqlmock.NewRows([]string{"subscription_id"}).AddRow("sub"))
	_, err = FindUnresolvedPendingCheckouts(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM pending_checkouts`).WillReturnRows(
		sqlmock.NewRows(cols).AddRow("sub", "pro", nil).RowError(0, errors.New("rowerr")))
	_, err = FindUnresolvedPendingCheckouts(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")

	_ = time.Now
}

func TestResolvePendingCheckout_Branches(t *testing.T) {
	ctx := context.Background()

	require.NoError(t, ResolvePendingCheckout(ctx, nil, "sub"))
	db, _ := newMock(t)
	require.NoError(t, ResolvePendingCheckout(ctx, db, "")) // empty subscription id

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE pending_checkouts SET resolved_at`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, ResolvePendingCheckout(ctx, db2, "sub"))

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE pending_checkouts SET resolved_at`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, ResolvePendingCheckout(ctx, db3, "sub"), "boom")
}

func TestEnqueuePendingPropagation_Branches(t *testing.T) {
	ctx := context.Background()

	_, err := EnqueuePendingPropagation(ctx, nil, "", uuid.New(), "", nil)
	require.ErrorContains(t, err, "kind required")

	_, err = EnqueuePendingPropagation(ctx, nil, PropagationKindTierElevation, uuid.Nil, "", nil)
	require.ErrorContains(t, err, "team_id required")

	db, mock := newMock(t)
	id := uuid.New()
	mock.ExpectQuery(`INSERT INTO pending_propagations`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
	got, err := EnqueuePendingPropagation(ctx, db, PropagationKindTierElevation, uuid.New(), "pro", []byte(`{"a":1}`))
	require.NoError(t, err)
	require.Equal(t, id, got)

	// empty tier + nil payload defaults path + error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO pending_propagations`).WillReturnError(errors.New("boom"))
	_, err = EnqueuePendingPropagation(ctx, db2, PropagationKindTierElevation, uuid.New(), "", nil)
	require.ErrorContains(t, err, "boom")
}
