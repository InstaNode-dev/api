package models

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func pgpCols() []string {
	return []string{"id", "team_id", "subscription_id", "status", "started_at", "expires_at", "reminders_sent", "last_reminder_at", "recovered_at", "terminated_at"}
}

func TestCreatePaymentGracePeriod_Branches(t *testing.T) {
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	_, err := CreatePaymentGracePeriod(ctx, nil, CreatePaymentGracePeriodParams{})
	require.ErrorContains(t, err, "team_id is required")
	_, err = CreatePaymentGracePeriod(ctx, nil, CreatePaymentGracePeriodParams{TeamID: uuid.New(), SubscriptionID: " "})
	require.ErrorContains(t, err, "subscription_id is required")
	_, err = CreatePaymentGracePeriod(ctx, nil, CreatePaymentGracePeriodParams{TeamID: uuid.New(), SubscriptionID: "s"})
	require.ErrorContains(t, err, "expires_at is required")

	// happy (also exercises StartedAt-zero default)
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO payment_grace_periods`).
		WillReturnRows(sqlmock.NewRows(pgpCols()).AddRow(uuid.New(), uuid.New(), "s", "active", time.Now(), exp, 0, nil, nil, nil))
	g, err := CreatePaymentGracePeriod(ctx, db, CreatePaymentGracePeriodParams{TeamID: uuid.New(), SubscriptionID: "s", ExpiresAt: exp})
	require.NoError(t, err)
	require.Equal(t, "active", g.Status)

	// unique violation -> already active
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO payment_grace_periods`).WillReturnError(&pq.Error{Code: "23505"})
	_, err = CreatePaymentGracePeriod(ctx, db2, CreatePaymentGracePeriodParams{TeamID: uuid.New(), SubscriptionID: "s", ExpiresAt: exp, StartedAt: time.Now()})
	require.ErrorIs(t, err, ErrPaymentGraceAlreadyActive)

	// other error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`INSERT INTO payment_grace_periods`).WillReturnError(errors.New("boom"))
	_, err = CreatePaymentGracePeriod(ctx, db3, CreatePaymentGracePeriodParams{TeamID: uuid.New(), SubscriptionID: "s", ExpiresAt: exp, StartedAt: time.Now()})
	require.ErrorContains(t, err, "boom")
}

func TestGetActivePaymentGracePeriod_Branches(t *testing.T) {
	ctx := context.Background()

	_, err := GetActivePaymentGracePeriod(ctx, nil, uuid.Nil)
	require.ErrorContains(t, err, "team_id is required")

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM payment_grace_periods`).
		WillReturnRows(sqlmock.NewRows(pgpCols()).AddRow(uuid.New(), uuid.New(), "s", "active", time.Now(), time.Now(), 0, nil, nil, nil))
	g, err := GetActivePaymentGracePeriod(ctx, db, uuid.New())
	require.NoError(t, err)
	require.NotNil(t, g)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM payment_grace_periods`).WillReturnError(errNoRows())
	g, err = GetActivePaymentGracePeriod(ctx, db2, uuid.New())
	require.NoError(t, err)
	require.Nil(t, g)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM payment_grace_periods`).WillReturnError(errors.New("boom"))
	_, err = GetActivePaymentGracePeriod(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestMarkPaymentGraceRecovered_Branches(t *testing.T) {
	ctx := context.Background()

	_, err := MarkPaymentGraceRecovered(ctx, nil, uuid.Nil, time.Time{})
	require.ErrorContains(t, err, "team_id is required")

	// happy (zero recoveredAt default)
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE payment_grace_periods`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := MarkPaymentGraceRecovered(ctx, db, uuid.New(), time.Time{})
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE payment_grace_periods`).WillReturnError(errors.New("boom"))
	_, err = MarkPaymentGraceRecovered(ctx, db2, uuid.New(), time.Now())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE payment_grace_periods`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = MarkPaymentGraceRecovered(ctx, db3, uuid.New(), time.Now())
	require.ErrorContains(t, err, "raerr")
}

func TestTerminateAllPaymentGracePeriodsForTeam_Branches(t *testing.T) {
	ctx := context.Background()

	_, err := TerminateAllPaymentGracePeriodsForTeam(ctx, nil, uuid.Nil, time.Time{})
	require.ErrorContains(t, err, "team_id is required")

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE payment_grace_periods`).WillReturnResult(sqlmock.NewResult(0, 2))
	n, err := TerminateAllPaymentGracePeriodsForTeam(ctx, db, uuid.New(), time.Time{})
	require.NoError(t, err)
	require.Equal(t, int64(2), n)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE payment_grace_periods`).WillReturnError(errors.New("boom"))
	_, err = TerminateAllPaymentGracePeriodsForTeam(ctx, db2, uuid.New(), time.Now())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE payment_grace_periods`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = TerminateAllPaymentGracePeriodsForTeam(ctx, db3, uuid.New(), time.Now())
	require.ErrorContains(t, err, "raerr")
}

func TestHasTerminatedPaymentGracePeriod_Branches(t *testing.T) {
	ctx := context.Background()

	_, err := HasTerminatedPaymentGracePeriod(ctx, nil, uuid.Nil)
	require.ErrorContains(t, err, "team_id is required")

	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COUNT\(1\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	ok, err := HasTerminatedPaymentGracePeriod(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COUNT\(1\)`).WillReturnError(errors.New("boom"))
	_, err = HasTerminatedPaymentGracePeriod(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestMarkPaymentGraceTerminated_Branches(t *testing.T) {
	ctx := context.Background()

	_, err := MarkPaymentGraceTerminated(ctx, nil, uuid.Nil, time.Time{})
	require.ErrorContains(t, err, "team_id is required")

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE payment_grace_periods`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := MarkPaymentGraceTerminated(ctx, db, uuid.New(), time.Time{})
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE payment_grace_periods`).WillReturnError(errors.New("boom"))
	_, err = MarkPaymentGraceTerminated(ctx, db2, uuid.New(), time.Now())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE payment_grace_periods`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = MarkPaymentGraceTerminated(ctx, db3, uuid.New(), time.Now())
	require.ErrorContains(t, err, "raerr")
}
