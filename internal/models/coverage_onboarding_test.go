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

func TestOnboardingErrorStrings(t *testing.T) {
	require.Contains(t, (&ErrOnboardingNotFound{JTI: "j"}).Error(), "j")
	require.Contains(t, (&ErrOnboardingAlreadyUsed{JTI: "j"}).Error(), "j")
}

func obCols() []string {
	return []string{"id", "fingerprint", "jwt_issued_at", "jwt_expires_at", "converted_at", "team_id", "resource_tokens", "jti"}
}

func TestCreateOnboardingEvent_Branches(t *testing.T) {
	ctx := context.Background()
	tok := uuid.New()

	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO onboarding_events`).
		WillReturnRows(sqlmock.NewRows(obCols()).AddRow(uuid.New(), "fp", time.Now(), time.Now(), nil, nil, pq.Array([]string{tok.String(), "not-a-uuid"}), "jti"))
	ev, err := CreateOnboardingEvent(ctx, db, "fp", "jti", time.Now(), []uuid.UUID{tok})
	require.NoError(t, err)
	require.Len(t, ev.ResourceTokens, 1) // bad uuid filtered out

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO onboarding_events`).WillReturnError(errors.New("boom"))
	_, err = CreateOnboardingEvent(ctx, db2, "fp", "jti", time.Now(), nil)
	require.ErrorContains(t, err, "boom")
}

func TestGetOnboardingByJTI_Branches(t *testing.T) {
	ctx := context.Background()
	tok := uuid.New()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM onboarding_events WHERE jti`).
		WillReturnRows(sqlmock.NewRows(obCols()).AddRow(uuid.New(), "fp", time.Now(), time.Now(), nil, nil, pq.Array([]string{tok.String()}), "jti"))
	ev, err := GetOnboardingByJTI(ctx, db, "jti")
	require.NoError(t, err)
	require.Len(t, ev.ResourceTokens, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM onboarding_events WHERE jti`).WillReturnError(errNoRows())
	_, err = GetOnboardingByJTI(ctx, db2, "jti")
	var nf *ErrOnboardingNotFound
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM onboarding_events WHERE jti`).WillReturnError(errors.New("boom"))
	_, err = GetOnboardingByJTI(ctx, db3, "jti")
	require.ErrorContains(t, err, "boom")
}

func TestMarkOnboardingConvertedPreliminary_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE onboarding_events`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkOnboardingConvertedPreliminary(ctx, db, "jti"))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE onboarding_events`).WillReturnResult(sqlmock.NewResult(0, 0))
	var used *ErrOnboardingAlreadyUsed
	require.ErrorAs(t, MarkOnboardingConvertedPreliminary(ctx, db2, "jti"), &used)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE onboarding_events`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkOnboardingConvertedPreliminary(ctx, db3, "jti"), "boom")
}

func TestMarkOnboardingConverted_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE onboarding_events`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkOnboardingConverted(ctx, db, "jti", uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE onboarding_events`).WillReturnResult(sqlmock.NewResult(0, 0))
	var used *ErrOnboardingAlreadyUsed
	require.ErrorAs(t, MarkOnboardingConverted(ctx, db2, "jti", uuid.New()), &used)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE onboarding_events`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkOnboardingConverted(ctx, db3, "jti", uuid.New()), "boom")
}
