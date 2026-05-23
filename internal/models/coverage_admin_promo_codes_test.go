package models

// coverage_admin_promo_codes_test.go — sqlmock-driven branch coverage for
// admin_promo_codes.go. White-box (package models) so the unexported
// generatePromoCode var seam can be stubbed for the deterministic
// collision-retry path. Every error branch is reached by injecting the
// matching sqlmock failure; the happy paths assert the returned row shape.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestIsValidPromoKind_AllBranches(t *testing.T) {
	require.True(t, IsValidPromoKind(PromoKindPercentOff))
	require.True(t, IsValidPromoKind(PromoKindFirstMonthFree))
	require.True(t, IsValidPromoKind(PromoKindAmountOff))
	require.False(t, IsValidPromoKind("nope"))
	require.ElementsMatch(t,
		[]string{PromoKindPercentOff, PromoKindFirstMonthFree, PromoKindAmountOff},
		ValidPromoKinds())
}

func TestIsValidPromoAuditEvent_AllBranches(t *testing.T) {
	require.True(t, IsValidPromoAuditEvent(PromoAuditEventIssued))
	require.True(t, IsValidPromoAuditEvent(PromoAuditEventRedeemed))
	require.True(t, IsValidPromoAuditEvent(PromoAuditEventExpired))
	require.False(t, IsValidPromoAuditEvent("garbage"))
}

func TestIssueAdminPromoCode_Validation(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	ctx := context.Background()

	_, err := IssueAdminPromoCode(ctx, db, CreateAdminPromoCodeParams{Kind: "bad", ValidForDays: 1, IssuedByEmail: "a@b.com"})
	require.ErrorIs(t, err, ErrInvalidPromoKind)

	_, err = IssueAdminPromoCode(ctx, db, CreateAdminPromoCodeParams{Kind: PromoKindPercentOff, ValidForDays: 0, IssuedByEmail: "a@b.com"})
	require.ErrorIs(t, err, ErrInvalidPromoDuration)

	_, err = IssueAdminPromoCode(ctx, db, CreateAdminPromoCodeParams{Kind: PromoKindPercentOff, ValidForDays: 1, Value: -1, IssuedByEmail: "a@b.com"})
	require.ErrorIs(t, err, ErrInvalidPromoValue)

	_, err = IssueAdminPromoCode(ctx, db, CreateAdminPromoCodeParams{Kind: PromoKindPercentOff, ValidForDays: 1, IssuedByEmail: "  "})
	require.Error(t, err)
}

func TestIssueAdminPromoCode_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	ctx := context.Background()

	mock.ExpectQuery(`INSERT INTO admin_promo_codes`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "code", "team_id", "issued_by_email", "kind", "value", "applies_to", "used_at", "expires_at", "created_at",
		}).AddRow(uuid.New(), "ABCD1234", uuid.New(), "a@b.com", PromoKindPercentOff, 10, 5, nil, time.Now(), time.Now()))

	row, err := IssueAdminPromoCode(ctx, db, CreateAdminPromoCodeParams{
		TeamID: uuid.New(), IssuedByEmail: "a@b.com", Kind: PromoKindPercentOff, Value: 10, AppliesTo: 5, ValidForDays: 30,
	})
	require.NoError(t, err)
	require.Equal(t, "ABCD1234", row.Code)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIssueAdminPromoCode_GenError(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orig := generatePromoCode
	defer func() { generatePromoCode = orig }()
	generatePromoCode = func() (string, error) { return "", errors.New("rng dead") }

	_, err := IssueAdminPromoCode(context.Background(), db, CreateAdminPromoCodeParams{
		IssuedByEmail: "a@b.com", Kind: PromoKindPercentOff, ValidForDays: 1,
	})
	require.ErrorContains(t, err, "rng dead")
}

func TestIssueAdminPromoCode_NonUniqueDBError(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`INSERT INTO admin_promo_codes`).WillReturnError(errors.New("disk full"))

	_, err = IssueAdminPromoCode(context.Background(), db, CreateAdminPromoCodeParams{
		IssuedByEmail: "a@b.com", Kind: PromoKindPercentOff, Value: 0, ValidForDays: 1,
	})
	require.ErrorContains(t, err, "disk full")
}

func TestIssueAdminPromoCode_CollisionRetriesExhausted(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	for i := 0; i < 5; i++ {
		mock.ExpectQuery(`INSERT INTO admin_promo_codes`).WillReturnError(errors.New("duplicate key value violates unique constraint admin_promo_codes_code_key"))
	}
	_, err = IssueAdminPromoCode(context.Background(), db, CreateAdminPromoCodeParams{
		IssuedByEmail: "a@b.com", Kind: PromoKindAmountOff, Value: 100, ValidForDays: 7,
	})
	require.ErrorContains(t, err, "collision after retries")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetAdminPromoCodeByCode_Branches(t *testing.T) {
	ctx := context.Background()
	cols := []string{"id", "code", "team_id", "issued_by_email", "kind", "value", "applies_to", "used_at", "expires_at", "created_at"}

	// happy
	db, mock, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`SELECT id, code, team_id`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow(uuid.New(), "X", uuid.New(), "a@b.com", PromoKindPercentOff, 5, nil, nil, time.Now(), time.Now()))
	got, err := GetAdminPromoCodeByCode(ctx, db, " x ", uuid.New())
	require.NoError(t, err)
	require.Equal(t, "X", got.Code)
	db.Close()

	// not found
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`SELECT id, code, team_id`).WillReturnError(errNoRows())
	_, err = GetAdminPromoCodeByCode(ctx, db, "x", uuid.New())
	require.ErrorIs(t, err, ErrAdminPromoCodeNotFound)
	db.Close()

	// transient
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`SELECT id, code, team_id`).WillReturnError(errors.New("conn reset"))
	_, err = GetAdminPromoCodeByCode(ctx, db, "x", uuid.New())
	require.ErrorContains(t, err, "conn reset")
	db.Close()
}

func TestMarkAdminPromoCodeUsed_Branches(t *testing.T) {
	ctx := context.Background()

	// happy — 1 row
	db, mock, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectExec(`UPDATE admin_promo_codes`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkAdminPromoCodeUsed(ctx, db, uuid.New()))
	db.Close()

	// already used — 0 rows
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectExec(`UPDATE admin_promo_codes`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, MarkAdminPromoCodeUsed(ctx, db, uuid.New()), ErrAdminPromoCodeAlreadyUsed)
	db.Close()

	// exec error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectExec(`UPDATE admin_promo_codes`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkAdminPromoCodeUsed(ctx, db, uuid.New()), "boom")
	db.Close()

	// rows-affected error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectExec(`UPDATE admin_promo_codes`).WillReturnResult(sqlmock.NewErrorResult(errors.New("ra boom")))
	require.ErrorContains(t, MarkAdminPromoCodeUsed(ctx, db, uuid.New()), "ra boom")
	db.Close()
}

func TestListPromoAuditEvents_Branches(t *testing.T) {
	ctx := context.Background()
	cols := []string{"event_type", "code", "team_id", "team_email", "issued_by_email", "kind", "value", "applies_to", "issued_at", "redeemed_at", "expired_at", "event_at"}

	// happy + scan
	db, mock, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`WITH promo_events`).WillReturnRows(
		sqlmock.NewRows(cols).AddRow("issued", "C", uuid.New(), "a@b.com", "a@b.com", PromoKindPercentOff, 10, 0, time.Now(), nil, nil, time.Now()))
	out, err := ListPromoAuditEvents(ctx, db, ListPromoAuditEventsParams{Limit: 10})
	require.NoError(t, err)
	require.Len(t, out, 1)
	db.Close()

	// query error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`WITH promo_events`).WillReturnError(errors.New("qerr"))
	_, err = ListPromoAuditEvents(ctx, db, ListPromoAuditEventsParams{})
	require.ErrorContains(t, err, "qerr")
	db.Close()

	// scan error (wrong column count)
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`WITH promo_events`).WillReturnRows(sqlmock.NewRows([]string{"event_type"}).AddRow("issued"))
	_, err = ListPromoAuditEvents(ctx, db, ListPromoAuditEventsParams{})
	require.Error(t, err)
	db.Close()

	// rows.Err()
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`WITH promo_events`).WillReturnRows(
		sqlmock.NewRows(cols).AddRow("issued", "C", uuid.New(), "a@b.com", "a@b.com", PromoKindPercentOff, 10, 0, time.Now(), nil, nil, time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ListPromoAuditEvents(ctx, db, ListPromoAuditEventsParams{})
	require.ErrorContains(t, err, "rowerr")
	db.Close()
}

func TestComputePromoStats_Branches(t *testing.T) {
	ctx := context.Background()

	// happy with leaderboards
	db, mock, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`COUNT\(\*\) AS issued_total`).WillReturnRows(sqlmock.NewRows([]string{"issued_total", "redeemed_total", "expired_total"}).AddRow(10, 3, 2))
	mock.ExpectQuery(`GROUP BY lower\(issued_by_email\)`).WillReturnRows(sqlmock.NewRows([]string{"email", "n"}).AddRow("a@b.com", 7))
	mock.ExpectQuery(`WHERE used_at IS NOT NULL\s+GROUP BY code`).WillReturnRows(sqlmock.NewRows([]string{"code", "n"}).AddRow("X", 3))
	s, err := ComputePromoStats(ctx, db)
	require.NoError(t, err)
	require.Equal(t, 10, s.IssuedTotal)
	require.InDelta(t, 0.3, s.RedemptionRate, 0.0001)
	require.Len(t, s.TopIssuers, 1)
	require.Len(t, s.TopCodesByRedemption, 1)
	db.Close()

	// totals error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`COUNT\(\*\) AS issued_total`).WillReturnError(errors.New("terr"))
	_, err = ComputePromoStats(ctx, db)
	require.ErrorContains(t, err, "terr")
	db.Close()

	// issuers query error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`COUNT\(\*\) AS issued_total`).WillReturnRows(sqlmock.NewRows([]string{"issued_total", "redeemed_total", "expired_total"}).AddRow(0, 0, 0))
	mock.ExpectQuery(`GROUP BY lower\(issued_by_email\)`).WillReturnError(errors.New("ierr"))
	_, err = ComputePromoStats(ctx, db)
	require.ErrorContains(t, err, "ierr")
	db.Close()

	// issuers scan error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`COUNT\(\*\) AS issued_total`).WillReturnRows(sqlmock.NewRows([]string{"issued_total", "redeemed_total", "expired_total"}).AddRow(5, 1, 0))
	mock.ExpectQuery(`GROUP BY lower\(issued_by_email\)`).WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("a@b.com"))
	_, err = ComputePromoStats(ctx, db)
	require.Error(t, err)
	db.Close()

	// codes query error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`COUNT\(\*\) AS issued_total`).WillReturnRows(sqlmock.NewRows([]string{"issued_total", "redeemed_total", "expired_total"}).AddRow(5, 1, 0))
	mock.ExpectQuery(`GROUP BY lower\(issued_by_email\)`).WillReturnRows(sqlmock.NewRows([]string{"email", "n"}).AddRow("a@b.com", 5))
	mock.ExpectQuery(`WHERE used_at IS NOT NULL\s+GROUP BY code`).WillReturnError(errors.New("cerr"))
	_, err = ComputePromoStats(ctx, db)
	require.ErrorContains(t, err, "cerr")
	db.Close()

	// codes scan error
	db, mock, _ = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	mock.ExpectQuery(`COUNT\(\*\) AS issued_total`).WillReturnRows(sqlmock.NewRows([]string{"issued_total", "redeemed_total", "expired_total"}).AddRow(5, 1, 0))
	mock.ExpectQuery(`GROUP BY lower\(issued_by_email\)`).WillReturnRows(sqlmock.NewRows([]string{"email", "n"}).AddRow("a@b.com", 5))
	mock.ExpectQuery(`WHERE used_at IS NOT NULL\s+GROUP BY code`).WillReturnRows(sqlmock.NewRows([]string{"code"}).AddRow("X"))
	_, err = ComputePromoStats(ctx, db)
	require.Error(t, err)
	db.Close()
}
