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

func TestIsUniqueViolation(t *testing.T) {
	require.False(t, isUniqueViolation(nil))
	require.True(t, isUniqueViolation(errors.New("duplicate key value violates unique constraint")))
	require.True(t, isUniqueViolation(errors.New("pq: 23505")))
	require.False(t, isUniqueViolation(errors.New("other")))
}

func TestGenerateVerificationToken(t *testing.T) {
	tok, err := generateVerificationToken()
	require.NoError(t, err)
	require.Len(t, tok, 32)
}

func cdCols() []string {
	return []string{"id", "team_id", "stack_id", "hostname", "verification_token", "status", "verified_at", "cert_ready_at", "last_check_at", "last_check_err", "created_at"}
}

func cdRow() *sqlmock.Rows {
	return sqlmock.NewRows(cdCols()).AddRow(uuid.New(), uuid.New(), uuid.New(), "x.com", "tok", "pending_verification", nil, nil, nil, nil, time.Now())
}

func TestCreateCustomDomain_Branches(t *testing.T) {
	ctx := context.Background()

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	_, err := CreateCustomDomain(ctx, db, uuid.New(), uuid.New(), "x.com")
	require.ErrorContains(t, err, "beginerr")

	// happy
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`INSERT INTO custom_domains`).WillReturnRows(cdRow())
	mock2.ExpectCommit()
	got, err := CreateCustomDomain(ctx, db2, uuid.New(), uuid.New(), "x.com")
	require.NoError(t, err)
	require.Equal(t, "x.com", got.Hostname)

	// unique violation
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`INSERT INTO custom_domains`).WillReturnError(errors.New("duplicate key value violates unique constraint"))
	mock3.ExpectRollback()
	_, err = CreateCustomDomain(ctx, db3, uuid.New(), uuid.New(), "x.com")
	require.ErrorIs(t, err, ErrCustomDomainTaken)

	// other scan error
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`INSERT INTO custom_domains`).WillReturnError(errors.New("boom"))
	mock4.ExpectRollback()
	_, err = CreateCustomDomain(ctx, db4, uuid.New(), uuid.New(), "x.com")
	require.ErrorContains(t, err, "boom")

	// commit error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`INSERT INTO custom_domains`).WillReturnRows(cdRow())
	mock5.ExpectCommit().WillReturnError(errors.New("commiterr"))
	_, err = CreateCustomDomain(ctx, db5, uuid.New(), uuid.New(), "x.com")
	require.ErrorContains(t, err, "commiterr")
}

func TestGetCustomDomainByID_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM custom_domains WHERE id`).WillReturnRows(cdRow())
	_, err := GetCustomDomainByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM custom_domains WHERE id`).WillReturnError(errNoRows())
	_, err = GetCustomDomainByID(ctx, db2, uuid.New())
	require.ErrorIs(t, err, ErrCustomDomainNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM custom_domains WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetCustomDomainByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestListCustomDomainsByStack_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE stack_id`).WillReturnRows(cdRow())
	out, err := ListCustomDomainsByStack(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE stack_id`).WillReturnError(errors.New("qerr"))
	_, err = ListCustomDomainsByStack(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE stack_id`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListCustomDomainsByStack(ctx, db3, uuid.New())
	require.Error(t, err)
}

func TestListCustomDomainsByTeam_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM custom_domains\s+WHERE team_id`).WillReturnRows(cdRow())
	out, err := ListCustomDomainsByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM custom_domains\s+WHERE team_id`).WillReturnError(errors.New("qerr"))
	_, err = ListCustomDomainsByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM custom_domains\s+WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListCustomDomainsByTeam(ctx, db3, uuid.New())
	require.Error(t, err)
}

func TestUpdateCustomDomainStatus_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE custom_domains`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateCustomDomainStatus(ctx, db, uuid.New(), "verified", "someerr"))

	// empty err path
	db1b, mock1b := newMock(t)
	mock1b.ExpectExec(`UPDATE custom_domains`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateCustomDomainStatus(ctx, db1b, uuid.New(), "verified", ""))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE custom_domains`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, UpdateCustomDomainStatus(ctx, db2, uuid.New(), "verified", ""), ErrCustomDomainNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE custom_domains`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateCustomDomainStatus(ctx, db3, uuid.New(), "verified", ""), "boom")
}

func TestMarkCustomDomainVerified_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE custom_domains`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkCustomDomainVerified(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE custom_domains`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, MarkCustomDomainVerified(ctx, db2, uuid.New()), ErrCustomDomainNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE custom_domains`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkCustomDomainVerified(ctx, db3, uuid.New()), "boom")
}

func TestMarkCertReady_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE custom_domains`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkCertReady(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE custom_domains`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, MarkCertReady(ctx, db2, uuid.New()), ErrCustomDomainNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE custom_domains`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkCertReady(ctx, db3, uuid.New()), "boom")
}

func TestDeleteCustomDomain_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM custom_domains`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, DeleteCustomDomain(ctx, db, uuid.New(), uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`DELETE FROM custom_domains`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, DeleteCustomDomain(ctx, db2, uuid.New(), uuid.New()), ErrCustomDomainNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`DELETE FROM custom_domains`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, DeleteCustomDomain(ctx, db3, uuid.New(), uuid.New()), "boom")
}
