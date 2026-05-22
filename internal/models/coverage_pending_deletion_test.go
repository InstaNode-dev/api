package models

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndHashPendingDeletion(t *testing.T) {
	pt, err := GeneratePendingDeletionPlaintext()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(pt, PendingDeletionTokenPrefix))
	require.Len(t, HashPendingDeletionToken(pt), 64)
}

func TestMaskEmail(t *testing.T) {
	require.Equal(t, "a***@example.com", MaskEmail("alice@example.com"))
	require.Equal(t, "a@example.com", MaskEmail("a@example.com"))
	require.Equal(t, "no-at", MaskEmail("no-at"))
	require.Equal(t, "@example.com", MaskEmail("@example.com")) // at index 0 -> returned unchanged
}

func pdCols() []string {
	return []string{"id", "resource_id", "resource_type", "team_id", "requested_by_user_id", "requested_at", "expires_at", "confirmation_token_hash", "status", "confirmed_at", "cancelled_at", "email_sent_to"}
}

func pdRow() *sqlmock.Rows {
	return sqlmock.NewRows(pdCols()).AddRow(uuid.New(), uuid.New(), "deploy", uuid.New(), uuid.New(), time.Now(), time.Now().Add(time.Hour), "h", "pending", nil, nil, "a@b.com")
}

func TestCreatePendingDeletion_Branches(t *testing.T) {
	ctx := context.Background()

	// invalid resource type
	_, _, err := CreatePendingDeletion(ctx, nil, uuid.New(), "bad", uuid.New(), uuid.New(), "a@b.com", time.Minute)
	require.ErrorContains(t, err, "invalid resource_type")

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	_, _, err = CreatePendingDeletion(ctx, db, uuid.New(), PendingDeletionResourceDeploy, uuid.New(), uuid.New(), "a@b.com", time.Minute)
	require.ErrorContains(t, err, "beginerr")

	// already exists
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`SELECT id FROM pending_deletions`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock2.ExpectRollback()
	_, _, err = CreatePendingDeletion(ctx, db2, uuid.New(), PendingDeletionResourceStack, uuid.New(), uuid.New(), "a@b.com", time.Minute)
	require.ErrorIs(t, err, ErrPendingDeletionAlreadyExists)

	// dedup query error
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`SELECT id FROM pending_deletions`).WillReturnError(errors.New("dboom"))
	mock3.ExpectRollback()
	_, _, err = CreatePendingDeletion(ctx, db3, uuid.New(), PendingDeletionResourceDeploy, uuid.New(), uuid.New(), "a@b.com", time.Minute)
	require.ErrorContains(t, err, "dboom")

	// insert error
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`SELECT id FROM pending_deletions`).WillReturnError(errNoRows())
	mock4.ExpectQuery(`INSERT INTO pending_deletions`).WillReturnError(errors.New("inserr"))
	mock4.ExpectRollback()
	_, _, err = CreatePendingDeletion(ctx, db4, uuid.New(), PendingDeletionResourceDeploy, uuid.New(), uuid.New(), "a@b.com", time.Minute)
	require.ErrorContains(t, err, "inserr")

	// commit error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`SELECT id FROM pending_deletions`).WillReturnError(errNoRows())
	mock5.ExpectQuery(`INSERT INTO pending_deletions`).WillReturnRows(pdRow())
	mock5.ExpectCommit().WillReturnError(errors.New("commiterr"))
	_, _, err = CreatePendingDeletion(ctx, db5, uuid.New(), PendingDeletionResourceDeploy, uuid.New(), uuid.New(), "a@b.com", time.Minute)
	require.ErrorContains(t, err, "commiterr")

	// happy
	db6, mock6 := newMock(t)
	mock6.ExpectBegin()
	mock6.ExpectQuery(`SELECT id FROM pending_deletions`).WillReturnError(errNoRows())
	mock6.ExpectQuery(`INSERT INTO pending_deletions`).WillReturnRows(pdRow())
	mock6.ExpectCommit()
	pd, plaintext, err := CreatePendingDeletion(ctx, db6, uuid.New(), PendingDeletionResourceDeploy, uuid.New(), uuid.New(), "a@b.com", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, plaintext)
	require.Equal(t, "pending", pd.Status)
}

func TestGetPendingDeletionByTokenHash_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE confirmation_token_hash`).WillReturnRows(pdRow())
	_, err := GetPendingDeletionByTokenHash(ctx, db, "h")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE confirmation_token_hash`).WillReturnError(errNoRows())
	_, err = GetPendingDeletionByTokenHash(ctx, db2, "h")
	require.ErrorIs(t, err, ErrPendingDeletionNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE confirmation_token_hash`).WillReturnError(errors.New("boom"))
	_, err = GetPendingDeletionByTokenHash(ctx, db3, "h")
	require.ErrorContains(t, err, "boom")
}

func TestGetPendingDeletionByResource_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE resource_id = \$1 AND resource_type`).WillReturnRows(pdRow())
	_, err := GetPendingDeletionByResource(ctx, db, uuid.New(), "deploy")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE resource_id = \$1 AND resource_type`).WillReturnError(errNoRows())
	_, err = GetPendingDeletionByResource(ctx, db2, uuid.New(), "deploy")
	require.ErrorIs(t, err, ErrPendingDeletionNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE resource_id = \$1 AND resource_type`).WillReturnError(errors.New("boom"))
	_, err = GetPendingDeletionByResource(ctx, db3, uuid.New(), "deploy")
	require.ErrorContains(t, err, "boom")
}

func TestMarkPendingDeletionConfirmed_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE pending_deletions`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := MarkPendingDeletionConfirmed(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE pending_deletions`).WillReturnError(errors.New("boom"))
	_, err = MarkPendingDeletionConfirmed(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE pending_deletions`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = MarkPendingDeletionConfirmed(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "raerr")
}

func TestMarkPendingDeletionCancelled_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE pending_deletions`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := MarkPendingDeletionCancelled(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE pending_deletions`).WillReturnError(errors.New("boom"))
	_, err = MarkPendingDeletionCancelled(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE pending_deletions`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = MarkPendingDeletionCancelled(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "raerr")
}

func TestExpireOldPendingDeletions_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`UPDATE pending_deletions`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "resource_id", "resource_type", "team_id", "requested_at"}).AddRow(uuid.New(), uuid.New(), "deploy", uuid.New(), time.Now()))
	out, err := ExpireOldPendingDeletions(ctx, db)
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`UPDATE pending_deletions`).WillReturnError(errors.New("qerr"))
	_, err = ExpireOldPendingDeletions(ctx, db2)
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`UPDATE pending_deletions`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ExpireOldPendingDeletions(ctx, db3)
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`UPDATE pending_deletions`).WillReturnRows(
		sqlmock.NewRows([]string{"id", "resource_id", "resource_type", "team_id", "requested_at"}).AddRow(uuid.New(), uuid.New(), "deploy", uuid.New(), time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ExpireOldPendingDeletions(ctx, db4)
	require.ErrorContains(t, err, "rowerr")
}
