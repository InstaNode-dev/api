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

func TestGenerateAndHashMagicLink(t *testing.T) {
	pt, err := GenerateMagicLinkPlaintext()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(pt, MagicLinkPrefix))
	require.Len(t, HashMagicLink(pt), 64)
}

func mlCols() []string {
	return []string{"id", "email", "token_hash", "return_to", "expires_at", "consumed_at", "created_at"}
}

func TestCreateMagicLink_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO magic_links`).
		WillReturnRows(sqlmock.NewRows(mlCols()).AddRow(uuid.New(), "a@b.com", "h", "/", time.Now(), nil, time.Now()))
	got, err := CreateMagicLink(ctx, db, "a@b.com", "plain", "/", time.Hour)
	require.NoError(t, err)
	require.Equal(t, "a@b.com", got.Email)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO magic_links`).WillReturnError(errors.New("boom"))
	_, err = CreateMagicLink(ctx, db2, "a@b.com", "plain", "/", time.Hour)
	require.ErrorContains(t, err, "boom")
}

func TestMarkMagicLinkSent(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE magic_links`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkMagicLinkSent(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE magic_links`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkMagicLinkSent(ctx, db2, uuid.New()), "boom")
}

func TestMarkMagicLinkSendFailed(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE magic_links`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkMagicLinkSendFailed(ctx, db, uuid.New(), errors.New(strings.Repeat("x", 600))))

	// nil error path
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE magic_links`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkMagicLinkSendFailed(ctx, db2, uuid.New(), nil))

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE magic_links`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkMagicLinkSendFailed(ctx, db3, uuid.New(), errors.New("x")), "boom")
}

func TestMarkMagicLinkSendAbandoned(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE magic_links`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkMagicLinkSendAbandoned(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE magic_links`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkMagicLinkSendAbandoned(ctx, db2, uuid.New()), "boom")
}

func TestListMagicLinksForReconcile_Branches(t *testing.T) {
	ctx := context.Background()
	cols := []string{"id", "email", "token_hash", "return_to", "email_send_status", "email_send_attempts", "created_at", "expires_at"}

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM magic_links`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow(uuid.New(), "a@b.com", "h", "/", "pending", 1, time.Now(), time.Now()))
	out, err := ListMagicLinksForReconcile(ctx, db, time.Now(), 0) // default limit
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM magic_links`).WillReturnError(errors.New("qerr"))
	_, err = ListMagicLinksForReconcile(ctx, db2, time.Now(), 10)
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM magic_links`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListMagicLinksForReconcile(ctx, db3, time.Now(), 10)
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM magic_links`).WillReturnRows(
		sqlmock.NewRows(cols).AddRow(uuid.New(), "a@b.com", "h", "/", "pending", 1, time.Now(), time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ListMagicLinksForReconcile(ctx, db4, time.Now(), 10)
	require.ErrorContains(t, err, "rowerr")
}

func TestUpdateMagicLinkTokenHash(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE magic_links`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateMagicLinkTokenHash(ctx, db, uuid.New(), "newhash"))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE magic_links`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateMagicLinkTokenHash(ctx, db2, uuid.New(), "h"), "boom")
}

func TestGetMagicLinkByID_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM magic_links\s+WHERE id`).
		WillReturnRows(sqlmock.NewRows(mlCols()).AddRow(uuid.New(), "a@b.com", "h", "/", time.Now(), nil, time.Now()))
	_, err := GetMagicLinkByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM magic_links\s+WHERE id`).WillReturnError(errNoRows())
	_, err = GetMagicLinkByID(ctx, db2, uuid.New())
	require.ErrorIs(t, err, ErrMagicLinkNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM magic_links\s+WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetMagicLinkByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestGetMagicLinkForConsumption_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE token_hash`).
		WillReturnRows(sqlmock.NewRows(mlCols()).AddRow(uuid.New(), "a@b.com", "h", "/", time.Now(), nil, time.Now()))
	_, err := GetMagicLinkForConsumption(ctx, db, "h")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE token_hash`).WillReturnError(errNoRows())
	_, err = GetMagicLinkForConsumption(ctx, db2, "h")
	require.ErrorIs(t, err, ErrMagicLinkNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE token_hash`).WillReturnError(errors.New("boom"))
	_, err = GetMagicLinkForConsumption(ctx, db3, "h")
	require.ErrorContains(t, err, "boom")
}

func TestConsumeMagicLink_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE magic_links SET consumed_at`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := ConsumeMagicLink(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE magic_links SET consumed_at`).WillReturnResult(sqlmock.NewResult(0, 0))
	ok, err = ConsumeMagicLink(ctx, db2, uuid.New())
	require.NoError(t, err)
	require.False(t, ok)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE magic_links SET consumed_at`).WillReturnError(errors.New("boom"))
	_, err = ConsumeMagicLink(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE magic_links SET consumed_at`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = ConsumeMagicLink(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "raerr")
}
