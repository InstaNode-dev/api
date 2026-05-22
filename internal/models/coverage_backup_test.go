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

func backupCols() []string {
	return []string{"id", "resource_id", "status", "backup_kind", "started_at", "finished_at", "s3_key", "size_bytes", "tier_at_backup", "error_summary", "triggered_by", "created_at", "sha256"}
}

func backupRow() *sqlmock.Rows {
	return sqlmock.NewRows(backupCols()).AddRow(uuid.New(), uuid.New(), "pending", "manual", time.Now(), nil, nil, nil, nil, nil, nil, time.Now(), nil)
}

func restoreCols() []string {
	return []string{"id", "resource_id", "backup_id", "status", "started_at", "finished_at", "error_summary", "triggered_by", "created_at"}
}

func restoreRow() *sqlmock.Rows {
	return sqlmock.NewRows(restoreCols()).AddRow(uuid.New(), uuid.New(), uuid.New(), "pending", time.Now(), nil, nil, uuid.New(), time.Now())
}

func TestCreateBackupRow_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO resource_backups`).WillReturnRows(backupRow())
	got, err := CreateBackupRow(ctx, db, CreateBackupParams{ResourceID: uuid.New(), BackupKind: BackupKindManual})
	require.NoError(t, err)
	require.Equal(t, "pending", got.Status)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO resource_backups`).WillReturnError(errors.New("boom"))
	_, err = CreateBackupRow(ctx, db2, CreateBackupParams{ResourceID: uuid.New()})
	require.ErrorContains(t, err, "boom")
}

func TestGetBackupByID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM resource_backups\s+WHERE id`).WillReturnRows(backupRow())
	_, err := GetBackupByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM resource_backups\s+WHERE id`).WillReturnError(errNoRows())
	_, err = GetBackupByID(ctx, db2, uuid.New())
	require.ErrorIs(t, err, errNoRows())
}

func TestGetBackupByIDForTeam_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM resource_backups b\s+JOIN resources r`).WillReturnRows(backupRow())
	_, err := GetBackupByIDForTeam(ctx, db, uuid.New(), uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`JOIN resources r`).WillReturnError(errNoRows())
	_, err = GetBackupByIDForTeam(ctx, db2, uuid.New(), uuid.New())
	require.ErrorIs(t, err, errNoRows())
}

func TestHasInflightRestore_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err := HasInflightRestore(ctx, db, uuid.New(), uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT EXISTS`).WillReturnError(errors.New("boom"))
	_, err = HasInflightRestore(ctx, db2, uuid.New(), uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestListBackupsByResource_Branches(t *testing.T) {
	ctx := context.Background()

	// before-zero + default limit
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE resource_id = \$1\s+ORDER BY`).WillReturnRows(backupRow())
	out, err := ListBackupsByResource(ctx, db, uuid.New(), 0, time.Time{})
	require.NoError(t, err)
	require.Len(t, out, 1)

	// before non-zero + over-max limit
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`AND created_at < \$2`).WillReturnRows(sqlmock.NewRows(backupCols()))
	_, err = ListBackupsByResource(ctx, db2, uuid.New(), 9999, time.Now())
	require.NoError(t, err)

	// query error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM resource_backups`).WillReturnError(errors.New("qerr"))
	_, err = ListBackupsByResource(ctx, db3, uuid.New(), 10, time.Time{})
	require.ErrorContains(t, err, "qerr")

	// scan error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM resource_backups`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListBackupsByResource(ctx, db4, uuid.New(), 10, time.Time{})
	require.Error(t, err)

	// rows.Err()
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM resource_backups`).WillReturnRows(backupRow().RowError(0, errors.New("rowerr")))
	_, err = ListBackupsByResource(ctx, db5, uuid.New(), 10, time.Time{})
	require.ErrorContains(t, err, "rowerr")
}

func TestCountBackupsByResource_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`COUNT\(\*\) FROM resource_backups`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
	n, err := CountBackupsByResource(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 7, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`COUNT\(\*\) FROM resource_backups`).WillReturnError(errors.New("boom"))
	_, err = CountBackupsByResource(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestCreateRestoreRow_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO resource_restores`).WillReturnRows(restoreRow())
	got, err := CreateRestoreRow(ctx, db, CreateRestoreParams{ResourceID: uuid.New(), BackupID: uuid.New(), TriggeredBy: uuid.New()})
	require.NoError(t, err)
	require.Equal(t, "pending", got.Status)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO resource_restores`).WillReturnError(errors.New("boom"))
	_, err = CreateRestoreRow(ctx, db2, CreateRestoreParams{})
	require.ErrorContains(t, err, "boom")
}

func TestListRestoresByResource_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM resource_restores\s+WHERE resource_id = \$1\s+ORDER BY`).WillReturnRows(restoreRow())
	out, err := ListRestoresByResource(ctx, db, uuid.New(), 0, time.Time{})
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`AND created_at < \$2`).WillReturnRows(sqlmock.NewRows(restoreCols()))
	_, err = ListRestoresByResource(ctx, db2, uuid.New(), 9999, time.Now())
	require.NoError(t, err)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM resource_restores`).WillReturnError(errors.New("qerr"))
	_, err = ListRestoresByResource(ctx, db3, uuid.New(), 10, time.Time{})
	require.ErrorContains(t, err, "qerr")

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM resource_restores`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListRestoresByResource(ctx, db4, uuid.New(), 10, time.Time{})
	require.Error(t, err)

	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM resource_restores`).WillReturnRows(restoreRow().RowError(0, errors.New("rowerr")))
	_, err = ListRestoresByResource(ctx, db5, uuid.New(), 10, time.Time{})
	require.ErrorContains(t, err, "rowerr")
}

func TestCountRestoresByResource_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`COUNT\(\*\) FROM resource_restores`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	n, err := CountRestoresByResource(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 2, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`COUNT\(\*\) FROM resource_restores`).WillReturnError(errors.New("boom"))
	_, err = CountRestoresByResource(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}
