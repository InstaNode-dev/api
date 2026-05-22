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

func vaultCols() []string {
	return []string{"id", "team_id", "env", "key", "encrypted_value", "version", "created_by", "created_at", "updated_at"}
}

func TestCreateVaultSecret_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO vault_secrets`).
		WillReturnRows(sqlmock.NewRows(vaultCols()).AddRow(uuid.New(), uuid.New(), "prod", "K", []byte("ct"), 1, nil, time.Now(), time.Now()))
	got, err := CreateVaultSecret(ctx, db, uuid.New(), "prod", "K", []byte("ct"), uuid.NullUUID{})
	require.NoError(t, err)
	require.Equal(t, "K", got.Key)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO vault_secrets`).WillReturnError(errors.New("boom"))
	_, err = CreateVaultSecret(ctx, db2, uuid.New(), "prod", "K", []byte("ct"), uuid.NullUUID{})
	require.ErrorContains(t, err, "boom")
}

func TestGetVaultSecretLatest_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM vault_secrets`).
		WillReturnRows(sqlmock.NewRows(vaultCols()).AddRow(uuid.New(), uuid.New(), "prod", "K", []byte("ct"), 2, nil, time.Now(), time.Now()))
	_, err := GetVaultSecretLatest(ctx, db, uuid.New(), "prod", "K")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM vault_secrets`).WillReturnError(errNoRows())
	_, err = GetVaultSecretLatest(ctx, db2, uuid.New(), "prod", "K")
	require.ErrorIs(t, err, ErrVaultSecretNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM vault_secrets`).WillReturnError(errors.New("boom"))
	_, err = GetVaultSecretLatest(ctx, db3, uuid.New(), "prod", "K")
	require.ErrorContains(t, err, "boom")
}

func TestGetVaultSecretVersion_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`AND version = \$4`).
		WillReturnRows(sqlmock.NewRows(vaultCols()).AddRow(uuid.New(), uuid.New(), "prod", "K", []byte("ct"), 1, nil, time.Now(), time.Now()))
	_, err := GetVaultSecretVersion(ctx, db, uuid.New(), "prod", "K", 1)
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`AND version = \$4`).WillReturnError(errNoRows())
	_, err = GetVaultSecretVersion(ctx, db2, uuid.New(), "prod", "K", 1)
	require.ErrorIs(t, err, ErrVaultSecretNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`AND version = \$4`).WillReturnError(errors.New("boom"))
	_, err = GetVaultSecretVersion(ctx, db3, uuid.New(), "prod", "K", 1)
	require.ErrorContains(t, err, "boom")
}

func TestListVaultKeys_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT DISTINCT key FROM vault_secrets`).
		WillReturnRows(sqlmock.NewRows([]string{"key"}).AddRow("A").AddRow("B"))
	keys, err := ListVaultKeys(ctx, db, uuid.New(), "prod")
	require.NoError(t, err)
	require.Equal(t, []string{"A", "B"}, keys)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT DISTINCT key FROM vault_secrets`).WillReturnError(errors.New("qerr"))
	_, err = ListVaultKeys(ctx, db2, uuid.New(), "prod")
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT DISTINCT key FROM vault_secrets`).
		WillReturnRows(sqlmock.NewRows([]string{"key"}).AddRow("A").RowError(0, errors.New("rowerr")))
	_, err = ListVaultKeys(ctx, db3, uuid.New(), "prod")
	require.ErrorContains(t, err, "rowerr")
}

func TestListVaultKeys_ScanError(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	// non-string scan source forces Scan error
	mock.ExpectQuery(`SELECT DISTINCT key FROM vault_secrets`).
		WillReturnRows(sqlmock.NewRows([]string{"key"}).AddRow(nil))
	_, err := ListVaultKeys(ctx, db, uuid.New(), "prod")
	require.Error(t, err)
}

func TestDeleteVaultSecret_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM vault_secrets`).WillReturnResult(sqlmock.NewResult(0, 3))
	n, err := DeleteVaultSecret(ctx, db, uuid.New(), "prod", "K")
	require.NoError(t, err)
	require.Equal(t, int64(3), n)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`DELETE FROM vault_secrets`).WillReturnError(errors.New("boom"))
	_, err = DeleteVaultSecret(ctx, db2, uuid.New(), "prod", "K")
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`DELETE FROM vault_secrets`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = DeleteVaultSecret(ctx, db3, uuid.New(), "prod", "K")
	require.ErrorContains(t, err, "raerr")
}

func TestAppendVaultAudit_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO vault_audit_log`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, AppendVaultAudit(ctx, db, uuid.New(), uuid.NullUUID{}, "read", "prod", "K", "1.2.3.4"))

	// empty ip path + error
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`INSERT INTO vault_audit_log`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, AppendVaultAudit(ctx, db2, uuid.New(), uuid.NullUUID{}, "read", "prod", "K", ""), "boom")
}

func TestCountVaultKeysByTeam_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`COUNT\(DISTINCT key\) FROM vault_secrets`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
	n, err := CountVaultKeysByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 4, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`COUNT\(DISTINCT key\) FROM vault_secrets`).WillReturnError(errors.New("boom"))
	_, err = CountVaultKeysByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestCountVaultAudit_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`COUNT\(\*\) FROM vault_audit_log`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	n, err := CountVaultAudit(ctx, db, uuid.New(), "read", "prod", "K")
	require.NoError(t, err)
	require.Equal(t, 2, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`COUNT\(\*\) FROM vault_audit_log`).WillReturnError(errors.New("boom"))
	_, err = CountVaultAudit(ctx, db2, uuid.New(), "read", "prod", "K")
	require.ErrorContains(t, err, "boom")
}
