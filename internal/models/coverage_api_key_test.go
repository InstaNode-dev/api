package models

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndHashAPIKey(t *testing.T) {
	pt, err := GenerateAPIKeyPlaintext()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(pt, APIKeyPrefix))
	h := HashAPIKey(pt)
	require.Len(t, h, 64) // sha256 hex
	require.Equal(t, h, HashAPIKey(pt))
}

func TestHasScope(t *testing.T) {
	k := &APIKey{Scopes: []string{"write"}}
	require.True(t, k.HasScope("read"))
	require.True(t, k.HasScope("write"))
	require.False(t, k.HasScope("admin"))
	require.False(t, k.HasScope("bogus"))
	admin := &APIKey{Scopes: []string{"ADMIN"}}
	require.True(t, admin.HasScope("admin"))
	none := &APIKey{Scopes: []string{"bad"}}
	require.False(t, none.HasScope("read"))
}

func apiKeyCols() []string {
	return []string{"id", "team_id", "created_by", "name", "key_hash", "scopes", "last_used_at", "revoked_at", "created_at"}
}

func TestCreateAPIKey_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO api_keys`).
		WillReturnRows(sqlmock.NewRows(apiKeyCols()).AddRow(uuid.New(), uuid.New(), nil, "n", "h", pq.Array([]string{"read", "write"}), nil, nil, time.Now()))
	got, err := CreateAPIKey(ctx, db, uuid.New(), uuid.NullUUID{}, "n", "h", nil) // nil scopes -> default
	require.NoError(t, err)
	require.Equal(t, "n", got.Name)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO api_keys`).WillReturnError(errors.New("boom"))
	_, err = CreateAPIKey(ctx, db2, uuid.New(), uuid.NullUUID{}, "n", "h", []string{"admin"})
	require.ErrorContains(t, err, "boom")
}

func TestGetAPIKeyByHash_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM api_keys WHERE key_hash`).
		WillReturnRows(sqlmock.NewRows(apiKeyCols()).AddRow(uuid.New(), uuid.New(), nil, "n", "h", pq.Array([]string{"read"}), nil, nil, time.Now()))
	got, err := GetAPIKeyByHash(ctx, db, "h")
	require.NoError(t, err)
	require.Equal(t, "n", got.Name)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM api_keys WHERE key_hash`).WillReturnError(errNoRows())
	_, err = GetAPIKeyByHash(ctx, db2, "h")
	require.ErrorIs(t, err, ErrAPIKeyNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM api_keys WHERE key_hash`).WillReturnError(errors.New("boom"))
	_, err = GetAPIKeyByHash(ctx, db3, "h")
	require.ErrorContains(t, err, "boom")
}

func TestTouchAPIKey(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE api_keys SET last_used_at`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, TouchAPIKey(ctx, db, uuid.New()))
}

func TestListAPIKeysByTeam_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM api_keys WHERE team_id`).
		WillReturnRows(sqlmock.NewRows(apiKeyCols()).AddRow(uuid.New(), uuid.New(), nil, "n", "h", pq.Array([]string{"read"}), nil, nil, time.Now()))
	out, err := ListAPIKeysByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM api_keys WHERE team_id`).WillReturnError(errors.New("qerr"))
	_, err = ListAPIKeysByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM api_keys WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListAPIKeysByTeam(ctx, db3, uuid.New())
	require.Error(t, err)
}

func TestRevokeAPIKey_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE api_keys SET revoked_at`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, RevokeAPIKey(ctx, db, uuid.New(), uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE api_keys SET revoked_at`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, RevokeAPIKey(ctx, db2, uuid.New(), uuid.New()), ErrAPIKeyNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE api_keys SET revoked_at`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, RevokeAPIKey(ctx, db3, uuid.New(), uuid.New()), "boom")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE api_keys SET revoked_at`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	require.ErrorContains(t, RevokeAPIKey(ctx, db4, uuid.New(), uuid.New()), "raerr")
}
