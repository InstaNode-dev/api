package handlers

// internal_e2e_account_seed_whitebox_test.go — whitebox coverage for the
// with_resources seed error arms (seedFastResources). The happy seed path is
// covered end-to-end by the external suite against a real test DB; these tests
// drive the two failure branches deterministically with sqlmock so the 100%-
// patch gate is satisfied without a flaky "make the real DB fail" dance:
//
//   - CreateResource error  → seedFastResources returns "seed <type>: ..."
//   - MarkResourceActive err → seedFastResources returns "activate seeded ...: ..."

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
)

// resourceReturningRow builds a single fully-populated resources row in the
// exact column order scanResource expects, so a mocked CreateResource INSERT …
// RETURNING parses cleanly and the test can advance to the MarkResourceActive
// step. Values are placeholders — only the shape matters.
func resourceReturningRow() *sqlmock.Rows {
	cols := []string{
		"id", "team_id", "token", "resource_type", "name", "connection_url", "key_prefix", "tier",
		"env", "fingerprint", "cloud_vendor", "country_code", "status", "migration_status",
		"expires_at", "storage_bytes", "provider_resource_id", "created_request_id", "parent_resource_id", "paused_at",
		"last_seen_at", "degraded", "degraded_reason", "last_reconciled_at", "auth_mode", "created_at",
	}
	return sqlmock.NewRows(cols).AddRow(
		uuid.New(), uuid.New(), uuid.New(), "cache", nil, nil, nil, "pro",
		"development", nil, nil, nil, "pending", "none",
		nil, int64(0), nil, nil, nil, nil,
		nil, false, nil, nil, "legacy_open", time.Now(),
	)
}

func TestSeedFastResources_CreateResourceError(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	// First seed type's INSERT fails outright.
	mock.ExpectQuery(`INSERT INTO resources`).WillReturnError(errors.New("insert boom"))

	h := &E2EAccountHandler{db: db, cfg: &config.Config{}}
	toks, serr := h.seedFastResources(context.Background(), uuid.New(), "pro", "")
	require.Error(t, serr)
	require.Contains(t, serr.Error(), "seed")
	require.Contains(t, serr.Error(), "insert boom")
	require.Nil(t, toks)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSeedFastResources_MarkResourceActiveError(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	// INSERT succeeds (returns a pending row); the activate UPDATE then fails.
	mock.ExpectQuery(`INSERT INTO resources`).WillReturnRows(resourceReturningRow())
	mock.ExpectExec(`UPDATE resources SET status = 'active'`).WillReturnError(errors.New("update boom"))

	h := &E2EAccountHandler{db: db, cfg: &config.Config{}}
	toks, serr := h.seedFastResources(context.Background(), uuid.New(), "pro", "")
	require.Error(t, serr)
	require.Contains(t, serr.Error(), "activate seeded")
	require.Contains(t, serr.Error(), "update boom")
	require.Nil(t, toks)
	require.NoError(t, mock.ExpectationsWereMet())
}
