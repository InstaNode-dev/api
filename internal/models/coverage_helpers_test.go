package models

// coverage_helpers_test.go — shared sqlmock plumbing for the coverage_*_test.go
// suite. These tests are white-box (package models) so they can stub the
// unexported package-level seams (generatePromoCode, generateInviteToken,
// generateVerificationToken, …) and reach every DB-error branch deterministically
// without standing up a real Postgres. The integration-style happy-path tests
// that need a real DB live in the existing *_test.go files (package models_test).

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

// newMock returns a sqlmock-backed *sql.DB using the regexp query matcher
// (so test expectations match SQL fragments rather than exact strings) plus
// the mock controller. The DB is closed via t.Cleanup.
func newMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

// errNoRows is the canonical sql.ErrNoRows the model funcs branch on.
func errNoRows() error { return sql.ErrNoRows }

// nullTimeValid returns a non-zero valid sql.NullTime for fixtures that need a
// populated nullable timestamp (e.g. accepted_at).
func nullTimeValid() sql.NullTime { return sql.NullTime{Time: time.Now(), Valid: true} }
