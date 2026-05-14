package models_test

// users_is_primary_test.go — DB-backed tests covering migration 029's
// is_primary column on users. Skips when TEST_DATABASE_URL is unset so
// the suite runs cleanly without Postgres.
//
// Asserts:
//   1. After migration backfill, exactly one user per team is_primary.
//   2. Inserting a second primary user for the same team fails with a
//      unique-violation from uq_users_one_primary_per_team.
//   3. CreateUser flips is_primary on the FIRST user of a team and
//      leaves it false on subsequent users.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func requireDBPrimary(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

// seedPrimaryTeam inserts a fresh team and returns its id.
func seedPrimaryTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`INSERT INTO teams (name) VALUES ('primary-test') RETURNING id`).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestUsersIsPrimary_BackfillExactlyOnePerTeam(t *testing.T) {
	requireDBPrimary(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := seedPrimaryTeam(t, db)

	// Insert two users in created_at order. The first should be flipped
	// to is_primary=true by CreateUser's NOT EXISTS check; the second
	// should land with is_primary=false.
	_, err := models.CreateUser(context.Background(), db, teamID,
		"first-primary-"+uuid.NewString()+"@example.com", "", "", "owner")
	require.NoError(t, err)
	_, err = models.CreateUser(context.Background(), db, teamID,
		"second-member-"+uuid.NewString()+"@example.com", "", "", "member")
	require.NoError(t, err)

	// Read back: confirm exactly one primary, and it's the earliest user.
	var primaryCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM users WHERE team_id = $1 AND is_primary = true`, teamID).Scan(&primaryCount)
	require.NoError(t, err)
	assert.Equal(t, 1, primaryCount, "team must have exactly one primary user")

	var firstEmail, primaryEmail string
	require.NoError(t, db.QueryRow(`
		SELECT email FROM users WHERE team_id = $1 ORDER BY created_at ASC LIMIT 1
	`, teamID).Scan(&firstEmail))
	require.NoError(t, db.QueryRow(`
		SELECT email FROM users WHERE team_id = $1 AND is_primary = true
	`, teamID).Scan(&primaryEmail))
	assert.Equal(t, firstEmail, primaryEmail, "is_primary should track the earliest-created user")
}

func TestUsersIsPrimary_SecondPrimaryViolatesUniqueIndex(t *testing.T) {
	requireDBPrimary(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := seedPrimaryTeam(t, db)

	// Seed one primary user via CreateUser (which flips is_primary).
	_, err := models.CreateUser(context.Background(), db, teamID,
		"the-primary-"+uuid.NewString()+"@example.com", "", "", "owner")
	require.NoError(t, err)

	// Direct INSERT with is_primary=true MUST fail on the partial
	// unique index uq_users_one_primary_per_team.
	_, err = db.Exec(`
		INSERT INTO users (team_id, email, role, is_primary)
		VALUES ($1, $2, 'member', true)
	`, teamID, "second-primary-"+uuid.NewString()+"@example.com")
	require.Error(t, err, "expected unique-index violation on second primary insert")
	assert.True(t,
		strings.Contains(err.Error(), "uq_users_one_primary_per_team") ||
			strings.Contains(strings.ToLower(err.Error()), "unique"),
		"expected unique-violation error, got %v", err)
}

func TestUsersIsPrimary_CreateUserOnlyFlipsFirst(t *testing.T) {
	requireDBPrimary(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := seedPrimaryTeam(t, db)

	// First user → is_primary should be true.
	u1, err := models.CreateUser(context.Background(), db, teamID,
		"u1-"+uuid.NewString()+"@example.com", "", "", "owner")
	require.NoError(t, err)

	// Second user → is_primary should be false.
	u2, err := models.CreateUser(context.Background(), db, teamID,
		"u2-"+uuid.NewString()+"@example.com", "", "", "member")
	require.NoError(t, err)

	var u1Primary, u2Primary bool
	require.NoError(t, db.QueryRow(`SELECT is_primary FROM users WHERE id = $1`, u1.ID).Scan(&u1Primary))
	require.NoError(t, db.QueryRow(`SELECT is_primary FROM users WHERE id = $1`, u2.ID).Scan(&u2Primary))
	assert.True(t, u1Primary, "first user must be is_primary")
	assert.False(t, u2Primary, "second user must NOT be is_primary")
}
