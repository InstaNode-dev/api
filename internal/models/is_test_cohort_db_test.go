package models_test

// is_test_cohort_db_test.go — DB-backed smoke for migration 067
// (teams.is_test_cohort). Asserts the column exists, defaults to false, is
// scanned onto the Team struct, and round-trips through SetTestCohort /
// IsTestCohort. Skips when TEST_DATABASE_URL is unset so the suite runs
// cleanly without Postgres.

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func TestIsTestCohort_MigrationSmokeAndRoundTrip(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	// A freshly-created team defaults to is_test_cohort = false (inert by
	// default — behaviour unchanged for every real team).
	team, err := models.CreateTeam(ctx, db, "cohort-smoke")
	require.NoError(t, err)
	require.False(t, team.IsTestCohort, "new team must default to is_test_cohort=false")

	// IsTestCohort helper agrees on the default.
	isTest, err := models.IsTestCohort(ctx, db, team.ID)
	require.NoError(t, err)
	require.False(t, isTest)

	// Flip it via the seeder setter and confirm both the helper and the
	// GetTeamByID scan path observe the new value.
	require.NoError(t, models.SetTestCohort(ctx, db, team.ID, true))

	isTest, err = models.IsTestCohort(ctx, db, team.ID)
	require.NoError(t, err)
	require.True(t, isTest)

	reread, err := models.GetTeamByID(ctx, db, team.ID)
	require.NoError(t, err)
	require.True(t, reread.IsTestCohort, "GetTeamByID must scan is_test_cohort")

	// SetTestCohort on a non-existent team returns ErrTeamNotFound.
	err = models.SetTestCohort(ctx, db, uuid.New(), true)
	var notFound *models.ErrTeamNotFound
	require.ErrorAs(t, err, &notFound)

	// IsTestCohort on a non-existent team is (false, nil).
	isTest, err = models.IsTestCohort(ctx, db, uuid.New())
	require.NoError(t, err)
	require.False(t, isTest)
}
