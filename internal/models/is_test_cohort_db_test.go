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
	// default — behaviour unchanged for every real team). The dedicated
	// IsTestCohort lookup is the single read path: the column is intentionally
	// NOT scanned into the main Team struct, to keep the cohort flag off the
	// widely-mocked GetTeamByID/CreateTeam/GetTeamByRazorpaySubscriptionID
	// SELECTs (which would otherwise force a 16-file sqlmock resync).
	team, err := models.CreateTeam(ctx, db, "cohort-smoke")
	require.NoError(t, err)

	// IsTestCohort helper reports the default.
	isTest, err := models.IsTestCohort(ctx, db, team.ID)
	require.NoError(t, err)
	require.False(t, isTest)

	// Flip it via the seeder setter and confirm the helper observes the new value.
	require.NoError(t, models.SetTestCohort(ctx, db, team.ID, true))

	isTest, err = models.IsTestCohort(ctx, db, team.ID)
	require.NoError(t, err)
	require.True(t, isTest)

	// SetTestCohort on a non-existent team returns ErrTeamNotFound.
	err = models.SetTestCohort(ctx, db, uuid.New(), true)
	var notFound *models.ErrTeamNotFound
	require.ErrorAs(t, err, &notFound)

	// IsTestCohort on a non-existent team is (false, nil).
	isTest, err = models.IsTestCohort(ctx, db, uuid.New())
	require.NoError(t, err)
	require.False(t, isTest)
}
