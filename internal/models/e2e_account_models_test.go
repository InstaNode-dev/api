package models_test

// e2e_account_models_test.go — DB-backed coverage for the model functions
// backing the CI-only ephemeral-test-account surface:
//   - CreateTestCohortTeam      (is_test_cohort=true at INSERT time)
//   - DeleteTeamHard            (hard-delete + idempotent re-delete)
//   - MarkTeamResourcesForReaper(tier→free + expires_at→now so the reaper reaps)
//
// Skips when TEST_DATABASE_URL is unset.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func skipUnlessE2EModelsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

func TestCreateTestCohortTeam_SetsCohortFlag(t *testing.T) {
	skipUnlessE2EModelsDB(t)
	ctx := context.Background()
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	team, err := models.CreateTestCohortTeam(ctx, db, "cohort-mint")
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, team.ID)
	require.Equal(t, "free", team.PlanTier, "minted cohort team starts at free")

	isCohort, err := models.IsTestCohort(ctx, db, team.ID)
	require.NoError(t, err)
	require.True(t, isCohort, "CreateTestCohortTeam must set is_test_cohort at INSERT time")

	// And the ordinary CreateTeam path must NOT set it (contrast — ensures the
	// flag is only ever set by the cohort constructor / seeder).
	real, err := models.CreateTeam(ctx, db, "real-team")
	require.NoError(t, err)
	realCohort, err := models.IsTestCohort(ctx, db, real.ID)
	require.NoError(t, err)
	require.False(t, realCohort)
}

func TestDeleteTeamHard_DeletesAndIsIdempotent(t *testing.T) {
	skipUnlessE2EModelsDB(t)
	ctx := context.Background()
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	team, err := models.CreateTestCohortTeam(ctx, db, "to-delete")
	require.NoError(t, err)

	deleted, err := models.DeleteTeamHard(ctx, db, team.ID)
	require.NoError(t, err)
	require.True(t, deleted, "first delete removes the row")

	// Row is gone.
	_, err = models.GetTeamByID(ctx, db, team.ID)
	var notFound *models.ErrTeamNotFound
	require.ErrorAs(t, err, &notFound)

	// Idempotent: re-delete reports false, no error.
	deleted, err = models.DeleteTeamHard(ctx, db, team.ID)
	require.NoError(t, err)
	require.False(t, deleted, "re-delete of a gone team is a clean no-op")
}

// TestDeleteTeamHard_CascadesPendingCheckouts is the regression guard for
// migration 069: a team that started a checkout has a pending_checkouts row, and
// before 069 that FK had no ON DELETE CASCADE — so DeleteTeamHard (the e2e reap)
// failed with `pending_checkouts_team_id_fkey` and the cohort team LEAKED. This
// surfaced the instant test-cohort checkout was armed (a cohort Pro upgrade
// creates a pending_checkouts row → the reap 503'd). With the cascade, deleting
// the team removes its pending_checkouts rows and the reap succeeds.
func TestDeleteTeamHard_CascadesPendingCheckouts(t *testing.T) {
	skipUnlessE2EModelsDB(t)
	ctx := context.Background()
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	team, err := models.CreateTestCohortTeam(ctx, db, "cohort-with-checkout")
	require.NoError(t, err)

	// Seed a pending_checkouts row (the exact FK that used to block the delete).
	subID := "sub_test_" + uuid.NewString()
	_, err = db.ExecContext(ctx,
		`INSERT INTO pending_checkouts (subscription_id, team_id, customer_email, plan_tier)
		 VALUES ($1, $2, $3, $4)`,
		subID, team.ID, "cohort@example.com", "pro")
	require.NoError(t, err, "seed pending_checkouts")

	// Pre-069 this returned the FK-violation error; with the cascade it succeeds.
	deleted, err := models.DeleteTeamHard(ctx, db, team.ID)
	require.NoError(t, err, "DeleteTeamHard must cascade pending_checkouts, not error on the FK")
	require.True(t, deleted)

	// The child row is gone too (cascaded), not orphaned.
	var n int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM pending_checkouts WHERE subscription_id = $1`, subID).Scan(&n))
	require.Equal(t, 0, n, "pending_checkouts row must be cascade-deleted with the team")
}

func TestMarkTeamResourcesForReaper_RetiersAndExpires(t *testing.T) {
	skipUnlessE2EModelsDB(t)
	ctx := context.Background()
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	team, err := models.CreateTestCohortTeam(ctx, db, "reaper-mark")
	require.NoError(t, err)

	// Two resources at a paid tier with no expiry, plus one already-deleted row
	// that must be left alone.
	var activeID, pausedID, deletedID string
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1, 'postgres', 'pro', 'active') RETURNING id::text`, team.ID).Scan(&activeID))
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1, 'redis', 'pro', 'paused') RETURNING id::text`, team.ID).Scan(&pausedID))
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1, 'mongodb', 'pro', 'deleted') RETURNING id::text`, team.ID).Scan(&deletedID))

	marked, err := models.MarkTeamResourcesForReaper(ctx, db, team.ID)
	require.NoError(t, err)
	require.Equal(t, int64(2), marked, "only non-deleted rows are marked")

	assertMarked := func(id string, wantMarked bool) {
		var tier string
		var expiresAt sql.NullTime
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT tier, expires_at FROM resources WHERE id = $1`, id).Scan(&tier, &expiresAt))
		if wantMarked {
			require.Equal(t, "free", tier)
			require.True(t, expiresAt.Valid)
			require.True(t, expiresAt.Time.Before(time.Now().Add(time.Minute)))
		} else {
			require.Equal(t, "pro", tier, "deleted row must be untouched")
			require.False(t, expiresAt.Valid)
		}
	}
	assertMarked(activeID, true)
	assertMarked(pausedID, true)
	assertMarked(deletedID, false)

	// Idempotent: re-marking already-marked rows re-stamps without error.
	marked, err = models.MarkTeamResourcesForReaper(ctx, db, team.ID)
	require.NoError(t, err)
	require.Equal(t, int64(2), marked)
}
