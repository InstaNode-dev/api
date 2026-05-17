package models_test

// deployment_count_test.go — coverage for CountActiveDeploymentsByTeam,
// the helper that powers per-tier deployments_apps enforcement in
// POST /deploy/new (api/internal/handlers/deploy.go).
//
// Skips when TEST_DATABASE_URL is unset (see requireDB in resource_env_test.go).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestCountActiveDeploymentsByTeam_CountsRowsExcludingDeleted asserts that
// the count returns the number of deployment rows whose status is not the
// soft-delete sentinel, and that hard-deleted rows drop out entirely.
func TestCountActiveDeploymentsByTeam_CountsRowsExcludingDeleted(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()

	// Initially: zero.
	n, err := models.CountActiveDeploymentsByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "new team must start with zero deployments")

	// Create three deployments — all default status='building'.
	for i := 0; i < 3; i++ {
		d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
			TeamID: teamID,
			AppID:  "app-count-" + uuid.NewString()[:8],
			Tier:   "hobby",
		})
		require.NoError(t, err)
		defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)
	}

	n, err = models.CountActiveDeploymentsByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, 3, n, "three building deployments must count")

	// Soft-delete one — status='deleted' is treated as "slot freed".
	var killID uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT id FROM deployments WHERE team_id = $1 LIMIT 1`, teamID,
	).Scan(&killID))
	_, err = db.ExecContext(ctx, `UPDATE deployments SET status = 'deleted' WHERE id = $1`, killID)
	require.NoError(t, err)

	n, err = models.CountActiveDeploymentsByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "soft-deleted (status='deleted') row must NOT count toward the cap")

	// Mark another 'failed' — a failed build runs no pod and consumes no
	// compute, so it must free the slot too (P1-B regression guard).
	var failID uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT id FROM deployments WHERE team_id = $1 AND status = 'building' LIMIT 1`, teamID,
	).Scan(&failID))
	_, err = db.ExecContext(ctx, `UPDATE deployments SET status = 'failed' WHERE id = $1`, failID)
	require.NoError(t, err)

	n, err = models.CountActiveDeploymentsByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "failed deployment must NOT count toward the cap")
}

// TestCountActiveDeploymentsByTeam_ExcludesStoppedAndExpired is the P1-E
// regression guard. A 'stopped' deployment is user-paused (pod scaled to
// zero) and an 'expired' deployment's TTL elapsed — neither runs a pod, so
// neither occupies a billable tier slot. The previous negative filter
// (NOT IN deleted/expired/failed) still counted 'stopped', which both
// wedged the tier cap and disagreed with the dashboard usage counter.
func TestCountActiveDeploymentsByTeam_ExcludesStoppedAndExpired(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()

	// Five deployments, one per status: building, deploying, healthy,
	// stopped, expired. Only the first three occupy a slot.
	statuses := []string{"building", "deploying", "healthy", "stopped", "expired"}
	for _, st := range statuses {
		d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
			TeamID: teamID,
			AppID:  "app-st-" + uuid.NewString()[:8],
			Tier:   "pro",
		})
		require.NoError(t, err)
		defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)
		_, err = db.ExecContext(ctx, `UPDATE deployments SET status = $1 WHERE id = $2`, st, d.ID)
		require.NoError(t, err)
	}

	n, err := models.CountActiveDeploymentsByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, 3, n,
		"only building/deploying/healthy occupy a slot — stopped + expired must be excluded")
}

// TestCountActiveDeploymentsByTeam_IsolatesByTeam guards a /24-style
// cross-team mistake: counting another team's deployments would let one
// tenant burn another tenant's quota.
func TestCountActiveDeploymentsByTeam_IsolatesByTeam(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id IN ($1, $2)`, teamA, teamB)

	ctx := context.Background()

	// Team A: 2 deployments. Team B: 1.
	for i := 0; i < 2; i++ {
		d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
			TeamID: teamA,
			AppID:  "app-iso-a-" + uuid.NewString()[:8],
			Tier:   "hobby",
		})
		require.NoError(t, err)
		defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)
	}
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamB,
		AppID:  "app-iso-b-" + uuid.NewString()[:8],
		Tier:   "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	nA, err := models.CountActiveDeploymentsByTeam(ctx, db, teamA)
	require.NoError(t, err)
	nB, err := models.CountActiveDeploymentsByTeam(ctx, db, teamB)
	require.NoError(t, err)

	assert.Equal(t, 2, nA, "team A count must include only team A's rows")
	assert.Equal(t, 1, nB, "team B count must include only team B's rows")
}
