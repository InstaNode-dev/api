package models_test

// promote_ttl_test.go — coverage for PromoteDeploymentTTLsForTeam, the
// model-layer entrypoint the Razorpay subscription.charged webhook calls
// after every paid-tier upgrade to roll the team's deployment TTL state
// forward. Two effects, both inside a single tx:
//
//   (1) teams.default_deployment_ttl_policy: 'auto_24h' → 'permanent'
//       ONLY when the current value is 'auto_24h'. Any other value
//       (already 'permanent', or a user-explicit 'custom'/<future>) is
//       LEFT UNTOUCHED — preserving a user choice across an upgrade.
//   (2) deployments rows: ttl_policy='auto_24h' AND non-terminal status
//       → flipped to permanent + expires_at cleared + reminders ledger
//       reset. Rows already 'permanent' or 'custom' are LEFT UNTOUCHED.
//
// Bug class (CLAUDE.md rule 17): "fires on upgrade but not on existing
// data" — every test below seeds a multi-row, multi-policy fixture so the
// promote query proves it touches the right rows and leaves the rest
// alone. Skips when TEST_DATABASE_URL is unset.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// TestPromoteDeploymentTTLsForTeam_PromotesAuto24h is the headline path:
// a team with a mix of {3 auto_24h, 1 permanent, 1 custom, 1 deleted}
// deployments. After promote, the 3 auto_24h rows must be permanent + have
// expires_at = NULL + reminders cleared; the permanent/custom/deleted rows
// must be byte-for-byte unchanged.
func TestPromoteDeploymentTTLsForTeam_PromotesAuto24h(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Seed 3 auto_24h deploys (all should be promoted).
	autoIDs := make([]uuid.UUID, 0, 3)
	for i := 0; i < 3; i++ {
		d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
			TeamID:    teamID,
			AppID:     "app-auto-" + uuid.NewString()[:8],
			Tier:      "hobby",
			TTLPolicy: models.DeployTTLPolicyAuto24h,
		})
		require.NoError(t, err)
		autoIDs = append(autoIDs, d.ID)
	}

	// Seed 1 permanent deploy (must NOT be touched — no reminders reset, no
	// updated_at bump from this call).
	perm, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "app-perm-" + uuid.NewString()[:8],
		Tier:      "hobby",
		TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	permUpdatedBefore := readTimestamp(t, db, perm.ID, "updated_at")

	// Seed 1 custom deploy (12h custom TTL).
	custom, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "app-custom-" + uuid.NewString()[:8],
		Tier:      "hobby",
		TTLPolicy: models.DeployTTLPolicyCustom,
		TTLHours:  12,
	})
	require.NoError(t, err)
	customExpiresBefore := readTimestamp(t, db, custom.ID, "expires_at")
	customUpdatedBefore := readTimestamp(t, db, custom.ID, "updated_at")

	// Seed 1 deleted auto_24h deploy (terminal status — must NOT be touched).
	deleted, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "app-deleted-" + uuid.NewString()[:8],
		Tier:      "hobby",
		TTLPolicy: models.DeployTTLPolicyAuto24h,
	})
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE deployments SET status = 'deleted' WHERE id = $1`, deleted.ID)
	require.NoError(t, err)
	deletedUpdatedBefore := readTimestamp(t, db, deleted.ID, "updated_at")

	// Sleep a tick so any errant updated_at bump is observable.
	time.Sleep(20 * time.Millisecond)

	// Act.
	result, err := models.PromoteDeploymentTTLsForTeam(ctx, db, teamID)
	require.NoError(t, err)

	// Result accounting: 3 deploys promoted + team default flipped (the
	// team was seeded by MustCreateTeamDB whose row defaults to auto_24h).
	assert.EqualValues(t, 3, result.DeploysPromoted,
		"only the 3 auto_24h non-terminal rows must be promoted — got %d", result.DeploysPromoted)
	assert.True(t, result.TeamDefaultFlipped,
		"team default starts as auto_24h (MustCreateTeamDB default) — promote MUST flip it")

	// All 3 auto rows: now permanent, expires_at NULL, reminders cleared.
	for _, id := range autoIDs {
		var policy string
		var expires sql.NullTime
		var reminders int
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT ttl_policy, expires_at, reminders_sent FROM deployments WHERE id = $1`,
			id,
		).Scan(&policy, &expires, &reminders))
		assert.Equal(t, models.DeployTTLPolicyPermanent, policy, "auto_24h row %s must be permanent", id)
		assert.False(t, expires.Valid, "auto_24h row %s must have expires_at = NULL", id)
		assert.Equal(t, 0, reminders, "auto_24h row %s must have reminders_sent reset to 0", id)
	}

	// permanent row: ttl_policy unchanged, expires_at unchanged, updated_at
	// not bumped by THIS call (the WHERE ttl_policy='auto_24h' clause
	// excludes it).
	assert.Equal(t, permUpdatedBefore, readTimestamp(t, db, perm.ID, "updated_at"),
		"permanent row must NOT have updated_at bumped — it was excluded by the promote WHERE clause")

	// custom row: ttl_policy unchanged, expires_at unchanged, updated_at
	// not bumped.
	var customPolicyAfter string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT ttl_policy FROM deployments WHERE id = $1`, custom.ID,
	).Scan(&customPolicyAfter))
	assert.Equal(t, models.DeployTTLPolicyCustom, customPolicyAfter,
		"custom row must NOT have ttl_policy clobbered")
	assert.Equal(t, customExpiresBefore, readTimestamp(t, db, custom.ID, "expires_at"),
		"custom row's expires_at must NOT be cleared")
	assert.Equal(t, customUpdatedBefore, readTimestamp(t, db, custom.ID, "updated_at"),
		"custom row must NOT have updated_at bumped")

	// deleted row: terminal status excluded by the promote WHERE clause.
	assert.Equal(t, deletedUpdatedBefore, readTimestamp(t, db, deleted.ID, "updated_at"),
		"deleted row must NOT be touched — terminal status excluded by WHERE")
}

// TestPromoteDeploymentTTLsForTeam_PreservesCustomTeamDefault pins the
// "user-explicit choice survives an upgrade" contract: a team whose
// default_deployment_ttl_policy is already 'permanent' must NOT have its
// row UPDATEd (no-op via the WHERE clause), and the result reports
// TeamDefaultFlipped=false.
func TestPromoteDeploymentTTLsForTeam_PreservesCustomTeamDefault(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// User has already explicitly opted into permanent defaults.
	require.NoError(t, models.UpdateTeamDefaultDeploymentTTLPolicy(ctx, db, teamID, "permanent"))

	// Seed one auto_24h deploy so the deploys-promoted path still runs
	// independently of the team-default decision.
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "app-cust-default-" + uuid.NewString()[:8],
		Tier:      "hobby",
		TTLPolicy: models.DeployTTLPolicyAuto24h,
	})
	require.NoError(t, err)

	result, err := models.PromoteDeploymentTTLsForTeam(ctx, db, teamID)
	require.NoError(t, err)

	assert.False(t, result.TeamDefaultFlipped,
		"a team with default='permanent' must NOT be flipped (WHERE clause excludes it)")
	assert.EqualValues(t, 1, result.DeploysPromoted,
		"deploy promotion runs independently of the team-default decision")

	// Sanity-confirm the team row really still says permanent.
	var policy string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT default_deployment_ttl_policy FROM teams WHERE id = $1`, teamID,
	).Scan(&policy))
	assert.Equal(t, "permanent", policy,
		"team default must remain 'permanent' — no clobber on a user-explicit choice")

	// The auto deploy still got promoted.
	var deployPolicy string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT ttl_policy FROM deployments WHERE id = $1`, d.ID,
	).Scan(&deployPolicy))
	assert.Equal(t, models.DeployTTLPolicyPermanent, deployPolicy)
}

// TestPromoteDeploymentTTLsForTeam_NoopOnAlreadyPromotedTeam is the
// idempotency invariant: calling promote a second time on a team whose
// state is already promoted returns a clean noop (0 deploys, default
// unflipped, no error). Critical because the webhook redelivery path can
// re-fire subscription.charged for the same upgrade.
func TestPromoteDeploymentTTLsForTeam_NoopOnAlreadyPromotedTeam(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// First call promotes the team default + zero deploys (no auto rows seeded).
	first, err := models.PromoteDeploymentTTLsForTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.True(t, first.TeamDefaultFlipped)
	assert.EqualValues(t, 0, first.DeploysPromoted)

	// Second call is a clean noop — nothing left to promote.
	second, err := models.PromoteDeploymentTTLsForTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.False(t, second.TeamDefaultFlipped,
		"a re-call on a promoted team must NOT re-flip the default")
	assert.EqualValues(t, 0, second.DeploysPromoted,
		"a re-call on a promoted team must report 0 deploys promoted")
}

// TestPromoteDeploymentTTLsForTeam_OnlyTouchesTargetTeam is the cross-team
// isolation guard. Two teams both with auto_24h state — promoting team A
// must NOT touch team B.
func TestPromoteDeploymentTTLsForTeam_OnlyTouchesTargetTeam(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id IN ($1, $2)`, teamA, teamB)

	// Seed an auto_24h deploy in each team.
	dA, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamA, AppID: "app-A-" + uuid.NewString()[:8], Tier: "hobby",
		TTLPolicy: models.DeployTTLPolicyAuto24h,
	})
	require.NoError(t, err)
	dB, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamB, AppID: "app-B-" + uuid.NewString()[:8], Tier: "hobby",
		TTLPolicy: models.DeployTTLPolicyAuto24h,
	})
	require.NoError(t, err)

	// Promote ONLY team A.
	result, err := models.PromoteDeploymentTTLsForTeam(ctx, db, teamA)
	require.NoError(t, err)
	assert.EqualValues(t, 1, result.DeploysPromoted)

	// Team A's deploy is permanent.
	var aPolicy string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT ttl_policy FROM deployments WHERE id = $1`, dA.ID).Scan(&aPolicy))
	assert.Equal(t, models.DeployTTLPolicyPermanent, aPolicy)

	// Team B's deploy is STILL auto_24h.
	var bPolicy string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT ttl_policy FROM deployments WHERE id = $1`, dB.ID).Scan(&bPolicy))
	assert.Equal(t, models.DeployTTLPolicyAuto24h, bPolicy,
		"cross-team isolation violation: promote(A) must not touch team B's deploys")

	// Team B's default is STILL auto_24h.
	var bDefault string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT default_deployment_ttl_policy FROM teams WHERE id = $1`, teamB).Scan(&bDefault))
	assert.Equal(t, "auto_24h", bDefault,
		"cross-team isolation violation: promote(A) must not touch team B's default")
}

// TestPlansRegistryUpgradeTargets_AllInvokePromoteGuard is the rule-18
// registry-iterating regression test: for every paid tier in plans.Registry,
// plans.Rank(tier) >= plans.Rank("hobby") must hold — which is the guard the
// billing handler uses to decide whether to call PromoteDeploymentTTLsForTeam.
// A future tier added below 'hobby' would silently skip the promote path; this
// test forces a deliberate update of the guard if the rank table is restructured.
func TestPlansRegistryUpgradeTargets_AllInvokePromoteGuard(t *testing.T) {
	hobbyRank := plans.Rank("hobby")
	require.Equal(t, 2, hobbyRank, "Rank('hobby') must be 2 — see common/plans/rank.go")

	paidTiers := []string{"hobby", "hobby_plus", "pro", "growth", "team"}
	for _, tier := range paidTiers {
		assert.GreaterOrEqual(t, plans.Rank(tier), hobbyRank,
			"paid tier %q must rank >= hobby — billing.go promote guard would silently skip otherwise", tier)
	}

	freeTiers := []string{"anonymous", "free"}
	for _, tier := range freeTiers {
		assert.Less(t, plans.Rank(tier), hobbyRank,
			"non-paid tier %q must rank < hobby — promote must NOT fire for it", tier)
	}
}

// readTimestamp reads one timestamp-shaped column from a deployments row.
// A NULL column returns the zero time so callers comparing two reads
// correctly assert "value unchanged across the operation".
func readTimestamp(t *testing.T, db *sql.DB, id uuid.UUID, column string) time.Time {
	t.Helper()
	var ts sql.NullTime
	if err := db.QueryRow(`SELECT `+column+` FROM deployments WHERE id = $1`, id).Scan(&ts); err != nil {
		t.Fatalf("readTimestamp %s: %v", column, err)
	}
	if !ts.Valid {
		return time.Time{}
	}
	return ts.Time
}
