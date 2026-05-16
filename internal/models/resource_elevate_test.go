package models_test

// resource_elevate_test.go — unit tests for ElevateResourceTiersByTeam,
// the function the Razorpay subscription.charged webhook calls to turn a
// freshly-claimed-but-anonymous (or already-permanent-being-upgraded)
// resource into the customer's paid tier.
//
// This is revenue-critical code: a regression here means either paying
// customers don't get their upgraded limits, or non-paying customers get
// their anonymous TTL silently cleared. Both are bad.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func requireDBElevate(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

// Helper: inserts a resource directly via SQL so we can pin tier + expires_at
// to specific test fixtures without going through CreateResource's defaults.
func insertResourceForTest(t *testing.T, db *sql.DB, teamID *uuid.UUID, tier string, expiresAt sql.NullTime) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var teamUUID interface{}
	if teamID != nil {
		teamUUID = *teamID
	} else {
		teamUUID = nil
	}
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, expires_at)
		VALUES ($1, $2, 'redis', $3, 'production', 'active', $4)
		RETURNING id
	`, teamUUID, uuid.NewString(), tier, expiresAt).Scan(&id)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE id = $1`, id) })
	return id
}

// TestElevate_AnonymousTeamOwned_GetsElevatedAndPermanent verifies the new
// pay-from-day-one path: a resource claim transferred ownership but kept
// the 24h TTL; the webhook fires and must (a) clear the TTL and (b) set
// the paid tier.
func TestElevate_AnonymousTeamOwned_GetsElevatedAndPermanent(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	// Anonymous resource, team-owned, TTL still in the future (10h away).
	resourceID := insertResourceForTest(t, db, &teamID, "anonymous",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true})

	err := models.ElevateResourceTiersByTeam(context.Background(), db, teamID, "hobby")
	require.NoError(t, err)

	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM resources WHERE id = $1`, resourceID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "hobby", tier, "anonymous resource must be elevated to paid tier")
	assert.False(t, expiresAt.Valid, "expires_at must be cleared on elevation")
}

// TestElevate_AlreadyPermanent_TierUpgraded verifies the legacy upgrade path:
// an existing paid resource (tier=hobby, expires_at=NULL) being upgraded to
// pro should still get its tier flipped.
func TestElevate_AlreadyPermanent_TierUpgraded(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	resourceID := insertResourceForTest(t, db, &teamID, "hobby",
		sql.NullTime{Valid: false})

	err := models.ElevateResourceTiersByTeam(context.Background(), db, teamID, "pro")
	require.NoError(t, err)

	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM resources WHERE id = $1`, resourceID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "pro", tier)
	assert.False(t, expiresAt.Valid, "expires_at remains NULL after upgrade")
}

// TestElevate_AlreadyExpired_NotResurrected verifies the reaper-race guard:
// a resource whose TTL has already elapsed (but reaper hasn't deleted yet)
// should NOT be elevated — paying after expiry doesn't bring it back.
func TestElevate_AlreadyExpired_NotResurrected(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	// Anonymous resource, team-owned, but TTL elapsed 1h ago.
	resourceID := insertResourceForTest(t, db, &teamID, "anonymous",
		sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true})

	err := models.ElevateResourceTiersByTeam(context.Background(), db, teamID, "hobby")
	require.NoError(t, err)

	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM resources WHERE id = $1`, resourceID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", tier, "expired resource must NOT be elevated")
	assert.True(t, expiresAt.Valid, "expires_at must remain set on expired resource")
}

// TestElevate_FreeTeamOwned_GetsElevatedAndPermanent verifies the
// claimed-but-unpaid path: after onboarding.Claim flips tier from
// `anonymous` -> `free`, the Razorpay webhook fires and must (a) clear the
// TTL and (b) lift the tier to the paid value. Same mechanics as the
// anonymous case — proves the query doesn't filter on a specific tier value.
func TestElevate_FreeTeamOwned_GetsElevatedAndPermanent(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	// Free resource (post-claim), team-owned, TTL still in the future (10h away).
	resourceID := insertResourceForTest(t, db, &teamID, "free",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true})

	err := models.ElevateResourceTiersByTeam(context.Background(), db, teamID, "hobby")
	require.NoError(t, err)

	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM resources WHERE id = $1`, resourceID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "hobby", tier,
		"free resource must be elevated to paid tier (free -> hobby on first payment)")
	assert.False(t, expiresAt.Valid,
		"expires_at must be cleared on elevation regardless of source tier")
}

// TestElevate_OtherTeam_Untouched verifies isolation — elevating team A
// must not affect team B's resources.
func TestElevate_OtherTeam_Untouched(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))

	// Team B owns an anonymous resource — shouldn't be touched.
	resourceB := insertResourceForTest(t, db, &teamB, "anonymous",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true})

	err := models.ElevateResourceTiersByTeam(context.Background(), db, teamA, "pro")
	require.NoError(t, err)

	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM resources WHERE id = $1`, resourceB).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", tier, "team B resource must not be touched")
	assert.True(t, expiresAt.Valid, "team B expires_at must remain set")
}

// ---- Deployment elevation tests ----

// insertDeploymentForTest inserts a deployment row with specific tier and expires_at
// so we can test elevation without going through the full provision flow.
func insertDeploymentForTest(t *testing.T, db *sql.DB, teamID uuid.UUID, tier string, expiresAt sql.NullTime, ttlPolicy string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO deployments (team_id, tier, expires_at, ttl_policy, status, env)
		VALUES ($1, $2, $3, $4, 'healthy', 'development')
		RETURNING id
	`, teamID, tier, expiresAt, ttlPolicy).Scan(&id)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM deployments WHERE id = $1`, id) })
	return id
}

// TestElevateDeployments_AnonymousTTL_GetsClearedOnUpgrade verifies the
// P1-cluster-C fix: when a paying user's subscription.charged fires, an
// anonymous deployment (still within its 24h TTL) must be elevated to the
// paid tier and have its TTL cleared and ttl_policy set to 'permanent'.
func TestElevateDeployments_AnonymousTTL_GetsClearedOnUpgrade(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	deployID := insertDeploymentForTest(t, db, teamID, "anonymous",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true}, "auto_24h")

	err := models.ElevateDeploymentTiersByTeam(context.Background(), db, teamID, "hobby")
	require.NoError(t, err)

	var tier, ttlPolicy string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at, ttl_policy FROM deployments WHERE id = $1`, deployID).
		Scan(&tier, &expiresAt, &ttlPolicy)
	require.NoError(t, err)
	assert.Equal(t, "hobby", tier, "deployment tier must be elevated")
	assert.False(t, expiresAt.Valid, "expires_at must be cleared on elevation")
	assert.Equal(t, "permanent", ttlPolicy, "ttl_policy must be set to permanent")
}

// TestElevateDeployments_TerminalStatuses_Skipped verifies that deleted and
// expired deployments are NOT resurrected during an upgrade.
func TestElevateDeployments_TerminalStatuses_Skipped(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))

	// Insert two terminal-status deployments. We simulate by inserting normally
	// then updating status so we can track the IDs.
	deletedID := insertDeploymentForTest(t, db, teamID, "anonymous",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true}, "auto_24h")
	_, err := db.Exec(`UPDATE deployments SET status = 'deleted' WHERE id = $1`, deletedID)
	require.NoError(t, err)

	expiredID := insertDeploymentForTest(t, db, teamID, "anonymous",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true}, "auto_24h")
	_, err = db.Exec(`UPDATE deployments SET status = 'expired' WHERE id = $1`, expiredID)
	require.NoError(t, err)

	err = models.ElevateDeploymentTiersByTeam(context.Background(), db, teamID, "hobby")
	require.NoError(t, err)

	for _, id := range []uuid.UUID{deletedID, expiredID} {
		var tier string
		var expiresAt sql.NullTime
		err = db.QueryRow(`SELECT tier, expires_at FROM deployments WHERE id = $1`, id).
			Scan(&tier, &expiresAt)
		require.NoError(t, err)
		assert.Equal(t, "anonymous", tier, "terminal deployment must not be elevated (id=%s)", id)
		assert.True(t, expiresAt.Valid, "terminal deployment expires_at must remain set (id=%s)", id)
	}
}

// ---- Stack elevation tests ----

// insertStackForTest inserts a stack row with specific tier and expires_at.
func insertStackForTest(t *testing.T, db *sql.DB, teamID uuid.UUID, tier string, expiresAt sql.NullTime) uuid.UUID {
	t.Helper()
	slug := uuid.NewString()[:8] // short random slug to avoid unique-index collisions
	var id uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO stacks (team_id, slug, tier, expires_at, status, env)
		VALUES ($1, $2, $3, $4, 'healthy', 'development')
		RETURNING id
	`, teamID, slug, tier, expiresAt).Scan(&id)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM stacks WHERE id = $1`, id) })
	return id
}

// TestElevateStacks_AnonymousTTL_GetsClearedOnUpgrade verifies the
// P1-cluster-C fix for stacks: a paying user's subscription.charged fires
// and an anonymous stack (still within its 24h TTL) must be elevated to the
// paid tier and have its TTL cleared.
func TestElevateStacks_AnonymousTTL_GetsClearedOnUpgrade(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	stackID := insertStackForTest(t, db, teamID, "anonymous",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true})

	err := models.ElevateStackTiersByTeam(context.Background(), db, teamID, "hobby")
	require.NoError(t, err)

	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM stacks WHERE id = $1`, stackID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "hobby", tier, "stack tier must be elevated")
	assert.False(t, expiresAt.Valid, "expires_at must be cleared on elevation")
}

// TestElevateStacks_DeletingStatus_Skipped verifies that mid-teardown stacks
// (status='deleting') are NOT touched during an upgrade.
func TestElevateStacks_DeletingStatus_Skipped(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	stackID := insertStackForTest(t, db, teamID, "anonymous",
		sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true})
	_, err := db.Exec(`UPDATE stacks SET status = 'deleting' WHERE id = $1`, stackID)
	require.NoError(t, err)

	err = models.ElevateStackTiersByTeam(context.Background(), db, teamID, "hobby")
	require.NoError(t, err)

	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM stacks WHERE id = $1`, stackID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", tier, "deleting stack must not be elevated")
	assert.True(t, expiresAt.Valid, "deleting stack expires_at must remain set")
}

// ---- UpgradeTeamAllTiers integration tests ----

// TestUpgradeTeamAllTiers_HobbyTeam_PromotesResourceDeploymentAndStack is the
// primary P1-cluster-C regression test. A hobby team with one anonymous
// resource, one anonymous deployment, and one anonymous stack all with live
// TTLs — after UpgradeTeamAllTiers to "pro" all three rows must have tier=pro
// and expires_at=NULL.
func TestUpgradeTeamAllTiers_HobbyTeam_PromotesResourceDeploymentAndStack(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	ttl := sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true}

	resourceID := insertResourceForTest(t, db, &teamID, "anonymous", ttl)
	deployID := insertDeploymentForTest(t, db, teamID, "anonymous", ttl, "auto_24h")
	stackID := insertStackForTest(t, db, teamID, "anonymous", ttl)

	err := models.UpgradeTeamAllTiers(context.Background(), db, teamID, "pro")
	require.NoError(t, err)

	// Verify resource elevated.
	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM resources WHERE id = $1`, resourceID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "pro", tier, "resource tier must be elevated")
	assert.False(t, expiresAt.Valid, "resource expires_at must be cleared")

	// Verify deployment elevated.
	var ttlPolicy string
	err = db.QueryRow(`SELECT tier, expires_at, ttl_policy FROM deployments WHERE id = $1`, deployID).
		Scan(&tier, &expiresAt, &ttlPolicy)
	require.NoError(t, err)
	assert.Equal(t, "pro", tier, "deployment tier must be elevated")
	assert.False(t, expiresAt.Valid, "deployment expires_at must be cleared")
	assert.Equal(t, "permanent", ttlPolicy, "deployment ttl_policy must be permanent")

	// Verify stack elevated.
	err = db.QueryRow(`SELECT tier, expires_at FROM stacks WHERE id = $1`, stackID).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "pro", tier, "stack tier must be elevated")
	assert.False(t, expiresAt.Valid, "stack expires_at must be cleared")

	// Verify team tier updated.
	var planTier string
	err = db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1`, teamID).Scan(&planTier)
	require.NoError(t, err)
	assert.Equal(t, "pro", planTier, "team plan_tier must be updated")
}

// TestUpgradeTeamAllTiers_OtherTeam_Untouched verifies cross-team isolation:
// upgrading team A must not affect any of team B's rows (resource, deployment, stack).
func TestUpgradeTeamAllTiers_OtherTeam_Untouched(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	ttl := sql.NullTime{Time: time.Now().Add(10 * time.Hour), Valid: true}

	resB := insertResourceForTest(t, db, &teamB, "anonymous", ttl)
	depB := insertDeploymentForTest(t, db, teamB, "anonymous", ttl, "auto_24h")
	stkB := insertStackForTest(t, db, teamB, "anonymous", ttl)

	err := models.UpgradeTeamAllTiers(context.Background(), db, teamA, "pro")
	require.NoError(t, err)

	// Team B resource untouched.
	var tier string
	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT tier, expires_at FROM resources WHERE id = $1`, resB).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", tier, "team B resource must not be elevated")
	assert.True(t, expiresAt.Valid, "team B resource expires_at must remain set")

	// Team B deployment untouched.
	err = db.QueryRow(`SELECT tier, expires_at FROM deployments WHERE id = $1`, depB).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", tier, "team B deployment must not be elevated")
	assert.True(t, expiresAt.Valid, "team B deployment expires_at must remain set")

	// Team B stack untouched.
	err = db.QueryRow(`SELECT tier, expires_at FROM stacks WHERE id = $1`, stkB).
		Scan(&tier, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", tier, "team B stack must not be elevated")
	assert.True(t, expiresAt.Valid, "team B stack expires_at must remain set")
}
