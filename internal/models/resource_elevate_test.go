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
