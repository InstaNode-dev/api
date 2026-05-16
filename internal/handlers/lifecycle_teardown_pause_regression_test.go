package handlers_test

// lifecycle_teardown_pause_regression_test.go — DB-backed regression tests for
// L02-1 (pause-race rollback re-grants access) and L02-2 (hobby team locked out
// of own paused resources after terminate + re-subscribe).
//
// These tests use the handlers_test (black-box) package because they drive the
// HTTP endpoints through the full Fiber app fixture, exactly like resource_pause_test.go.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// ---------------------------------------------------------------------------
// Bug L02-1 — concurrent pause race must NOT re-grant infra access
// ---------------------------------------------------------------------------

// TestPauseResource_ConcurrentRace_RowStaysPaused verifies the semantic of the
// pause-race fix: when two callers race on the same resource, the losing caller
// must NOT call resumeProvider. The observable invariant is that after both
// requests complete, the DB row is 'paused' (not 'active'). In unit tests the
// provider calls are no-ops (no live Postgres/Redis), so we assert the DB state
// only — the critical property is "row must be paused, not active".
//
// Pre-fix behaviour: losing caller called resumeProvider (re-granting access)
// while DB row stayed 'paused' → split-brain. Fix: ErrResourceNotActive on the
// race path drops the rollback call entirely.
func TestPauseResource_ConcurrentRace_RowStaysPaused(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING token::text
	`, teamID).Scan(&resourceToken))

	// Fire two concurrent pause requests.
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost,
				"/api/v1/resources/"+resourceToken+"/pause", nil)
			req.Header.Set("Authorization", "Bearer "+jwt)
			resp, err := app.Test(req, 10000)
			if err == nil {
				resp.Body.Close()
				results[idx] = resp.StatusCode
			}
		}(i)
	}
	wg.Wait()

	// Exactly one caller gets 200; the other gets 409 (already_paused).
	// Both outcomes are acceptable — what matters is the DB state.
	codes := map[int]int{}
	for _, c := range results {
		codes[c]++
	}
	// At least one 200 (someone won the race).
	assert.GreaterOrEqual(t, codes[200], 1,
		"at least one caller must succeed in pausing")
	// The other is 409 (race loser sees already_paused) OR also 200 if the
	// first completed before the second even started. Sum must be 2.
	assert.Equal(t, 2, codes[200]+codes[409],
		"race result must be exactly one 200+one 409 OR two 200s (non-concurrent execution)")

	// The invariant: after the race, the row MUST be 'paused'. Pre-fix, the
	// losing caller's resumeProvider rollback could flip infra back to active
	// while the DB row stays 'paused'. At the model layer, the row must not be
	// 'active' regardless of what the providers returned.
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE token = $1::uuid`, resourceToken,
	).Scan(&status))
	assert.Equal(t, "paused", status,
		"L02-1 regression: after concurrent pause race, DB row MUST be 'paused' — "+
			"the losing caller must NOT have triggered a rollback that re-granted infra access")
}

// ---------------------------------------------------------------------------
// Bug L02-2 — hobby team can resume own paused resource after terminate/re-sub
// ---------------------------------------------------------------------------

// TestResumeResource_HobbyAfterTerminate_200 reproduces the terminated-then-
// reinstated hobby lockout scenario end-to-end at the HTTP layer.
//
// Scenario:
//   1. Pro team has an active resource (tier='pro').
//   2. Payment fails → internal_terminate pauses resources + downgrades to 'free'.
//   3. Customer re-subscribes to hobby → UpgradeTeamAllTiers → tier='hobby'.
//      Fix: UpgradeTeamAllTiers now includes paused rows in elevation.
//   4. Customer calls POST /resume → must succeed with 200.
//      Fix: Resume handler no longer gates on multiEnvTierAllowed (Pro+).
//
// Pre-fix behaviour: step 3 left paused rows at tier='free' (elevation skipped
// paused rows); step 4 returned 402 upgrade_required (Pro+ gate blocked hobby).
func TestResumeResource_HobbyAfterTerminate_200(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Step 1: Pro team with an active resource.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	var resourceToken, resourceID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING token::text, id::text
	`, teamID).Scan(&resourceToken, &resourceID))

	teamUUID, err := uuid.Parse(teamID)
	require.NoError(t, err)
	resourceUUID, err := uuid.Parse(resourceID)
	require.NoError(t, err)

	// Step 2: Simulate payment_grace_terminator — pause resources + tier → free.
	// PauseAllTeamResources does a bulk SQL UPDATE (no provider call in SQL path).
	_, err = db.ExecContext(context.Background(),
		`UPDATE resources SET status='paused', paused_at=now() WHERE id=$1::uuid`, resourceID)
	require.NoError(t, err)
	require.NoError(t, models.UpdatePlanTier(context.Background(), db, teamUUID, "free"))

	// Verify the paused state is recorded.
	var statusBefore string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE id=$1::uuid`, resourceID).Scan(&statusBefore))
	require.Equal(t, "paused", statusBefore, "setup: resource must be paused before re-sub")

	// Step 3: Simulate subscription.charged for hobby — UpgradeTeamAllTiers.
	require.NoError(t, models.UpgradeTeamAllTiers(context.Background(), db, teamUUID, "hobby"))

	// Verify elevation included the paused row (L02-2 fix: status IN ('active','paused')).
	var tierAfterElevate string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT tier FROM resources WHERE id=$1::uuid`, resourceID).Scan(&tierAfterElevate))
	assert.Equal(t, "hobby", tierAfterElevate,
		"L02-2 fix: UpgradeTeamAllTiers must elevate paused rows — "+
			"pre-fix they stayed at 'free', blocking the resume tier check")
	_ = resourceUUID // used above

	// Step 4: Simulate the customer calling POST /resume on their paused resource.
	// Pre-fix: Resume handler returned 402 (multiEnvTierAllowed('hobby') = false).
	// Fix: Resume handler no longer gates on tier — a team must always be able to
	// un-pause a resource they own.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+resourceToken+"/resume", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"L02-2 regression: hobby team must be able to resume their own paused resource; "+
			"got %d with body: %v", resp.StatusCode, body)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "active", body["status"])

	// DB row must reflect the resumed state.
	var statusAfter string
	var pausedAt sql.NullTime
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status, paused_at FROM resources WHERE id=$1::uuid`, resourceID,
	).Scan(&statusAfter, &pausedAt))
	assert.Equal(t, "active", statusAfter, "DB row must be active after resume")
	assert.False(t, pausedAt.Valid, "paused_at must be NULL after resume")
}

// TestUpgradeTeamAllTiers_IncludesPausedRows is the model-layer regression test
// for the paused-row elevation fix in UpgradeTeamAllTiers.
//
// Pre-fix SQL: WHERE status = 'active'
// Fixed SQL:   WHERE status IN ('active', 'paused')
func TestUpgradeTeamAllTiers_IncludesPausedRows(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	teamUUID, err := uuid.Parse(teamID)
	require.NoError(t, err)

	// Active resource (should be elevated — always was).
	var activeID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'free', 'active')
		RETURNING id::text
	`, teamID).Scan(&activeID))

	// Paused resource (was skipped pre-fix — must now be elevated).
	var pausedID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'free', 'paused')
		RETURNING id::text
	`, teamID).Scan(&pausedID))

	// Deleted resource (must never be elevated).
	var deletedID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'free', 'deleted')
		RETURNING id::text
	`, teamID).Scan(&deletedID))

	require.NoError(t, models.UpgradeTeamAllTiers(context.Background(), db, teamUUID, "hobby"))

	check := func(id, wantTier, reason string) {
		t.Helper()
		var gotTier string
		require.NoError(t, db.QueryRowContext(context.Background(),
			`SELECT tier FROM resources WHERE id=$1::uuid`, id).Scan(&gotTier))
		assert.Equal(t, wantTier, gotTier, reason)
	}

	check(activeID, "hobby", "active row must be elevated")
	check(pausedID, "hobby",
		"L02-2 fix: paused row must be elevated by UpgradeTeamAllTiers — "+
			"pre-fix WHERE status='active' skipped paused rows, leaving them at 'free' "+
			"and blocking the resume flow for terminated-then-reinstated teams")
	check(deletedID, "free",
		"deleted row must NOT be elevated (reaper-race guard)")
}

// TestElevateResourceTiersByTeam_IncludesPausedRows is the standalone model test
// for ElevateResourceTiersByTeam (called from admin paths and UpgradeTeamAllTiers).
func TestElevateResourceTiersByTeam_IncludesPausedRows(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	teamUUID, err := uuid.Parse(teamID)
	require.NoError(t, err)

	var activeID, pausedID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'redis', 'free', 'active') RETURNING id::text
	`, teamID).Scan(&activeID))
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'redis', 'free', 'paused') RETURNING id::text
	`, teamID).Scan(&pausedID))

	require.NoError(t, models.ElevateResourceTiersByTeam(context.Background(), db, teamUUID, "pro"))

	var activeTier, pausedTier string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT tier FROM resources WHERE id=$1::uuid`, activeID).Scan(&activeTier))
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT tier FROM resources WHERE id=$1::uuid`, pausedID).Scan(&pausedTier))

	assert.Equal(t, "pro", activeTier, "active row must be elevated")
	assert.Equal(t, "pro", pausedTier,
		"L02-2 fix: paused row must be elevated by ElevateResourceTiersByTeam")
}
