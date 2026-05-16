package handlers_test

// claim_ordering_test.go — regression tests for A01 (P1).
//
// Bug: POST /claim created team+user BEFORE calling MarkOnboardingConverted.
// If MarkOnboardingConverted failed (transient error), the handler returned
// 503 but the JWT was left unconsumed — re-claimable by anyone holding it.
// Concurrent double-claims could both slip past the pre-check SELECT and
// produce two orphaned teams.
//
// Fix: MarkOnboardingConverted is now called FIRST (atomic UPDATE WHERE
// converted_at IS NULL). The winner creates team+user; concurrent losers
// get 409 immediately. If team/user creation fails after MarkConverted
// succeeds, the JWT is already consumed — the caller sees 503 and must
// contact support for a fresh JWT (acceptable trade-off).
//
// These tests extend the existing concurrent-claim test in onboarding_test.go
// with specific assertions about the A01 ordering invariant.
//
// These are integration tests that require a real Postgres database.
// Set TEST_DATABASE_URL and TEST_REDIS_URL to run them.

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestClaim_Ordering_MarkConvertedBeforeTeamCreation asserts that after a
// concurrent burst of identical claims, the onboarding_events.converted_at
// is set (JWT consumed) regardless of whether the winning claim ultimately
// created a team. This is the A01 invariant: "mark first, create after".
//
// We verify by checking that after all concurrent goroutines finish, the
// JTI is marked as converted — even if some returned 503.
func TestClaim_Ordering_MarkConvertedBeforeTeamCreation(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("claim_ordering_test: TEST_DATABASE_URL not set — skipping integration test")
	}
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}

	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	res := testhelpers.MustProvisionCacheFull(t, app, fp)
	require.NotEmpty(t, res.JWT, "provision response must include an onboarding JWT")
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, res.Token)

	const concurrency = 5
	var wg sync.WaitGroup
	wg.Add(concurrency)
	codes := make([]int, concurrency)

	for i := 0; i < concurrency; i++ {
		i := i
		go func() {
			defer wg.Done()
			body := map[string]any{
				"jwt":       res.JWT,
				"email":     fmt.Sprintf("a01-race-%d-%s@instant.dev", i, uuid.NewString()[:6]),
				"team_name": fmt.Sprintf("team-a01-%d-%s", i, uuid.NewString()[:6]),
			}
			r := testhelpers.PostJSON(t, app, "/claim", body)
			r.Body.Close()
			codes[i] = r.StatusCode
		}()
	}
	wg.Wait()

	// Count outcomes.
	created := 0
	conflict := 0
	for _, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflict++
		}
	}

	// Exactly one must succeed; all others must conflict.
	assert.Equal(t, 1, created, "exactly one concurrent claim must succeed (A01)")
	assert.Equal(t, concurrency-1, conflict,
		"all other concurrent claims must return 409 Conflict (A01 — MarkConverted wins the race)")

	// The JTI must be marked as converted in the DB regardless of any
	// subsequent team creation outcome — that is the A01 invariant.
	var convertedNull bool
	err := db.QueryRow(`
		SELECT converted_at IS NULL FROM onboarding_events
		WHERE $1::uuid = ANY(resource_tokens)`, res.Token).Scan(&convertedNull)
	require.NoError(t, err)
	assert.False(t, convertedNull,
		"onboarding_events.converted_at must be set after a successful claim — A01 ordering invariant")

	// Cleanup.
	db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)
}

// TestClaim_JTIAlwaysConsumedBeforeTeamCreation verifies the single-claim
// path: after POST /claim returns 201, the JTI is consumed in the DB.
// This is the non-concurrent companion to the test above.
func TestClaim_JTIAlwaysConsumedBeforeTeamCreation(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("claim_ordering_test: TEST_DATABASE_URL not set — skipping integration test")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	res := testhelpers.MustProvisionCacheFull(t, app, fp)
	require.NotEmpty(t, res.JWT)
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, res.Token)

	email := testhelpers.UniqueEmail(t)
	r := testhelpers.PostJSON(t, app, "/claim", map[string]any{
		"jwt":       res.JWT,
		"email":     email,
		"team_name": "a01-single-" + uuid.NewString()[:8],
	})
	defer r.Body.Close()
	require.Equal(t, http.StatusCreated, r.StatusCode)
	defer db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)

	// After a 201, the JTI must be consumed.
	var convertedNull bool
	err := db.QueryRow(`
		SELECT converted_at IS NULL FROM onboarding_events
		WHERE $1::uuid = ANY(resource_tokens)`, res.Token).Scan(&convertedNull)
	require.NoError(t, err)
	assert.False(t, convertedNull,
		"JTI must be consumed (converted_at set) after successful claim — A01 ordering invariant")

	// A second claim with the same JWT must get 409 (JTI already consumed).
	r2 := testhelpers.PostJSON(t, app, "/claim", map[string]any{
		"jwt":       res.JWT,
		"email":     testhelpers.UniqueEmail(t),
		"team_name": "a01-replay-" + uuid.NewString()[:8],
	})
	defer r2.Body.Close()
	assert.Equal(t, http.StatusConflict, r2.StatusCode,
		"re-using a consumed JWT must return 409 — A01 re-claimability guard")
}
