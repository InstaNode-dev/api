package handlers_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestOnboarding_GetStart_ValidJWT_Returns302WithClaimRedirect(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/start?t="+res.JWT, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"GET /start with valid JWT must redirect to dashboard /claim")

	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/claim", "redirect must target /claim")
	assert.Contains(t, loc, "t=", "redirect must include JWT parameter")
}

func TestOnboarding_GetStart_ExpiredJWT_Returns400LinkExpired(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	expiredJWT := testhelpers.MustSignExpiredJWT(t, testhelpers.OnboardingClaims{
		Fingerprint: "fp-whatever",
	})

	req := httptest.NewRequest(http.MethodGet, "/start?t="+expiredJWT, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"expired JWT must return 400")

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	msg, _ := body["error"].(string)
	assert.NotEmpty(t, msg)
}

func TestOnboarding_GetStart_TamperedJWT_Returns400InvalidLink(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// A completely made-up JWT with bad signature.
	tampered := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.badsig"
	req := httptest.NewRequest(http.MethodGet, "/start?t="+tampered, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"tampered JWT must return 400")

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	msg, _ := body["error"].(string)
	assert.NotEmpty(t, msg, "error field must be present")
}

func TestOnboarding_GetStart_ExpiredResources_ShownGracefully(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	// Provision to get a real JWT with onboarding_events row.
	res := testhelpers.MustProvisionCacheFull(t, app, fp)
	require.NotEmpty(t, res.JWT, "provision response must include an onboarding JWT")

	// Mark the resource as deleted to simulate expiry.
	_, err := db.Exec(`UPDATE resources SET status = 'deleted' WHERE token = $1`, res.Token)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, res.Token)

	req := httptest.NewRequest(http.MethodGet, "/start?t="+res.JWT, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode,
		"expired resources must still redirect, not cause a 500")

	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/claim",
		"redirect must target /claim even with expired resources")
}

func TestOnboarding_PostClaim_ValidJWT_SetsConvertedAtAndTeamID(t *testing.T) {
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

	email := testhelpers.UniqueEmail(t)
	body := map[string]any{
		"jwt":       res.JWT,
		"email":     email,
		"team_name": "acme-test-" + uuid.NewString()[:8],
	}
	claimResp := testhelpers.PostJSON(t, app, "/claim", body)
	defer claimResp.Body.Close()

	require.Equal(t, http.StatusCreated, claimResp.StatusCode)

	// Verify the resource was claimed: team_id set, tier flipped to 'free',
	// expires_at preserved (pay-from-day-one keeps the 24h TTL ticking).
	var teamIDNull bool
	var tier string
	var expiresAtNull bool
	err := db.QueryRow(
		`SELECT team_id IS NULL, tier, expires_at IS NULL FROM resources WHERE token = $1`,
		res.Token,
	).Scan(&teamIDNull, &tier, &expiresAtNull)
	require.NoError(t, err)
	assert.False(t, teamIDNull, "team_id must be set on resource after claim")
	assert.Equal(t, "free", tier,
		"claim must flip tier from 'anonymous' to 'free' (claimed-but-unpaid audience)")
	assert.False(t, expiresAtNull,
		"claim must NOT clear expires_at — only Razorpay subscription.charged does that")

	// Verify onboarding event marked as converted.
	// Query by resource token since fingerprint in DB is the middleware hash, not the raw test fp.
	var convertedNull bool
	err = db.QueryRow(`
		SELECT converted_at IS NULL FROM onboarding_events
		WHERE $1::uuid = ANY(resource_tokens)`, res.Token).Scan(&convertedNull)
	require.NoError(t, err)
	assert.False(t, convertedNull, "onboarding_events.converted_at must be set after claim")

	// Cleanup the team that was created.
	db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)
}

func TestOnboarding_PostClaim_AlreadyClaimed_Returns409Conflict(t *testing.T) {
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

	claimBody := map[string]any{
		"jwt":       res.JWT,
		"email":     testhelpers.UniqueEmail(t),
		"team_name": "acme-dupe-" + uuid.NewString()[:8],
	}

	// First claim succeeds.
	resp1 := testhelpers.PostJSON(t, app, "/claim", claimBody)
	resp1.Body.Close()
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	defer db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)

	// Second claim with the same JWT must return 409.
	resp2 := testhelpers.PostJSON(t, app, "/claim", claimBody)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode,
		"claiming an already-claimed JWT must return 409 Conflict")
}

func TestOnboarding_PostClaim_Atomic_ConcurrentClaims_OnlyOneSucceeds(t *testing.T) {
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

	const concurrency = 10
	results := make([]int, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		i := i
		go func() {
			defer wg.Done()
			claimBody := map[string]any{
				"jwt":       res.JWT,
				"email":     fmt.Sprintf("race-%d-%s@instant.dev", i, uuid.NewString()[:6]),
				"team_name": fmt.Sprintf("team-race-%d-%s", i, uuid.NewString()[:6]),
			}
			r := testhelpers.PostJSON(t, app, "/claim", claimBody)
			r.Body.Close()
			results[i] = r.StatusCode
		}()
	}
	wg.Wait()

	successCount := 0
	conflictCount := 0
	for _, code := range results {
		switch code {
		case http.StatusCreated:
			successCount++
		case http.StatusConflict:
			conflictCount++
		}
	}

	assert.Equal(t, 1, successCount,
		"exactly 1 concurrent claim must succeed")
	assert.Equal(t, concurrency-1, conflictCount,
		"all other concurrent claims must return 409 Conflict")

	// Cleanup the winning team.
	db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)
}

// ---------------------------------------------------------------------------
// TestStartLanding_* — HTML landing page tests
// ---------------------------------------------------------------------------

func TestStartLanding_NoToken_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/start", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"GET /start without ?t must return 400")
}

func TestStartLanding_TamperedJWT_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	tampered := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.badsig"
	req := httptest.NewRequest(http.MethodGet, "/start?t="+tampered, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"tampered JWT must return 400")
}

func TestStartLanding_ValidJWT_Returns302Redirect(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/start?t="+res.JWT, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode, "GET /start must redirect to dashboard")

	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/claim", "redirect must point to /claim")
	assert.Contains(t, loc, "t=", "redirect must include the onboarding JWT")
}

func TestStartLanding_AlreadyClaimed_Returns302(t *testing.T) {
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

	claimBody := map[string]any{
		"jwt":       res.JWT,
		"email":     testhelpers.UniqueEmail(t),
		"team_name": "html-test-" + uuid.NewString()[:8],
	}
	claimResp := testhelpers.PostJSON(t, app, "/claim", claimBody)
	claimResp.Body.Close()
	require.Equal(t, http.StatusCreated, claimResp.StatusCode, "first claim must succeed")
	defer db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)

	req := httptest.NewRequest(http.MethodGet, "/start?t="+res.JWT, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode,
		"already-claimed must redirect")
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "already_claimed=true",
		"redirect must indicate already-claimed")
}

func TestOnboarding_JWTWithFutureIssuedAt_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	future := time.Now().Add(30 * time.Minute)
	claims := testhelpers.OnboardingClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(future),
			ExpiresAt: jwt.NewNumericDate(future.Add(15 * time.Minute)),
		},
	}
	jwtStr := testhelpers.MustSignJWT(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/start?t="+jwtStr, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"token with future IssuedAt must be rejected with 400")
}

// TestOnboarding_PostClaim_EmitsAuditLogRow verifies that a successful POST
// /claim writes one audit_log row with kind = "onboarding.claimed". The row
// drives the Loops "welcome" lifecycle email; if the emit is silently dropped
// the user gets no email even though their claim succeeded.
//
// The audit write runs in a detached goroutine, so the test polls for up to
// ~2s for the row to land (same pattern as TestExperimentsConverted_*).
func TestOnboarding_PostClaim_EmitsAuditLogRow(t *testing.T) {
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

	email := testhelpers.UniqueEmail(t)
	body := map[string]any{
		"jwt":       res.JWT,
		"email":     email,
		"team_name": "audit-claim-" + uuid.NewString()[:8],
	}
	claimResp := testhelpers.PostJSON(t, app, "/claim", body)
	defer claimResp.Body.Close()
	require.Equal(t, http.StatusCreated, claimResp.StatusCode)

	// Resolve the team_id that was created by the claim so we can scope the
	// audit_log lookup. The claim response carries it directly.
	var claimBody map[string]any
	testhelpers.DecodeJSON(t, claimResp, &claimBody)
	teamID, _ := claimBody["team_id"].(string)
	require.NotEmpty(t, teamID, "claim response must carry team_id")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// The audit write is async — poll for up to ~2s for the row to land.
	var kind, summary, metaText string
	for i := 0; i < 40; i++ {
		err := db.QueryRow(`
			SELECT kind, summary, metadata::text
			  FROM audit_log
			 WHERE team_id = $1::uuid AND kind = 'onboarding.claimed'
			 ORDER BY created_at DESC
			 LIMIT 1`, teamID).Scan(&kind, &summary, &metaText)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, "onboarding.claimed", kind,
		"audit_log row with kind='onboarding.claimed' must exist after a successful claim")
	assert.NotEmpty(t, summary)
	assert.Contains(t, metaText, email,
		"audit metadata should capture the claiming user's email for Loops payload")
}
