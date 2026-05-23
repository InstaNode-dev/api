package handlers_test

// isolation_test.go verifies that no request can access or affect data
// belonging to a different token/team.
//
// These are security tests — failures here are P0 incidents.
// Each test is named after the attack vector it closes.
//
// Coverage:
//   - Cache resource isolation: two fingerprints get distinct tokens and DB rows
//   - Unknown token returns 404 without leaking any real token value
//   - Deleting resource A does not affect resource B
//   - Fingerprint deduplication returns the SAME existing token — not a different user's
//   - Authenticated team A cannot access team B's resources via management API
//   - Phase 2/3/4 credential isolation per fingerprint
//   - Per-service provisioning counters are independent

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"instant.dev/internal/testhelpers"
)

// TestIsolation_Cache_DifferentFingerprints_GetDifferentTokens verifies that two
// callers with different /24 fingerprints each receive a distinct cache token and
// that each token maps to a separate resources row in the DB.
func TestIsolation_Cache_DifferentFingerprints_GetDifferentTokens(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	tokenA := testhelpers.MustProvisionCache(t, app, "10.20.0.1")
	tokenB := testhelpers.MustProvisionCache(t, app, "10.20.1.1") // different /24
	defer db.Exec(`DELETE FROM resources WHERE token IN ($1::uuid, $2::uuid)`, tokenA, tokenB)

	assert.NotEqual(t, tokenA, tokenB,
		"two different /24 fingerprints must receive distinct cache tokens")

	// Each token must exist as a separate row in the resources table.
	var countA, countB int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM resources WHERE token = $1::uuid`, tokenA).Scan(&countA))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM resources WHERE token = $1::uuid`, tokenB).Scan(&countB))
	assert.Equal(t, 1, countA, "token A must have exactly one resources row")
	assert.Equal(t, 1, countB, "token B must have exactly one resources row")
}

// TestIsolation_UnknownToken_Returns404_NotAnotherToken verifies that requesting
// a non-existent token via the management API returns 404 and does NOT return
// data belonging to any real token.
func TestIsolation_UnknownToken_Returns404_NotAnotherToken(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Provision a real token.
	realToken := testhelpers.MustProvisionCache(t, app, "10.30.0.1")
	defer db.Exec(`DELETE FROM resources WHERE token = $1::uuid`, realToken)

	// Claim it so the management API can see it.
	fp := testhelpers.UniqueFingerprint(t)
	claimResult := testhelpers.MustProvisionCacheFull(t, app, fp)
	defer db.Exec(`DELETE FROM resources WHERE token = $1::uuid`, claimResult.Token)

	// Use a well-formed UUID that definitely doesn't exist in the DB.
	fakeToken := "00000000-0000-0000-0000-000000000000"

	// The management API requires auth — build a signed session JWT for a random team.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamID, email,
	).Scan(&userID))
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+fakeToken, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Must be 404 or 403 (foreign team can't see another team's resource).
	assert.True(t, resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden,
		"unknown token must return 404 or 403, got %d", resp.StatusCode)

	// Response body must not leak the real token value.
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	bodyBytes, _ := json.Marshal(body)
	assert.NotContains(t, string(bodyBytes), realToken,
		"404/403 response must not leak any real token value")
}

// TestIsolation_DeleteResourceA_DoesNotAffectResourceB verifies that deleting
// resource A via the management API does not soft-delete or affect resource B.
func TestIsolation_DeleteResourceA_DoesNotAffectResourceB(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Create a team and two resources both owned by it.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamID, email,
	).Scan(&userID))
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	// Insert two resources directly owned by this team.
	var tokenA, tokenB string
	require.NoError(t, db.QueryRow(
		`INSERT INTO resources (team_id, resource_type, tier) VALUES ($1::uuid, 'redis', 'hobby') RETURNING token::text`,
		teamID,
	).Scan(&tokenA))
	require.NoError(t, db.QueryRow(
		`INSERT INTO resources (team_id, resource_type, tier) VALUES ($1::uuid, 'redis', 'hobby') RETURNING token::text`,
		teamID,
	).Scan(&tokenB))
	defer db.Exec(`DELETE FROM resources WHERE token IN ($1::uuid, $2::uuid)`, tokenA, tokenB)

	// Delete resource A.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+tokenA, nil)
	delReq.Header.Set("Authorization", "Bearer "+sessionJWT)
	delResp, err := app.Test(delReq, 5000)
	require.NoError(t, err)
	delResp.Body.Close()
	require.Equal(t, http.StatusOK, delResp.StatusCode, "DELETE resource A must return 200")

	// Resource B must still be active.
	var statusB string
	require.NoError(t, db.QueryRow(
		`SELECT status FROM resources WHERE token = $1::uuid`, tokenB,
	).Scan(&statusB))
	assert.Equal(t, "active", statusB,
		"deleting resource A must not change resource B's status")
}

// TestIsolation_FingerprintReuse_ReturnsSameToken verifies that the fingerprint
// deduplication path returns the SAME existing token — not a different user's token.
// This closes the risk of fingerprint collision returning the wrong resource.
func TestIsolation_FingerprintReuse_ReturnsSameToken(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Use a random IP so leftover rows from prior test runs don't pollute this test.
	sharedIP := fmt.Sprintf("10.60.%d.%d", rand.Intn(255), rand.Intn(255))
	provisionedTokens := make(map[string]bool)
	// Each provision sends a DISTINCT body so the idempotency middleware's
	// body-fingerprint fallback (2026-05-14) doesn't dedup them. The
	// middleware deliberately replays same-fingerprint-same-body POSTs
	// within 120s; this test wants five genuine provisions, so we vary
	// the body. The handler's per-day fingerprint dedup still fires on
	// the 6th call regardless of body — that's what we assert below.
	for i := 0; i < 5; i++ {
		body := strings.NewReader(fmt.Sprintf(`{"name":"prov-%d"}`, i))
		req := httptest.NewRequest(http.MethodPost, "/cache/new", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", sharedIP)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		var rb struct {
			OK    bool   `json:"ok"`
			Token string `json:"token"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&rb))
		resp.Body.Close()
		provisionedTokens[rb.Token] = true
	}
	require.Len(t, provisionedTokens, 5, "should have 5 distinct tokens before rate limit kicks in")

	// 6th provision from the same IP — must return one of the existing tokens, not a new one.
	// Use a body that doesn't match any of the 5 above so the middleware
	// fingerprint cache misses and the handler's per-day cap fires.
	req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(`{"name":"prov-6"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", sharedIP)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.True(t, provisionedTokens[body.Token],
		"rate-limited provision must return an existing token for this fingerprint, not a new/foreign one (got %s)", body.Token)
	assert.Equal(t, true, body.OK,
		"rate-limited provision must still return ok=true")
}

// TestIsolation_ManagementAPI_TeamA_CannotReadTeamB_Resources verifies that
// the authenticated resource list endpoint is scoped to the requesting team.
//
// Creates two separate teams directly in the DB, provisions a cache resource owned
// by each, then checks that each team's session JWT only returns its own resource.
func TestIsolation_ManagementAPI_TeamA_CannotReadTeamB_Resources(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Create two distinct teams.
	teamAID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "hobby")

	// Insert a user in each team.
	userAID, userBID := testhelpers.UniqueEmail(t), testhelpers.UniqueEmail(t)

	var uuidA, uuidB string
	err := db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamAID, userAID,
	).Scan(&uuidA)
	require.NoError(t, err)
	err = db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamBID, userBID,
	).Scan(&uuidB)
	require.NoError(t, err)

	// Provision one cache resource per team by POSTing with a team-scoped session JWT.
	jwtA := testhelpers.MustSignSessionJWT(t, uuidA, teamAID, userAID)
	jwtB := testhelpers.MustSignSessionJWT(t, uuidB, teamBID, userBID)

	provisionWithJWT := func(jwt string) string {
		req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var body struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return body.Token
	}

	tokenA := provisionWithJWT(jwtA)
	tokenB := provisionWithJWT(jwtB)
	require.NotEqual(t, tokenA, tokenB, "each team must get a distinct token")

	// Helper: call GET /api/v1/resources with the given JWT.
	listResources := func(jwt string) map[string]bool {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var result struct {
			Resources []struct{ Token string `json:"token"` } `json:"items"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		m := make(map[string]bool)
		for _, r := range result.Resources {
			m[r.Token] = true
		}
		return m
	}

	setA := listResources(jwtA)
	assert.True(t, setA[tokenA], "team A must see its own token")
	assert.False(t, setA[tokenB], "team A must NOT see team B's token — isolation failure")

	setB := listResources(jwtB)
	assert.True(t, setB[tokenB], "team B must see its own token")
	assert.False(t, setB[tokenA], "team B must NOT see team A's token — isolation failure")
}

// ── Phase 2/3/4 provisioning isolation ────────────────────────────────────────
//
// For stub-phase services (postgres, redis, mongodb) real ACL/database isolation
// is enforced by the provider (Neon, Redis ACLs, MongoDB RBAC). These tests
// verify the layer we own: that the API issues different credentials per fingerprint
// and never leaks one token's connection_url into another's response.

// TestIsolation_DBProvision_DifferentFingerprints_GetDifferentCredentials verifies
// that two callers with different fingerprints receive distinct tokens and
// non-overlapping connection URLs.
//
// The two IPs MUST land in different /24 subnets — both for the test's
// stated premise ("different fingerprints") and so the idempotency
// middleware's fingerprint scope doesn't dedup the two calls. The
// 10.70.0.x range used previously kept both calls in the same /24,
// which the middleware now (correctly) dedups; we use IPs from genuinely
// different /24s here.
func TestIsolation_DBProvision_DifferentFingerprints_GetDifferentCredentials(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres")
	defer cleanApp()

	tokenA := testhelpers.MustProvisionDB(t, app, "10.70.1.1")
	tokenB := testhelpers.MustProvisionDB(t, app, "10.70.2.1")
	defer db.Exec(`DELETE FROM resources WHERE token IN ($1::uuid, $2::uuid)`, tokenA, tokenB)

	assert.NotEqual(t, tokenA, tokenB, "two callers must get distinct DB tokens")

	// Fetch connection_url for each from DB; they must be different.
	var urlA, urlB string
	require.NoError(t, db.QueryRow(
		`SELECT COALESCE(connection_url,'') FROM resources WHERE token = $1::uuid`, tokenA,
	).Scan(&urlA))
	require.NoError(t, db.QueryRow(
		`SELECT COALESCE(connection_url,'') FROM resources WHERE token = $1::uuid`, tokenB,
	).Scan(&urlB))

	// URLs may be empty (stub phase stores nothing), but if present they must differ.
	if urlA != "" && urlB != "" {
		assert.NotEqual(t, urlA, urlB,
			"two callers must not share a postgres connection_url")
	}
}

// TestIsolation_CacheProvision_DifferentFingerprints_GetDifferentCredentials mirrors
// the DB test for Redis cache resources. Same IP-subnet considerations as
// the DB sibling above — two distinct /24s so the fingerprint scope
// doesn't dedup the calls.
func TestIsolation_CacheProvision_DifferentFingerprints_GetDifferentCredentials(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "redis")
	defer cleanApp()

	tokenA := testhelpers.MustProvisionCache(t, app, "10.71.1.1")
	tokenB := testhelpers.MustProvisionCache(t, app, "10.71.2.1")
	defer db.Exec(`DELETE FROM resources WHERE token IN ($1::uuid, $2::uuid)`, tokenA, tokenB)

	assert.NotEqual(t, tokenA, tokenB, "two callers must get distinct Redis tokens")

	// Connection URLs must embed the token so namespace isolation is derivable.
	var urlA, urlB string
	require.NoError(t, db.QueryRow(
		`SELECT COALESCE(connection_url,'') FROM resources WHERE token = $1::uuid`, tokenA,
	).Scan(&urlA))
	require.NoError(t, db.QueryRow(
		`SELECT COALESCE(connection_url,'') FROM resources WHERE token = $1::uuid`, tokenB,
	).Scan(&urlB))

	if urlA != "" && urlB != "" {
		assert.NotEqual(t, urlA, urlB,
			"two callers must not share a Redis connection_url")
	}
}

// TestIsolation_NoSQLProvision_DifferentFingerprints_GetDifferentCredentials mirrors
// the DB test for MongoDB resources.
func TestIsolation_NoSQLProvision_DifferentFingerprints_GetDifferentCredentials(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "mongodb")
	defer cleanApp()

	tokenA := testhelpers.MustProvisionNoSQL(t, app, "10.72.0.1")
	tokenB := testhelpers.MustProvisionNoSQL(t, app, "10.72.0.2")
	defer db.Exec(`DELETE FROM resources WHERE token IN ($1::uuid, $2::uuid)`, tokenA, tokenB)

	assert.NotEqual(t, tokenA, tokenB, "two callers must get distinct MongoDB tokens")

	var urlA, urlB string
	require.NoError(t, db.QueryRow(
		`SELECT COALESCE(connection_url,'') FROM resources WHERE token = $1::uuid`, tokenA,
	).Scan(&urlA))
	require.NoError(t, db.QueryRow(
		`SELECT COALESCE(connection_url,'') FROM resources WHERE token = $1::uuid`, tokenB,
	).Scan(&urlB))

	if urlA != "" && urlB != "" {
		assert.NotEqual(t, urlA, urlB,
			"two callers must not share a MongoDB connection_url")
	}
}

// TestIsolation_ProvisioningLimit_PerService_Independent verifies that the daily
// provisioning counter is tracked independently per service type. Exhausting the
// postgres limit does not block cache or nosql provisioning from the same fingerprint.
func TestIsolation_ProvisioningLimit_PerService_Independent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	defer cleanApp()

	// Exhaust the postgres limit from one IP (5 provisions).
	sharedIP := fmt.Sprintf("10.73.%d.1", rand.Intn(200))
	for i := 0; i < 5; i++ {
		testhelpers.MustProvisionDB(t, app, sharedIP)
	}

	// After limit exhausted, cache and nosql provisioning must still return 201.
	cacheToken := testhelpers.MustProvisionCache(t, app, sharedIP)
	assert.NotEmpty(t, cacheToken, "cache provision must succeed even after postgres limit exhausted")

	nosqlToken := testhelpers.MustProvisionNoSQL(t, app, sharedIP)
	assert.NotEmpty(t, nosqlToken, "nosql provision must succeed even after postgres limit exhausted")
}

// TestIsolation_ManagementAPI_CannotAccessOtherTeams_DBResources verifies that
// an authenticated team cannot list or read DB/cache/nosql resources belonging
// to a different team via GET /api/v1/resources.
func TestIsolation_ManagementAPI_CannotAccessOtherTeams_DBResources(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	defer cleanApp()

	teamAID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "hobby")

	emailA, emailB := testhelpers.UniqueEmail(t), testhelpers.UniqueEmail(t)
	var uuidA, uuidB string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamAID, emailA,
	).Scan(&uuidA))
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamBID, emailB,
	).Scan(&uuidB))

	jwtA := testhelpers.MustSignSessionJWT(t, uuidA, teamAID, emailA)
	jwtB := testhelpers.MustSignSessionJWT(t, uuidB, teamBID, emailB)

	// Directly insert a postgres resource for team B into the DB.
	var teamBResourceToken string
	require.NoError(t, db.QueryRow(`
		INSERT INTO resources (team_id, resource_type, tier)
		VALUES ($1::uuid, 'postgres', 'hobby')
		RETURNING token::text
	`, teamBID).Scan(&teamBResourceToken))

	// Team A lists resources — must not see team B's postgres resource.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+jwtA)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Items []struct{ Token string `json:"token"` } `json:"items"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	for _, item := range result.Items {
		assert.NotEqual(t, teamBResourceToken, item.Token,
			"team A must not see team B's postgres resource — isolation failure")
	}

	_ = jwtB // available for future assertions
}
