package handlers_test

// resource_metrics_test.go — covers GET /api/v1/resources/:id/metrics.
//
// Mirrors resource_pause_test.go's style: each test stands up its own
// DB + Redis + Fiber app, builds a team + user + JWT, inserts a resource row
// directly via SQL, fires the request, asserts the response shape AND (for
// tier walls) the agent_action prose.
//
// The metrics handler currently runs the Option-C STUB code path
// (resource_metrics.go::generateStubMetrics). The test asserts the response
// carries `data_source: "stub"` so when Option A / real Option C lands, the
// expected-string update lives next to the contract change instead of being
// silently rotated out from under the dashboard.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// metricsTestFixture wires up the common test setup: app, DB, Redis, team
// (on the requested plan tier), user, JWT, and a single postgres resource
// row owned by the team. Returns the resource token and the JWT.
type metricsTestFixture struct {
	app           metricsApp
	resourceToken string
	jwt           string
	teamID        string
}

type metricsApp interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}

func setupMetricsFixture(t *testing.T, planTier string, resourceType string) metricsTestFixture {
	t.Helper()

	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	t.Cleanup(cleanApp)

	teamID := testhelpers.MustCreateTeamDB(t, db, planTier)
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
		VALUES ($1::uuid, $2, $3, 'active')
		RETURNING token::text
	`, teamID, resourceType, planTier).Scan(&resourceToken))

	return metricsTestFixture{
		app:           app,
		resourceToken: resourceToken,
		jwt:           jwt,
		teamID:        teamID,
	}
}

// doMetrics GETs /api/v1/resources/:id/metrics with an optional ?window= param.
func doMetrics(t *testing.T, app metricsApp, jwt, token, window string) *http.Response {
	t.Helper()
	path := "/api/v1/resources/" + token + "/metrics"
	if window != "" {
		path += "?window=" + window
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestMetrics_Pro_DefaultWindow_HappyPath — a Pro team gets the default 1h
// window without specifying ?window=. Validates the full response shape.
func TestMetrics_Pro_DefaultWindow_HappyPath(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "postgres")

	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "postgres", body["resource_type"])
	// 1h default → 3600 seconds.
	assert.Equal(t, float64(3600), body["window_seconds"])
	assert.Equal(t, float64(60), body["sample_interval_seconds"])
	// 3600 / 60 = 60 samples.
	assert.Equal(t, float64(60), body["samples_count"])
	// Stub flag must surface so the dashboard knows whether to show the
	// "waiting for samples" banner.
	assert.Equal(t, "stub", body["data_source"])

	metrics, ok := body["metrics"].(map[string]any)
	require.True(t, ok, "metrics must be an object")

	expectedSeries := []string{
		"latency_p50_ms", "latency_p95_ms", "latency_p99_ms",
		"connections_active", "storage_bytes", "error_rate_pct",
	}
	for _, key := range expectedSeries {
		arr, ok := metrics[key].([]any)
		require.True(t, ok, "metrics.%s must be a number array", key)
		assert.Len(t, arr, 60, "metrics.%s must have samples_count entries", key)
	}
}

// TestMetrics_Pro_24hWindow — pro tier accepts 24h. Asserts the resolved
// window_seconds and samples_count scale correctly.
func TestMetrics_Pro_24hWindow(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "redis")

	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "24h")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, float64(86400), body["window_seconds"])
	assert.Equal(t, float64(1440), body["samples_count"]) // 24h × 60
}

// TestMetrics_Hobby_24hWindow_402 — hobby tier's max window is 1h. A 24h
// request returns 402 with a tier-specific agent_action.
func TestMetrics_Hobby_24hWindow_402(t *testing.T) {
	fix := setupMetricsFixture(t, "hobby", "postgres")

	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "24h")
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "upgrade_required", body["error"])
	assert.Equal(t, "https://instanode.dev/pricing", body["upgrade_url"])

	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action, "402 must carry agent_action")
	assert.Contains(t, action, "Tell the user", "agent_action must satisfy U3 imperative-opening")
	assert.Contains(t, action, "hobby", "agent_action must name the caller's current tier")
	assert.Contains(t, action, "1h", "agent_action must name the hobby ceiling")
	assert.Contains(t, action, "https://instanode.dev/", "agent_action must carry the upgrade URL")
}

// TestMetrics_Hobby_1hWindow_OK — hobby tier accepts a 1h window (the cap).
func TestMetrics_Hobby_1hWindow_OK(t *testing.T) {
	fix := setupMetricsFixture(t, "hobby", "postgres")

	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "1h")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, float64(3600), body["window_seconds"])
}

// TestMetrics_Anonymous_402 — the anonymous tier is denied outright. The 402
// agent_action must NOT mention a window cap — it must say the feature itself
// requires upgrade. Distinguishes "you hit a ceiling" from "you have no
// access at all".
func TestMetrics_Anonymous_402(t *testing.T) {
	fix := setupMetricsFixture(t, "anonymous", "postgres")

	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "")
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, "upgrade_required", body["error"])
	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action)
	assert.Contains(t, action, "Tell the user")
	assert.Contains(t, action, "Pro", "anonymous wall must name the Pro plan")
	assert.Contains(t, action, "https://instanode.dev/")
}

// TestMetrics_Free_402 — symmetric with anonymous; "free" tier (used by
// claimed-but-unpaid teams in some flows) gets the same 402.
func TestMetrics_Free_402(t *testing.T) {
	fix := setupMetricsFixture(t, "free", "postgres")

	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "")
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"])
}

// TestMetrics_GrowthTier_7d_OK — growth tier accepts the 7d max window.
func TestMetrics_GrowthTier_7d_OK(t *testing.T) {
	fix := setupMetricsFixture(t, "growth", "mongodb")

	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "168h") // 7 days
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, float64(7*24*3600), body["window_seconds"])
}

// TestMetrics_CrossTeam_404 — Team B cannot read Team A's resource metrics.
// Returns 404 (not 403) — cross-team access must not leak existence.
func TestMetrics_CrossTeam_404(t *testing.T) {
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	t.Cleanup(cleanApp)

	teamAID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "pro")
	emailB := testhelpers.UniqueEmail(t)
	var userBID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamBID, emailB,
	).Scan(&userBID))
	jwtB := testhelpers.MustSignSessionJWT(t, userBID, teamBID, emailB)

	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING token::text
	`, teamAID).Scan(&resourceToken))

	resp := doMetrics(t, app, jwtB, resourceToken, "")
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "not_found", body["error"])
}

// TestMetrics_InvalidUUID_400 — bad :id param.
func TestMetrics_InvalidUUID_400(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "postgres")
	resp := doMetrics(t, fix.app, fix.jwt, "not-a-uuid", "")
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_id", body["error"])
}

// TestMetrics_NotFound_404 — well-formed UUID that doesn't exist → 404.
// The 404 path runs BEFORE the team-ownership check, so a non-existent
// resource never leaks owner-team information.
func TestMetrics_NotFound_404(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "postgres")
	// Random UUID — guaranteed not to exist in the test DB.
	resp := doMetrics(t, fix.app, fix.jwt, "00000000-0000-0000-0000-000000000000", "")
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "not_found", body["error"])
}

// TestMetrics_Unauthenticated_401 — no Bearer token → 401.
func TestMetrics_Unauthenticated_401(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "postgres")
	resp := doMetrics(t, fix.app, "", fix.resourceToken, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestMetrics_InvalidWindow_400 — garbage window param → 400 invalid_window.
func TestMetrics_InvalidWindow_400(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "postgres")
	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "garbage")
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_window", body["error"])
}

// TestMetrics_BareSecondsWindow_OK — "3600" is accepted as 1 hour. Documented
// in the OpenAPI spec as the ergonomic alternative to "1h".
func TestMetrics_BareSecondsWindow_OK(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "postgres")
	resp := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "3600")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, float64(3600), body["window_seconds"])
}

// TestMetrics_StubDeterminism — two calls for the same (resource, window)
// must return the same series. Without determinism the dashboard's 60s poll
// would visibly thrash. Once Option A / real Option C lands, this contract
// stops mattering (real data CHANGES every poll) — at that point this test
// should be deleted with the stub.
func TestMetrics_StubDeterminism(t *testing.T) {
	fix := setupMetricsFixture(t, "pro", "postgres")

	resp1 := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "")
	defer resp1.Body.Close()
	var body1 map[string]any
	require.NoError(t, json.NewDecoder(resp1.Body).Decode(&body1))

	resp2 := doMetrics(t, fix.app, fix.jwt, fix.resourceToken, "")
	defer resp2.Body.Close()
	var body2 map[string]any
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&body2))

	assert.Equal(t, body1["metrics"], body2["metrics"],
		"stub must be deterministic per (resource, window) — same input → same output")
}
