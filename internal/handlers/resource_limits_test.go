package handlers_test

// resource_limits_test.go — regression tests for P1-cluster-D bugs.
//
//  1. resourceToMap must emit storage_limit_bytes and connections_limit
//     (derived from the resource's snapshot tier via plans.Registry).
//  2. storage_exceeded must be present on both the list endpoint (GET
//     /api/v1/resources) and the single-resource endpoint (GET
//     /api/v1/resources/:id).
//  3. pause/resume adapter: the response envelope uses key "resource", not
//     "item" — the resource shape inside it must carry limit fields too.
//
// Tests use the in-memory plans.Default() registry so no disk I/O is needed.
// Limit values are read dynamically from plans.Default() rather than hardcoded
// so a future plans.yaml bump doesn't silently break the assertions.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// listResourcesJSON is a tiny helper that calls GET /api/v1/resources and
// returns the decoded response body map and the HTTP status code.
func listResourcesJSON(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, jwt string) (map[string]any, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body, resp.StatusCode
}

// getResourceJSON calls GET /api/v1/resources/:token and returns the decoded
// body and status code.
func getResourceJSON(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, jwt, token string) (map[string]any, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+token, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body, resp.StatusCode
}

// TestResourceToMap_EmitsLimitFields verifies that GET /api/v1/resources (list)
// returns storage_limit_bytes and connections_limit on each item, derived from
// the resource's snapshot tier via plans.Registry. This is the regression test
// for D02-03 / C01-F1 / U06-P1 where the quota bars rendered NaN%/0.
func TestResourceToMap_EmitsLimitFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	reg := plans.Default()

	// Create a hobby-tier team so we can inspect hobby entitlements.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	// Insert a postgres resource owned by the team with hobby tier.
	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'hobby', 'active')
		RETURNING token::text
	`, teamID).Scan(&resourceToken))

	body, status := listResourcesJSON(t, app, jwt)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, body["ok"])

	items, ok := body["items"].([]any)
	require.True(t, ok, "items must be a JSON array")
	require.Len(t, items, 1, "expected exactly one resource")

	item, ok := items[0].(map[string]any)
	require.True(t, ok, "each item must be a JSON object")

	// storage_limit_bytes must be present and equal to the plans.Registry
	// value for hobby/postgres (never hardcoded — pulled from the live registry).
	expectedLimitMB := reg.StorageLimitMB("hobby", "postgres")
	expectedLimitBytes := float64(expectedLimitMB) * 1_000_000

	storageLimitBytes, hasField := item["storage_limit_bytes"]
	assert.True(t, hasField, "list item must contain storage_limit_bytes")
	assert.Equal(t, expectedLimitBytes, storageLimitBytes,
		"storage_limit_bytes must equal plans.Registry.StorageLimitMB(%q, %q) * 1_000_000", "hobby", "postgres")

	// connections_limit must be present.
	expectedConns := float64(reg.ConnectionsLimit("hobby", "postgres"))
	connectionsLimit, hasConns := item["connections_limit"]
	assert.True(t, hasConns, "list item must contain connections_limit")
	assert.Equal(t, expectedConns, connectionsLimit,
		"connections_limit must equal plans.Registry.ConnectionsLimit(%q, %q)", "hobby", "postgres")

	// storage_exceeded must be present (not missing/undefined).
	_, hasExceeded := item["storage_exceeded"]
	assert.True(t, hasExceeded, "list item must contain storage_exceeded (C01-F2 regression)")

	// Verify the resource can also be fetched by token via the single-GET path.
	getBody, getStatus := getResourceJSON(t, app, jwt, resourceToken)
	require.Equal(t, http.StatusOK, getStatus, "GET /api/v1/resources/:token must return 200 when looking up by token")
	getItem, ok := getBody["item"].(map[string]any)
	require.True(t, ok, "single-GET response must contain 'item'")
	assert.Equal(t, expectedLimitBytes, getItem["storage_limit_bytes"],
		"single-GET storage_limit_bytes must match list")
}

// TestResourceToMap_UnlimitedTier_EmitsSentinel verifies that a team-tier
// resource emits storage_limit_bytes = -1 (unlimitedSentinel) instead of a
// positive byte count so the TS side can render "unlimited" rather than
// "/ -1 MB". This is required by the D02-03 fix spec.
func TestResourceToMap_UnlimitedTier_EmitsSentinel(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	reg := plans.Default()
	teamLimitMB := reg.StorageLimitMB("team", "postgres")
	if teamLimitMB != -1 {
		t.Skip("test only meaningful when team tier is unlimited; plans.yaml changed")
	}

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'team', 'active')
		RETURNING token::text
	`, teamID).Scan(new(string)))

	body, status := listResourcesJSON(t, app, jwt)
	require.Equal(t, http.StatusOK, status)
	items, ok := body["items"].([]any)
	require.True(t, ok)
	require.Len(t, items, 1)
	item := items[0].(map[string]any)

	// -1 sentinel must propagate as a JSON number so TS can branch on it.
	storageLimitBytes, hasField := item["storage_limit_bytes"]
	assert.True(t, hasField, "team-tier item must contain storage_limit_bytes")
	assert.Equal(t, float64(-1), storageLimitBytes,
		"unlimited team tier must emit -1 sentinel, not 0 or a large byte count")

	// storage_exceeded must be false for unlimited tier.
	assert.Equal(t, false, item["storage_exceeded"],
		"unlimited tier must never set storage_exceeded=true")
}

// TestResourceToMap_StorageExceeded_OnListPath verifies that storage_exceeded
// is correctly computed on the list endpoint (not only single-GET) when a
// resource's storage_bytes exceeds the tier limit. This is the regression
// test for C01-F2 / D02-03.
func TestResourceToMap_StorageExceeded_OnListPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	reg := plans.Default()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	// Set storage_bytes to 1 more than the limit so the resource is "exceeded".
	limitMB := reg.StorageLimitMB("hobby", "postgres")
	require.Greater(t, limitMB, 0, "hobby postgres limit must be positive for this test")
	exceededBytes := int64(limitMB)*1_000_000 + 1

	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, storage_bytes)
		VALUES ($1::uuid, 'postgres', 'hobby', 'active', $2)
		RETURNING token::text
	`, teamID, exceededBytes).Scan(new(string)))

	body, status := listResourcesJSON(t, app, jwt)
	require.Equal(t, http.StatusOK, status)
	items := body["items"].([]any)
	require.Len(t, items, 1)
	item := items[0].(map[string]any)

	assert.Equal(t, true, item["storage_exceeded"],
		"list endpoint must set storage_exceeded=true when storage_bytes exceeds tier limit")
}

// TestPauseResponse_ContainsLimitFields verifies that the pause/resume response
// envelope returns a "resource" key (not "item") and that the resource shape
// includes storage_limit_bytes and connections_limit. This covers D02-02
// (wrong key name crashes the adapter) combined with D02-03 (missing limits).
func TestPauseResponse_ContainsLimitFields(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "postgres")

	resp := doPauseOrResume(t, fix.app, fix.jwt, "pause", fix.resourceToken)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	// The API must use key "resource", not "item" (D02-02 regression).
	resourceShape, hasResource := body["resource"]
	assert.True(t, hasResource,
		"pause response must contain 'resource' key (not 'item') so the TS adapter can read it")

	resourceMap, ok := resourceShape.(map[string]any)
	require.True(t, ok, "'resource' value must be a JSON object")

	// Limit fields must be present in the pause response resource shape.
	_, hasLimitBytes := resourceMap["storage_limit_bytes"]
	assert.True(t, hasLimitBytes,
		"pause response resource must contain storage_limit_bytes so quota bars update without a refetch")

	_, hasConnsLimit := resourceMap["connections_limit"]
	assert.True(t, hasConnsLimit,
		"pause response resource must contain connections_limit")
}
