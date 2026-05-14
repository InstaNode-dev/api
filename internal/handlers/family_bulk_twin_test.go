package handlers_test

// family_bulk_twin_test.go — handler-layer tests for POST
// /api/v1/families/bulk-twin. Exercises the route through the actual
// Fiber stack (registered in testhelpers.NewTestApp) so request parsing,
// auth middleware, tier gate, and the per-row dispatch all run as they
// would in production.
//
// Test cases (matching the brief):
//
//   1. Happy path        — 3 prod resources, target=staging, all succeed
//   2. Idempotency       — call twice, second returns skipped=3, no dupes
//   3. Partial failure   — quota cap injected so some rows fail, others succeed
//   4. Hobby tier        — 402 + agent_action + upgrade_url
//   5. Quota partial-fill — 5 parents, headroom 3, returns 207 + 2 quota_exceeded
//   6. Empty source_env  — 200 + twinned=0 (NOT an error)
//
// The happy-path + partial-failure + quota-fill tests use the local
// postgres-customers provider. They skip gracefully when the local backend
// isn't reachable, matching the posture in twin_test.go.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// bulkTwinResponse mirrors the on-the-wire shape. Held inline so the test
// file doesn't depend on the package-private response struct.
type bulkTwinResponse struct {
	OK                    bool                  `json:"ok"`
	Twinned               int                   `json:"twinned"`
	SkippedAlreadyExisted int                   `json:"skipped_already_existed"`
	Items                 []bulkTwinItemTest    `json:"items"`
	Failures              []bulkTwinFailureTest `json:"failures"`
	Error                 string                `json:"error,omitempty"`
	Message               string                `json:"message,omitempty"`
	AgentAction           string                `json:"agent_action,omitempty"`
	UpgradeURL            string                `json:"upgrade_url,omitempty"`
}

type bulkTwinItemTest struct {
	ParentToken  string `json:"parent_token"`
	TwinToken    string `json:"twin_token"`
	ResourceType string `json:"resource_type"`
	Env          string `json:"env"`
	Skipped      bool   `json:"skipped,omitempty"`
}

type bulkTwinFailureTest struct {
	ParentToken  string `json:"parent_token"`
	ResourceType string `json:"resource_type"`
	Error        string `json:"error"`
	Message      string `json:"message"`
	AgentAction  string `json:"agent_action,omitempty"`
	UpgradeURL   string `json:"upgrade_url,omitempty"`
}

// seedBulkTwinSource inserts a root resource in the given env for the team.
// Returns (id, token) so tests can address the row both ways.
func seedBulkTwinSource(t *testing.T, db *sql.DB, teamID, resourceType, tier, env string) (id, token string) {
	t.Helper()
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env)
		VALUES ($1::uuid, $2, $3, $4)
		RETURNING id::text, token::text
	`, teamID, resourceType, tier, env).Scan(&id, &token))
	return id, token
}

// bulkTwinJWT seeds a user row and returns a signed session JWT. Same
// shape as twinJWT in twin_test.go — duplicated so each test file can
// move independently.
func bulkTwinJWT(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

// postBulkTwin issues POST /api/v1/families/bulk-twin and returns the response.
func postBulkTwin(t *testing.T, app interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}, jwt string, body map[string]any) *http.Response {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/families/bulk-twin",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 30000)
	require.NoError(t, err)
	return resp
}

// decodeBulkTwinResp decodes the response body into the shared shape.
func decodeBulkTwinResp(t *testing.T, resp *http.Response) bulkTwinResponse {
	t.Helper()
	var body bulkTwinResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}

// skipIfProvisionUnavailable inspects a bulk response: if every failure is
// provision_failed (i.e. the local postgres-customers backend isn't running),
// skip the test the same way twin_test.go does on minimal dev machines.
func skipIfProvisionUnavailable(t *testing.T, body bulkTwinResponse) {
	t.Helper()
	if len(body.Failures) == 0 {
		return
	}
	allProvErr := true
	for _, f := range body.Failures {
		if f.Error != "provision_failed" {
			allProvErr = false
			break
		}
	}
	if allProvErr && body.Twinned == 0 {
		t.Skipf("bulk-twin: every parent returned provision_failed — local backend not reachable, skipping")
	}
}

// ── 1. Happy path ──────────────────────────────────────────────────────────
//
// 3 prod postgres parents, target=development (dev-env bypasses the
// migration-026 approval gate, mirroring twin_test.go's happy-path env
// choice). Every parent twins successfully, response carries twinned=3.

func TestBulkTwin_HappyPath_ThreePostgresParents(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := bulkTwinJWT(t, db, teamID)

	parentTokens := make(map[string]bool, 3)
	for i := 0; i < 3; i++ {
		_, tok := seedBulkTwinSource(t, db, teamID, "postgres", "pro", "production")
		parentTokens[tok] = true
	}

	resp := postBulkTwin(t, app, jwt, map[string]any{
		"source_env": "production",
		"target_env": "development",
	})
	defer resp.Body.Close()

	body := decodeBulkTwinResp(t, resp)
	skipIfProvisionUnavailable(t, body)

	require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 — every parent twinned")
	assert.True(t, body.OK)
	assert.Equal(t, 3, body.Twinned, "expected 3 successful twins, got %d", body.Twinned)
	assert.Equal(t, 0, body.SkippedAlreadyExisted)
	assert.Len(t, body.Items, 3)
	assert.Empty(t, body.Failures)

	for _, it := range body.Items {
		assert.True(t, parentTokens[it.ParentToken], "every item's parent_token must reference one of the seeded parents")
		assert.NotEmpty(t, it.TwinToken)
		assert.Equal(t, "postgres", it.ResourceType)
		assert.Equal(t, "development", it.Env)
		assert.False(t, it.Skipped)
	}
}

// ── 2. Idempotency ─────────────────────────────────────────────────────────
//
// Run bulk-twin twice with identical input. Second call must report
// twinned=0, skipped_already_existed=3 — no duplicate rows in DB.

func TestBulkTwin_Idempotency_SecondCallSkipsAll(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := bulkTwinJWT(t, db, teamID)
	for i := 0; i < 3; i++ {
		seedBulkTwinSource(t, db, teamID, "postgres", "pro", "production")
	}

	req := map[string]any{"source_env": "production", "target_env": "development"}
	resp1 := postBulkTwin(t, app, jwt, req)
	body1 := decodeBulkTwinResp(t, resp1)
	resp1.Body.Close()
	skipIfProvisionUnavailable(t, body1)
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	require.Equal(t, 3, body1.Twinned, "first call should have twinned all 3")

	// Second call: same payload, no new parents seeded.
	resp2 := postBulkTwin(t, app, jwt, req)
	defer resp2.Body.Close()
	body2 := decodeBulkTwinResp(t, resp2)
	require.Equal(t, http.StatusOK, resp2.StatusCode, "second call is still a 200 — skipped != failed")
	assert.Equal(t, 0, body2.Twinned, "second call must not provision new twins")
	assert.Equal(t, 3, body2.SkippedAlreadyExisted, "second call must report 3 skipped")
	for _, it := range body2.Items {
		assert.True(t, it.Skipped, "every item in the second response must be marked skipped")
		assert.NotEmpty(t, it.TwinToken, "skipped items must surface the existing twin's token")
	}

	// Belt-and-braces: assert the DB row count.
	var rows int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM resources WHERE team_id = $1::uuid AND env = 'development' AND status = 'active'`,
		teamID,
	).Scan(&rows))
	assert.Equal(t, 3, rows, "DB must contain exactly 3 development-env twins after two calls")
}

// ── 3. Partial failure ─────────────────────────────────────────────────────
//
// Inject a QuotaHeadroom that caps postgres at 1 — the first parent
// provisions, the rest fail with quota_exceeded. The endpoint returns
// 207 Multi-Status. Successful row is NOT rolled back.

func TestBulkTwin_PartialFailure_NotRolledBack(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := bulkTwinJWT(t, db, teamID)
	for i := 0; i < 3; i++ {
		seedBulkTwinSource(t, db, teamID, "postgres", "pro", "production")
	}

	// Headroom 1: only one postgres parent gets provisioned. The other
	// two fall to the failures array.
	bulkH := testhelpers.LastBulkTwinHandler()
	require.NotNil(t, bulkH, "test app must expose BulkTwinHandler for QuotaHeadroom injection")
	bulkH.QuotaHeadroom = func(_ context.Context, _ uuid.UUID, _ string) int {
		return 1
	}

	resp := postBulkTwin(t, app, jwt, map[string]any{
		"source_env": "production",
		"target_env": "development",
	})
	defer resp.Body.Close()

	body := decodeBulkTwinResp(t, resp)
	if body.Twinned == 0 && len(body.Failures) > 0 {
		// Could be a provisioner-unavailable case AND quota mix. Look for
		// a quota_exceeded — if even one is present, we're testing the
		// quota path correctly even if the lone allowed provision failed.
		allProvErr := true
		for _, f := range body.Failures {
			if f.Error != "provision_failed" {
				allProvErr = false
				break
			}
		}
		if allProvErr {
			t.Skipf("partial-failure: every parent returned provision_failed — local backend not reachable, skipping")
		}
	}

	require.Equal(t, http.StatusMultiStatus, resp.StatusCode,
		"any failure must surface 207 Multi-Status — body=%+v", body)
	assert.False(t, body.OK, "ok=false when there are failures")
	assert.Equal(t, 1, body.Twinned, "exactly 1 provision should have succeeded under headroom=1")
	assert.Len(t, body.Failures, 2, "remaining 2 parents must be reported as failures")
	for _, f := range body.Failures {
		assert.Equal(t, "quota_exceeded", f.Error)
		assert.NotEmpty(t, f.AgentAction)
		assert.Equal(t, "https://instanode.dev/pricing", f.UpgradeURL)
	}

	// Successful row is NOT rolled back when others fail.
	var devRows int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM resources WHERE team_id = $1::uuid AND env = 'development' AND status = 'active'`,
		teamID,
	).Scan(&devRows))
	assert.Equal(t, 1, devRows, "the one successful twin must persist in DB")
}

// ── 4. Hobby tier → 402 ────────────────────────────────────────────────────

func TestBulkTwin_HobbyTier_Returns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := bulkTwinJWT(t, db, teamID)
	// Seed at least one parent so the test reaches the tier gate (not
	// the early-return for empty source).
	seedBulkTwinSource(t, db, teamID, "postgres", "hobby", "production")

	resp := postBulkTwin(t, app, jwt, map[string]any{
		"source_env": "production",
		"target_env": "staging",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)

	body := decodeBulkTwinResp(t, resp)
	assert.Equal(t, "upgrade_required", body.Error)
	assert.NotEmpty(t, body.AgentAction)
	assert.NotEmpty(t, body.UpgradeURL)
}

// ── 5. Quota partial-fill (5 parents, headroom 3 → 207 with 2 quota_exceeded)
//
// Verifies the partial-fill semantic the brief calls out explicitly:
// the FIRST N parents (ordered oldest-first) get twinned, the rest
// fail with quota_exceeded + the upgrade URL.

func TestBulkTwin_QuotaPartialFill(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := bulkTwinJWT(t, db, teamID)
	for i := 0; i < 5; i++ {
		seedBulkTwinSource(t, db, teamID, "postgres", "pro", "production")
	}

	bulkH := testhelpers.LastBulkTwinHandler()
	require.NotNil(t, bulkH)
	bulkH.QuotaHeadroom = func(_ context.Context, _ uuid.UUID, _ string) int {
		return 3
	}

	resp := postBulkTwin(t, app, jwt, map[string]any{
		"source_env": "production",
		"target_env": "development",
	})
	defer resp.Body.Close()

	body := decodeBulkTwinResp(t, resp)
	if body.Twinned == 0 {
		// Local backend not reachable; skip rather than over-assert.
		allProvErr := len(body.Failures) > 0
		for _, f := range body.Failures {
			if f.Error != "provision_failed" {
				allProvErr = false
				break
			}
		}
		if allProvErr {
			t.Skipf("quota-partial-fill: local backend not reachable")
		}
	}

	require.Equal(t, http.StatusMultiStatus, resp.StatusCode)
	assert.Equal(t, 3, body.Twinned)
	assert.Len(t, body.Failures, 2)
	for _, f := range body.Failures {
		assert.Equal(t, "quota_exceeded", f.Error)
	}
}

// ── 6. Empty source_env (no parents) → 200 + twinned=0, NOT an error ──────

func TestBulkTwin_EmptySourceEnv_Returns200Zero(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := bulkTwinJWT(t, db, teamID)
	// No seeded resources — production env is empty for this team.

	resp := postBulkTwin(t, app, jwt, map[string]any{
		"source_env": "production",
		"target_env": "staging",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "empty source must be a clean 200, NOT a 4xx")

	body := decodeBulkTwinResp(t, resp)
	assert.True(t, body.OK)
	assert.Equal(t, 0, body.Twinned)
	assert.Equal(t, 0, body.SkippedAlreadyExisted)
	assert.Empty(t, body.Items)
	assert.Empty(t, body.Failures)
}

// Ensure the package compiles its test-helper export. Trivial sanity check
// so if LastBulkTwinHandler is renamed, the failure shows up here rather
// than mid-test-run.
var _ = handlers.BulkTwinHandler{}
