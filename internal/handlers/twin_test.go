package handlers_test

// twin_test.go — handler-layer tests for slice 3 of env-aware deployments.
// Exercises POST /api/v1/resources/:id/provision-twin through the actual
// Fiber router stack (registered in testhelpers.NewTestApp), so route
// ordering, auth middleware, body parsing, and JSON shapes are all
// covered. Coverage targets the 8 cases called out in the slice 3 prompt:
//
//   1. Hobby tier → 402 + agent_action + upgrade_url
//   2. Cross-team source → 403 (no metadata leak)
//   3. Source not found → 404
//   4. env == source.env → 400 same_env
//   5. Existing twin in target env → 409 twin_exists
//   6. Unsupported resource type (webhook/queue/storage) → 400 unsupported_for_twin
//   7. Missing/invalid env → 400 missing_env / invalid_env
//   8. Happy path (pro tier, root source, no existing twin) → 201 + family linkage
//
// The happy-path test (8) hits the live local Postgres provisioner; it
// skips gracefully when postgres-customers isn't reachable so the suite
// stays green on minimal dev machines. The other seven cases short-circuit
// before provisioning runs, so they never need a real backend.

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

	"instant.dev/internal/testhelpers"
)

// twinErrorBody is the response shape every non-201 path returns. Carrying
// the optional agent_action / upgrade_url here lets the 402 assertion
// share a decoder with every other error case.
type twinErrorBody struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error"`
	Message     string `json:"message"`
	AgentAction string `json:"agent_action,omitempty"`
	UpgradeURL  string `json:"upgrade_url,omitempty"`
}

// seedTwinSource inserts a family-root resource owned by teamID at
// production env. Returns the row's id+token so the test can target it.
// Direct SQL keeps the test independent of CreateResource signature drift.
func seedTwinSource(t *testing.T, db *sql.DB, teamID, resourceType, tier string) (id, token string) {
	t.Helper()
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env)
		VALUES ($1::uuid, $2, $3, 'production')
		RETURNING id::text, token::text
	`, teamID, resourceType, tier).Scan(&id, &token)
	require.NoError(t, err, "seedTwinSource(team=%s, type=%s, tier=%s)", teamID, resourceType, tier)
	return id, token
}

// seedTwinSibling inserts a non-root member at the given env, linked to
// parentID. Used to set up the duplicate-twin-in-env conflict case.
func seedTwinSibling(t *testing.T, db *sql.DB, teamID, parentID, resourceType, tier, env string) string {
	t.Helper()
	var id string
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env, parent_resource_id)
		VALUES ($1::uuid, $2, $3, $4, $5::uuid)
		RETURNING id::text
	`, teamID, resourceType, tier, env, parentID).Scan(&id)
	require.NoError(t, err, "seedTwinSibling(team=%s, type=%s, env=%s)", teamID, resourceType, env)
	return id
}

// twinJWT seeds a user row and returns a signed session JWT. Mirrors the
// makeAuthedJWT helper in resource_family_test.go but kept inline so this
// file can move/rename independently of slice 2.
func twinJWT(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

// postTwin issues POST /api/v1/resources/:id/provision-twin with the given
// JSON body and JWT. Returns the response — caller closes the body.
func postTwin(t *testing.T, app interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}, sourceToken, jwt string, body map[string]any) *http.Response {
	t.Helper()
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+sourceToken+"/provision-twin",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// decodeErr decodes the standard error response shape.
func decodeErr(t *testing.T, resp *http.Response) twinErrorBody {
	t.Helper()
	var body twinErrorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}

//  1. Hobby tier → 402 with agent_action + upgrade_url. Multi-env is a
//     Pro+ differentiator (see plans.yaml + PricingPage.tsx); the response
//     must hand an agent enough context to know what to ask the user.
func TestProvisionTwin_HobbyTier_Returns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := twinJWT(t, db, teamID)
	// Source is hobby-tier — handler reads team.plan_tier, not resource.tier.
	_, sourceToken := seedTwinSource(t, db, teamID, "postgres", "hobby")

	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)

	body := decodeErr(t, resp)
	assert.Equal(t, "upgrade_required", body.Error)
	assert.NotEmpty(t, body.AgentAction, "402 must carry agent_action so MCP knows what to tell the user")
	assert.NotEmpty(t, body.UpgradeURL, "402 must carry upgrade_url")
}

//  2. Cross-team source → 404. The caller is authenticated, but the source
//     belongs to a different team. The response must NOT confirm that the
//     resource exists in another tenant — 404 keeps it indistinguishable
//     from a non-existent id.
func TestProvisionTwin_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")

	// Team A owns the source.
	_, sourceToken := seedTwinSource(t, db, teamA, "postgres", "pro")
	// Team B authenticates.
	jwtB := twinJWT(t, db, teamB)

	resp := postTwin(t, app, sourceToken, jwtB, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team source must be 404 — never confirm the resource's existence to a non-owner")

	body := decodeErr(t, resp)
	assert.Equal(t, "not_found", body.Error)
}

//  3. Source not found → 404. Caller passes a syntactically-valid UUID
//     that doesn't exist in the resources table.
func TestProvisionTwin_SourceNotFound_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)

	missing := uuid.New().String()
	resp := postTwin(t, app, missing, jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	body := decodeErr(t, resp)
	assert.Equal(t, "not_found", body.Error)
}

//  4. env == source.env → 400 same_env. Without this guard the agent would
//     get a confusing 409 twin_exists (the source itself occupies the env).
//     A typed 400 lets the agent prompt the user for the right env.
func TestProvisionTwin_SameEnv_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	// Source is in production; we'll ask for a production twin.
	_, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "production"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body := decodeErr(t, resp)
	assert.Equal(t, "same_env", body.Error,
		"requesting a twin in the source's own env is a client error, not a 409")
}

//  5. Existing twin in target env → 409 twin_exists. One twin per env per
//     family — the migration-level partial unique index is the schema
//     guard; the handler returns a friendly 409 instead of leaking the
//     Postgres constraint string.
//
//     Uses env="development" so the migration-026 email-link approval
//     gate is bypassed (dev-env twins execute immediately). The
//     duplicate-twin guard is the contract under test here, not the
//     approval flow — that lives in promote_approval_test.go.
func TestProvisionTwin_DuplicateInEnv_Returns409(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)

	rootID, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")
	// Pre-existing development sibling occupies the target slot.
	seedTwinSibling(t, db, teamID, rootID, "postgres", "pro", "development")

	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "development"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)

	body := decodeErr(t, resp)
	assert.Equal(t, "twin_exists", body.Error)
}

//  6. Unsupported resource type → 400 unsupported_for_twin. The webhook /
//     queue / storage types either have no per-env infra (webhook stores a
//     token, queue is a logical NATS subject) or model env at the prefix
//     level (storage). The handler refuses cleanly with an actionable code.
func TestProvisionTwin_UnsupportedType_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	// Webhook resources can't have an env-twin — there's no infra per env.
	_, sourceToken := seedTwinSource(t, db, teamID, "webhook", "pro")

	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body := decodeErr(t, resp)
	assert.Equal(t, "unsupported_for_twin", body.Error)
}

//  7. Missing or invalid env → 400 missing_env / invalid_env. Covers the
//     two body-validation paths in one table-driven test so they don't
//     drift apart silently.
func TestProvisionTwin_BadEnv_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	_, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	cases := []struct {
		name     string
		body     map[string]any
		wantCode string
	}{
		{"missing env", map[string]any{}, "missing_env"},
		{"empty env", map[string]any{"env": ""}, "missing_env"},
		// Uppercase + invalid chars both fail the ^[a-z0-9-]{1,32}$ guard.
		{"uppercase env", map[string]any{"env": "STAGING"}, "invalid_env"},
		{"space in env", map[string]any{"env": "stag ing"}, "invalid_env"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp := postTwin(t, app, sourceToken, jwt, tc.body)
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			body := decodeErr(t, resp)
			assert.Equal(t, tc.wantCode, body.Error)
		})
	}
}

//  8. Happy path — Pro tier, root source, no existing twin in target env.
//     Provisions a real Postgres twin via the local provider, asserts the
//     201 shape carries family_root_id + connection_url + tier=pro + env.
//     Skips when the postgres-customers backend isn't reachable (same skip
//     posture as MustProvisionDB) so this stays green on minimal dev
//     machines. The DB row is also asserted directly to confirm
//     parent_resource_id points at the family root.
//
//     Uses env="development" so the migration-026 email-link approval
//     gate is bypassed — the happy-path provisioning contract is the
//     contract under test here, NOT the approval flow. Non-dev happy-
//     path coverage lives in promote_approval_test.go via the
//     manual-trigger approval_id branch.
func TestProvisionTwin_Pro_HappyPath_Returns201(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	// Postgres must be enabled — otherwise the per-service handler returns
	// 503 service_disabled before ever provisioning.
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	rootID, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	resp := postTwin(t, app, sourceToken, jwt, map[string]any{
		"env":  "development",
		"name": "my-app-db-development",
	})
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		// The local postgres-customers backend isn't reachable in this
		// dev environment; the handler correctly returned 503
		// provision_failed. Skip rather than fail — the path is exercised
		// end-to-end in api/e2e against the live cluster.
		var body twinErrorBody
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body.Error == "provision_failed" || body.Error == "service_disabled" {
			t.Skipf("provision-twin happy path skipped: %s (%s)", body.Error, body.Message)
		}
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode, "expected 201 on happy path")

	var ok struct {
		OK            bool   `json:"ok"`
		ID            string `json:"id"`
		Token         string `json:"token"`
		Name          string `json:"name"`
		ConnectionURL string `json:"connection_url"`
		Tier          string `json:"tier"`
		Env           string `json:"env"`
		FamilyRootID  string `json:"family_root_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&ok))
	assert.True(t, ok.OK)
	assert.NotEmpty(t, ok.ID)
	assert.NotEmpty(t, ok.Token)
	assert.NotEmpty(t, ok.ConnectionURL, "twin must carry a fresh connection_url")
	assert.Equal(t, "pro", ok.Tier, "twin inherits source.Tier")
	assert.Equal(t, "development", ok.Env)
	assert.Equal(t, rootID, ok.FamilyRootID, "twin's family_root_id must point at the source root")

	// Verify the DB row carries the linkage. Belt-and-braces — the JSON
	// response could lie about family_root_id without the row being right.
	var parentID sql.NullString
	var env string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT parent_resource_id::text, env FROM resources WHERE id = $1::uuid`,
		ok.ID,
	).Scan(&parentID, &env))
	require.True(t, parentID.Valid, "twin row must have parent_resource_id set")
	assert.Equal(t, rootID, parentID.String, "DB row parent_resource_id must equal source root id")
	assert.Equal(t, "development", env)
}
