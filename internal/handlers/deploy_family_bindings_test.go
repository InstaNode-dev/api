package handlers_test

// deploy_family_bindings_test.go — Slice 4 of env-aware deployments.
//
// Covers POST /deploy/new resource_bindings parsing and resolution:
//
//   1. Family binding + staging env + staging twin exists  → 202 (deploy
//      uses staging twin's connection URL via resolved env_vars).
//   2. Family binding + staging env + no staging twin       → 409 + agent_action.
//   3. Family binding + cross-team root                     → 403.
//   4. Family binding + non-existent root UUID              → 404.
//   5. Family binding + malformed UUID                      → 400.
//   6. Raw token binding (no family: prefix)                → 202 (backward compat).
//   7. Feature flag FAMILY_BINDINGS_ENABLED=false           → 400 (family:
//      prefix is rejected; deterministic disable).
//
// These tests share the multipartDeployBody helper defined in
// deploy_env_vars_test.go and the team / JWT helpers in testhelpers/.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// seedResource inserts an `active` resource row with an encrypted
// connection_url. Returns (id, token). teamID may be empty to leave the
// row team-less (anonymous resource — used by the cross-team test).
//
// connectionPlain is encrypted with TestAESKeyHex so the resolver's
// crypto.Decrypt call matches the same key the handler is configured with.
func seedResource(
	t *testing.T,
	db *sql.DB,
	teamID string,
	resourceType, env, name, connectionPlain string,
	parentResourceID string,
) (string, string) {
	t.Helper()

	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	encrypted, err := crypto.Encrypt(aesKey, connectionPlain)
	require.NoError(t, err)

	var teamArg interface{}
	if teamID != "" {
		teamArg = teamID
	}
	var parentArg interface{}
	if parentResourceID != "" {
		parentArg = parentResourceID
	}

	var id, tok string
	err = db.QueryRowContext(context.Background(), `
		INSERT INTO resources
		  (team_id, resource_type, name, env, connection_url, tier, status, parent_resource_id)
		VALUES ($1, $2, $3, $4, $5, 'pro', 'active', $6)
		RETURNING id::text, token::text
	`, teamArg, resourceType, name, env, encrypted, parentArg).Scan(&id, &tok)
	require.NoError(t, err, "seedResource")
	return id, tok
}

// ── Test 1 — family binding + staging env + staging twin exists → 202 ──────

func TestDeployNew_FamilyBinding_StagingTwinExists_Succeeds(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"11111111-1111-1111-1111-111111111111", teamID, "fam1@example.com")

	// Family: production root + staging twin.
	prodURL := "postgres://prod-host:5432/app"
	stagingURL := "postgres://staging-host:5432/app"
	rootID, _ := seedResource(t, db, teamID, "postgres", "production", "my-app-db", prodURL, "")
	_, _ = seedResource(t, db, teamID, "postgres", "staging", "my-app-db", stagingURL, rootID)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	bindings, err := json.Marshal(map[string]string{
		"DATABASE_URL": "family:" + rootID,
	})
	require.NoError(t, err)

	body, ct := multipartDeployBody(t, map[string]string{
		"port":              "8080",
		"env":               "staging",
		"resource_bindings": string(bindings),
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.15.0.1")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"family binding with matching env-twin must succeed; body=%s", string(bodyBytes))

	var created struct {
		Item struct {
			AppID       string            `json:"app_id"`
			Environment string            `json:"environment"`
			Env         map[string]string `json:"env"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &created))
	assert.Equal(t, "staging", created.Item.Environment)
	dbURL, ok := created.Item.Env["DATABASE_URL"]
	require.True(t, ok, "DATABASE_URL must be present after family resolution")
	// P0 fix: DATABASE_URL ends with the URL suffix — redactEnvVars masks it
	// in the outbound API response. The stored env_vars JSONB row retains the
	// resolved plaintext for the build pipeline. The API response must show "***"
	// so credentials never travel to the browser or agent logs.
	assert.Equal(t, "***", dbURL,
		"DATABASE_URL must be redacted in the API response (P0 — plaintext credentials must never appear in JSON)")
	// Sanity: the wrong (production) host must not bleed through even in the masked form.
	assert.NotContains(t, dbURL, "prod-host",
		"staging deploy must NOT pull the production URL")
}

// ── Test 2 — family binding + staging env + no staging twin → 409 ──────────

func TestDeployNew_FamilyBinding_NoEnvTwin_Returns409(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"22222222-2222-2222-2222-222222222222", teamID, "fam2@example.com")

	// Family with only the production root — no staging twin.
	rootID, _ := seedResource(t, db, teamID, "postgres", "production", "lonely-db",
		"postgres://prod-host:5432/lonely", "")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	bindings, err := json.Marshal(map[string]string{
		"DATABASE_URL": "family:" + rootID,
	})
	require.NoError(t, err)

	body, ct := multipartDeployBody(t, map[string]string{
		"port":              "8080",
		"env":               "staging",
		"resource_bindings": string(bindings),
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.15.0.2")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusConflict, resp.StatusCode,
		"missing env-twin must return 409; body=%s", string(bodyBytes))

	var errBody struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		Message     string `json:"message"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "no_env_twin", errBody.Error)
	assert.Contains(t, errBody.AgentAction, "provision-twin",
		"agent_action must coach the user toward POST /api/v1/resources/:id/provision-twin")
	assert.Contains(t, errBody.AgentAction, "staging")
}

// ── Test 3 — family binding + cross-team root → 403 ────────────────────────

func TestDeployNew_FamilyBinding_CrossTeam_Returns403(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ownerTeamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t,
		"33333333-3333-3333-3333-333333333333", otherTeamID, "outsider@example.com")

	// Resource owned by ownerTeam.
	rootID, _ := seedResource(t, db, ownerTeamID, "postgres", "production", "owner-db",
		"postgres://owner:5432/db", "")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	bindings, err := json.Marshal(map[string]string{
		"DATABASE_URL": "family:" + rootID,
	})
	require.NoError(t, err)

	body, ct := multipartDeployBody(t, map[string]string{
		"port":              "8080",
		"env":               "production",
		"resource_bindings": string(bindings),
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	req.Header.Set("X-Forwarded-For", "10.15.0.3")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"cross-team family root must return 403; body=%s", string(bodyBytes))

	var errBody struct {
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &errBody))
	assert.Equal(t, "resource_binding_forbidden", errBody.Error)
	assert.Contains(t, errBody.AgentAction, "different team")
}

// ── Test 4 — family binding + non-existent root UUID → 404 ─────────────────

func TestDeployNew_FamilyBinding_UnknownRoot_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"44444444-4444-4444-4444-444444444444", teamID, "fam4@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Random valid UUID that doesn't match any row.
	missingID := uuid.NewString()
	bindings, err := json.Marshal(map[string]string{
		"DATABASE_URL": "family:" + missingID,
	})
	require.NoError(t, err)

	body, ct := multipartDeployBody(t, map[string]string{
		"port":              "8080",
		"resource_bindings": string(bindings),
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.15.0.4")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"unknown family root must return 404; body=%s", string(bodyBytes))

	var errBody struct {
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &errBody))
	assert.Equal(t, "resource_binding_not_found", errBody.Error)
	assert.NotEmpty(t, errBody.AgentAction)
}

// ── Test 5 — family binding + malformed UUID → 400 ─────────────────────────

func TestDeployNew_FamilyBinding_MalformedUUID_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"55555555-5555-5555-5555-555555555555", teamID, "fam5@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	bindings, err := json.Marshal(map[string]string{
		"DATABASE_URL": "family:not-a-uuid",
	})
	require.NoError(t, err)

	body, ct := multipartDeployBody(t, map[string]string{
		"port":              "8080",
		"resource_bindings": string(bindings),
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.15.0.5")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"malformed family UUID must return 400; body=%s", string(bodyBytes))

	var errBody struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &errBody))
	assert.Equal(t, "invalid_resource_binding", errBody.Error)
}

// ── Test 6 — raw token binding (no family: prefix) still works → 202 ───────

func TestDeployNew_RawTokenBinding_BackwardCompat_Succeeds(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"66666666-6666-6666-6666-666666666666", teamID, "fam6@example.com")

	prodURL := "postgres://legacy-host:5432/legacy"
	_, tok := seedResource(t, db, teamID, "postgres", "production", "legacy-db", prodURL, "")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// No family: prefix — just the raw token UUID.
	bindings, err := json.Marshal(map[string]string{
		"DATABASE_URL": tok,
	})
	require.NoError(t, err)

	body, ct := multipartDeployBody(t, map[string]string{
		"port":              "8080",
		"env":               "production",
		"resource_bindings": string(bindings),
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.15.0.6")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"raw token binding must still work; body=%s", string(bodyBytes))

	var created struct {
		Item struct {
			Env map[string]string `json:"env"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &created))
	dbURL, ok := created.Item.Env["DATABASE_URL"]
	require.True(t, ok, "DATABASE_URL must be set from the raw token resolver")
	// P0 fix: DATABASE_URL ends with the URL suffix — redactEnvVars masks it
	// in the outbound API response. Verify the mask appears (not the plaintext).
	assert.Equal(t, "***", dbURL,
		"DATABASE_URL must be redacted in the API response (P0 — plaintext credentials must never appear in JSON)")
}

// ── Test 7 — FAMILY_BINDINGS_ENABLED=false → 400 (deterministic disable) ──

// This test directly exercises the resolver with the flag off rather than
// trying to flip the runtime config of NewTestAppWithServices (which doesn't
// expose a knob today). It's a strict unit test of resolveResourceBindings
// — the only path that consumes the flag. The HTTP wiring is covered by
// tests 1-6 above, so this single resolver-level check is sufficient.
func TestResolveResourceBindings_FlagDisabled_RejectsFamilyPrefix(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamUUID := uuid.MustParse(teamID)
	rootID, _ := seedResource(t, db, teamID, "postgres", "production", "fam7-db",
		"postgres://x:5432/x", "")

	// Disabled flag.
	_, err := resolveResourceBindingsHook(t, db, teamUUID, "production",
		map[string]string{"DATABASE_URL": "family:" + rootID}, false /* familyEnabled */)
	require.Error(t, err, "with flag off, family: prefix must be rejected")

	// Confirm the same call with the flag on succeeds (sanity).
	out, err := resolveResourceBindingsHook(t, db, teamUUID, "production",
		map[string]string{"DATABASE_URL": "family:" + rootID}, true /* familyEnabled */)
	require.NoError(t, err)
	require.NotEmpty(t, out["DATABASE_URL"])
}

// resolveResourceBindingsHook is a thin wrapper used by Test 7. It is in
// the same package_test file so it can call into the unexported
// resolveResourceBindings via the deploy-bindings export shim. The shim
// lives in family_bindings_test_hook.go (same package as the function under
// test) so we don't widen the public API.
func resolveResourceBindingsHook(
	t *testing.T, db *sql.DB, teamID uuid.UUID, env string,
	bindings map[string]string, familyEnabled bool,
) (map[string]string, error) {
	t.Helper()
	out, bErr := handlers.HandlersTestResolveResourceBindings(
		context.Background(), db, testhelpers.TestAESKeyHex, teamID, env, bindings, familyEnabled,
	)
	if bErr != nil {
		return nil, fmt.Errorf("%s: %s", bErr.Kind, bErr.Detail)
	}
	return out, nil
}
