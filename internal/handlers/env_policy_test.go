package handlers_test

// env_policy_test.go — Slice 6 (per-env access policy) coverage.
//
// The non-negotiable test is the FIRST one: an empty `{}` policy MUST allow
// every action by every role. If that ever flips, every team that hasn't
// explicitly configured a policy would be locked out. Treat any change to
// that test's expectations as a P0 regression.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// envPolicyApp wires the minimum set of routes needed by these tests:
//   - GET/PUT /api/v1/team/env-policy
//   - DELETE /api/v1/resources/:id (env-policy gated by resource.env)
//   - POST /api/v1/vault/copy-mock (env-policy gated by "to")
//   - POST /deploy-new-mock (env-policy gated by multipart form "env")
//
// The vault and deploy routes are stubs that just return 200 after the
// middleware accepts — the goal is to verify middleware behaviour, not
// full handler semantics (covered by existing handler tests).
func envPolicyApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Mirror the production ErrorHandler: ErrResponseWritten means
			// respondError already wrote the body — short-circuit so we
			// don't overwrite the 400/403/etc. with a 500.
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			if e, ok := err.(*fiber.Error); ok {
				return c.Status(e.Code).JSON(fiber.Map{"ok": false, "error": "fiber_error"})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": "internal"})
		},
	})

	middleware.SetRoleLookupDB(db)
	middleware.SetEnvPolicyDB(db)

	envPolicyH := handlers.NewEnvPolicyHandler(db)

	api := app.Group("/api/v1", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())
	api.Get("/team/env-policy", envPolicyH.Get)
	api.Put("/team/env-policy", envPolicyH.Put)

	// DELETE /resources/:id — env-policy via resource-row lookup. We use a
	// stub OK handler after the middleware because the real ResourceHandler
	// has too many dependencies (provisioner, storage provider, ...).
	api.Delete("/resources/:id",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeleteResource,
			middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
				return handlers.ResourceEnvByTokenOrIDForMiddleware(c, db)
			}),
		),
		func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) },
	)

	api.Post("/vault/copy-mock",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite),
		func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) },
	)

	deployGroup := app.Group("/deploy", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())
	deployGroup.Post("/new",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy,
			middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
				if v := c.FormValue("env"); v != "" {
					return v, nil
				}
				return "", nil
			}),
		),
		func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) },
	)

	return app
}

func insertUserWithRole(t *testing.T, db *sql.DB, teamID, role string) string {
	t.Helper()
	var uid string
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO users (team_id, email, role) VALUES ($1, $2, $3)
		RETURNING id::text
	`, teamID, fmt.Sprintf("user-%s@example.com", uuid.NewString()[:8]), role).Scan(&uid)
	require.NoError(t, err)
	return uid
}

func insertResourceRow(t *testing.T, db *sql.DB, teamID, env string) string {
	t.Helper()
	var token string
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, name, tier, env, status)
		VALUES ($1, 'postgres', 'r', 'pro', $2, 'active')
		RETURNING token::text
	`, teamID, env).Scan(&token)
	require.NoError(t, err)
	return token
}

func setEnvPolicy(t *testing.T, db *sql.DB, teamID, policyJSON string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`UPDATE teams SET env_policy = $1::jsonb WHERE id = $2`, policyJSON, teamID)
	require.NoError(t, err)
}

func doReq(t *testing.T, app *fiber.App, method, path, jwt string, body []byte, ctype string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func multipartDeployReq(t *testing.T, env string) ([]byte, string) {
	t.Helper()
	// Build the smallest possible multipart with just the "env" field —
	// our stub deploy handler never reads the tarball.
	buf := &bytes.Buffer{}
	// Boundary chosen to be stable + match the Content-Type below.
	boundary := "----testboundary"
	fmt.Fprintf(buf, "--%s\r\n", boundary)
	buf.WriteString("Content-Disposition: form-data; name=\"env\"\r\n\r\n")
	buf.WriteString(env)
	buf.WriteString("\r\n")
	fmt.Fprintf(buf, "--%s--\r\n", boundary)
	return buf.Bytes(), "multipart/form-data; boundary=" + boundary
}

// ── 1. CRITICAL: empty policy {} allows EVERY action by EVERY role ────────────
//
// This is the backward-compat guarantee. If this test ever fails, real teams
// will get locked out of resources they own. Keep it first; keep it simple.

func TestEnvPolicy_EmptyPolicy_AllowsEverything(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	// teams.env_policy defaults to '{}' — don't touch it.

	devID := insertUserWithRole(t, db, teamID, "developer")
	viewerID := insertUserWithRole(t, db, teamID, "viewer")
	resToken := insertResourceRow(t, db, teamID, "production")

	app := envPolicyApp(t, db)

	// (a) Developer can deploy to production with empty policy.
	devJWT := testhelpers.MustSignSessionJWT(t, devID, teamID, "dev@example.com")
	body, ctype := multipartDeployReq(t, "production")
	code, _ := doReq(t, app, http.MethodPost, "/deploy/new", devJWT, body, ctype)
	assert.Equal(t, http.StatusOK, code, "empty policy MUST allow developer to deploy production")

	// (b) Viewer can DELETE a production resource with empty policy.
	viewerJWT := testhelpers.MustSignSessionJWT(t, viewerID, teamID, "viewer@example.com")
	code, _ = doReq(t, app, http.MethodDelete, "/api/v1/resources/"+resToken, viewerJWT, nil, "")
	assert.Equal(t, http.StatusOK, code, "empty policy MUST allow viewer to delete prod resource")

	// (c) Viewer can vault-copy to production with empty policy.
	cp := map[string]any{"to": "production", "from": "staging"}
	raw, _ := json.Marshal(cp)
	code, _ = doReq(t, app, http.MethodPost, "/api/v1/vault/copy-mock", viewerJWT, raw, "application/json")
	assert.Equal(t, http.StatusOK, code, "empty policy MUST allow viewer to vault-copy to production")
}

// ── 2. production.deploy:[owner] + developer user → 403 + agent_action ──────

func TestEnvPolicy_ProdDeployOwnerOnly_DeveloperDenied(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	setEnvPolicy(t, db, teamID, `{"production":{"deploy":["owner"]}}`)

	devID := insertUserWithRole(t, db, teamID, "developer")
	devJWT := testhelpers.MustSignSessionJWT(t, devID, teamID, "dev@example.com")

	app := envPolicyApp(t, db)
	body, ctype := multipartDeployReq(t, "production")
	code, respBody := doReq(t, app, http.MethodPost, "/deploy/new", devJWT, body, ctype)

	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "env_policy_denied", respBody["error"])
	assert.Equal(t, "production", respBody["env"])
	assert.Equal(t, "deploy", respBody["action"])
	assert.Equal(t, "developer", respBody["role"])
	// allowed_roles arrives as []interface{} from json.Unmarshal into map[string]any.
	allowed, ok := respBody["allowed_roles"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"owner"}, allowed)
	agentAction, ok := respBody["agent_action"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, agentAction)
	assert.Contains(t, agentAction, "owner")
	assert.Contains(t, agentAction, "developer")
	assert.Contains(t, agentAction, "production")
}

// ── 3. production.deploy:[owner] + owner user → 200 ──────────────────────────

func TestEnvPolicy_ProdDeployOwnerOnly_OwnerAllowed(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	setEnvPolicy(t, db, teamID, `{"production":{"deploy":["owner"]}}`)

	ownerID := insertUserWithRole(t, db, teamID, "owner")
	ownerJWT := testhelpers.MustSignSessionJWT(t, ownerID, teamID, "owner@example.com")

	app := envPolicyApp(t, db)
	body, ctype := multipartDeployReq(t, "production")
	code, _ := doReq(t, app, http.MethodPost, "/deploy/new", ownerJWT, body, ctype)
	assert.Equal(t, http.StatusOK, code, "owner must be allowed when policy lists owner")
}

// ── 4. Developer deletes a staging resource (not in policy) → 200 ────────────
//
// Policy only restricts production.delete_resource — staging is not gated,
// so the developer can delete a staging resource freely.

func TestEnvPolicy_DeleteStagingResource_NotInPolicy_Allowed(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	setEnvPolicy(t, db, teamID, `{"production":{"delete_resource":["owner"]}}`)

	devID := insertUserWithRole(t, db, teamID, "developer")
	devJWT := testhelpers.MustSignSessionJWT(t, devID, teamID, "dev@example.com")

	stagingToken := insertResourceRow(t, db, teamID, "staging")

	app := envPolicyApp(t, db)
	code, _ := doReq(t, app, http.MethodDelete, "/api/v1/resources/"+stagingToken, devJWT, nil, "")
	assert.Equal(t, http.StatusOK, code, "developer must be allowed to delete staging resource (not in policy)")
}

// ── 4b. Counterpart: developer deletes a production resource → 403 ───────────

func TestEnvPolicy_DeleteProductionResource_OwnerOnly_DeveloperDenied(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	setEnvPolicy(t, db, teamID, `{"production":{"delete_resource":["owner"]}}`)

	devID := insertUserWithRole(t, db, teamID, "developer")
	devJWT := testhelpers.MustSignSessionJWT(t, devID, teamID, "dev@example.com")

	prodToken := insertResourceRow(t, db, teamID, "production")

	app := envPolicyApp(t, db)
	code, body := doReq(t, app, http.MethodDelete, "/api/v1/resources/"+prodToken, devJWT, nil, "")
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "env_policy_denied", body["error"])
	assert.Equal(t, "delete_resource", body["action"])
}

// ── 5. PUT /team/env-policy as non-owner → 403 ──────────────────────────────

func TestEnvPolicy_PutAsDeveloper_Denied(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	devID := insertUserWithRole(t, db, teamID, "developer")
	devJWT := testhelpers.MustSignSessionJWT(t, devID, teamID, "dev@example.com")

	app := envPolicyApp(t, db)
	code, body := doReq(t, app, http.MethodPut, "/api/v1/team/env-policy", devJWT,
		[]byte(`{"production":{"deploy":["owner"]}}`), "application/json")
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "owner_required", body["error"])
	assert.Contains(t, body["agent_action"], "owner")
}

// ── 6. PUT /team/env-policy with malformed JSON → 400 ───────────────────────

func TestEnvPolicy_PutMalformedJSON_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := insertUserWithRole(t, db, teamID, "owner")
	ownerJWT := testhelpers.MustSignSessionJWT(t, ownerID, teamID, "owner@example.com")

	app := envPolicyApp(t, db)

	// (a) Total garbage JSON.
	code, body := doReq(t, app, http.MethodPut, "/api/v1/team/env-policy", ownerJWT,
		[]byte(`{not json`), "application/json")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_env_policy", body["error"])

	// (b) Unknown action — typo guard.
	code, body = doReq(t, app, http.MethodPut, "/api/v1/team/env-policy", ownerJWT,
		[]byte(`{"production":{"deplay":["owner"]}}`), "application/json")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_env_policy", body["error"])
	assert.Contains(t, body["message"], "deplay")

	// (c) Invalid env name — embedded space survives lowercasing.
	code, body = doReq(t, app, http.MethodPut, "/api/v1/team/env-policy", ownerJWT,
		[]byte(`{"prod env":{"deploy":["owner"]}}`), "application/json")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_env_policy", body["error"])
}

// ── 7. PUT then GET reflects the new policy ──────────────────────────────────

func TestEnvPolicy_PutThenGet_RoundTrip(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := insertUserWithRole(t, db, teamID, "owner")
	ownerJWT := testhelpers.MustSignSessionJWT(t, ownerID, teamID, "owner@example.com")

	app := envPolicyApp(t, db)

	wantPolicy := `{"production":{"deploy":["owner"],"vault_write":["owner","admin"]},"staging":{"deploy":["owner","developer"]}}`

	code, body := doReq(t, app, http.MethodPut, "/api/v1/team/env-policy", ownerJWT,
		[]byte(wantPolicy), "application/json")
	require.Equal(t, http.StatusOK, code, "PUT must accept a valid policy; body=%v", body)

	code, body = doReq(t, app, http.MethodGet, "/api/v1/team/env-policy", ownerJWT, nil, "")
	require.Equal(t, http.StatusOK, code)
	require.True(t, body["ok"].(bool))

	policy, ok := body["policy"].(map[string]any)
	require.True(t, ok, "policy must be a JSON object")

	// Spot-check the round-tripped shape; the model normalises to lowercase
	// + dedupes role lists, but for valid lowercase input the shape is
	// preserved verbatim.
	prod, ok := policy["production"].(map[string]any)
	require.True(t, ok)
	deploy, ok := prod["deploy"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"owner"}, deploy)

	vaultWrite, ok := prod["vault_write"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"owner", "admin"}, vaultWrite)

	staging, ok := policy["staging"].(map[string]any)
	require.True(t, ok)
	stagingDeploy, ok := staging["deploy"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"owner", "developer"}, stagingDeploy)
}

// ── 8. GET /team/env-policy as any member (non-owner) → 200 ────────────────────
//
// Members must be able to read the policy so the dashboard can show "why
// can't I deploy here?" without surfacing a 403 just for asking.

func TestEnvPolicy_GetAsDeveloper_Allowed(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	setEnvPolicy(t, db, teamID, `{"production":{"deploy":["owner"]}}`)

	devID := insertUserWithRole(t, db, teamID, "developer")
	devJWT := testhelpers.MustSignSessionJWT(t, devID, teamID, "dev@example.com")

	app := envPolicyApp(t, db)
	code, body := doReq(t, app, http.MethodGet, "/api/v1/team/env-policy", devJWT, nil, "")
	require.Equal(t, http.StatusOK, code)
	require.True(t, body["ok"].(bool))
}
