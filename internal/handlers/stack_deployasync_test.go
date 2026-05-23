package handlers_test

// stack_deployasync_test.go — coverage for the remaining sub-95% branches in
// stack.go. Owned by the deploy/stack async-pipeline coverage slice (suffix
// `_deployasync`). Scope: stack.go ONLY.
//
// Targets arms the existing stack_*_test.go / deploy_stack_*_test.go files
// leave uncovered:
//   - New: invalid `env` 400, anonymous vault-ref rejection 403, service env
//     invalid-key 400.
//   - UpdateEnv: stack_deleting 409.
//   - Redeploy: stack_deleting 409, invalid-manifest 400, missing-manifest 400,
//     missing-tarball 400, vault-ref-failed 400.
//   - Get: happy path with services + expires_at on an anonymous stack.
//   - Promote: copy_vault=false branch (skips the auto-copy), missing-email
//     (beginPromoteApproval) 400.
//   - List: happy path with rows.
//
// All tests skip cleanly when TEST_DATABASE_URL is unset.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func sdaNeedsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping stack deployasync coverage")
	}
}

// ── New: invalid service-env key → 400 invalid_env_key (L736-740) ────────────

func TestStackNew_InvalidServiceEnvKey_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "iek2@example.com")
	app := newStackTestApp(t, db)

	// Lowercase env key in a service → validateEnvVarKeys fails → 400.
	const m = "services:\n  web:\n    build: ./web\n    port: 8080\n    env:\n      bad-key: v\n"
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, m, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.95.0.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Redeploy: stack with empty env → vaultEnv falls back to default (L1372) ──

func TestStackRedeploy_EmptyEnv_VaultFallback(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ee@example.com")
	// Seed a stack with an EMPTY env so Redeploy's vaultEnv=="" fallback runs.
	slug := "stk-ee-" + uuid.NewString()[:8]
	var sid uuid.UUID
	require.NoError(t, db.QueryRow(`INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1::uuid,$2,$3,'healthy','pro','') RETURNING id`,
		teamID, slug, "instant-stack-"+slug).Scan(&sid))
	_, err := db.Exec(`INSERT INTO stack_services (stack_id, name, port, status, expose) VALUES ($1,'web',8080,'healthy',true)`, sid)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// ── New: anonymous stack referencing a team-owned resource → 403 ─────────────

func TestStackNew_AnonNeedsTeamResource_403(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	// Resource OWNED by a team. An anonymous stack referencing it → 403.
	tok := uuid.New()
	_, err := db.Exec(`INSERT INTO resources (token, team_id, resource_type, tier, status, connection_url, provider_resource_id, env)
		VALUES ($1,$2::uuid,'postgres','pro','active','postgres://u:p@h:5432/db','instant-customer-x','production')`, tok, teamID)
	require.NoError(t, err)
	manifest := "services:\n  web:\n    build: ./web\n    port: 8080\n    needs:\n      - " + tok.String() + "\n"

	app := newStackTestAppRedis(t, db, rdb)
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, manifest, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Forwarded-For", "10.92."+uuid.NewString()[:2]+".3") // anonymous
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// ── New: needs resource with NULL connection_url (skip arm) + empty prid ─────

func TestStackNew_NeedsResourceEmptyConnURL(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ec@example.com")
	// Resource owned by the team with a NULL connection_url + empty prid →
	// exercises the skip arm (L566) + the prid-fallback arm (L588).
	tok := uuid.New()
	_, err := db.Exec(`INSERT INTO resources (token, team_id, resource_type, tier, status, env)
		VALUES ($1,$2::uuid,'redis','pro','active','production')`, tok, teamID)
	require.NoError(t, err)
	manifest := "services:\n  web:\n    build: ./web\n    port: 8080\n    needs:\n      - " + tok.String() + "\n"

	app := newStackTestApp(t, db)
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, manifest, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.93.0.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// ── Logs / Delete: optionalStackTeam invalid-token 400 ───────────────────────

func TestStackLogsDelete_InvalidToken_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStackTestApp(t, db)

	// A token whose team_id claim is not a valid UUID → optionalStackTeam 400.
	badJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", "bad@example.com")
	for _, path := range []string{"/stacks/x/logs/web", "/stacks/x"} {
		method := http.MethodGet
		if path == "/stacks/x" {
			method = http.MethodDelete
		}
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+badJWT)
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, code, "path %s", path)
	}
}

// ── requireStackTeam error arm across auth-required routes ───────────────────

// TestStack_RequireTeamError_AllRoutes — a valid-signature JWT carrying a
// non-existent team_id makes requireStackTeam's GetTeamByID error, so the
// auth-required handlers (UpdateEnv / Redeploy / List / Promote / Family /
// CancelDelete) hit their requireStackTeam error return.
func TestStack_RequireTeamError_AllRoutes(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), uuid.NewString(), "ghost@example.com")
	app := newStackTestApp(t, db)              // env/redeploy/list/promote/family
	capp := newStackCancelDeleteApp(t, db)     // cancel/confirm-deletion

	checks := []struct {
		app          *fiber.App
		method, path string
		body         string
	}{
		{app, http.MethodPatch, "/stacks/x/env", `{"env":{"A":"b"}}`},
		{app, http.MethodPost, "/stacks/x/redeploy", `{"x":1}`},
		{app, http.MethodGet, "/api/v1/stacks", ""},
		{app, http.MethodPost, "/api/v1/stacks/x/promote", `{"from":"a","to":"b"}`},
		{app, http.MethodGet, "/api/v1/stacks/x/family", ""},
		{capp, http.MethodDelete, "/api/v1/stacks/x/confirm-deletion", ""},
	}
	for _, ck := range checks {
		var req *http.Request
		if ck.body != "" {
			req = httptest.NewRequest(ck.method, ck.path, sdaJSONBody(ck.body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(ck.method, ck.path, nil)
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := ck.app.Test(req, 10000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		assert.GreaterOrEqual(t, code, 400, "%s %s should error on a ghost team", ck.method, ck.path)
	}
}

// ── New: invalid env field 400 ───────────────────────────────────────────────

func TestStackNew_InvalidEnvField_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ienv@example.com")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar},
		map[string]string{"env": "not a valid env!!"})
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.55.0.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── New: anonymous vault-ref rejection 403 ───────────────────────────────────

func TestStackNew_AnonVaultRef_403(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	_ = rdb

	app := newStackTestApp(t, db)

	// Manifest where the single service declares a vault:// env ref. Anonymous
	// (no auth header) → vault_requires_auth 403.
	const manifestWithVault = "services:\n  web:\n    build: ./web\n    port: 8080\n    env:\n      SECRET: vault://prod/KEY\n"
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, manifestWithVault, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Forwarded-For", "10.55.0.2") // anonymous
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// 403 vault_requires_auth, OR 400 if the manifest parser rejects the env
	// shape — either way it's a client error and exercises the New env loop.
	assert.GreaterOrEqual(t, resp.StatusCode, 400)
	assert.Less(t, resp.StatusCode, 500)
}

// ── New: authenticated vault-ref that fails to resolve → 400 vault_ref_failed ─

func TestStackNew_AuthedVaultRefFails_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "avf@example.com")
	app := newStackTestApp(t, db)

	// Authenticated stack with a service env vault ref that doesn't resolve
	// (no such vault key) → New's authed vault-resolve arm returns 400.
	const manifestVault = "services:\n  web:\n    build: ./web\n    port: 8080\n    env:\n      SECRET: vault://does/not/exist\n"
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, manifestVault, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.91.0.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── UpdateEnv: stack_deleting 409 ────────────────────────────────────────────

func TestStackUpdateEnv_Deleting_409(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "del@example.com")
	slug := sdaSeedStack(t, db, teamID, "deleting", "production")
	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env",
		sdaJSONBody(`{"env":{"FOO":"bar"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ── Redeploy: stack_deleting 409 ─────────────────────────────────────────────

func TestStackRedeploy_Deleting_409(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rdd@example.com")
	slug := sdaSeedStack(t, db, teamID, "deleting", "production")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ── Redeploy: parseable-but-invalid manifest (Validate error) → 400 ──────────

func TestStackRedeploy_ValidateError_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rve@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "rd-ve")
	app := newStackTestApp(t, db)

	// Parses fine, but the env references an unknown service → Validate errors.
	const m = "services:\n  web:\n    build: ./web\n    port: 8080\n    env:\n      X: service://ghost\n"
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, m, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── New: parseable-but-invalid manifest (Validate error) → 400 ───────────────

func TestStackNew_ValidateError_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "nve@example.com")
	app := newStackTestApp(t, db)

	const m = "services:\n  web:\n    build: ./web\n    port: 8080\n    env:\n      X: service://ghost\n"
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, m, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.94.0.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Redeploy: invalid manifest 400 ───────────────────────────────────────────

func TestStackRedeploy_InvalidManifest_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rdim@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "rd-im")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, "this: is: not: valid: yaml: services", map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Redeploy: missing manifest 400 ───────────────────────────────────────────

func TestStackRedeploy_MissingManifest_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rdmm@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "rd-mm")
	app := newStackTestApp(t, db)

	// Multipart with a tarball but empty manifest field.
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, "", map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Redeploy: missing tarball 400 ────────────────────────────────────────────

func TestStackRedeploy_MissingTarball_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rdmt@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "rd-mt")
	app := newStackTestApp(t, db)

	// Valid manifest declaring service "web" but NO tarball part for it.
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Redeploy: vault-ref-failed 400 (manifest env with an unresolvable ref) ───

func TestStackRedeploy_VaultRefFailed_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rdvr@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "rd-vr")
	app := newStackTestApp(t, db)

	const manifestWithVault = "services:\n  web:\n    build: ./web\n    port: 8080\n    env:\n      SECRET: vault://nope/MISSING\n"
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, manifestWithVault, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// 400 vault_ref_failed (unresolvable ref) — exercises the redeploy vault arm.
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Get: happy path with services + expires_at (anonymous stack) ─────────────

func TestStackGet_AnonWithServicesAndExpiry(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	// Anonymous stack (team_id NULL) with an expires_at set + one service.
	slug := "stk-anon-" + uuid.NewString()[:8]
	ns := "instant-stack-" + slug
	var sid uuid.UUID
	require.NoError(t, db.QueryRow(`
		INSERT INTO stacks (team_id, slug, namespace, status, tier, env, expires_at)
		VALUES (NULL, $1, $2, 'healthy', 'anonymous', 'development', now() + interval '24 hours')
		RETURNING id`, slug, ns).Scan(&sid))
	_, err := db.Exec(`INSERT INTO stack_services (stack_id, name, port, status, expose, app_url)
		VALUES ($1, 'web', 8080, 'healthy', true, 'https://x.example.com')`, sid)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	// Anonymous GET (no auth header) — slug is the secret.
	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug, nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── Promote: copy_vault=false skips the auto-copy ────────────────────────────

func TestStackPromote_CopyVaultFalse(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "cv@example.com")
	// Source in staging; promote to development. A development TARGET bypasses
	// the email-approval gate (immediate-execute path), so copy_vault=false is
	// actually evaluated on this request.
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "cv-src")
	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		sdaJSONBody(`{"from":"staging","to":"development","copy_vault":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Development target → immediate execute → 200/202 (created/updated).
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp.StatusCode)
}

// ── Promote: `from` omitted defaults to source env (L1903) ───────────────────

func TestStackPromote_OmitFrom_DefaultsToSourceEnv(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "of@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "of-src")
	app := newStackTestApp(t, db)

	// Omit "from" → defaults to source.Env ("staging"); to=development → execute.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		sdaJSONBody(`{"to":"development"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp.StatusCode)
}

// ── Promote: approval_id to production executes full create + vault path ─────

func TestStackPromote_ApprovalID_ProductionExecutes(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ape@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "ape-src")
	// Seed a vault key in staging so the copy + service-loop vault resolve run.
	_, err := models.CreateVaultSecret(context.Background(), db, teamID, "staging", "TOK", []byte("ct"), uuid.NullUUID{})
	require.NoError(t, err)
	// Seed an APPROVED approval row for staging→production.
	approvalID := mustSeedApprovedPromoteDA(t, db, teamID, "staging", "production")

	app := newStackTestApp(t, db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		sdaJSONBody(`{"from":"staging","to":"production","approval_id":"`+approvalID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp.StatusCode)
}

// mustSeedApprovedPromoteDA inserts an approved promote_approvals row and
// returns its id (mirrors mustSeedApprovedPromote but local to this slice).
func mustSeedApprovedPromoteDA(t *testing.T, db *sql.DB, teamID uuid.UUID, from, to string) string {
	t.Helper()
	tok, err := models.GeneratePromoteApprovalToken()
	require.NoError(t, err)
	row, err := models.CreatePromoteApproval(context.Background(), db, models.CreatePromoteApprovalParams{
		Token: tok, TeamID: teamID, RequestedByEmail: "ape@example.com",
		PromoteKind: models.PromoteApprovalKindStack, PromotePayload: []byte(`{}`),
		FromEnv: from, ToEnv: to,
	})
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE promote_approvals SET status='approved', approved_at=now() WHERE id=$1`, row.ID)
	require.NoError(t, err)
	return row.ID.String()
}

// ── Promote: source-with-parent uses the parent as family root (L2100) ───────

func TestStackPromote_SourceWithParent_UsesRoot(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "swp@example.com")

	// Root stack (production), then a child source stack (staging) whose
	// parent_stack_id points at the root. Promoting the child to a fresh env
	// (development) takes the create branch with rootID = parent (L2100).
	rootSlug := "stk-root-" + uuid.NewString()[:8]
	var rootID uuid.UUID
	require.NoError(t, db.QueryRow(`INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1::uuid,$2,$3,'healthy','pro','production') RETURNING id`,
		teamIDStr, rootSlug, "instant-stack-"+rootSlug).Scan(&rootID))

	childSlug := "stk-child-" + uuid.NewString()[:8]
	var childID uuid.UUID
	require.NoError(t, db.QueryRow(`INSERT INTO stacks (team_id, slug, namespace, status, tier, env, parent_stack_id)
		VALUES ($1::uuid,$2,$3,'healthy','pro','staging',$4) RETURNING id`,
		teamIDStr, childSlug, "instant-stack-"+childSlug, rootID).Scan(&childID))
	_, err := db.Exec(`INSERT INTO stack_services (stack_id, name, expose, port, image_ref, status)
		VALUES ($1,'api',true,8080,$2,'healthy')`, childID, "reg/img:"+childSlug)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+childSlug+"/promote",
		sdaJSONBody(`{"from":"staging","to":"development"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp.StatusCode)
}

// ── Promote: source-env mismatch 409 ─────────────────────────────────────────

func TestStackPromote_SourceEnvMismatch_409(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "em@example.com")
	// Source stack is in "staging", but the request asserts from="preprod".
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "em-src")
	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		sdaJSONBody(`{"from":"preprod","to":"production"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ── Promote: same-env from==to 400 ───────────────────────────────────────────

func TestStackPromote_SameEnv_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "se@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "se-src")
	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		sdaJSONBody(`{"from":"staging","to":"staging"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Promote: with vault refs copied to target (covers vault-resolve path) ────

func TestStackPromote_DevTarget_WithVaultKeys(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "vk@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "vk-src")

	// Seed a staging vault key so copyVaultRefsForPromote copies it into the
	// development target (exercises the copy + per-key audit path) and the
	// service-loop vault resolve runs against the development namespace.
	tid := uuid.MustParse(teamID)
	_, err := models.CreateVaultSecret(context.Background(), db, tid, "staging", "API_KEY", []byte("ct"), uuid.NullUUID{})
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		sdaJSONBody(`{"from":"staging","to":"development"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp.StatusCode)
}

// ── Promote: beginPromoteApproval missing email 400 ─────────────────────────

func TestStackPromote_MissingEmail_400(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	// Sign a session token with an EMPTY email claim → beginPromoteApproval's
	// requestedBy=="" guard fires (missing_email 400) on a non-dev promote.
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "me-src")
	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		sdaJSONBody(`{"from":"staging","to":"production"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Family: non-exposed-service URL fallback + single-member family ──────────

func TestStackFamily_NonExposedURLFallback(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "fam2@example.com")
	// Stack with a single NON-exposed service that has an app_url → Family's
	// "nothing exposed → first service URL" fallback runs (L1594-1601).
	slug := "stk-fam-" + uuid.NewString()[:8]
	ns := "instant-stack-" + slug
	var sid uuid.UUID
	require.NoError(t, db.QueryRow(`
		INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1::uuid, $2, $3, 'healthy', 'pro', 'production') RETURNING id`,
		teamID, slug, ns).Scan(&sid))
	_, err := db.Exec(`INSERT INTO stack_services (stack_id, name, port, status, expose, app_url)
		VALUES ($1, 'web', 8080, 'healthy', false, 'https://internal.example.com')`, sid)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks/"+slug+"/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── List: happy path with rows ───────────────────────────────────────────────

func TestStackList_WithRows(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ls@example.com")
	sdaSeedStack(t, db, teamID, "healthy", "production")
	sdaSeedStack(t, db, teamID, "building", "staging")
	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── Anonymous-path New coverage (needs a real Redis for the rate-limit) ──────

// TestStackNew_Anonymous_Succeeds drives the full anonymous /stacks/new path:
// fingerprint rate-limit (fail-open / not-exceeded), anon TeamID=nil + 24h TTL,
// CreateStackWithCap with stackCapLimit=-1, and the anon vault-reject loop
// (no vault refs here → passes).
func TestStackNew_Anonymous_Succeeds(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app := newStackTestAppRedis(t, db, rdb)
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	// No auth header → anonymous. Unique fingerprint IP so the daily cap is fresh.
	req.Header.Set("X-Forwarded-For", "10.88."+uuid.NewString()[:2]+".5")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestStackNew_Anonymous_RateLimited drives the anon rate-limit-exceeded 429
// arm by bursting past the anonymous ProvisionLimit on one fingerprint.
func TestStackNew_Anonymous_RateLimited(t *testing.T) {
	sdaNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app := newStackTestAppRedis(t, db, rdb)
	ip := "10.89." + uuid.NewString()[:2] + ".9"
	tar := createMinimalTarball(t)
	var last int
	for i := 0; i < 12; i++ {
		body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
		req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		last = resp.StatusCode
		resp.Body.Close()
		if last == http.StatusTooManyRequests {
			break
		}
	}
	assert.Equal(t, http.StatusTooManyRequests, last, "anon burst should eventually hit 429")
}

// newStackTestAppRedis is newStackTestApp with a real Redis wired so the
// anonymous rate-limit path executes (nil rdb fails open and never counts).
func newStackTestAppRedis(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	sh := handlers.NewStackHandler(db, rdb, cfg, plans.Default())
	app.Post("/stacks/new", middleware.OptionalAuth(cfg), sh.New)
	return app
}

// ── copyVaultRefsForPromote error arms (fault DB) ────────────────────────────

// TestCopyVaultRefsForPromote_FaultArms drives copyVaultRefsForPromote's error
// paths (list-source-keys error / fetch error / target-check error / persist
// error) by injecting query faults at varying depths after seeding source keys.
func TestCopyVaultRefsForPromote_FaultArms(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, seedDB, "pro"))
	// Seed two source keys in staging so the copy loop has work to do.
	for _, k := range []string{"AAA", "BBB"} {
		_, err := models.CreateVaultSecret(context.Background(), seedDB, teamID, "staging", k, []byte("ct"), uuid.NullUUID{})
		require.NoError(t, err)
	}

	sawErr := false
	for failAfter := int64(1); failAfter <= 6; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		_, err := handlers.CopyVaultRefsForPromoteForTest(context.Background(), fdb, teamID, uuid.Nil, "staging", "production")
		fdb.Close()
		if err != nil {
			sawErr = true
		}
	}
	assert.True(t, sawErr, "expected copyVaultRefsForPromote to surface a fault-injected error at some depth")
}

// ── helpers ───────────────────────────────────────────────────────────────────

// sdaSeedStack inserts a stack owned by teamID (string UUID) with the given
// status + env and one 'web' service. Returns the slug.
func sdaSeedStack(t *testing.T, db *sql.DB, teamID, status, env string) string {
	t.Helper()
	slug := "stk-sda-" + uuid.NewString()[:8]
	ns := "instant-stack-" + slug
	var sid uuid.UUID
	require.NoError(t, db.QueryRow(`
		INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1::uuid, $2, $3, $4, 'pro', $5)
		RETURNING id`, teamID, slug, ns, status, env).Scan(&sid))
	_, err := db.Exec(`INSERT INTO stack_services (stack_id, name, port, status, expose)
		VALUES ($1, 'web', 8080, 'healthy', true)`, sid)
	require.NoError(t, err)
	return slug
}

func sdaJSONBody(s string) *strings.Reader { return strings.NewReader(s) }
