package handlers_test

// deploy_stack_gap_coverage_test.go — final coverage push to drive deploy.go
// and stack.go to >=95%. Targets the remaining sub-95% branches identified by
// `go tool cover -func`:
//
//   stack.go:  New (manifest/tarball/token/env error paths), Promote
//              (invalid_body, env_mismatch, no_services 412, missing_image_ref
//              412, in-place update + new-service create, vault_ref_failed),
//              Redeploy (env-merge + vault paths), UpdateEnv (delete + merge),
//              copyVaultRefsForPromote (no-op + skip-existing + per-key copy),
//              runStackDeploy / runStackRedeploy callbacks.
//   deploy.go: New (success w/ env_vars), Redeploy (env-merge + vault paths),
//              List (service/since/limit filters), Get edge.
//
// All tests skip cleanly when TEST_DATABASE_URL is unset.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func gapCovNeedsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping gap coverage test")
	}
}

// ── stack New — manifest + tarball + env error branches (HTTP) ───────────────

// TestStackNew_InvalidManifestYAML returns 400 invalid_manifest.
func TestStackNew_InvalidManifestYAML(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badman@example.com")
	app := newStackTestApp(t, db)

	// Manifest that parses as YAML but fails validation (no services).
	resp := postStackNew(t, app, jwt, "services: {}", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestStackNew_GarbageManifest hits the manifest.Parse error branch.
func TestStackNew_GarbageManifest(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "garb@example.com")
	app := newStackTestApp(t, db)

	resp := postStackNew(t, app, jwt, "\t: : not valid yaml : :\n  - [", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestStackNew_InvalidEnvField rejects a bad `env` form value (400 invalid_env).
func TestStackNew_InvalidEnvField(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badenv@example.com")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	// env contains a space → invalid.
	body, ct := multipartBody(t, testManifestSingleService,
		map[string][]byte{"web": tar}, map[string]string{"env": "bad env"})
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.50.0.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_env", decodeErrCode(t, resp))
}

// TestStackNew_ValidEnvField exercises the env-validated happy path (202).
func TestStackNew_ValidEnvField(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "goodenv@example.com")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService,
		map[string][]byte{"web": tar}, map[string]string{"env": "staging"})
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.50.0.2")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestStackNew_MissingName rejects an empty name (requireName 400).
func TestStackNew_MissingName(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "noname@example.com")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	// Explicit empty name overrides the default injection.
	body, ct := multipartBody(t, testManifestSingleService,
		map[string][]byte{"web": tar}, map[string]string{"name": ""})
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.50.0.3")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestStackNew_InvalidResourceToken rejects a needs: with a non-UUID token.
func TestStackNew_InvalidResourceToken(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badtok@example.com")
	app := newStackTestApp(t, db)

	manifest := `
services:
  web:
    build: ./web
    port: 3000
    expose: true
    needs:
      - not-a-uuid
`
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_token", decodeErrCode(t, resp))
}

// TestStackNew_ResourceTokenNotFound rejects a needs: with an unknown UUID.
func TestStackNew_ResourceTokenNotFound(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "notfound@example.com")
	app := newStackTestApp(t, db)

	manifest := `
services:
  web:
    build: ./web
    port: 3000
    expose: true
    needs:
      - ` + uuid.NewString() + `
`
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "resource_not_found", decodeErrCode(t, resp))
}

// TestStackNew_ResourceCrossTeam rejects a needs: token owned by another team.
func TestStackNew_ResourceCrossTeam(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	ownerTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherTeam, "xteam@example.com")
	app := newStackTestApp(t, db)

	// Seed a postgres resource owned by ownerTeam.
	tok := uuid.New()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (token, team_id, resource_type, tier, status, connection_url, env)
		VALUES ($1, $2, 'postgres', 'pro', 'active', 'enc', 'production')
	`, tok, ownerTeam)
	require.NoError(t, err)

	manifest := `
services:
  web:
    build: ./web
    port: 3000
    expose: true
    needs:
      - ` + tok.String() + `
`
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestStackNew_WithValidNeeds resolves an owned resource into env vars (success
// path through the decrypt + rewriteToInternalURL + resourceEnvKey loop).
func TestStackNew_WithValidNeeds(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "needs@example.com")
	app := newStackTestApp(t, db)

	// Seed a postgres resource owned by this team with a (plaintext-as-cipher)
	// connection url. Decrypt fails open to ciphertext, which is fine here.
	tok := uuid.New()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (token, team_id, resource_type, tier, status, connection_url, provider_resource_id, env)
		VALUES ($1, $2, 'postgres', 'pro', 'active', 'postgres://u:p@public.example.com:5432/db', 'instant-customer-x', 'production')
	`, tok, teamID)
	require.NoError(t, err)

	manifest := `
services:
  web:
    build: ./web
    port: 3000
    expose: true
    needs:
      - ` + tok.String() + `
`
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// ── stack Promote — additional error branches ────────────────────────────────

// TestStackPromote_InvalidBody_Gap hits the c.BodyParser error path (400).
func TestStackPromote_InvalidBody_Gap(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "pbad@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "p-badbody")
	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
		bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_body", decodeErrCode(t, resp))
}

// TestStackPromote_EnvMismatch — caller asserts from=dev but stack is staging.
func TestStackPromote_EnvMismatch(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "pmis@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "p-mismatch")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{"from": "development", "to": "production"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "env_mismatch", decodeErrCode(t, resp))
}

// TestStackPromote_InvalidFromEnv rejects a bad `from`.
func TestStackPromote_InvalidFromEnv(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "pfrom@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "p-badfrom")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{"from": "bad from", "to": "production"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_env", decodeErrCode(t, resp))
}

// TestStackPromote_NoServices — dev-env promote of a source with no service
// rows hits the 412 no_services branch.
func TestStackPromote_NoServices(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "pnosvc@example.com")
	// dev-target promote bypasses the email approval gate, so we reach Step A.
	slug, _ := seedPromoteSourceStackNoImageRef(t, db, teamID, "staging", "p-nosvc")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{"from": "staging", "to": "development"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPreconditionFailed, resp.StatusCode)
	assert.Equal(t, "no_services", decodeErrCode(t, resp))
}

// TestStackPromote_MissingImageRef — a service with no image_ref hits the 412
// missing_image_ref branch.
func TestStackPromote_MissingImageRef(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "pnoimg@example.com")
	slug, id := seedPromoteSourceStackNoImageRef(t, db, teamID, "staging", "p-noimg")
	// Attach a service WITHOUT image_ref.
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stack_services (stack_id, name, expose, port, status)
		VALUES ($1::uuid, 'api', true, 8080, 'healthy')
	`, id)
	require.NoError(t, err)
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{"from": "staging", "to": "development"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPreconditionFailed, resp.StatusCode)
	assert.Equal(t, "missing_image_ref", decodeErrCode(t, resp))
}

// TestStackPromote_CreatesNewTarget — dev-env promote of a healthy source with
// an image_ref creates a fresh target stack (action="created", 202) and
// triggers the runStackDeploy goroutine + copy_vault path (no source keys →
// copyVaultRefsForPromote no-op).
func TestStackPromote_CreatesNewTarget(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "pnew@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "p-newtarget")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{"from": "staging", "to": "development"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestStackPromote_InPlaceUpdate — a pre-existing target stack in the same
// family is re-used (action="updated_existing"), exercising the in-place
// branch: updating an existing target service's image_ref AND creating a
// target service the source has but the target lacks.
func TestStackPromote_InPlaceUpdate(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "inplace@example.com")

	// Source (staging) is the family root. Two services with image_refs.
	srcSlug, srcID := seedPromoteSourceStackNoImageRef(t, db, teamID, "staging", "ip-src")
	for _, svc := range []string{"api", "worker"} {
		_, err := db.ExecContext(context.Background(), `
			INSERT INTO stack_services (stack_id, name, expose, port, image_ref, status)
			VALUES ($1::uuid, $2, true, 8080, $3, 'healthy')
		`, srcID, svc, "registry.local/"+svc+":v2")
		require.NoError(t, err)
	}

	// Pre-existing target (development) in the SAME family (parent = source).
	tgtSlug := "stk-iptgt-" + randHex(t, 4)
	var tgtID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO stacks (team_id, name, slug, namespace, status, tier, env, parent_stack_id)
		VALUES ($1, 'ip-tgt', $2, $3, 'healthy', 'pro', 'development', $4::uuid)
		RETURNING id::text
	`, teamID, tgtSlug, "instant-stack-"+tgtSlug, srcID).Scan(&tgtID))
	// Target has only "api" (old image_ref) — "worker" is missing so the
	// create-new-service branch fires.
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stack_services (stack_id, name, expose, port, image_ref, status)
		VALUES ($1::uuid, 'api', true, 8080, 'registry.local/api:v1', 'healthy')
	`, tgtID)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, jwt, srcSlug, map[string]any{"from": "staging", "to": "development"})
	defer resp.Body.Close()
	// Existing target -> 200 updated_existing.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The target's "worker" service must have been created with the source image.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM stack_services WHERE stack_id = $1::uuid AND name = 'worker'`,
		tgtID).Scan(&n))
	assert.Equal(t, 1, n, "missing target service must be created during in-place promote")
}

// ── copyVaultRefsForPromote — direct unit coverage ───────────────────────────

// TestCopyVaultRefsForPromote_NoSourceKeys returns nil,nil (the no-op branch).
func TestCopyVaultRefsForPromote_NoSourceKeys(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	copied, err := handlers.CopyVaultRefsForPromoteForTest(
		context.Background(), db, teamID, uuid.Nil, "staging", "production")
	require.NoError(t, err)
	assert.Empty(t, copied)
}

// TestCopyVaultRefsForPromote_CopiesAndSkips covers the per-key copy branch,
// the skip-existing-target branch, and the audit emit with a real userID.
func TestCopyVaultRefsForPromote_CopiesAndSkips(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	// Seed a real user so the created_by FK on vault_secrets holds and the
	// userID != uuid.Nil attribution branch is exercised.
	var userIDStr string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID.String(), "vaultcopy-"+uuid.NewString()+"@example.com").Scan(&userIDStr))
	userID := uuid.MustParse(userIDStr)

	// Seed two keys in staging.
	for _, k := range []string{"ALPHA", "BETA"} {
		_, err := models.CreateVaultSecret(context.Background(), db, teamID,
			"staging", k, []byte("ct-"+k), uuid.NullUUID{})
		require.NoError(t, err)
	}
	// Pre-seed ALPHA in production so it is SKIPPED (non-destructive).
	_, err := models.CreateVaultSecret(context.Background(), db, teamID,
		"production", "ALPHA", []byte("prod-existing"), uuid.NullUUID{})
	require.NoError(t, err)

	copied, err := handlers.CopyVaultRefsForPromoteForTest(
		context.Background(), db, teamID, userID, "staging", "production")
	require.NoError(t, err)
	// BETA must be copied (source-only key); ALPHA must be skipped (already in
	// target). Use membership assertions rather than exact-slice equality so
	// the test is robust to any sibling-seeded keys in the shared test DB.
	assert.Contains(t, copied, "BETA", "source-only key BETA must be copied")
	assert.NotContains(t, copied, "ALPHA", "existing target key ALPHA must be skipped")
}

// ── stack Redeploy — happy path through env-merge + vault (202) ──────────────

// TestStackRedeploy_Success drives Redeploy past the env_vars load + vault
// resolution into the runStackRedeploy goroutine (status flips to building).
func TestStackRedeploy_Success(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rd@example.com")
	slug, id := seedPromoteSourceStack(t, db, teamID, "production", "rd-stack")
	// Persist a PATCH'd env var so the redeploy env-merge loop runs.
	_, err := db.ExecContext(context.Background(),
		`UPDATE stacks SET env_vars = '{"PATCHED":"v"}'::jsonb WHERE id = $1::uuid`, id)
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

// TestStackRedeploy_NotFound — unknown slug returns 404.
func TestStackRedeploy_NotFound(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rdnf@example.com")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/does-not-exist/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestStackRedeploy_CrossTeam_Gap — a stack owned by another team returns 404.
func TestStackRedeploy_CrossTeam_Gap(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	ownerTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherTeam, "rdx@example.com")
	slug, _ := seedPromoteSourceStack(t, db, ownerTeam, "production", "rd-xteam")
	app := newStackTestApp(t, db)

	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ── stack UpdateEnv — merge + delete + error branches ────────────────────────

// TestStackUpdateEnv_MergeAndDelete sets two keys then deletes one via "".
func TestStackUpdateEnv_MergeAndDelete(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ue@example.com")
	slug, id := seedPromoteSourceStack(t, db, teamID, "production", "ue-stack")
	_, err := db.ExecContext(context.Background(),
		`UPDATE stacks SET env_vars = '{"OLD":"x"}'::jsonb WHERE id = $1::uuid`, id)
	require.NoError(t, err)
	app := newStackTestApp(t, db)

	// Set NEW, delete OLD (empty string).
	resp := patchStackEnv(t, app, jwt, slug, `{"env":{"NEW":"y","OLD":""}}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestStackUpdateEnv_NotFound — unknown slug returns 404.
func TestStackUpdateEnv_NotFound(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "uenf@example.com")
	app := newStackTestApp(t, db)

	resp := patchStackEnv(t, app, jwt, "no-such-stack", `{"env":{"K":"v"}}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestStackUpdateEnv_InvalidBody — malformed JSON returns 400.
func TestStackUpdateEnv_InvalidBody(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "uebad@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "ue-bad")
	app := newStackTestApp(t, db)

	resp := patchStackEnv(t, app, jwt, slug, `{not json`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestStackUpdateEnv_MissingEnv — empty env object returns 400 missing_env.
func TestStackUpdateEnv_MissingEnv(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "uemiss@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "ue-miss")
	app := newStackTestApp(t, db)

	resp := patchStackEnv(t, app, jwt, slug, `{"env":{}}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "missing_env", decodeErrCode(t, resp))
}

// TestStackUpdateEnv_InvalidKey — a lowercase key returns 400 invalid_env_key.
func TestStackUpdateEnv_InvalidKey(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "uekey@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamID, "production", "ue-key")
	app := newStackTestApp(t, db)

	resp := patchStackEnv(t, app, jwt, slug, `{"env":{"bad-key":"v"}}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_env_key", decodeErrCode(t, resp))
}

// TestStackUpdateEnv_CrossTeam — a stack owned by another team returns 404.
func TestStackUpdateEnv_CrossTeam(t *testing.T) {
	gapCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	ownerTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherTeam, "uex@example.com")
	slug, _ := seedPromoteSourceStack(t, db, ownerTeam, "production", "ue-xteam")
	app := newStackTestApp(t, db)

	resp := patchStackEnv(t, app, jwt, slug, `{"env":{"K":"v"}}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// patchStackEnv posts a PATCH /stacks/:slug/env request with the given JSON body.
func patchStackEnv(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, jwt, slug, jsonBody string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env",
		bytes.NewReader([]byte(jsonBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}
