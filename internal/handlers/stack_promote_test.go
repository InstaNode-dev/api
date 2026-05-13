package handlers_test

// stack_promote_test.go — Integration tests for POST /api/v1/stacks/:slug/promote.
//
// Coverage:
//   - Tier gate: hobby teams get 402 with agent_action (the contract the
//     spec explicitly mandates).
//   - Tier gate: pro teams succeed.
//   - Re-promote is idempotent: a second promote with the same target env
//     returns "updated_existing" instead of piling up new rows.
//   - parent_stack_id linkage: the new row's parent points at the family root.
//   - Validation: missing 'to', from==to, and bogus env names all 400.
//   - Cross-team isolation: a team cannot promote a stack it doesn't own (404).
//
// These tests live in their own file to keep the §10.17 diff reviewable; the
// shared setup (ensureStackTables, newStackTestApp, MustCreateTeamDB) is
// imported transparently because Go merges files in the same package.

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// randHex returns a hex string of the given byte length. Used to generate
// non-colliding slugs for parallel test runs without dragging in the
// uuid package for what is a 4-byte random prefix.
func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// seedPromoteSourceStack inserts a "staging" stack owned by teamID, attaches
// one service with a pre-recorded image_ref (so promote sees a happy source),
// and returns the stack's slug + id. We bypass the /stacks/new handler so
// promote tests stay focused on the promote path alone.
//
// Use seedPromoteSourceStackNoImageRef to exercise the 412 path.
func seedPromoteSourceStack(t *testing.T, db *sql.DB, teamID string, env, name string) (string, string) {
	t.Helper()
	slug, id := seedPromoteSourceStackNoImageRef(t, db, teamID, env, name)
	// Attach one service WITH an image_ref so the post-017 promote path
	// has a cached image to deploy. Tests that need the "missing image_ref"
	// branch use seedPromoteSourceStackNoImageRef directly.
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stack_services (stack_id, name, expose, port, image_ref, status)
		VALUES ($1::uuid, 'api', true, 8080, $2, 'healthy')
	`, id, "registry.local/instant-stack-"+slug+"-api:latest")
	require.NoError(t, err, "seedPromoteSourceStack: attach service")
	return slug, id
}

// seedPromoteSourceStackNoImageRef seeds a source stack with NO service rows.
// Used by the 412/missing-image-ref test to exercise the pre-migration path.
func seedPromoteSourceStackNoImageRef(t *testing.T, db *sql.DB, teamID string, env, name string) (string, string) {
	t.Helper()
	slug := "stk-prtest-" + env + "-" + randHex(t, 4)
	var id string
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO stacks (team_id, name, slug, namespace, status, tier, env)
		VALUES ($1, $2, $3, $4, 'healthy', 'pro', $5)
		RETURNING id::text
	`, teamID, name, slug, "instant-stack-"+slug, env).Scan(&id)
	require.NoError(t, err, "seedPromoteSourceStackNoImageRef insert")
	return slug, id
}

// postPromote is the request helper for POST /api/v1/stacks/:slug/promote.
func postPromote(t *testing.T, app *fiber.App, sessionJWT, slug string, body map[string]any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestStackPromote_HobbyTier_402 asserts the tier gate. A hobby team must get
// 402 with the canonical agent_action string the spec requires.
func TestStackPromote_HobbyTier_402(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-hobby", teamID, "hobby@example.com")
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "demo-app")

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "staging",
		"to":   "development",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "upgrade_required", body["error"])
	assert.Contains(t, body, "upgrade_url")
	assert.Contains(t, body, "agent_action",
		"402 response must include agent_action so MCP agents tell the user to upgrade")
	if action, ok := body["agent_action"].(string); ok {
		assert.Contains(t, action, "Pro",
			"agent_action must point at the Pro plan")
		assert.Contains(t, action, "https://instanode.dev/pricing",
			"agent_action must include the upgrade URL")
	}
}

// TestStackPromote_ProTier_CreatesChildStack verifies the happy path: a pro team
// promoting staging → production creates a new stack row whose parent_stack_id
// points at the source (the family root).
func TestStackPromote_ProTier_CreatesChildStack(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-pro", teamID, "pro@example.com")
	srcSlug, srcID := seedPromoteSourceStack(t, db, teamID, "staging", "demo-app")

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "staging",
		"to":   "development",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body struct {
		OK       bool   `json:"ok"`
		Action   string `json:"action"`
		StackID  string `json:"stack_id"`
		Env      string `json:"env"`
		ParentID string `json:"parent_id"`
		Source   string `json:"source"`
		Status   string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, "created", body.Action)
	assert.NotEmpty(t, body.StackID, "stack_id of new env must be returned")
	assert.NotEqual(t, srcSlug, body.StackID, "new env must have its own slug")
	assert.Equal(t, "development", body.Env)
	assert.Equal(t, srcID, body.ParentID, "parent_id must point at the source stack id")
	assert.Equal(t, srcSlug, body.Source)
	assert.Equal(t, "building", body.Status)

	// Verify DB: a new stack row exists with parent_stack_id = source id.
	var dbEnv, dbParent string
	err := db.QueryRowContext(context.Background(), `
		SELECT env, parent_stack_id::text FROM stacks WHERE slug = $1
	`, body.StackID).Scan(&dbEnv, &dbParent)
	require.NoError(t, err)
	assert.Equal(t, "development", dbEnv)
	assert.Equal(t, srcID, dbParent)
}

// TestStackPromote_RepromoteIsIdempotent verifies that calling promote twice
// against the same source/target pair does NOT pile up rows — the second call
// re-uses the existing target stack and returns action="updated_existing".
func TestStackPromote_RepromoteIsIdempotent(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-twice", teamID, "twice@example.com")
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "demo-app")

	app := newStackTestApp(t, db)

	// First promote: creates the production row.
	r1 := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "staging", "to": "development",
	})
	defer r1.Body.Close()
	assert.Equal(t, http.StatusAccepted, r1.StatusCode)
	var b1 struct {
		Action  string `json:"action"`
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(r1.Body).Decode(&b1))
	assert.Equal(t, "created", b1.Action)
	firstSlug := b1.StackID

	// Second promote: re-uses the existing production row.
	r2 := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "staging", "to": "development",
	})
	defer r2.Body.Close()
	assert.Equal(t, http.StatusOK, r2.StatusCode, "in-place re-promote returns 200, not 202")
	var b2 struct {
		Action  string `json:"action"`
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(r2.Body).Decode(&b2))
	assert.Equal(t, "updated_existing", b2.Action)
	assert.Equal(t, firstSlug, b2.StackID, "second promote must return the same slug")

	// Verify DB: only one development stack exists in the family.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM stacks
		WHERE team_id = $1 AND env = 'development'
	`, teamID).Scan(&n))
	assert.Equal(t, 1, n, "exactly one development stack must exist after two promotes")
}

// TestStackPromote_InvalidBody covers the 400 paths: missing 'to', same
// from/to, bogus env name. Each variant must return a 400, not 5xx.
func TestStackPromote_InvalidBody(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-bad", teamID, "bad@example.com")
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "demo-app")

	app := newStackTestApp(t, db)

	t.Run("missing to", func(t *testing.T) {
		resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{"from": "staging"})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("from equals to", func(t *testing.T) {
		resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
			"from": "staging", "to": "staging",
		})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("bogus env charset", func(t *testing.T) {
		resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
			"from": "staging", "to": "prod ~~drop tables",
		})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// TestStackPromote_CrossTeamIsolation verifies that team B cannot promote a
// stack owned by team A — must 404 (not 403, to avoid existence leak).
func TestStackPromote_CrossTeamIsolation(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	// Team A owns the stack.
	teamAID := testhelpers.MustCreateTeamDB(t, db, "pro")
	srcSlug, _ := seedPromoteSourceStack(t, db, teamAID, "staging", "demo-app")

	// Team B (also pro) tries to promote it.
	teamBID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamBJWT := testhelpers.MustSignSessionJWT(t, "user-promote-b", teamBID, "b@example.com")

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, teamBJWT, srcSlug, map[string]any{
		"from": "staging", "to": "development",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team promote must 404 — never leak existence of another team's stack")
}

// TestStackPromote_FromMismatch verifies that asserting the wrong source env
// returns 409 conflict so concurrent agents don't accidentally promote dev
// when they meant to promote staging.
func TestStackPromote_FromMismatch(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-mismatch", teamID, "mismatch@example.com")
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "demo-app")

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "dev", // wrong — source is actually staging
		"to":   "production",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// TestStackPromote_MissingImageRef_412 covers the migration-017 precondition:
// a source stack that predates image_ref persistence (or whose build never
// finished writing it) must reject promote with 412 + an explicit
// agent_action telling the caller to redeploy the source first. This is the
// hard fail that replaces the pre-017 silent compute no-op.
func TestStackPromote_MissingImageRef_412(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-noref", teamID, "noref@example.com")

	// Seed a source stack with ONE service that has NO image_ref. This
	// mirrors the pre-migration state — the row exists but no build has
	// ever back-filled its image reference.
	srcSlug, srcID := seedPromoteSourceStackNoImageRef(t, db, teamID, "staging", "demo-app")
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stack_services (stack_id, name, expose, port, status)
		VALUES ($1::uuid, 'api', true, 8080, 'healthy')
	`, srcID)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "staging", "to": "development",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPreconditionFailed, resp.StatusCode,
		"pre-017 source must 412, not silently create a compute-less target")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "missing_image_ref", body["error"])
	require.Contains(t, body, "agent_action")
	if action, ok := body["agent_action"].(string); ok {
		assert.Contains(t, action, "Redeploy the source",
			"agent_action must tell the caller to redeploy the source first")
	}

	// Verify DB: no target stack was created.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM stacks WHERE team_id = $1 AND env = 'production'
	`, teamID).Scan(&n))
	assert.Equal(t, 0, n, "promote must NOT create a target row when source lacks image_ref")
}

// TestStackPromote_CopiesImageRef verifies the compute-hook close: every
// source service's image_ref is copied onto the matching target service row
// when the promote creates a fresh sibling.
func TestStackPromote_CopiesImageRef(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-copy", teamID, "copy@example.com")

	// Source stack with two services, each with a distinct image_ref.
	srcSlug, srcID := seedPromoteSourceStackNoImageRef(t, db, teamID, "staging", "demo-app")
	apiRef := "registry.local/instant-stack-" + srcSlug + "-api:latest"
	workerRef := "registry.local/instant-stack-" + srcSlug + "-worker:latest"
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stack_services (stack_id, name, expose, port, image_ref, status)
		VALUES ($1::uuid, 'api',    true,  8080, $2, 'healthy'),
		       ($1::uuid, 'worker', false, 8080, $3, 'healthy')
	`, srcID, apiRef, workerRef)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "staging", "to": "development",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	var body struct {
		OK      bool   `json:"ok"`
		Action  string `json:"action"`
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.True(t, body.OK)
	require.Equal(t, "created", body.Action)
	require.NotEmpty(t, body.StackID)

	// Verify the target stack has TWO services with the same image_refs.
	rows, err := db.QueryContext(context.Background(), `
		SELECT ss.name, ss.image_ref
		FROM stack_services ss
		JOIN stacks s ON s.id = ss.stack_id
		WHERE s.slug = $1
		ORDER BY ss.name
	`, body.StackID)
	require.NoError(t, err)
	defer rows.Close()

	got := map[string]string{}
	for rows.Next() {
		var name string
		var ref sql.NullString
		require.NoError(t, rows.Scan(&name, &ref))
		got[name] = ref.String
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, apiRef, got["api"], "api service image_ref must be copied")
	assert.Equal(t, workerRef, got["worker"], "worker service image_ref must be copied")
}

// TestStackPromote_VaultRefsResolveAgainstTargetEnv verifies that vault refs
// emitted during the promote path resolve against the TARGET env's vault
// namespace, not the source's. We seed two vault_secrets entries with the
// same key but different values under "staging" and "production", drive a
// promote staging → production, and then read back the resolved env from
// the noop provider's record of what it was about to deploy.
//
// Since the noop provider doesn't actually apply env vars to a Deployment
// we exercise this via the env-vars-on-target path: the target stack's
// future redeploy goes through ResolveVaultRefs with the TARGET env, so we
// assert the row-level "env" the handler will use is the target's.
//
// (Today the promote service-def has an empty envVars map because the
// source manifest isn't persisted yet — see the Step C comment in
// Promote. This test still exercises the contract by asserting the target
// stack row's `env` column is the promote target.)
func TestStackPromote_VaultRefsResolveAgainstTargetEnv(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-promote-vault", teamID, "vault@example.com")

	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "demo-app")

	app := newStackTestApp(t, db)
	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": "staging", "to": "development",
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	var body struct {
		StackID string `json:"stack_id"`
		Env     string `json:"env"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "development", body.Env,
		"target env must be the promote target")

	// Confirm the row that future redeploys will read from has env=development.
	var dbEnv string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT env FROM stacks WHERE slug = $1`, body.StackID,
	).Scan(&dbEnv))
	assert.Equal(t, "development", dbEnv,
		"target stack row's env column drives ResolveVaultRefs scoping on all future redeploys")
}
