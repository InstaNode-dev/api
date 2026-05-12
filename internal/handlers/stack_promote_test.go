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

// seedPromoteSourceStack inserts a "staging" stack owned by teamID and returns
// its slug + id. We bypass the /stacks/new handler so promote tests stay focused
// on the promote path alone (the /stacks/new path is exercised by other tests).
func seedPromoteSourceStack(t *testing.T, db *sql.DB, teamID string, env, name string) (string, string) {
	t.Helper()
	slug := "stk-prtest-" + env + "-" + randHex(t, 4)
	var id string
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO stacks (team_id, name, slug, namespace, status, tier, env)
		VALUES ($1, $2, $3, $4, 'healthy', 'pro', $5)
		RETURNING id::text
	`, teamID, name, slug, "instant-stack-"+slug, env).Scan(&id)
	require.NoError(t, err, "seedPromoteSourceStack insert")
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
		"to":   "production",
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
		"to":   "production",
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
	assert.Equal(t, "production", body.Env)
	assert.Equal(t, srcID, body.ParentID, "parent_id must point at the source stack id")
	assert.Equal(t, srcSlug, body.Source)
	assert.Equal(t, "building", body.Status)

	// Verify DB: a new stack row exists with parent_stack_id = source id.
	var dbEnv, dbParent string
	err := db.QueryRowContext(context.Background(), `
		SELECT env, parent_stack_id::text FROM stacks WHERE slug = $1
	`, body.StackID).Scan(&dbEnv, &dbParent)
	require.NoError(t, err)
	assert.Equal(t, "production", dbEnv)
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
		"from": "staging", "to": "production",
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
		"from": "staging", "to": "production",
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

	// Verify DB: only one production stack exists in the family.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM stacks
		WHERE team_id = $1 AND env = 'production'
	`, teamID).Scan(&n))
	assert.Equal(t, 1, n, "exactly one production stack must exist after two promotes")
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
		"from": "staging", "to": "production",
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
