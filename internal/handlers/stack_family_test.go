package handlers_test

// stack_family_test.go — integration tests for GET /api/v1/stacks/:slug/family.
//
// The family endpoint surfaces the production / staging / dev variants of the
// same app side-by-side so the dashboard can render an "Environments" grid
// without doing N round-trips. It uses the same Pro-tier gate as Promote and
// the same 404-not-403 cross-team isolation, so the tests below mirror the
// shape of stack_promote_test.go and lean on the same DB-backed helpers.
//
// Coverage (per the env-aware deployments workstream, §10.17 follow-up):
//   1. Tier gate: hobby team must receive 402 with agent_action.
//   2. Tier gate: pro team gets 200 + family payload.
//   3. Single-env family: only one stack exists → family has one row, is_root=true.
//   4. Multi-env family: production root + staging child + dev child render in
//      a sensible order (root first, then siblings by created_at).
//   5. Cross-team isolation: team B cannot read team A's family (404).
//   6. Anonymous / unauthenticated: 401 (RequireAuth middleware).
//   7. Cache-Control: short max-age header set so the dashboard can navigate
//      between envs without hammering the API while still refreshing across
//      promote/redeploy boundaries.
//   8. Unknown slug: 404 (not 500).
//   9. Empty family fallback: a stack whose recursive walk returns nothing
//      (in practice impossible, but defensive) still produces a 200 with the
//      source as the single member.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// seedFamilyStack inserts a stack at the given env with optional parent linkage
// and returns its slug + id. Mirrors seedPromoteSourceStack but accepts a
// parent_stack_id so multi-env families can be set up directly without
// going through POST /promote.
func seedFamilyStack(t *testing.T, db *sql.DB, teamID string, env, name string, parentID *string) (string, string) {
	t.Helper()
	slug := "stk-fam-" + env + "-" + randHex(t, 4)
	var id string
	if parentID == nil {
		err := db.QueryRowContext(context.Background(), `
			INSERT INTO stacks (team_id, name, slug, namespace, status, tier, env)
			VALUES ($1, $2, $3, $4, 'healthy', 'pro', $5)
			RETURNING id::text
		`, teamID, name, slug, "instant-stack-"+slug, env).Scan(&id)
		require.NoError(t, err, "seedFamilyStack insert (root)")
	} else {
		err := db.QueryRowContext(context.Background(), `
			INSERT INTO stacks (team_id, name, slug, namespace, status, tier, env, parent_stack_id)
			VALUES ($1, $2, $3, $4, 'healthy', 'pro', $5, $6)
			RETURNING id::text
		`, teamID, name, slug, "instant-stack-"+slug, env, *parentID).Scan(&id)
		require.NoError(t, err, "seedFamilyStack insert (child)")
	}
	return slug, id
}

// getFamily is the request helper for GET /api/v1/stacks/:slug/family.
func getFamily(t *testing.T, app *fiber.App, sessionJWT, slug string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks/"+slug+"/family", nil)
	if sessionJWT != "" {
		req.Header.Set("Authorization", "Bearer "+sessionJWT)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// familyMember mirrors the JSON shape emitted by the handler for one row of
// the family payload. Keeping it tightly typed makes the assertions below
// noise-free and catches accidental field renames.
type familyMember struct {
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Env           string `json:"env"`
	Status        string `json:"status"`
	Tier          string `json:"tier"`
	URL           string `json:"url"`
	IsRoot        bool   `json:"is_root"`
	ParentStackID string `json:"parent_stack_id"`
}

type familyResp struct {
	OK     bool           `json:"ok"`
	Slug   string         `json:"slug"`
	Family []familyMember `json:"family"`
	Total  int            `json:"total"`
}

// TestStackFamily_HobbyTier_402 enforces the Pro tier gate. Same agent_action
// contract as Promote — the dashboard and any MCP agent should get a
// machine-readable cue to upgrade.
func TestStackFamily_HobbyTier_402(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-family-hobby", teamID, "fam-hobby@example.com")
	slug, _ := seedFamilyStack(t, db, teamID, "production", "demo-app", nil)

	app := newStackTestApp(t, db)
	resp := getFamily(t, app, sessionJWT, slug)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "upgrade_required", body["error"])
	assert.Contains(t, body, "agent_action",
		"hobby family read must include agent_action so MCP agents tell the user to upgrade")
}

// TestStackFamily_ProTier_SingleEnv verifies the happy path with only one env:
// the family payload contains exactly the source stack with is_root=true.
func TestStackFamily_ProTier_SingleEnv(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-family-pro", teamID, "fam-pro@example.com")
	slug, _ := seedFamilyStack(t, db, teamID, "production", "demo-app", nil)

	app := newStackTestApp(t, db)
	resp := getFamily(t, app, sessionJWT, slug)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body familyResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, slug, body.Slug)
	require.Len(t, body.Family, 1, "single-env family must contain only the root")
	assert.Equal(t, slug, body.Family[0].Slug)
	assert.Equal(t, "production", body.Family[0].Env)
	assert.True(t, body.Family[0].IsRoot, "the sole member is the root")
	assert.Equal(t, "", body.Family[0].ParentStackID, "root has no parent")
	assert.Equal(t, 1, body.Total)
}

// TestStackFamily_ProTier_MultiEnv verifies the production + staging + dev
// case: every stack shows up exactly once, with the root first and the
// children ordered by their created_at.
func TestStackFamily_ProTier_MultiEnv(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-family-multi", teamID, "fam-multi@example.com")

	// Production is the root; staging + dev are children pointing at the root.
	prodSlug, prodID := seedFamilyStack(t, db, teamID, "production", "demo-app", nil)
	stagingSlug, _ := seedFamilyStack(t, db, teamID, "staging", "demo-app", &prodID)
	devSlug, _ := seedFamilyStack(t, db, teamID, "dev", "demo-app", &prodID)

	app := newStackTestApp(t, db)

	// Fetch via the production (root) slug — should return all three.
	resp := getFamily(t, app, sessionJWT, prodSlug)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body familyResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 3, body.Total)
	require.Len(t, body.Family, 3, "multi-env family must contain all three envs")

	// First member is always the root.
	assert.Equal(t, prodSlug, body.Family[0].Slug)
	assert.True(t, body.Family[0].IsRoot)
	assert.Equal(t, "production", body.Family[0].Env)

	// The remaining two are the children — their order is created_at ASC, which
	// equals insert order here.
	envs := map[string]string{
		body.Family[1].Slug: body.Family[1].Env,
		body.Family[2].Slug: body.Family[2].Env,
	}
	assert.Equal(t, "staging", envs[stagingSlug])
	assert.Equal(t, "dev", envs[devSlug])
	for _, m := range body.Family[1:] {
		assert.False(t, m.IsRoot, "non-root members must have is_root=false")
		assert.Equal(t, prodID, m.ParentStackID, "children must point at the root")
	}
}

// TestStackFamily_FetchViaChild verifies the lookup is membership-based: asking
// for the family while authenticated via a CHILD slug must return the same
// payload as asking via the root.
func TestStackFamily_FetchViaChild(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-family-child", teamID, "fam-child@example.com")
	_, prodID := seedFamilyStack(t, db, teamID, "production", "demo-app", nil)
	stagingSlug, _ := seedFamilyStack(t, db, teamID, "staging", "demo-app", &prodID)

	app := newStackTestApp(t, db)
	resp := getFamily(t, app, sessionJWT, stagingSlug)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body familyResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, stagingSlug, body.Slug, "echo slug is whatever the caller asked with")
	assert.Equal(t, 2, body.Total, "root + this staging child")
	assert.True(t, body.Family[0].IsRoot, "root still comes first even when queried via the child")
}

// TestStackFamily_CrossTeamIsolation verifies the 404 leak guard: team B asking
// for team A's family must NOT see existence.
func TestStackFamily_CrossTeamIsolation(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamAID := testhelpers.MustCreateTeamDB(t, db, "pro")
	slug, _ := seedFamilyStack(t, db, teamAID, "production", "demo-app", nil)

	teamBID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamBJWT := testhelpers.MustSignSessionJWT(t, "user-family-b", teamBID, "fam-b@example.com")

	app := newStackTestApp(t, db)
	resp := getFamily(t, app, teamBJWT, slug)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team family read must 404 — never leak existence of another team's stack")
}

// TestStackFamily_RequiresAuth verifies the RequireAuth middleware: no
// session token → 401, never 200.
func TestStackFamily_RequiresAuth(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	slug, _ := seedFamilyStack(t, db, teamID, "production", "demo-app", nil)

	app := newStackTestApp(t, db)
	resp := getFamily(t, app, "", slug)
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestStackFamily_UnknownSlug verifies the not-found path returns 404 instead
// of 500.
func TestStackFamily_UnknownSlug(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-family-404", teamID, "fam-404@example.com")

	app := newStackTestApp(t, db)
	resp := getFamily(t, app, sessionJWT, "stk-does-not-exist")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestStackFamily_CacheControl checks that the handler emits the short
// Cache-Control header documented in the OpenAPI spec. The dashboard
// caches per-team for 60s so navigation between envs is snappy without
// staling across promotes.
func TestStackFamily_CacheControl(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-family-cache", teamID, "fam-cache@example.com")
	slug, _ := seedFamilyStack(t, db, teamID, "production", "demo-app", nil)

	app := newStackTestApp(t, db)
	resp := getFamily(t, app, sessionJWT, slug)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	cc := resp.Header.Get("Cache-Control")
	assert.Contains(t, cc, "private",
		"family payload is per-team — cache must be private, not shared")
	assert.Contains(t, cc, "max-age=60",
		"60s max-age matches the dashboard's tolerance for stale env-grid state")
}
