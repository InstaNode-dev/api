package handlers_test

// resources_lifecycle_block_integration_test.go — the W5 resource-lifecycle
// block: DB-backed integration coverage for the ten resource-lifecycle routes
// that were previously carried in route_donebar_guard_test.go's
// routeCoverageExemptions ("W5 lifecycle" TODO rows):
//
//   GET  /api/v1/resources/families
//   GET  /api/v1/resources/:id/family
//   POST /api/v1/resources/:id/provision-twin
//   POST /api/v1/families/bulk-twin
//   POST /api/v1/resources/:id/pause
//   POST /api/v1/resources/:id/resume
//   POST /api/v1/resources/:id/backup
//   GET  /api/v1/resources/:id/backups
//   POST /api/v1/resources/:id/restore
//   GET  /api/v1/resources/:id/restores
//
// Each route's happy path + tier-gate + cross-team 404 + invalid-id + bad-state
// contract is already exercised by the per-handler suites (resource_pause_test.go,
// backup_test.go, twin_test.go, family_bulk_twin_test.go, resource_family_test.go)
// — all of which drive the route through the production RequireAuth +
// PopulateTeamRole stack that testhelpers.NewTestApp / NewTestAppWithServices
// rebuilds from the same registrations as internal/router/router.go.
//
// What THOSE suites do NOT cover, and this block adds, is the ROLE axis. The
// owning-team callers in the existing suites are seeded with the default
// users.role (which the migrations promote to 'owner' for the team's first
// user). None of them prove that a NON-OWNER team member — a 'developer', the
// modal collaborator role — can drive the lifecycle routes. These routes carry
// NO RequireRole / requireOwner gate (ownership is team-scoped, enforced by the
// resource.team_id == caller.team_id check inside each handler), so a writable
// member MUST succeed. A future refactor that accidentally bolts a RequireRole
// owner-gate onto, say, /pause would silently lock every collaborator out of a
// resource they legitimately share; this block is the regression that REDs on
// that change.
//
// It also adds two registry-ITERATING sweeps (CLAUDE.md rule 18: iterate the
// surface set, don't hand-type per-route asserts) so adding an eleventh
// lifecycle route to lifecycleRoutes without wiring auth + ownership fails here:
//
//   - TestResourcesLifecycleBlock_AllRoutes_Unauthenticated_401 — every route,
//     no JWT → 401 (the api group's RequireAuth fires before any handler).
//   - TestResourcesLifecycleBlock_AllRoutes_CrossTeam_404 — every route, a
//     valid JWT for Team B against Team A's resource → 404 (cross-tenant
//     existence stays opaque; never 403).
//
// Pattern: testhelpers.SetupTestDB + NewTestAppWithServices (production route
// stack vs a real Postgres) + MustCreateTeamDB / MustSignSessionJWT — reusing
// the shared helpers, never redefining them.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// lifecycleRouteServices is the service set the lifecycle block needs enabled:
// the twin / bulk-twin happy paths run the postgres/redis/mongo provisioners
// (they gracefully skip when the local backend is unreachable), and the rest
// only need the route registered. Mirrors the set the twin happy-path suite
// uses so the routes register identically to production.
const lifecycleRouteServices = "postgres,redis,mongodb"

// lifecycleRoute is one (method, path-builder) pair in the lifecycle block.
// pathFor builds the concrete URL for a given resource token so the sweeps can
// hit per-resource (:id) routes and the two family-level routes uniformly.
type lifecycleRoute struct {
	name   string
	method string
	// pathFor returns the request path. token is the owning resource's token
	// (ignored by the two family-level routes, which take no :id).
	pathFor func(token string) string
	// body is the JSON request body, or nil for GET / param-less POST. The
	// auth sweeps short-circuit (401/404) before body validation, so a minimal
	// body is sufficient for the POST routes here.
	body map[string]any
}

// lifecycleRoutes enumerates the ten W5 routes. The two registry-iterating
// sweeps walk this slice; adding a route here (or, better, a new lifecycle
// route to router.go) without auth + cross-team handling REDs the sweeps.
func lifecycleRoutes() []lifecycleRoute {
	return []lifecycleRoute{
		{name: "GET families", method: http.MethodGet,
			pathFor: func(string) string { return "/api/v1/resources/families" }},
		{name: "GET family", method: http.MethodGet,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/family" }},
		{name: "POST provision-twin", method: http.MethodPost,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/provision-twin" },
			body:    map[string]any{"env": "development", "name": "twin-db-development"}},
		{name: "POST bulk-twin", method: http.MethodPost,
			pathFor: func(string) string { return "/api/v1/families/bulk-twin" },
			body:    map[string]any{"source_env": "production", "target_env": "development"}},
		{name: "POST pause", method: http.MethodPost,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/pause" }},
		{name: "POST resume", method: http.MethodPost,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/resume" }},
		{name: "POST backup", method: http.MethodPost,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/backup" }},
		{name: "GET backups", method: http.MethodGet,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/backups" }},
		{name: "POST restore", method: http.MethodPost,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/restore" },
			body:    map[string]any{"backup_id": "00000000-0000-0000-0000-000000000099", "destructive_acknowledgment": true}},
		{name: "GET restores", method: http.MethodGet,
			pathFor: func(tok string) string { return "/api/v1/resources/" + tok + "/restores" }},
	}
}

// lifecycleApp is the small surface the block's helpers use over *fiber.App.
type lifecycleApp interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}

// doLifecycleRequest issues one lifecycle-route request. jwt == "" omits the
// Authorization header (the unauthenticated sweep).
func doLifecycleRequest(t *testing.T, app lifecycleApp, rt lifecycleRoute, jwt, token string) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if rt.body != nil {
		b, err := json.Marshal(rt.body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(rt.method, rt.pathFor(token), reader)
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// seedTeamMemberJWT inserts a user with the given role on teamID and returns a
// signed session JWT. role="" defers to the users.role default ('member',
// which the legacy-role mapping treats as writable like 'developer'). Used to
// mint a NON-OWNER collaborator whose lifecycle access this block asserts.
func seedTeamMemberJWT(t *testing.T, db *sql.DB, teamID, role string) string {
	t.Helper()
	mail := testhelpers.UniqueEmail(t)
	var userID string
	if role == "" {
		require.NoError(t, db.QueryRowContext(context.Background(),
			`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
			teamID, mail,
		).Scan(&userID))
	} else {
		require.NoError(t, db.QueryRowContext(context.Background(),
			`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
			teamID, mail, role,
		).Scan(&userID))
	}
	return testhelpers.MustSignSessionJWT(t, userID, teamID, mail)
}

// seedActiveResource inserts an active resource of the given type owned by
// teamID at production env and returns its token + id. Mirrors the direct-SQL
// seeding the per-handler suites use (independent of CreateResource drift).
func seedActiveResource(t *testing.T, db *sql.DB, teamID, resourceType, tier string) (token, id string) {
	t.Helper()
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, env)
		VALUES ($1::uuid, $2, $3, 'active', 'production')
		RETURNING token::text, id::text
	`, teamID, resourceType, tier).Scan(&token, &id))
	return token, id
}

// ─────────────────────────────────────────────────────────────────────────────
// Role axis: a NON-OWNER writable team member drives every lifecycle route.
//
// These routes have NO RequireRole gate — ownership is team-scoped. A
// 'developer' member of the owning Pro team must therefore succeed on the
// state-mutating routes (pause/resume/backup/restore), be allowed to read the
// family/list routes, and be allowed past the tier+ownership gate on twin.
// Each test asserts the success contract AND, for the writes, the resulting DB
// row state — so it fails if a future RequireRole owner-gate is introduced.
// ─────────────────────────────────────────────────────────────────────────────

// TestResourcesLifecycleBlock_Member_PauseResume drives pause then resume as a
// non-owner 'developer'. The resource row must flip active→paused→active.
func TestResourcesLifecycleBlock_Member_PauseResume(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, lifecycleRouteServices)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	memberJWT := seedTeamMemberJWT(t, db, teamID, "developer")
	token, id := seedActiveResource(t, db, teamID, "postgres", "pro")

	// Pause as the member.
	resp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodPost, pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/pause"
		}}, memberJWT, token)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a non-owner developer must be allowed to pause a team resource (no RequireRole gate)")
	var pauseBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pauseBody))
	assert.Equal(t, "paused", pauseBody["status"])

	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE id = $1::uuid`, id).Scan(&status))
	assert.Equal(t, "paused", status, "member pause must persist to the row")

	// Resume as the same member.
	resp2 := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodPost, pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/resume"
		}}, memberJWT, token)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode,
		"a non-owner developer must be allowed to resume a team resource")
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE id = $1::uuid`, id).Scan(&status))
	assert.Equal(t, "active", status, "member resume must restore active")
}

// TestResourcesLifecycleBlock_Member_BackupAndList drives backup + list as a
// non-owner 'developer'. The pending row must land in resource_backups and be
// visible to the same member via GET /backups.
func TestResourcesLifecycleBlock_Member_BackupAndList(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, lifecycleRouteServices)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	memberJWT := seedTeamMemberJWT(t, db, teamID, "developer")
	token, id := seedActiveResource(t, db, teamID, "postgres", "pro")

	resp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodPost, pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/backup"
		}}, memberJWT, token)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a non-owner developer must be allowed to trigger a backup")
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "pending", body["status"], "backup is enqueued as a pending row for the worker")
	backupID, _ := body["backup_id"].(string)
	require.NotEmpty(t, backupID)

	// The pending row exists in the table, owned by the resource.
	var gotResourceID, gotStatus string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT resource_id::text, status FROM resource_backups WHERE id = $1::uuid`,
		backupID).Scan(&gotResourceID, &gotStatus))
	assert.Equal(t, id, gotResourceID)
	assert.Equal(t, "pending", gotStatus)

	// List as the same member surfaces the row.
	listResp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodGet, pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/backups"
		}}, memberJWT, token)
	defer listResp.Body.Close()
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	var listBody struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listBody))
	assert.True(t, listBody.OK)
	assert.GreaterOrEqual(t, listBody.Total, 1, "the member's backup must appear in their list")
	require.Len(t, listBody.Items, 1)
	assert.Equal(t, backupID, listBody.Items[0]["backup_id"])
}

// TestResourcesLifecycleBlock_Member_RestoreAndList drives restore + list as a
// non-owner 'developer' from a seeded 'ok' backup. Restore enqueues a pending
// row; list surfaces it. Proves the restore contract (validates backup, writes
// pending) is open to writable members, and the deferred worker leg (pending →
// running → ok) is out of scope here (it lives in the worker repo).
func TestResourcesLifecycleBlock_Member_RestoreAndList(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, lifecycleRouteServices)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	memberJWT := seedTeamMemberJWT(t, db, teamID, "developer")
	token, id := seedActiveResource(t, db, teamID, "postgres", "pro")

	// Seed an 'ok' backup for the resource (triggered_by must be a real user).
	var triggerUserID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner') RETURNING id::text`,
		teamID, testhelpers.UniqueEmail(t)).Scan(&triggerUserID))
	var backupID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, status, backup_kind, tier_at_backup, triggered_by)
		VALUES ($1::uuid, 'ok', 'scheduled', 'pro', $2::uuid)
		RETURNING id::text
	`, id, triggerUserID).Scan(&backupID))

	resp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodPost,
		pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/restore"
		},
		body: map[string]any{"backup_id": backupID, "destructive_acknowledgment": true},
	}, memberJWT, token)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a non-owner developer must be allowed to trigger a restore")
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "pending", body["status"], "restore is enqueued as a pending row for the worker")
	restoreID, _ := body["restore_id"].(string)
	require.NotEmpty(t, restoreID)

	// Pending restore row links the right backup + resource.
	var gotBackupID, gotResourceID, gotStatus string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT backup_id::text, resource_id::text, status
		FROM resource_restores WHERE id = $1::uuid
	`, restoreID).Scan(&gotBackupID, &gotResourceID, &gotStatus))
	assert.Equal(t, backupID, gotBackupID)
	assert.Equal(t, id, gotResourceID)
	assert.Equal(t, "pending", gotStatus)

	// List restores as the same member.
	listResp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodGet, pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/restores"
		}}, memberJWT, token)
	defer listResp.Body.Close()
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	var listBody struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listBody))
	assert.True(t, listBody.OK)
	assert.GreaterOrEqual(t, listBody.Total, 1)
	require.Len(t, listBody.Items, 1)
	assert.Equal(t, restoreID, listBody.Items[0]["restore_id"])
}

// TestResourcesLifecycleBlock_Member_FamilyReads drives GET /families and GET
// /:id/family as a non-owner 'developer'. Both must return the team's family
// data — the read routes are team-scoped, not owner-scoped.
func TestResourcesLifecycleBlock_Member_FamilyReads(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, lifecycleRouteServices)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	memberJWT := seedTeamMemberJWT(t, db, teamID, "developer")

	// A root + one env-twin child so the family has >1 member.
	rootToken, rootID := seedActiveResource(t, db, teamID, "postgres", "pro")
	require.NoError(t, func() error {
		_, err := db.ExecContext(context.Background(), `
			INSERT INTO resources (team_id, resource_type, tier, status, env, parent_resource_id)
			VALUES ($1::uuid, 'postgres', 'pro', 'active', 'development', $2::uuid)
		`, teamID, rootID)
		return err
	}())

	// GET /:id/family
	famResp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodGet, pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/family"
		}}, memberJWT, rootToken)
	defer famResp.Body.Close()
	require.Equal(t, http.StatusOK, famResp.StatusCode,
		"a non-owner developer must be able to read a resource family")
	var famBody struct {
		OK      bool             `json:"ok"`
		Members []map[string]any `json:"members"`
		Total   int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(famResp.Body).Decode(&famBody))
	assert.True(t, famBody.OK)
	assert.Equal(t, 2, famBody.Total, "root + one twin → two family members")

	// GET /families
	listResp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodGet, pathFor: func(string) string {
			return "/api/v1/resources/families"
		}}, memberJWT, "")
	defer listResp.Body.Close()
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	var listBody struct {
		OK       bool             `json:"ok"`
		Families []map[string]any `json:"families"`
		Total    int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listBody))
	assert.True(t, listBody.OK)
	assert.GreaterOrEqual(t, listBody.Total, 1, "the team's one family must appear for the member")
}

// TestResourcesLifecycleBlock_Member_TwinAndBulkTwin drives provision-twin and
// bulk-twin as a non-owner 'developer' on a Pro team. Both are Pro+ tier-gated
// (inside the handler) but carry no role gate, so a member must pass the gate.
// The actual provisioning leg needs a live postgres-customers backend; when
// that backend is unreachable in the dev/CI sandbox the handler returns 503
// provision_failed (or 207/partial for bulk) — we assert the route got PAST
// auth + ownership + tier (i.e. NOT 401/402/404) and defer the provisioned-row
// assertion to the api/e2e live-cluster suite.
func TestResourcesLifecycleBlock_Member_TwinAndBulkTwin(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, lifecycleRouteServices)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	memberJWT := seedTeamMemberJWT(t, db, teamID, "developer")
	token, _ := seedActiveResource(t, db, teamID, "postgres", "pro")

	// provision-twin: a member on Pro must pass the tier+ownership gate. The
	// status is 201 (live backend) or 503 provision_failed (no backend) — both
	// prove the call cleared auth (NOT 401), ownership (NOT 404), and the Pro+
	// tier wall (NOT 402).
	twinResp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodPost,
		pathFor: func(tok string) string {
			return "/api/v1/resources/" + tok + "/provision-twin"
		},
		body: map[string]any{"env": "development", "name": "member-twin-development"},
	}, memberJWT, token)
	defer twinResp.Body.Close()
	assert.NotContains(t, []int{
		http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusNotFound,
	}, twinResp.StatusCode,
		"member provision-twin must clear auth+ownership+tier; got %d", twinResp.StatusCode)

	// bulk-twin: same posture. 200/207 on a live backend, 503 when unreachable.
	bulkResp := doLifecycleRequest(t, app, lifecycleRoute{
		method: http.MethodPost,
		pathFor: func(string) string {
			return "/api/v1/families/bulk-twin"
		},
		body: map[string]any{"source_env": "production", "target_env": "development"},
	}, memberJWT, "")
	defer bulkResp.Body.Close()
	assert.NotContains(t, []int{
		http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusNotFound,
	}, bulkResp.StatusCode,
		"member bulk-twin must clear auth+ownership+tier; got %d", bulkResp.StatusCode)
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry-iterating authz sweeps (rule 18). Walk lifecycleRoutes() so a new
// lifecycle route added to the slice (and, ideally, router.go) without auth +
// cross-team handling REDs here.
// ─────────────────────────────────────────────────────────────────────────────

// TestResourcesLifecycleBlock_AllRoutes_Unauthenticated_401 — every lifecycle
// route, no JWT → 401. The api group's RequireAuth fires before any handler.
func TestResourcesLifecycleBlock_AllRoutes_Unauthenticated_401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, lifecycleRouteServices)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	token, _ := seedActiveResource(t, db, teamID, "postgres", "pro")

	for _, rt := range lifecycleRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			resp := doLifecycleRequest(t, app, rt, "", token)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"unauthenticated %s must be 401", rt.name)
		})
	}
}

// TestResourcesLifecycleBlock_AllRoutes_CrossTeam_404 — every per-resource
// lifecycle route, a valid JWT for Team B against Team A's resource → 404.
// Cross-tenant existence stays opaque (never 403). The two family-level routes
// (families, bulk-twin) take no :id and so cannot leak a specific resource;
// they are exercised by the unauth sweep + the member-success tests instead and
// are skipped here (a Team-B caller hitting /families just sees its own empty
// set, which is not a cross-team leak).
func TestResourcesLifecycleBlock_AllRoutes_CrossTeam_404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, lifecycleRouteServices)
	defer cleanApp()

	teamAID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwtB := seedTeamMemberJWT(t, db, teamBID, "owner")

	// Team A owns the resource; Team B will try to reach it.
	tokenA, _ := seedActiveResource(t, db, teamAID, "postgres", "pro")

	for _, rt := range lifecycleRoutes() {
		// Skip the two family-level routes that carry no :id — they cannot
		// address Team A's specific resource, so there is no cross-team leak
		// surface to probe.
		if rt.pathFor("PLACEHOLDER") == rt.pathFor("OTHER") {
			continue
		}
		t.Run(rt.name, func(t *testing.T) {
			resp := doLifecycleRequest(t, app, rt, jwtB, tokenA)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode,
				"cross-team %s must be 404 (not 403): %s", rt.name, rt.pathFor(tokenA))
		})
	}
}
