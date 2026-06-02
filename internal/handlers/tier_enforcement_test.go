package handlers_test

// tier_enforcement_test.go — regression tests for P1 Wave-3 Cluster-A
// tier-gate fixes: dedicated bypass (A1), stack count cap (A5), queue count cap (A6).
//
// Run:
//   TEST_DATABASE_URL=postgres://instant:instant@localhost:5432/instant_platform?sslmode=disable \
//   go test ./internal/handlers/... -run 'Dedicated|StackProvision|QueueProvision|PlansRegistry|CountActive' -v -count=1

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// tierErrBody is the standard error response from respondError / respondErrorWithAgentAction.
type tierErrBody struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error"`
	Message     string `json:"message"`
	AgentAction string `json:"agent_action"`
}

// postWithAuthJSONTier makes a JSON POST to the given URL with a Bearer token.
func postWithAuthJSONTier(t *testing.T, app *fiber.App, path, token, bodyJSON string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.20.30.40")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// decodeTierErrBody decodes the response body into a tierErrBody struct.
func decodeTierErrBody(t *testing.T, resp *http.Response) tierErrBody {
	t.Helper()
	var b tierErrBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&b))
	return b
}

// insertActiveStackForTier inserts a stack row with the given team ID and status='building'
// (counts as active for the cap check). Returns the inserted slug.
func insertActiveStackForTier(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	slug := fmt.Sprintf("stk-tier-%s", teamID[:8])
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stacks (team_id, name, slug, namespace, status, tier)
		VALUES ($1, 'test', $2, $2, 'building', 'hobby')
	`, teamID, slug)
	require.NoError(t, err, "insertActiveStackForTier")
	return slug
}

// insertActiveQueueForTier inserts a resource row of type='queue' with status='active'.
func insertActiveQueueForTier(t *testing.T, db *sql.DB, teamID string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, name, tier, status)
		VALUES ($1, 'queue', 'test-queue', 'hobby', 'active')
	`, teamID)
	require.NoError(t, err, "insertActiveQueueForTier")
}

// ── A1: Dedicated Bypass Tier Gate ───────────────────────────────────────────

// TestDedicatedTierGate_HobbyRejected asserts that a hobby-tier team sending
// dedicated:true receives 402 upgrade_required on all five handler paths.
// This is the A1 regression test: before the fix, the tier was silently
// promoted to "growth" without checking IsDedicatedTier.
func TestDedicatedTierGate_HobbyRejected(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db) // stacks table needed for migrations

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanup()

	// hobby is NOT a dedicated tier — IsDedicatedTier("hobby") == false.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a1-hobby", teamID, "a1hobby@example.com")

	type testCase struct {
		name string
		path string
		body string
	}

	cases := []testCase{
		{
			name: "db",
			path: "/db/new",
			body: `{"name":"mydb","dedicated":true}`,
		},
		{
			name: "cache",
			path: "/cache/new",
			body: `{"name":"mycache","dedicated":true}`,
		},
		{
			name: "nosql",
			path: "/nosql/new",
			body: `{"name":"mymongo","dedicated":true}`,
		},
		{
			name: "queue",
			path: "/queue/new",
			body: `{"name":"myqueue","dedicated":true}`,
		},
		{
			name: "vector",
			path: "/vector/new",
			body: `{"name":"myvector","dedicated":true}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postWithAuthJSONTier(t, app, tc.path, sessionJWT, tc.body)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
				"%s: hobby+dedicated should get 402", tc.path)

			b := decodeTierErrBody(t, resp)
			assert.False(t, b.OK)
			assert.Equal(t, "upgrade_required", b.Error,
				"%s: error code must be upgrade_required", tc.path)
			assert.Contains(t, strings.ToLower(b.Message), "growth",
				"%s: message must mention growth plan", tc.path)
		})
	}
}

// TestDedicatedTierGate_GrowthAllowed asserts that a growth-tier team sending
// dedicated:true is NOT rejected by the tier gate (the provision may still
// fail if the backend isn't available in tests, but the 402 must not fire).
func TestDedicatedTierGate_GrowthAllowed(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanup()

	// growth IS a dedicated tier — IsDedicatedTier("growth") == true.
	teamID := testhelpers.MustCreateTeamDB(t, db, "growth")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a1-growth", teamID, "a1growth@example.com")

	type testCase struct {
		name string
		path string
		body string
	}

	cases := []testCase{
		{name: "db", path: "/db/new", body: `{"name":"mydb","dedicated":true}`},
		{name: "cache", path: "/cache/new", body: `{"name":"mycache","dedicated":true}`},
		{name: "nosql", path: "/nosql/new", body: `{"name":"mymongo","dedicated":true}`},
		{name: "queue", path: "/queue/new", body: `{"name":"myqueue","dedicated":true}`},
		{name: "vector", path: "/vector/new", body: `{"name":"myvector","dedicated":true}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postWithAuthJSONTier(t, app, tc.path, sessionJWT, tc.body)
			defer resp.Body.Close()

			// We expect anything EXCEPT 402 upgrade_required. In the test environment
			// the provisioner is not running so the provision itself may fail with 503,
			// but the tier gate must NOT fire 402 for a growth team.
			if resp.StatusCode == http.StatusPaymentRequired {
				b := decodeTierErrBody(t, resp)
				assert.NotEqual(t, "upgrade_required", b.Error,
					"%s: growth+dedicated must not get upgrade_required 402", tc.path)
			}
		})
	}
}

// TestDedicatedTierGate_ProRejected asserts that pro tier (not dedicated-eligible)
// is rejected when sending dedicated:true.
func TestDedicatedTierGate_ProRejected(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()
	if planReg.IsDedicatedTier("pro") {
		t.Skip("pro is configured as dedicated-eligible — skipping rejection test")
	}

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a1-pro", teamID, "a1pro@example.com")

	resp := postWithAuthJSONTier(t, app, "/db/new", sessionJWT, `{"name":"prodb","dedicated":true}`)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"pro+dedicated should get 402 when not dedicated-eligible")

	b := decodeTierErrBody(t, resp)
	assert.Equal(t, "upgrade_required", b.Error)
}

// TestDedicatedTierGate_NonDedicatedField_Passthrough asserts that authenticated
// requests WITHOUT dedicated:true are not affected by the gate (regression guard
// to verify we didn't accidentally block all authenticated provisions).
func TestDedicatedTierGate_NonDedicatedField_Passthrough(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a1-passthrough", teamID, "a1pass@example.com")

	// No dedicated:true — hobby team should NOT get 402 upgrade_required.
	resp := postWithAuthJSONTier(t, app, "/db/new", sessionJWT, `{"name":"mydb"}`)
	defer resp.Body.Close()

	// The provision itself may fail (no provisioner in tests) with 503, but must
	// not fail with 402 upgrade_required.
	if resp.StatusCode == http.StatusPaymentRequired {
		b := decodeTierErrBody(t, resp)
		assert.NotEqual(t, "upgrade_required", b.Error,
			"hobby without dedicated:true must not get upgrade_required 402")
	}
}

// ── A5: Stack Count Cap ────────────────────────────────────────────────────────

// TestStackProvisionTierCap_HobbyLimitOne verifies that a hobby-tier team that
// already has 1 active stack receives 402 deployment_limit_reached on the next
// POST /stacks/new. hobby has deployments_apps=1 in plans.yaml.
func TestStackProvisionTierCap_HobbyLimitOne(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a5-hobby", teamID, "a5hobby@example.com")

	// Seed one active stack — hobby limit is 1, so a second must be rejected.
	insertActiveStackForTier(t, db, teamID)

	app := newStackTestApp(t, db) // uses plans.Default() internally

	// Verify the default registry used by newStackTestApp matches our expectation.
	require.Equal(t, 1, planReg.DeploymentsAppsLimit("hobby"),
		"plans.Default() hobby.deployments_apps must be 1 for this test to be meaningful")

	tarball := createMinimalTarball(t)
	resp := postStackNew(t, app, sessionJWT, testManifestSingleService, map[string][]byte{
		"web": tarball,
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"hobby team at stack cap should get 402")

	var b struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&b))
	assert.False(t, b.OK)
	assert.Equal(t, "deployment_limit_reached", b.Error)
}

// TestStackProvisionTierCap_UnlimitedTier verifies that a team-tier user is NOT
// blocked by the stack cap (deployments_apps=-1 = unlimited).
func TestStackProvisionTierCap_UnlimitedTier(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()
	require.Equal(t, -1, planReg.DeploymentsAppsLimit("team"),
		"team.deployments_apps must be -1 (unlimited) for this test")

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a5-team", teamID, "a5team@example.com")

	// Seed 5 stacks — team tier is unlimited, must not block.
	for i := range 5 {
		slug := fmt.Sprintf("stk-team-%d-%s", i, teamID[:6])
		_, err := db.ExecContext(context.Background(), `
			INSERT INTO stacks (team_id, name, slug, namespace, status, tier)
			VALUES ($1, 'test', $2, $2, 'building', 'team')
		`, teamID, slug)
		require.NoError(t, err)
	}

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	resp := postStackNew(t, app, sessionJWT, testManifestSingleService, map[string][]byte{
		"web": tarball,
	})
	defer resp.Body.Close()

	// Must NOT get 402 deployment_limit_reached.
	if resp.StatusCode == http.StatusPaymentRequired {
		var b struct{ Error string `json:"error"` }
		_ = json.NewDecoder(resp.Body).Decode(&b)
		assert.NotEqual(t, "deployment_limit_reached", b.Error,
			"team tier (unlimited) must not hit deployment_limit_reached")
	}
}

// TestStackProvisionTierCap_DeletedStackNotCounted verifies that stacks with
// status='deleted' do NOT count toward the cap (soft-deleted slots are freed).
func TestStackProvisionTierCap_DeletedStackNotCounted(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()
	require.Equal(t, 1, planReg.DeploymentsAppsLimit("hobby"),
		"hobby.deployments_apps must be 1 for this test")

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a5-del", teamID, "a5del@example.com")

	// Insert a DELETED stack — must not count.
	slug := fmt.Sprintf("stk-del-%s", teamID[:8])
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stacks (team_id, name, slug, namespace, status, tier)
		VALUES ($1, 'deleted-one', $2, $2, 'deleted', 'hobby')
	`, teamID, slug)
	require.NoError(t, err)

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	resp := postStackNew(t, app, sessionJWT, testManifestSingleService, map[string][]byte{
		"web": tarball,
	})
	defer resp.Body.Close()

	// deleted stack must not count — first new stack should succeed.
	assert.Equal(t, http.StatusAccepted, resp.StatusCode,
		"hobby team with only a deleted stack should still get 202 (slot is freed)")
}

// ── A6: Queue Count Cap ────────────────────────────────────────────────────────

// TestQueueProvisionTierCap_HobbyAtLimit verifies that a hobby-tier team that
// already has 3 active queues receives 402 queue_limit_reached. hobby allows 3.
func TestQueueProvisionTierCap_HobbyAtLimit(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()
	hobbyLimit := planReg.QueueCountLimit("hobby")
	require.Greater(t, hobbyLimit, 0,
		"hobby.queue_count must be positive for this test to be meaningful (got %d)", hobbyLimit)

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "queue")
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a6-hobby", teamID, "a6hobby@example.com")

	// Seed exactly hobbyLimit active queues.
	for range hobbyLimit {
		insertActiveQueueForTier(t, db, teamID)
	}

	resp := postWithAuthJSONTier(t, app, "/queue/new", sessionJWT, `{"name":"extra-queue"}`)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"hobby team at queue cap (%d) should get 402", hobbyLimit)

	b := decodeTierErrBody(t, resp)
	assert.False(t, b.OK)
	assert.Equal(t, "queue_limit_reached", b.Error)
}

// TestQueueProvisionTierCap_HobbyUnderLimit verifies that a hobby-tier team with
// fewer than 3 queues is NOT rejected by the queue cap.
func TestQueueProvisionTierCap_HobbyUnderLimit(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()
	hobbyLimit := planReg.QueueCountLimit("hobby")
	require.Greater(t, hobbyLimit, 1,
		"hobby.queue_count must be > 1 to have a 'under limit' state")

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "queue")
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a6-under", teamID, "a6under@example.com")

	// Seed hobbyLimit-1 queues (under the cap).
	for range hobbyLimit - 1 {
		insertActiveQueueForTier(t, db, teamID)
	}

	resp := postWithAuthJSONTier(t, app, "/queue/new", sessionJWT, `{"name":"ok-queue"}`)
	defer resp.Body.Close()

	// Queue provision itself may fail (no NATS backend in tests) with 503,
	// but must not fail with 402 queue_limit_reached.
	if resp.StatusCode == http.StatusPaymentRequired {
		b := decodeTierErrBody(t, resp)
		assert.NotEqual(t, "queue_limit_reached", b.Error,
			"hobby team under queue cap must not get queue_limit_reached")
	}
}

// TestQueueProvisionTierCap_GrowthUnlimited verifies that a growth-tier team
// (queue_count=-1) is never blocked by the queue cap.
func TestQueueProvisionTierCap_GrowthUnlimited(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()
	require.Equal(t, -1, planReg.QueueCountLimit("growth"),
		"growth.queue_count must be -1 (unlimited)")

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "queue")
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "growth")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a6-growth", teamID, "a6growth@example.com")

	// Seed 20 queues — unlimited tier must not block.
	for range 20 {
		insertActiveQueueForTier(t, db, teamID)
	}

	resp := postWithAuthJSONTier(t, app, "/queue/new", sessionJWT, `{"name":"growth-queue"}`)
	defer resp.Body.Close()

	// Must NOT get 402 queue_limit_reached.
	if resp.StatusCode == http.StatusPaymentRequired {
		b := decodeTierErrBody(t, resp)
		assert.NotEqual(t, "queue_limit_reached", b.Error,
			"growth tier (unlimited queues) must not hit queue_limit_reached")
	}
}

// TestQueueProvisionTierCap_TeamUnlimited verifies that team-tier teams are also unlimited.
func TestQueueProvisionTierCap_TeamUnlimited(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	planReg := plans.Default()
	require.Equal(t, -1, planReg.QueueCountLimit("team"),
		"team.queue_count must be -1 (unlimited)")

	app, cleanup := testhelpers.NewTestAppWithServices(t, db, nil, "queue")
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-a6-team", teamID, "a6team@example.com")

	insertActiveQueueForTier(t, db, teamID)

	resp := postWithAuthJSONTier(t, app, "/queue/new", sessionJWT, `{"name":"team-queue"}`)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPaymentRequired {
		b := decodeTierErrBody(t, resp)
		assert.NotEqual(t, "queue_limit_reached", b.Error,
			"team tier (unlimited queues) must not hit queue_limit_reached")
	}
}

// ── Plans Registry Unit Tests ────────────────────────────────────────────────

// TestPlansRegistry_IsDedicatedTier verifies that IsDedicatedTier returns the
// expected results for each tier in the default registry. This is the
// single-point assertion for the A1 fix's core predicate.
func TestPlansRegistry_IsDedicatedTier(t *testing.T) {
	r := plans.Default()

	type tc struct {
		tier     string
		wantTrue bool
	}

	cases := []tc{
		{"anonymous", false},
		{"free", false},
		{"hobby", false},
		{"hobby_plus", false},
		{"hobby_yearly", false},
		{"pro", false},
		{"pro_yearly", false},
		{"growth", true}, // dedicated infra
		{"team", true},   // bug bash #12: Team ($199, above Growth) is dedicated too
	}

	for _, c := range cases {
		t.Run(c.tier, func(t *testing.T) {
			got := r.IsDedicatedTier(c.tier)
			assert.Equal(t, c.wantTrue, got,
				"IsDedicatedTier(%q) should be %v", c.tier, c.wantTrue)
		})
	}
}

// TestPlansRegistry_QueueCountLimit verifies that QueueCountLimit returns the
// expected values for each tier. This is the single-point assertion for the
// A6 fix's plans.Registry integration.
func TestPlansRegistry_QueueCountLimit(t *testing.T) {
	r := plans.Default()

	type tc struct {
		tier string
		want int
	}

	cases := []tc{
		// unlimited tiers
		{"anonymous", -1},
		{"free", -1},
		{"growth", -1},
		{"team", -1},
		{"team_yearly", -1},
		// capped tiers — exact values set in plans.yaml
		{"hobby", 3},
		{"hobby_yearly", 3},
		{"hobby_plus", 5},
		{"hobby_plus_yearly", 5},
		{"pro", 20},
		{"pro_yearly", 20},
	}

	for _, c := range cases {
		t.Run(c.tier, func(t *testing.T) {
			got := r.QueueCountLimit(c.tier)
			assert.Equal(t, c.want, got,
				"QueueCountLimit(%q) should be %d", c.tier, c.want)
		})
	}
}

// TestCountActiveStacksByTeam_ExcludesDeleted verifies that the DB model
// function used by the A5 check counts only the stack statuses that actually
// occupy a billable slot (building/deploying/healthy — those run a pod) and
// excludes failed/stopped/deleting (no pod, no compute). This is the
// model-layer regression test for the P1-B tier-slot-leak fix.
func TestCountActiveStacksByTeam_ExcludesDeleted(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	ctx := context.Background()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	teamUUID, err := uuid.Parse(teamID)
	require.NoError(t, err)

	insertSlug := func(status string) string {
		slug := fmt.Sprintf("stk-%s-%s", status, teamID[:6])
		_, insertErr := db.ExecContext(ctx, `
			INSERT INTO stacks (team_id, name, slug, namespace, status, tier)
			VALUES ($1, $2, $3, $3, $4, 'hobby')
		`, teamID, "test-"+status, slug, status)
		require.NoError(t, insertErr)
		return slug
	}

	insertSlug("building")  // counts — running a pod
	insertSlug("deploying") // counts — running a pod
	insertSlug("healthy")   // counts — running a pod
	insertSlug("failed")    // must NOT count — no pod, no compute
	insertSlug("stopped")   // must NOT count — no pod, no compute
	insertSlug("deleting")  // must NOT count — being torn down

	n, err := models.CountActiveStacksByTeam(ctx, db, teamUUID)
	require.NoError(t, err)
	assert.Equal(t, 3, n, "CountActiveStacksByTeam should count only building/deploying/healthy stacks")
}

// requireTestDB skips the test if TEST_DATABASE_URL is not set.
// Defined here because stack_test.go and this file are in the same package;
// both define requireTestDB. Use build-tag logic to avoid re-declaration.
// NOTE: requireTestDB is already defined in stack_test.go — this file
// references it from there since we're in the same package.

// Compile-time guards: ensure the models function we test is accessible.
var _ = models.CountActiveStacksByTeam

// ensure bytes is used (for multipart helpers referenced from stack_test.go)
var _ = bytes.NewBuffer

// insertActiveQueueForTier uses the 'resources' table's name column, which
// may conflict with a NOT NULL constraint on other columns. Verify the resources
// table schema used in tests has only these required columns.
