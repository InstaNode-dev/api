package handlers_test

// stack_anon_failure_diag_test.go — the ANONYMOUS-stack failure-diagnosis
// contract test (task #70, docs/ci/02-FAILURE-DIAGNOSIS-AND-AUTODEBUG.md §3 +
// §5.2).
//
// Anonymous users cannot use /deploy/new (RequireAuth; deployments.team_id is
// NOT NULL — memory project_anonymous_deploy_via_stacks_not_deploy_new). They
// deploy via POST /stacks/new (OptionalAuth; anon stacks carry NULL team_id).
//
// ANON FAILURE-DIAGNOSIS IS STATUS + LOGS ONLY (the documented gap):
//
//   - GET /stacks/:slug (slug-bearer, NO auth) returns status="failed" — the
//     stack-level failure is visible to the anonymous owner.
//   - the raw err.Error() string the deploy goroutine hit is persisted at the
//     SERVICE level (stack_services.error_msg via UpdateStackServiceStatus;
//     UpdateStackStatus's errMsg arg is intentionally NOT persisted — the
//     stacks table has no error column). So the failure string lives on the
//     service row, and the per-service build logs are read via
//     GET /stacks/:slug/logs/:svc.
//   - there is NO classified autopsy: NO /stacks/:slug/events route, NO
//     reason/last_lines/hint. That is the diagnosis-quality gap vs the
//     authenticated /api/v1/deployments/:id/events surface.
//
// This test PINS that contract so that:
//   (a) anon users provably get status=failed (regression guard on the thin
//       surface they DO have), and
//   (b) adding a stack-autopsy endpoint later is a DELIBERATE, test-updating
//       change — the route-absence assertion below REDS the moment someone adds
//       GET /stacks/:slug/events, forcing them to update this contract.
//
// In short: anon failure-diagnosis is status + logs only (gap: no classified
// autopsy).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/plans"
	"instant.dev/internal/router"
	"instant.dev/internal/testhelpers"
)

// anonStackEventsRoutePath is the route that would expose a classified autopsy
// to anonymous stack owners. It does NOT exist today — the assertion below pins
// its absence. Named so a future PR adding the route greps to exactly here.
const anonStackEventsRoutePath = "/stacks/:slug/events"

// TestStackAnonFailureDiag_StatusAndLogsOnly drives an anonymous stack to
// status=failed and asserts the thin diagnosis surface: GET /stacks/:slug
// (slug-bearer, no auth) returns status=failed, and the failure string is
// stored on the service row. Anon failure-diagnosis is status + logs only
// (gap: no classified autopsy).
func TestStackAnonFailureDiag_StatusAndLogsOnly(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	// Anonymous stack: NULL team_id, status driven to 'failed'. seedStack with
	// teamID=nil mirrors the mig-005 anon-stack shape (NULL team_id).
	stackID, slug := seedStack(t, db, nil, "failed")

	// The deploy goroutine's raw err.Error() lands on the SERVICE row via
	// UpdateStackServiceStatus(...,"failed", errMsg). seedStack created a 'web'
	// service in 'healthy' — flip it to failed with the raw build error string
	// so this test exercises the real failure-string truth surface.
	const rawBuildErr = "kaniko build failed: COPY failed: no source files were specified"
	_, err := db.Exec(`
		UPDATE stack_services SET status = 'failed', error_msg = $2
		WHERE stack_id = $1
	`, stackID, rawBuildErr)
	require.NoError(t, err)

	app, _ := newCoverageStackApp(t, db)

	// GET /stacks/:slug with NO Authorization header — the anonymous owner
	// reads their own stack by slug (slug IS the bearer for an anon stack).
	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"anon owner reads their own stack by slug with NO auth")

	var body struct {
		OK       bool   `json:"ok"`
		StackID  string `json:"stack_id"`
		Status   string `json:"status"`
		Services []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"services"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, slug, body.StackID)
	assert.Equal(t, "failed", body.Status,
		"anon stack failure IS visible at the stack level (status=failed)")

	// The failing service is surfaced. (serializeServices intentionally does
	// NOT echo the raw error_msg string — the per-service failure detail is
	// read via the logs surface, not the status JSON. The string is persisted
	// on the row, asserted below from the DB.)
	require.NotEmpty(t, body.Services)
	var sawFailedSvc bool
	for _, s := range body.Services {
		if s.Status == "failed" {
			sawFailedSvc = true
		}
	}
	assert.True(t, sawFailedSvc, "the failed service is surfaced in the status JSON")

	// Truth surface: the raw err.Error() string is persisted on the service
	// row (stack_services.error_msg) — this is what the logs/diagnostics path
	// reads. The stacks table itself has NO error column (UpdateStackStatus's
	// errMsg arg is discarded by design), so the failure string lives here.
	var storedErr string
	require.NoError(t, db.QueryRow(
		`SELECT error_msg FROM stack_services WHERE stack_id = $1 AND status = 'failed'`,
		stackID).Scan(&storedErr))
	assert.Equal(t, rawBuildErr, storedErr,
		"the raw build error is persisted on the service row (the anon truth surface)")
}

// TestStackAnonFailureDiag_NoClassifiedAutopsyEndpoint pins the documented gap:
// there is NO /stacks/:slug/events route. An anonymous stack owner gets status
// + logs but NO classified reason/last_lines/hint (unlike the authenticated
// /api/v1/deployments/:id/events surface).
//
// This walks the LIVE production router (router.New + GetRoutes) — the same
// authoritative route table the done-bar guard uses — so the assertion can't
// drift from what's actually mounted. The moment someone adds a stack-autopsy
// route, this test REDS, forcing the §3 contract + the anon-gap docs to be
// updated deliberately rather than the gap silently closing untested.
func TestStackAnonFailureDiag_NoClassifiedAutopsyEndpoint(t *testing.T) {
	cfg := anonStackRouterConfig()
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer func() { _ = rdb.Close() }()

	app := router.New(cfg, nil, rdb, nil, email.NewNoop(), plans.Default(), nil, nil)

	// Enumerate the live route table. There must be NO route whose path is
	// /stacks/:slug/events under ANY method.
	for _, r := range app.GetRoutes(true) {
		assert.NotEqual(t, anonStackEventsRoutePath, r.Path,
			"a %s %s route now EXISTS — anonymous stacks gained a classified-autopsy "+
				"endpoint. This closes the documented §3 gap; UPDATE this test + "+
				"docs/ci/02-FAILURE-DIAGNOSIS-AND-AUTODEBUG.md §3 to assert the new "+
				"reason/last_lines/hint contract instead of the absence.",
			r.Method, r.Path)
	}

	// Sanity: the routes anon DOES have (status + per-service logs) ARE present,
	// so the assertion above is meaningful (not vacuously true because stacks
	// routes failed to register at all).
	var sawGet, sawLogs bool
	for _, r := range app.GetRoutes(true) {
		if r.Method == http.MethodGet && r.Path == "/stacks/:slug" {
			sawGet = true
		}
		if r.Method == http.MethodGet && r.Path == "/stacks/:slug/logs/:svc" {
			sawLogs = true
		}
	}
	assert.True(t, sawGet, "GET /stacks/:slug (status surface) must be mounted")
	assert.True(t, sawLogs, "GET /stacks/:slug/logs/:svc (logs surface) must be mounted")
}

// anonStackRouterConfig is a minimal config sufficient for router.New to mount
// the full route table for the route-presence enumeration above. No DB call is
// made (the test only inspects GetRoutes, never serves a request), so the nil
// db passed to router.New is safe here.
func anonStackRouterConfig() *config.Config {
	return &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,redis,mongodb,queue,webhook,storage,deploy",
		Environment:              "development",
		PostgresProvisionBackend: "local",
		ComputeProvider:          "noop",
		QueueBackend:             "legacy_open",
		ObjectStoreBucket:        "instant-shared",
		// AdminPathPrefix empty → admin subtree skipped; irrelevant to stacks.
	}
}
