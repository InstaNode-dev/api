package testhelpers

// testapp_smoke_test.go — minimal smoke tests that build a fully-wired test
// app via NewTestAppWithServices. The point isn't to verify routing behavior
// (that's the handler-layer suite's job) — it's to give the `testhelpers`
// package its own coverage on the route-registration block so additions to
// the test-app surface (new routes, new handlers) are picked up by the
// patch-coverage gate.
//
// Without an in-package test that exercises NewTestAppWithServices, every new
// `api.Get("/x", h.X)` line added to testhelpers.go shows up as uncovered in
// diff-cover even when every downstream handler test passes through it: the
// default `go test ./...` -coverprofile flow only attributes coverage to the
// package whose tests ran, and handler tests live in `package handlers_test`.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
)

// TestNewTestAppWithServices_RegistersDeployEventsRoute boots a deploy-enabled
// test app and confirms the GET /api/v1/deployments/:id/events route is wired
// (the route registered in PR #200). An unauthenticated request returns 401
// from the api group's RequireAuth middleware — that is enough to prove the
// route is registered (a missing route would 404), and it avoids the seeding
// the happy-path tests already cover.
func TestNewTestAppWithServices_RegistersDeployEventsRoute(t *testing.T) {
	db, cleanDB := SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/deployments/any-id/events", nil)
	req.Header.Set("X-Forwarded-For", "10.99.0.10")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 401 (auth middleware short-circuit) proves the route is mounted: a
	// missing route would 404 from the router before middleware fires.
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"deploy events route must be registered under the /api/v1 group")
}

// TestNewTestAppWithServices_AppliesConfigMutator proves the variadic config
// mutator seam runs against the test config before handlers are built. Handler
// tests exercise this with feature-flag mutators, but per-package coverage only
// credits the `testhelpers` package when an in-package test passes a mutator —
// so this gives the mutator loop its own coverage. A nil mutator interleaved
// with a real one confirms the nil-skip guard.
func TestNewTestAppWithServices_AppliesConfigMutator(t *testing.T) {
	db, cleanDB := SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := SetupTestRedis(t)
	defer cleanRedis()

	applied := false
	_, cleanApp := NewTestAppWithServices(t, db, rdb, "deploy",
		nil, // skipped by the m != nil guard
		func(c *config.Config) {
			c.DeploySourceImageEnabled = true
			applied = true
		})
	defer cleanApp()

	require.True(t, applied, "config mutator must run against the test config")
}
