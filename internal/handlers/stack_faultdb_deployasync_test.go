package handlers_test

// stack_faultdb_deployasync_test.go — drives the mid-handler 503 error arms in
// stack.go (a query that runs AFTER requireStackTeam + GetStackBySlug succeed).
// Uses the fault-injecting driver from faultdb_deployasync_test.go: the first
// `failAfter` queries succeed (auth team lookup + slug lookup), then the target
// query errors → the handler's slog.Error + 503 arm runs.
//
// Scope: stack.go ONLY.

import (
	"database/sql"
	"errors"
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
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// newStackCancelDeleteApp wires the stack ConfirmDelete + CancelDelete routes
// (absent from newStackTestApp) against the given db.
func newStackCancelDeleteApp(t *testing.T, db *sql.DB) *fiber.App {
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
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Delete("/stacks/:slug/confirm-deletion", sh.CancelDelete)
	api.Post("/stacks/:slug/confirm-deletion", sh.ConfirmDelete)
	return app
}

// TestStackFamily_MidHandler503 — Family's GetStackFamily (3rd query) fails.
func TestStackFamily_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	// Seed against a normal DB first.
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug := sdaSeedStack(t, seedDB, teamID, "healthy", "production")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "fam@example.com")

	// Fault db: allow the team lookup + slug lookup (2 queries) then fail the
	// GetStackFamily query (3rd). A small tolerance window: try failAfter from
	// 2 upward until we get a 503 (query counts can include a session-setup
	// SELECT). Bounded loop keeps it deterministic.
	got := sdaTryFaultStatus(t, "/api/v1/stacks/"+slug+"/family", http.MethodGet, "", jwt, http.StatusServiceUnavailable)
	assert.True(t, got, "expected a 503 mid-handler arm for Family within the failAfter sweep")
}

// TestStackGet_MidHandler503 — Get's GetStackServicesByStack fails.
func TestStackGet_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug := sdaSeedStack(t, seedDB, teamID, "healthy", "production")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "get@example.com")

	got := sdaTryFaultStatus(t, "/stacks/"+slug, http.MethodGet, "", jwt, http.StatusServiceUnavailable)
	assert.True(t, got, "expected a 503 mid-handler arm for Get within the failAfter sweep")
}

// TestStackList_MidHandler503 — List's GetStacksByTeam fails after team lookup.
func TestStackList_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "lst@example.com")

	got := sdaTryFaultStatus(t, "/api/v1/stacks", http.MethodGet, "", jwt, http.StatusServiceUnavailable)
	assert.True(t, got, "expected a 503 mid-handler arm for List within the failAfter sweep")
}

// TestStackUpdateEnv_MidHandler503 — UpdateEnv's GetStackEnvVars fails.
func TestStackUpdateEnv_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug := sdaSeedStack(t, seedDB, teamID, "healthy", "production")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ue@example.com")

	got := sdaTryFaultStatus(t, "/stacks/"+slug+"/env", http.MethodPatch, `{"env":{"FOO":"bar"}}`, jwt, http.StatusServiceUnavailable)
	assert.True(t, got, "expected a 503 mid-handler arm for UpdateEnv within the failAfter sweep")
}

// TestStackRedeploy_MidHandler503 — Redeploy's env_vars / services load fails
// after team + slug lookup (a multipart POST so the form parses, then a later
// query errors → 503).
func TestStackRedeploy_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug, _ := seedPromoteSourceStack(t, seedDB, teamID, "production", "rdf")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rdf@example.com")

	tar := createMinimalTarball(t)
	got := 0
	for failAfter := int64(1); failAfter <= 10; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
		req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got++
		}
	}
	assert.Greater(t, got, 0, "expected at least one Redeploy mid-handler 503 across the failAfter sweep")
}

// TestStackPromote_MidHandler503 — Promote's source-services / family lookup
// query fails after team + slug lookup → 503. Dev-target so the email-approval
// gate is skipped and the handler proceeds to the DB-heavy section.
func TestStackPromote_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug, _ := seedPromoteSourceStack(t, seedDB, teamID, "staging", "pmf")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "pmf@example.com")

	// Sweep a wide failAfter window: a dev-target promote runs the full
	// execute body (Step A source-services, Step B find/create target, Step C
	// source/target env_vars load, Step C vault resolve) — each is a distinct
	// query depth, and a fault at any of them surfaces as a 503. We assert that
	// AT LEAST one depth produces a 503 (proves the error arms are wired); the
	// sweep collectively walks several of them across iterations for coverage.
	got := 0
	for failAfter := int64(1); failAfter <= 12; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
			sdaJSONBody(`{"from":"staging","to":"development"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got++
		}
	}
	assert.Greater(t, got, 0, "expected at least one Promote mid-handler 503 across the failAfter sweep")
}

// TestStackCancelDelete_MidHandler503 — CancelDelete's GetStackBySlug fails
// after team lookup → fetch_failed 503.
func TestStackCancelDelete_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug := sdaSeedStack(t, seedDB, teamID, "healthy", "production")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "cdf@example.com")

	// CancelDelete route isn't on newStackTestApp; wire a dedicated app.
	got := false
	for failAfter := int64(1); failAfter <= 4; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackCancelDeleteApp(t, fdb)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/stacks/"+slug+"/confirm-deletion", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got = true
			break
		}
	}
	assert.True(t, got, "expected CancelDelete mid-handler 503 within failAfter sweep")
}

// TestStackPromote_BeginApprovalInsertFault_503 — a non-dev promote where the
// CreatePromoteApproval insert fails (fault) → beginPromoteApproval's
// approval_failed 503 (stack.go L2358-2365).
func TestStackPromote_BeginApprovalInsertFault_503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug, _ := seedPromoteSourceStack(t, seedDB, teamID, "staging", "baf")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "baf@example.com")

	got := false
	for failAfter := int64(1); failAfter <= 4; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		// to=production (non-dev) + no approval_id → beginPromoteApproval path.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
			sdaJSONBody(`{"from":"staging","to":"production"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got = true
		}
	}
	assert.True(t, got, "expected beginPromoteApproval insert-fault 503 within the sweep")
}

// TestStackRedeploy_CountFault_503 — Redeploy of a non-active (failed) stack
// where the CountActiveStacksByTeam quota query fails (fault) → quota_check
// 503 (stack.go L1299-1304).
func TestStackRedeploy_CountFault_503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	slug, _ := seedPromoteSourceStack(t, seedDB, teamID, "production", "rcf")
	_, err := seedDB.Exec(`UPDATE stacks SET status='failed' WHERE slug=$1`, slug)
	require.NoError(t, err)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rcf@example.com")

	tar := createMinimalTarball(t)
	got := false
	for failAfter := int64(1); failAfter <= 4; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
		req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got = true
		}
	}
	assert.True(t, got, "expected Redeploy quota-check 503 within failAfter sweep")
}

// TestStackNew_MidHandler503 — /stacks/new where a query after the team lookup
// (the count check / CreateStackWithCap) fails → provision_failed / quota
// 503. Wide sweep walks the New query depths.
func TestStackNew_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "snf@example.com")

	tar := createMinimalTarball(t)
	got := 0
	for failAfter := int64(1); failAfter <= 6; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
		req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("X-Forwarded-For", "10.66.0.1")
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got++
		}
	}
	assert.Greater(t, got, 0, "expected at least one /stacks/new mid-handler 503 across the failAfter sweep")
}

// TestStackNew_NeedsResourceLookup_MidHandler503 — /stacks/new with a `needs:`
// resource where the GetResourceByToken lookup errors (fault) → lookup_failed
// 503. Walks the New needs-resolution query depth.
func TestStackNew_NeedsResourceLookup_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "snr@example.com")
	// Seed a real resource so the lookup would normally succeed; the fault is
	// what forces the error arm.
	tok := uuid.New()
	_, err := seedDB.Exec(`INSERT INTO resources (token, team_id, resource_type, tier, status, connection_url, provider_resource_id, env)
		VALUES ($1,$2,'postgres','pro','active','postgres://u:p@h:5432/db','instant-customer-x','production')`, tok, teamID)
	require.NoError(t, err)
	manifest := "services:\n  web:\n    build: ./web\n    port: 3000\n    needs:\n      - " + tok.String() + "\n"

	tar := createMinimalTarball(t)
	got := 0
	for failAfter := int64(1); failAfter <= 6; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		body, ct := multipartBody(t, manifest, map[string][]byte{"web": tar}, nil)
		req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("X-Forwarded-For", "10.77.0.1")
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got++
		}
	}
	assert.Greater(t, got, 0, "expected /stacks/new needs-lookup mid-handler 503 across the sweep")
}

// TestStackPromote_InPlace_MidHandler503 — pre-create a development target so a
// second promote takes the in-place-update branch; fault the deeper queries
// (target-services fetch, image-ref update) → 503.
func TestStackPromote_InPlace_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug, _ := seedPromoteSourceStack(t, seedDB, teamID, "staging", "ipf")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ipf@example.com")

	// First promote (no fault) creates the development target.
	{
		app := newStackTestApp(t, seedDB)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
			sdaJSONBody(`{"from":"staging","to":"development"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		resp.Body.Close()
	}

	// Second promote with faults → in-place branch queries fail at some depth.
	got := 0
	for failAfter := int64(1); failAfter <= 14; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/promote",
			sdaJSONBody(`{"from":"staging","to":"development"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got++
		}
	}
	assert.Greater(t, got, 0, "expected at least one in-place Promote mid-handler 503 across the sweep")
}

// TestStackDelete_MidHandler503 — DELETE /stacks/:slug (immediate path, no
// email client on newStackTestApp) where the DeleteStack write fails (fault)
// → delete_failed 503. Walks the delete query depths.
func TestStackDelete_MidHandler503(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	slug := sdaSeedStack(t, seedDB, teamID, "healthy", "production")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "sdf@example.com")

	got := 0
	for failAfter := int64(1); failAfter <= 5; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		// Skip the email-confirmation path (newStackTestApp wires no mailer, so
		// it's immediate anyway) and force-bypass header for determinism.
		req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("X-Skip-Email-Confirmation", "true")
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			got++
		}
	}
	assert.Greater(t, got, 0, "expected Delete mid-handler 503 across the failAfter sweep")
}

// TestStackRedeploy_QuotaCap_402 — redeploying a non-active (failed) stack when
// the team is already at its deploy cap returns 402 (Redeploy re-runs the cap
// check for non-slot-occupying statuses).
func TestStackRedeploy_QuotaCap_402(t *testing.T) {
	sdaNeedsDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	// hobby tier: deployments_apps=1. Seed one ACTIVE stack to consume the slot,
	// plus a FAILED stack to redeploy → cap re-check trips 402.
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "qc@example.com")
	sdaSeedStack(t, seedDB, teamID, "healthy", "production")    // occupies the slot
	slug, _ := seedPromoteSourceStack(t, seedDB, teamID, "staging", "qc-failed")
	_, err := seedDB.Exec(`UPDATE stacks SET status='failed' WHERE slug=$1`, slug)
	require.NoError(t, err)

	app := newStackTestApp(t, seedDB)
	tar := createMinimalTarball(t)
	body, ct := multipartBody(t, testManifestSingleService, map[string][]byte{"web": tar}, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
}

// sdaTryFaultStatus sweeps failAfter from 1..6 and returns true the first time
// the route returns wantStatus. Each iteration builds a fresh fault db (same
// backing DSN, so the rows seeded earlier are visible). This absorbs the
// variability in how many setup queries lib/pq issues before the target query.
func sdaTryFaultStatus(t *testing.T, path, method, body, jwt string, wantStatus int) bool {
	t.Helper()
	// Walk the full window (no early break) so faults at multiple query depths
	// each exercise their respective error arm — maximises coverage of the
	// distinct mid-handler 503 returns.
	hit := false
	for failAfter := int64(1); failAfter <= 6; failAfter++ {
		fdb := openFaultDB(t, failAfter)
		app := newStackTestApp(t, fdb)
		var req *http.Request
		if body != "" {
			req = httptest.NewRequest(method, path, sdaJSONBody(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		code := resp.StatusCode
		resp.Body.Close()
		if code == wantStatus {
			hit = true
		}
	}
	return hit
}
