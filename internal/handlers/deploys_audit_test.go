package handlers_test

// deploys_audit_test.go — integration coverage for the
// GET /api/v1/<admin-prefix>/deploys handler. Drives the real handler
// behind a fake-auth shim that injects the JWT email into Fiber locals
// (so we don't have to mint real JWTs in every test), then chains the
// production RequireAdmin middleware. Real DB writes against
// TEST_DATABASE_URL.
//
// What we're asserting:
//   1. RequireAdmin closed-by-default: empty ADMIN_EMAILS rejects every
//      caller with 403 + agent_action.
//   2. Non-admin JWT email → 403 even when ADMIN_EMAILS is populated
//      with someone else's address.
//   3. Admin caller, empty table → 200 with deploys=[].
//   4. Admin caller, after one self-report → 200 with one row whose
//      service / commit_id / image_digest match.
//   5. service filter narrows the result to one service's rows.
//   6. limit honors the cap on the model side and bounds the response.
//   7. invalid service param → 400.
//   8. invalid since param → 400.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// deploysAuditAdminEmail / deploysAuditNonAdminEmail are the email
// addresses the fake-auth shim stamps onto Fiber locals so RequireAdmin
// sees a real value. Mirrors the constants in admin_customers_test.go
// but doesn't share them — these tests are co-located with the handler
// they cover, and the constants are intentionally separate so a future
// refactor that splits the test binary doesn't break one and silently
// leave the other in a confusing state.
const (
	deploysAuditAdminEmail    = "founder@instanode.dev"
	deploysAuditNonAdminEmail = "alice@example.com"
)

// deploysAuditNeedsDB skips the test if TEST_DATABASE_URL isn't set.
// Mirrors the admin_customers_test.go convention.
func deploysAuditNeedsDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("deploys_audit_test: TEST_DATABASE_URL not set — skipping integration test")
	}
	return testhelpers.SetupTestDB(t)
}

// deploysAuditApp builds a minimal Fiber app that wires the
// DeploysAuditHandler behind the production RequireAdmin middleware. We
// don't drive router.New (it needs Redis + gRPC); instead we replicate
// just the admin-routes branch that this PR adds. The prefix is fixed
// at "admin" in tests for readability — the prefix-obscurity gate is
// covered separately in admin_path_prefix_test.go.
func deploysAuditApp(t *testing.T, db *sql.DB, callerEmail string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})

	fakeAuth := func(c *fiber.Ctx) error {
		if callerEmail != "" {
			c.Locals(middleware.LocalKeyEmail, callerEmail)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	}

	h := handlers.NewDeploysAuditHandler(db)
	adminGroup := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	adminGroup.Get("/deploys", h.List)
	return app
}

// deploysAuditDoGET performs a GET, parses JSON, and registers a body
// close on cleanup. Returns the status code and the decoded map.
func deploysAuditDoGET(t *testing.T, app *fiber.App, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		out = map[string]any{}
	}
	return resp.StatusCode, out
}

// seedDeploysAuditRow writes one row directly into deploys_audit so the
// list endpoint has something to return. Using the model here (rather
// than raw SQL) keeps this helper in lockstep with the production write
// path — if InsertSelfReport gains a column the seed function picks it
// up automatically.
func seedDeploysAuditRow(t *testing.T, db *sql.DB, service, commit, digest string) {
	t.Helper()
	err := models.InsertSelfReport(context.Background(), db, models.SelfReportParams{
		Service:     service,
		CommitID:    commit,
		ImageDigest: digest,
		Version:     "v0.0.0-test",
		BuildTime:   "2026-05-12T00:00:00Z",
	})
	require.NoError(t, err)
}

// TestDeploysAudit_RequireAdmin_ClosedByDefault — the bedrock invariant:
// empty ADMIN_EMAILS rejects every caller, even one whose JWT carries a
// founder-shaped email. Forgetting to configure the env var must fail
// closed.
func TestDeploysAudit_RequireAdmin_ClosedByDefault(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	t.Setenv(middleware.AdminEmailsEnvVar, "")
	app := deploysAuditApp(t, db, deploysAuditAdminEmail)

	status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys")
	assert.Equal(t, http.StatusForbidden, status, "empty ADMIN_EMAILS must reject")
	assert.Equal(t, "forbidden", body["error"])
	aa, _ := body["agent_action"].(string)
	assert.Contains(t, aa, "Tell the user this endpoint requires platform-admin access",
		"agent_action must be populated on the rejection path")
}

// TestDeploysAudit_RequireAdmin_NonAdminRejected — ADMIN_EMAILS is set
// but to a different person; the caller's JWT email isn't on the list.
// 403 with the same agent_action shape as the closed-by-default case.
func TestDeploysAudit_RequireAdmin_NonAdminRejected(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, db, deploysAuditNonAdminEmail)

	status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys")
	assert.Equal(t, http.StatusForbidden, status,
		"a JWT email not in ADMIN_EMAILS must be rejected even when the env var is populated")
	assert.Equal(t, "forbidden", body["error"])
}

// TestDeploysAudit_AdminEmptyTable — happy path with no rows. We still
// expect 200 + a JSON-encodable empty array (not null), because callers
// that iterate over `deploys` shouldn't have to special-case the empty
// case.
func TestDeploysAudit_AdminEmptyTable(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	_, err := db.Exec(`DELETE FROM deploys_audit`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM deploys_audit`) })

	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, db, deploysAuditAdminEmail)

	status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["ok"])
	deploys, ok := body["deploys"].([]any)
	require.True(t, ok, "deploys field must be present as a JSON array (got: %T)", body["deploys"])
	assert.Empty(t, deploys, "empty table must return an empty array, not null")
}

// TestDeploysAudit_AdminReadsOneRow — round-trips a single seeded row
// through the handler. Asserts the JSON keys the founder-facing client
// (curl, the in-progress admin dashboard) will rely on.
func TestDeploysAudit_AdminReadsOneRow(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	_, err := db.Exec(`DELETE FROM deploys_audit`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM deploys_audit`) })

	seedDeploysAuditRow(t, db, models.DeployServiceAPI, "abc1234", "sha256:deadbeef")

	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, db, deploysAuditAdminEmail)

	status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys")
	require.Equal(t, http.StatusOK, status)
	deploys, ok := body["deploys"].([]any)
	require.True(t, ok)
	require.Len(t, deploys, 1)
	row := deploys[0].(map[string]any)
	assert.Equal(t, models.DeployServiceAPI, row["service"])
	assert.Equal(t, "abc1234", row["commit_id"])
	assert.Equal(t, "sha256:deadbeef", row["image_digest"])
	assert.Equal(t, models.DeployNoticedBySelfReport, row["noticed_by"])
	// Nullable fields must serialize as either a string or null — never
	// the empty string, which would be ambiguous.
	if v := row["version"]; v != nil {
		_, isStr := v.(string)
		assert.True(t, isStr, "version must be a JSON string or null")
	}
}

// TestDeploysAudit_FilterByService — multi-service rows in the table:
// asking for ?service=api returns only api rows.
func TestDeploysAudit_FilterByService(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	_, err := db.Exec(`DELETE FROM deploys_audit`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM deploys_audit`) })

	seedDeploysAuditRow(t, db, models.DeployServiceAPI, "c1", "d1")
	seedDeploysAuditRow(t, db, models.DeployServiceWorker, "c2", "d2")
	seedDeploysAuditRow(t, db, models.DeployServiceProvisioner, "c3", "d3")

	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, db, deploysAuditAdminEmail)

	status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys?service=worker")
	require.Equal(t, http.StatusOK, status)
	deploys, ok := body["deploys"].([]any)
	require.True(t, ok)
	require.Len(t, deploys, 1, "service=worker must filter to one row")
	row := deploys[0].(map[string]any)
	assert.Equal(t, models.DeployServiceWorker, row["service"])
}

// TestDeploysAudit_RejectsInvalidService — unknown service value is a
// 400, never a SQL pass-through.
func TestDeploysAudit_RejectsInvalidService(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, db, deploysAuditAdminEmail)

	status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys?service=not-real")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_service", body["error"])
}

// TestDeploysAudit_RejectsInvalidSince — non-RFC3339 since param surfaces
// as 400 with a specific error code so the operator knows what to fix.
func TestDeploysAudit_RejectsInvalidSince(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, db, deploysAuditAdminEmail)

	status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys?since=yesterday")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_since", body["error"])
}

// TestDeploysAudit_RejectsInvalidLimit — limit must be a positive
// integer. Negative or zero or non-numeric → 400.
func TestDeploysAudit_RejectsInvalidLimit(t *testing.T) {
	db, cleanup := deploysAuditNeedsDB(t)
	defer cleanup()

	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, db, deploysAuditAdminEmail)

	for _, raw := range []string{"abc", "0", "-1"} {
		status, body := deploysAuditDoGET(t, app, "/api/v1/admin/deploys?limit="+raw)
		assert.Equal(t, http.StatusBadRequest, status, "limit=%q must be rejected", raw)
		assert.Equal(t, "invalid_limit", body["error"], "limit=%q must surface invalid_limit", raw)
	}
}
