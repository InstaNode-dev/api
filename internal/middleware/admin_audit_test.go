package middleware_test

// admin_audit_test.go — every hit on the admin route prefix MUST write
// an audit_log row with kind="admin.access", success or 403 alike. The
// metadata blob MUST NOT contain the ADMIN_PATH_PREFIX literal — the
// prefix is a secret and the audit_log row is operator-readable.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// auditApp builds a Fiber app mirroring the production admin chain order:
//
//	Fingerprint → AdminRateLimit → fake-auth → RequireAdmin → AdminAuditEmit → handler
//
// The fake-auth shim lets the test pin a JWT email + team_id on locals
// without spinning up real OAuth. callerEmail="" simulates an
// unauthenticated probe (RequireAdmin will reject with 403).
func auditApp(t *testing.T, db *sql.DB, prefix, callerEmail string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Use(func(c *fiber.Ctx) error {
		if callerEmail != "" {
			c.Locals(middleware.LocalKeyEmail, callerEmail)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	// No real Redis here — for the audit tests we don't drive the rate
	// limiter. nil Redis makes AdminRateLimit a no-op.
	//
	// AUDIT MUST RUN BEFORE RequireAdmin — production chain order. The
	// reason: RequireAdmin returns a 403 directly on rejection (no
	// c.Next), so middleware sitting AFTER it never runs on the
	// rejection path. Putting AdminAuditEmit BEFORE lets its internal
	// c.Next() drive the rest of the chain and observe the final status.
	//
	// Bind the middlewares to a route group rather than app.Use — Fiber's
	// route-param matching (c.Params("team_id")) is only populated for
	// middleware registered via Group, not for app-wide Use middleware
	// that runs before route matching.
	group := app.Group("/api/v1/"+prefix,
		middleware.AdminRateLimit(nil),
		middleware.AdminAuditEmit(db, prefix),
		middleware.RequireAdmin(),
	)
	group.Get("/customers/:team_id/tier", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	group.Get("/customers", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	return app
}

// readLatestAdminAccess returns the latest admin.access audit row in the
// platform DB, or fails the test if none exists. We scope by metadata's
// `email` field to disambiguate when multiple tests run against the
// shared TEST_DATABASE_URL.
func readLatestAdminAccess(t *testing.T, db *sql.DB, expectedEmail string) (status int, suffix, deniedBy string, raw string) {
	t.Helper()
	row := db.QueryRow(`
		SELECT metadata
		FROM audit_log
		WHERE kind = $1 AND metadata->>'email' = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, models.AuditKindAdminAccess, expectedEmail)
	var meta sql.NullString
	require.NoError(t, row.Scan(&meta))
	require.True(t, meta.Valid, "metadata column must be non-null")
	var m middleware.AdminAuditMetadata
	require.NoError(t, json.Unmarshal([]byte(meta.String), &m))
	return m.HTTPStatus, m.PathSuffix, m.DeniedBy, meta.String
}

// adminAuditCleanup deletes any admin.access rows the tests wrote so
// repeated runs against a shared TEST_DATABASE_URL don't pollute each
// other.
func adminAuditCleanup(t *testing.T, db *sql.DB, email string) {
	t.Helper()
	t.Cleanup(func() {
		db.Exec(`DELETE FROM audit_log WHERE kind = $1 AND metadata->>'email' = $2`,
			models.AuditKindAdminAccess, email)
	})
}

// TestAdminAuditEmit_Success_WritesRow — a successful admin request lands
// one admin.access audit row with the full metadata payload.
func TestAdminAuditEmit_Success_WritesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — requires TEST_DATABASE_URL")
	}
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	prefix := strings.Repeat("a", 32)
	email := "founder+success@instanode.dev"
	t.Setenv("ADMIN_EMAILS", email)
	adminAuditCleanup(t, db, email)

	app := auditApp(t, db, prefix, email)
	// audit_log.team_id has an FK to teams.id — seed a real team so the
	// insert lands cleanly. The admin route's :team_id param feeds the
	// audit middleware's team_id resolution.
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	t.Cleanup(func() {
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})
	path := "/api/v1/" + prefix + "/customers/" + teamID.String() + "/tier"

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 test-suite")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	status, suffix, deniedBy, raw := readLatestAdminAccess(t, db, email)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "customers/"+teamID.String()+"/tier", suffix,
		"path_suffix MUST be the URL with the secret prefix stripped — no leading slash")
	assert.Empty(t, deniedBy, "success row must have denied_by empty")
	// IRON RULE — the raw metadata blob must NEVER contain the prefix.
	assert.NotContains(t, raw, prefix,
		"the persisted metadata MUST NOT contain ADMIN_PATH_PREFIX — it's a secret")
}

// TestAdminAuditEmit_RateLimited_Writes403Row — even when the rate-limit
// middleware mutes the request, an admin.access row STILL gets written
// with http_status=403. This is the operator-visibility property: brute-
// force probes must appear in audit_log even though the response body
// claims "not an admin."
//
// We simulate the rate-limit path by setting the locals flag directly
// (avoids depending on real Redis + bucket exhaustion mechanics here —
// those are covered in admin_rate_limit_test.go). The audit middleware
// reads the flag and stamps denied_by="rate_limit" on the metadata.
func TestAdminAuditEmit_RateLimited_Writes403Row(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — requires TEST_DATABASE_URL")
	}
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	prefix := strings.Repeat("b", 32)
	email := "founder+ratelimited@instanode.dev"
	// Closed by default — empty ADMIN_EMAILS rejects every caller. But
	// we want to exercise the rate-limit branch, so wire the email in
	// AND inject the rate-limit-exceeded marker on locals upstream of
	// RequireAdmin. We emulate it with a custom mini-app.
	t.Setenv("ADMIN_EMAILS", email)
	adminAuditCleanup(t, db, email)

	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyEmail, email)
		c.Locals(middleware.LocalKeyAdminRateLimitExceeded, true)
		return c.Next()
	})
	// Audit middleware runs BEFORE the muted handler so its internal
	// c.Next() can observe the 403 status the handler writes. Bind via
	// Group so c.Params("team_id") is populated when the audit middleware
	// runs (app.Use middleware runs pre-route-match and sees empty Params).
	group := app.Group("/api/v1/"+prefix,
		middleware.AdminAuditEmit(db, prefix),
	)
	// Simulate the rate-limit-mute by short-circuiting to a 403 with the
	// canonical body — exactly what AdminRateLimit does. We intentionally
	// skip RequireAdmin here because in the real chain the limiter runs
	// FIRST and the email never reaches RequireAdmin. Route defines the
	// :team_id param so the audit middleware can resolve a FK-valid team.
	group.Get("/customers/:team_id/tier", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"ok":           false,
			"error":        "forbidden",
			"message":      "platform-admin access required",
			"agent_action": "Tell the user this endpoint requires platform-admin access. Ask contact@instanode.dev via https://instanode.dev/support if you think this is wrong.",
		})
	})

	// Seed a real team so audit_log FK validates. Probes against the real
	// admin endpoint would resolve the URL :team_id (which a brute-force
	// would supply as a guessed UUID — and the audit row needs that
	// :team_id to FK-validate, OR the row is skipped + a slog.Warn fires
	// to preserve operator visibility).
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	t.Cleanup(func() {
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})
	path := "/api/v1/" + prefix + "/customers/" + teamID.String() + "/tier"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	status, suffix, deniedBy, raw := readLatestAdminAccess(t, db, email)
	assert.Equal(t, http.StatusForbidden, status,
		"the audit row MUST record the 403, not silently downgrade to 200")
	assert.Equal(t, "customers/"+teamID.String()+"/tier", suffix)
	assert.Equal(t, "rate_limit", deniedBy,
		"the rate-limit branch MUST stamp denied_by=rate_limit on the audit metadata")
	assert.NotContains(t, raw, prefix,
		"the persisted metadata MUST NOT contain ADMIN_PATH_PREFIX — it's a secret")
}

// TestAdminAuditEmit_AllowlistMiss_Writes403WithReason — when RequireAdmin
// rejects a caller whose email isn't on the allowlist, the audit row
// records the 403 with denied_by="allowlist_miss".
func TestAdminAuditEmit_AllowlistMiss_Writes403WithReason(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — requires TEST_DATABASE_URL")
	}
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	prefix := strings.Repeat("c", 32)
	adminEmail := "founder@instanode.dev"
	probeEmail := "probe+allowlistmiss@example.com"
	t.Setenv("ADMIN_EMAILS", adminEmail)
	adminAuditCleanup(t, db, probeEmail)

	// callerEmail = probeEmail → RequireAdmin rejects (not on allowlist).
	app := auditApp(t, db, prefix, probeEmail)
	// Real team required for the FK on audit_log.team_id.
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	t.Cleanup(func() {
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})
	path := "/api/v1/" + prefix + "/customers/" + teamID.String() + "/tier"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	status, _, deniedBy, raw := readLatestAdminAccess(t, db, probeEmail)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "allowlist_miss", deniedBy)
	assert.NotContains(t, raw, prefix)
}

// TestAdminAuditMetadata_PathSuffixStripsPrefix — pure unit test on the
// helper that builds the suffix. We don't need a DB / Fiber app for this;
// the goal is to lock in the strip behavior so a future refactor can't
// silently start persisting the full path.
func TestAdminAuditMetadata_PathSuffixStripsPrefix(t *testing.T) {
	prefix := strings.Repeat("a", 32)
	cases := []struct {
		path     string
		expected string
	}{
		{"/api/v1/" + prefix + "/customers", "customers"},
		{"/api/v1/" + prefix + "/customers/00000000-0000-0000-0000-000000000000/tier",
			"customers/00000000-0000-0000-0000-000000000000/tier"},
		{"/api/v1/" + prefix, ""}, // bare prefix
		// Misconfigured strip: path doesn't start with the prefix template.
		{"/api/v1/admin/customers", "<INVALID>"},
		{"/api/v1/" + strings.Repeat("z", 32) + "/customers", "<INVALID>"},
	}
	for _, tc := range cases {
		got := middleware.AdminAuditPathSuffixForTest(tc.path, prefix)
		assert.Equal(t, tc.expected, got, "path=%q", tc.path)
		assert.NotContains(t, got, prefix,
			"the suffix MUST NOT contain the secret prefix")
	}
}

// TestAdminAuditEnsureMetadataNoPrefix — the prefix-leak grep that we
// expose for cross-package tests. Sanity-check it does what it says.
func TestAdminAuditEnsureMetadataNoPrefix(t *testing.T) {
	prefix := strings.Repeat("a", 32)
	clean := middleware.AdminAuditMetadata{
		Email:      "founder@instanode.dev",
		IP:         "10.0.0.1",
		PathSuffix: "customers/x/tier",
		HTTPStatus: 200,
	}
	assert.True(t, middleware.AdminAuditEnsureMetadataNoPrefix(clean, prefix))

	dirty := middleware.AdminAuditMetadata{
		Email:      "founder@instanode.dev",
		PathSuffix: "/api/v1/" + prefix + "/customers", // mistakenly stored full path
		HTTPStatus: 200,
	}
	assert.False(t, middleware.AdminAuditEnsureMetadataNoPrefix(dirty, prefix),
		"the assertion MUST flag a metadata blob carrying the prefix")
}
