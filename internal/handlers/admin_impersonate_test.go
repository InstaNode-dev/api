package handlers_test

// admin_impersonate_test.go — integration coverage for
// POST /api/v1/admin/customers/:team_id/impersonate.
//
// What we assert:
//   1. Endpoint mints a JWT carrying read_only=true + impersonated_by=<admin email>.
//   2. JWT's exp is ~10min in the future.
//   3. Endpoint writes an audit_log row with kind=admin.impersonation_started.
//   4. Non-admin caller → 403 (RequireAdmin).
//   5. Impersonated session can hit a GET-style RequireAuth-gated handler.
//   6. Impersonated session POST → 403 (RequireWritable).
//   7. Real session POST → 200 (regression — gate must be no-op for normal sessions).
//   8. Token expires after 10min (jwt.ParseWithClaims rejects an expired token).
//
// Test rig:
//   - The mint endpoint sits behind RequireAdmin → uses adminAppWithImpersonate
//     which wires RequireAuth-less but admin-emailed fake auth (same shim as
//     adminApp).
//   - To exercise the read-only enforcement (tests 5/6/7) we need a *real*
//     RequireAuth → RequireWritable chain because the gate reads the JWT,
//     not the fake-auth locals. The chain is built in
//     impersonateGuardedApp(), using the same JWT_SECRET test helper.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// adminAppWithImpersonate builds a Fiber app wired to the
// AdminImpersonateHandler behind the same fake-auth + RequireAdmin chain
// adminApp() uses. The fake auth pins the caller's email so RequireAdmin
// can read it against ADMIN_EMAILS.
func adminAppWithImpersonate(t *testing.T, db *sql.DB, callerEmail string) *fiber.App {
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

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	fakeAuth := func(c *fiber.Ctx) error {
		if callerEmail != "" {
			c.Locals(middleware.LocalKeyEmail, callerEmail)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	}

	impH := handlers.NewAdminImpersonateHandler(db, cfg)
	adminGroup := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	adminGroup.Post("/customers/:team_id/impersonate", impH.Impersonate)
	return app
}

// impersonateGuardedApp builds a tiny Fiber app with the real
// RequireAuth → RequireWritable chain installed and one GET + one POST
// route so we can drive the read-only enforcement end-to-end (test 5/6/7).
func impersonateGuardedApp() *fiber.App {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	app := fiber.New()
	app.Use(middleware.RequireAuth(cfg))
	app.Use(middleware.RequireWritable())
	app.Get("/probe", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"ok":              true,
			"read_only":       middleware.IsReadOnly(c),
			"impersonated_by": middleware.GetImpersonatedBy(c),
		})
	})
	app.Post("/mutate", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	return app
}

// extractToken pulls the `token` field out of an Impersonate response.
func extractToken(t *testing.T, resp map[string]any) string {
	t.Helper()
	tok, _ := resp["token"].(string)
	require.NotEmpty(t, tok, "response must carry token: %v", resp)
	return tok
}

// parseClaimsAllowExpired parses a JWT into a map without enforcing exp.
// Used by the expiry-test which needs to inspect the exp claim of an
// already-expired token. ParseUnverified skips signature + exp checks.
func parseClaimsAllowExpired(t *testing.T, signed string) map[string]any {
	t.Helper()
	parsed, _, err := new(jwt.Parser).ParseUnverified(signed, jwt.MapClaims{})
	require.NoError(t, err)
	mc, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return mc
}

// TestImpersonate_MintsReadOnlyToken_WithImpersonatedByClaim is the
// headline assertion: the minted JWT carries read_only=true and
// impersonated_by=<admin email>. Both are required for the
// RequireWritable / /auth/me consumers downstream.
func TestImpersonate_MintsReadOnlyToken_WithImpersonatedByClaim(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "pro")

	status, resp := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/impersonate", nil)
	require.Equal(t, http.StatusOK, status, "mint must succeed: %v", resp)
	tok := extractToken(t, resp)
	assert.Equal(t, teamID.String(), resp["team_id"])

	// Parse the minted JWT and assert the two impersonation claims.
	claims := parseClaimsAllowExpired(t, tok)
	assert.Equal(t, true, claims["read_only"],
		"minted token must carry read_only=true")
	assert.Equal(t, adminCallerEmail, claims["impersonated_by"],
		"minted token must carry impersonated_by=<admin email>")
	assert.Equal(t, teamID.String(), claims["tid"],
		"minted token's tid must match the target team")
}

// TestImpersonate_TokenExpiresIn10Minutes asserts the JWT's exp claim is
// approximately impersonationTokenTTL (10 min) in the future. The exact
// nanosecond offset is irrelevant — we just need confidence that the TTL
// constant flowed through to the wire (regression: a 0-second TTL would
// give an immediately-expired token).
func TestImpersonate_TokenExpiresIn10Minutes(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "pro")
	mintedAt := time.Now()

	_, resp := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/impersonate", nil)
	tok := extractToken(t, resp)
	expiresAtStr, _ := resp["expires_at"].(string)
	require.NotEmpty(t, expiresAtStr, "response must carry expires_at")
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtStr)
	require.NoError(t, err)

	delta := expiresAt.Sub(mintedAt)
	assert.True(t, delta > 9*time.Minute && delta < 11*time.Minute,
		"exp must be ~10min from mint time (got %v)", delta)

	// Cross-check the JWT's own exp claim against the response field.
	claims := parseClaimsAllowExpired(t, tok)
	expFloat, _ := claims["exp"].(float64)
	require.NotZero(t, expFloat, "JWT must carry exp claim")
	assert.InDelta(t, expiresAt.Unix(), int64(expFloat), 2,
		"JWT exp claim and response expires_at must match within 2s")
}

// TestImpersonate_WritesAuditRow_StartedKind — every issuance must record
// an audit_log row so a future investigation can answer "who viewed which
// customer, when, for how long" without parsing JWTs after the fact.
func TestImpersonate_WritesAuditRow_StartedKind(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "pro")

	status, _ := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/impersonate", nil)
	require.Equal(t, http.StatusOK, status)

	var (
		kind, summary string
		metaRaw       sql.NullString
	)
	err := db.QueryRowContext(context.Background(), `
		SELECT kind, summary, metadata::text
		FROM audit_log
		WHERE team_id = $1 AND kind = $2
		ORDER BY created_at DESC LIMIT 1
	`, teamID, handlers.AuditKindAdminImpersonationStarted).Scan(&kind, &summary, &metaRaw)
	require.NoError(t, err, "audit row with kind=admin.impersonation_started must exist for team")
	assert.Equal(t, handlers.AuditKindAdminImpersonationStarted, kind)

	require.True(t, metaRaw.Valid)
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(metaRaw.String), &meta))
	assert.Equal(t, adminCallerEmail, meta["by_admin_email"])
	assert.Equal(t, teamID.String(), meta["target_team_id"])
	assert.Equal(t, float64(int(10*time.Minute/time.Second)), meta["ttl_seconds"])
}

// TestImpersonate_NonAdmin_403 — the impersonation route is RequireAdmin-
// gated like the rest of the admin surface. A non-admin caller must 403
// BEFORE the mint runs.
func TestImpersonate_NonAdmin_403(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminNonAdminEmail)

	teamID, _ := adminSeedTeam(t, db, "pro")
	status, body := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/impersonate", nil)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "forbidden", body["error"])
}

// TestImpersonate_UnknownTeam_404 — non-existent target team id must 404
// at the precheck, before any user lookup or token mint.
func TestImpersonate_UnknownTeam_404(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminCallerEmail)

	status, body := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+uuid.NewString()+"/impersonate", nil)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "team_not_found", body["error"])
}

// TestImpersonate_TeamWithNoUsers_409 — minting a token for a team that
// has zero users on file is technically valid but useless; we 409 rather
// than silently mint a token tied to a nil uid (which RequireAuth would
// reject downstream anyway, producing a confusing 401 for the admin).
func TestImpersonate_TeamWithNoUsers_409(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminCallerEmail)

	// Create a bare team row with no users.
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	t.Cleanup(func() {
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})

	status, body := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/impersonate", nil)
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "team_has_no_users", body["error"])
}

// TestImpersonate_TokenCanCallGetEndpoint — the minted token must pass
// RequireAuth and reach a GET handler. Verifies the JWT is signed with
// the same secret RequireAuth validates against, and that the read_only
// flag does NOT block GETs.
func TestImpersonate_TokenCanCallGetEndpoint(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "pro")
	_, resp := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/impersonate", nil)
	tok := extractToken(t, resp)

	// Hit a GET behind RequireAuth + RequireWritable. The chain must let
	// us through and the probe handler must see read_only=true.
	guarded := impersonateGuardedApp()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	got, err := guarded.Test(req, 5000)
	require.NoError(t, err)
	defer got.Body.Close()
	assert.Equal(t, http.StatusOK, got.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(got.Body).Decode(&body))
	assert.Equal(t, true, body["read_only"],
		"GET handler must see read_only=true on the impersonated session")
	assert.Equal(t, adminCallerEmail, body["impersonated_by"],
		"GET handler must see the admin email from the impersonation token")
}

// TestImpersonate_TokenCannotPOST — the minted token's read_only flag
// MUST cause RequireWritable to 403 every POST/PUT/PATCH/DELETE. This is
// the headline regression test for the "view-as-customer" invariant.
//
// Also asserts the response carries the canonical agent_action string so
// the U3 contract holds end-to-end (mint → middleware → response body).
func TestImpersonate_TokenCannotPOST(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppWithImpersonate(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "pro")
	_, resp := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/impersonate", nil)
	tok := extractToken(t, resp)

	guarded := impersonateGuardedApp()
	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	got, err := guarded.Test(req, 5000)
	require.NoError(t, err)
	defer got.Body.Close()
	assert.Equal(t, http.StatusForbidden, got.StatusCode,
		"POST under impersonated session must 403 via RequireWritable")

	var body map[string]any
	require.NoError(t, json.NewDecoder(got.Body).Decode(&body))
	assert.Equal(t, "read_only_session", body["error"],
		"error code must be the distinct read_only_session keyword")
	aa, _ := body["agent_action"].(string)
	assert.Contains(t, aa, "read-only impersonated session",
		"agent_action must name the specific rejection reason")
	assert.Contains(t, aa, "https://instanode.dev/app",
		"agent_action must contain a full https URL")
}

// TestImpersonate_RealSessionPOST_StillWorks — regression: a normal
// (non-impersonated) session must still be able to POST after this
// middleware lands. The gate is a no-op for tokens without read_only=true,
// and this test pins that invariant.
func TestImpersonate_RealSessionPOST_StillWorks(t *testing.T) {
	tok := testhelpers.MustSignSessionJWT(t, uuid.NewString(), uuid.NewString(), "real@example.com")

	guarded := impersonateGuardedApp()
	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	got, err := guarded.Test(req, 5000)
	require.NoError(t, err)
	defer got.Body.Close()
	assert.Equal(t, http.StatusOK, got.StatusCode,
		"a real (non-impersonated) session must still be allowed to POST — RequireWritable must be a no-op for read_only=false tokens")
}

// TestImpersonate_TokenExpires_RejectedByAuth — an expired impersonation
// token must be rejected by RequireAuth (401), NOT silently accepted as
// read-only. Mints a token via the real handler, hand-rewrites its exp to
// the past, and asserts RequireAuth's 401 path fires.
//
// We don't sleep 10 minutes — instead we mint a token with a manually
// crafted exp claim via the test's local jwt-signing helper, signed with
// the same secret, and verify it's rejected. This is a defensive check
// because the impersonation TTL is short by design and a regression that
// neutered the exp claim would be invisible at normal request rates.
func TestImpersonate_TokenExpires_RejectedByAuth(t *testing.T) {
	// Build a JWT identical in shape to what AdminImpersonateHandler
	// emits, but with exp = 1 hour in the past. RequireAuth must reject.
	type impersonateClaims struct {
		UserID         string `json:"uid"`
		TeamID         string `json:"tid"`
		Email          string `json:"email"`
		ReadOnly       bool   `json:"read_only"`
		ImpersonatedBy string `json:"impersonated_by"`
		jwt.RegisteredClaims
	}
	expired := time.Now().Add(-1 * time.Hour)
	claims := impersonateClaims{
		UserID:         uuid.NewString(),
		TeamID:         uuid.NewString(),
		Email:          "target@example.com",
		ReadOnly:       true,
		ImpersonatedBy: adminCallerEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(expired.Add(-10 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(expired),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)

	guarded := impersonateGuardedApp()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	got, err := guarded.Test(req, 5000)
	require.NoError(t, err)
	defer got.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, got.StatusCode,
		"expired impersonation token must be rejected by RequireAuth (401), NOT silently accepted as read-only")
}
