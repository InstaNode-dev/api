package router_test

// admin_path_prefix_test.go — pins the defense-in-depth contract for the
// founder-only customer-management surface.
//
// Two independent gates protect the surface:
//
//   1. ADMIN_PATH_PREFIX (this file): an unguessable 32+ char alphanumeric
//      URL segment. Empty/unset → routes are NOT registered (404 for every
//      caller). Set → routes register under /api/v1/<prefix>/customers/...
//      and the literal /api/v1/admin/customers returns 404.
//
//   2. ADMIN_EMAILS (covered separately in internal/handlers/admin_customers_test.go):
//      JWT email allowlist. Caller must be on the list. Closed by default.
//
// This file covers gate 1 in isolation — we don't drive the real Fiber router
// (which needs Postgres + Redis + gRPC), we exercise the prefix validator and
// a minimal route-registration shim that mirrors router.go's branch. The
// admin_customers_test.go file already covers the second gate end-to-end.
//
// What we're asserting:
//   1. config.ValidateAdminPathPrefix accepts empty (closed-by-default).
//   2. config.ValidateAdminPathPrefix rejects a < 32 char value.
//   3. config.ValidateAdminPathPrefix rejects any non-alphanumeric byte.
//   4. Empty prefix → admin routes are not registered (404 on
//      /api/v1/admin/customers, regardless of auth).
//   5. Valid 32-char alphanumeric prefix → routes register under
//      /api/v1/<prefix>/customers (mock handler returns 200) and the
//      legacy /api/v1/admin/customers path returns 404.

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
)

// ─── Validator unit tests ───────────────────────────────────────────────────

// TestValidateAdminPathPrefix_EmptyAccepted — closed-by-default. An empty
// or unset value MUST be allowed at the config layer (the router checks the
// emptiness flag and skips registration). Treating "empty" as a hard fatal
// would force every dev / CI environment to mint a real prefix even when
// the admin surface is not exercised.
func TestValidateAdminPathPrefix_EmptyAccepted(t *testing.T) {
	require.NoError(t, config.ValidateAdminPathPrefix(""))
}

// TestValidateAdminPathPrefix_RejectsShortPrefix — a < 32 char prefix is
// guessable with modest computation and provides only the illusion of
// obscurity. We refuse to start rather than silently accept it (a weak
// prefix is worse than none — it can convince an operator they're safe).
func TestValidateAdminPathPrefix_RejectsShortPrefix(t *testing.T) {
	cases := []string{
		"a",
		"abcdefghij",                   // 10 chars
		"abcdefghijklmnopqrstuvwxyz",   // 26 chars
		"0123456789012345678901234567", // 28 chars
		strings.Repeat("a", 31),        // 31 — one shy of the floor
	}
	for _, tc := range cases {
		err := config.ValidateAdminPathPrefix(tc)
		require.Error(t, err, "len=%d should be rejected", len(tc))
		assert.Contains(t, err.Error(), "ADMIN_PATH_PREFIX",
			"error must name the env var so the operator can find it")
		assert.Contains(t, err.Error(), "32",
			"error must state the minimum length so the operator knows the fix")
	}
}

// TestValidateAdminPathPrefix_RejectsNonAlphanumeric — the prefix is a URL
// segment. Bytes outside [A-Za-z0-9] can collide with Fiber's route parser,
// trigger percent-encoding inconsistencies between curl and the browser,
// or be confused with path-traversal attempts (../, etc.). Refusing them
// at startup keeps the surface predictable.
func TestValidateAdminPathPrefix_RejectsNonAlphanumeric(t *testing.T) {
	base := strings.Repeat("a", 32) // 32 alnum chars
	cases := []struct {
		name  string
		input string
	}{
		{"dash", base[:31] + "-"},
		{"slash", base[:31] + "/"},
		{"dot", base[:31] + "."},
		{"underscore", base[:31] + "_"},
		{"space", base[:31] + " "},
		{"percent", base[:31] + "%"},
		{"path_traversal_dotdot", strings.Repeat("a", 30) + ".."},
		{"unicode_em_dash", base[:29] + "—"}, // multi-byte: rejected on first non-ASCII byte
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := config.ValidateAdminPathPrefix(tc.input)
			require.Error(t, err, "%q should be rejected", tc.input)
			assert.Contains(t, err.Error(), "alphanumeric",
				"error must explain the constraint so the operator knows what to fix")
		})
	}
}

// TestValidateAdminPathPrefix_AcceptsValidPrefix — happy path: 32+ chars,
// alphanumeric only. We also try longer / mixed-case values because in
// production the canonical recipe is `openssl rand -hex 32` (64 lowercase
// hex) but operators are free to use any alnum string.
func TestValidateAdminPathPrefix_AcceptsValidPrefix(t *testing.T) {
	cases := []string{
		strings.Repeat("a", 32),                                              // minimum length
		strings.Repeat("Z", 32),                                              // uppercase
		"0123456789abcdef0123456789abcdef",                                   // 32-char hex
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64-char hex (openssl rand -hex 32)
		"MixedCase0123456789ABCDEFmixedcs",                                   // mixed case + digits
	}
	for _, tc := range cases {
		require.NoError(t, config.ValidateAdminPathPrefix(tc), "len=%d should pass", len(tc))
	}
}

// ─── Route-registration tests ───────────────────────────────────────────────

// adminProbeApp builds a Fiber app that mirrors the conditional registration
// branch in router.go's admin-routes block:
//
//	if cfg.AdminPathPrefix != "" {
//	    api.Group("/"+cfg.AdminPathPrefix, RequireAdmin).Get("/customers", ...)
//	}
//
// We can't drive the real router.New (it needs DB + Redis + gRPC), so we
// replicate the branch verbatim with a stub handler. RequireAdmin is left
// out: the goal of this file is to prove the prefix gate is doing its job,
// not to re-test the allowlist gate.
func adminProbeApp(prefix string) *fiber.App {
	app := fiber.New()
	api := app.Group("/api/v1")
	if prefix != "" {
		g := api.Group("/" + prefix)
		g.Get("/customers", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true, "from": "admin_stub"})
		})
		g.Get("/customers/:team_id", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true})
		})
		g.Post("/customers/:team_id/tier", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true})
		})
		g.Post("/customers/:team_id/promo", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true})
		})
	}
	return app
}

// TestAdminRoutes_NotRegisteredWhenPrefixEmpty — closed-by-default. With
// ADMIN_PATH_PREFIX unset, the admin endpoints must not exist on the wire.
// /api/v1/admin/customers must 404 — the very name of the surface stops
// being a valid route. Drive-by scanners get no signal.
//
// This is the key invariant the path-prefix gate adds on top of the
// existing allowlist gate: even an attacker holding a leaked admin session
// token cannot reach the surface if they don't know the prefix.
func TestAdminRoutes_NotRegisteredWhenPrefixEmpty(t *testing.T) {
	app := adminProbeApp("")
	paths := []string{
		"/api/v1/admin/customers",
		"/api/v1/admin/customers/00000000-0000-0000-0000-000000000000",
	}
	for _, p := range paths {
		req := httptest.NewRequest("GET", p, nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNotFound, resp.StatusCode,
			"%s must 404 when ADMIN_PATH_PREFIX is empty (closed-by-default)", p)
	}
}

// TestAdminRoutes_RegisteredUnderPrefixWhenSet — valid 32+ char prefix.
// Routes register under /api/v1/<prefix>/customers/...; literal
// /api/v1/admin/customers stops being a valid path and returns 404.
func TestAdminRoutes_RegisteredUnderPrefixWhenSet(t *testing.T) {
	prefix := strings.Repeat("a", 32)
	require.NoError(t, config.ValidateAdminPathPrefix(prefix))

	app := adminProbeApp(prefix)

	// Hit the real prefix → 200.
	req := httptest.NewRequest("GET", "/api/v1/"+prefix+"/customers", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode,
		"GET /api/v1/<prefix>/customers must reach the handler")

	// Hit the legacy guessable path → 404. The defense-in-depth invariant.
	req = httptest.NewRequest("GET", "/api/v1/admin/customers", nil)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode,
		"GET /api/v1/admin/customers must 404 — the path itself must not be a hint")
}

// TestAdminRoutes_LegacyPathAlwaysHidden — even if a malicious operator
// were tempted to set ADMIN_PATH_PREFIX="admin" (which is rejected by the
// validator anyway because len < 32), the contract is that
// /api/v1/admin/customers must never be the live route. We assert this
// indirectly: the validator rejects "admin" outright, so the dangerous
// configuration can't be reached.
func TestAdminRoutes_LegacyPathAlwaysHidden(t *testing.T) {
	err := config.ValidateAdminPathPrefix("admin")
	require.Error(t, err, "the literal string 'admin' must be rejected by length validation")
}
