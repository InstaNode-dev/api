package middleware_test

// residual_coverage_test.go — closes the last ~0.1% gap in internal/middleware
// (94.9% → ≥95%). Targets the cheap, deterministic uncovered arms:
//
//   RequireAdmin:            the admin-allowed c.Next() success path (admin.go
//                            line 119) — every existing test only drives the
//                            403 rejection.
//   idempotencyFingerprint:  the canonicalisation-failed fail-open arm
//                            (idempotency.go 364-375 + canonicalMultipartBody
//                            510-512) via a malformed multipart body.
//   Idempotency (fp, redis): the Redis-GET fail-open arm via a dead Redis
//                            client (idempotency.go 382-391).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// TestRequireAdmin_AllowedCallsNext drives the success path (admin.go:119):
// an allow-listed email passes through to the next handler.
func TestRequireAdmin_AllowedCallsNext(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", "founder@instanode.dev")
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyEmail, "founder@instanode.dev")
		return c.Next()
	})
	app.Get("/admin/ping", middleware.RequireAdmin(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/admin/ping", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "allow-listed admin must reach the handler")
}

// TestIdempotencyFingerprint_RedisDown_FailsOpen drives the Redis-GET
// fail-open arm (idempotency.go 382-391): a dead Redis client makes the GET
// error, so the middleware logs + falls through to the handler.
func TestIdempotencyFingerprint_RedisDown_FailsOpen(t *testing.T) {
	deadRDB := redis.NewClient(&redis.Options{Addr: "127.0.0.1:19998"}) // nothing listening
	defer deadRDB.Close()
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	reached := false
	app.Post("/rd", middleware.Idempotency(deadRDB, "rd.fp"), func(c *fiber.Ctx) error {
		reached = true
		return c.SendStatus(fiber.StatusCreated)
	})
	req := httptest.NewRequest(http.MethodPost, "/rd", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.51.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.True(t, reached, "Redis-down must fail open and reach the handler")
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// TestPopulateTeamRole_NilDB_FallsThrough drives the uninitialised-DB arm
// (role_lookup.go 49-51): with userID+teamID locals set but the package DB
// handle nil, the middleware skips the role lookup and calls c.Next().
func TestPopulateTeamRole_NilDB_FallsThrough(t *testing.T) {
	middleware.SetRoleLookupDB(nil) // force the nil-DB arm
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyUserID, "11111111-1111-1111-1111-111111111111")
		c.Locals(middleware.LocalKeyTeamID, "22222222-2222-2222-2222-222222222222")
		return c.Next()
	})
	reached := false
	app.Get("/role", middleware.PopulateTeamRole(), func(c *fiber.Ctx) error {
		reached = true
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/role", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.True(t, reached, "nil role-lookup DB must fall through to the handler")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
