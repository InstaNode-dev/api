package middleware_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/common/logctx"
	"instant.dev/internal/middleware"
)

// TestLoggerContext_CopiesRequestID asserts that LoggerContext lifts the
// request_id Fiber local — populated upstream by RequestID() — onto the
// Go ctx so any slog call downstream can read it via the logctx handler.
func TestLoggerContext_CopiesRequestID(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Use(middleware.LoggerContext())

	var seen string
	app.Get("/probe", func(c *fiber.Ctx) error {
		seen = logctx.TraceIDFromContext(c.UserContext())
		return c.SendStatus(fiber.StatusNoContent)
	})

	req := httptest.NewRequest("GET", "/probe", nil)
	req.Header.Set(middleware.HeaderRequestID, "fixed-id-123")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNoContent, resp.StatusCode)
	require.Equal(t, "fixed-id-123", seen, "LoggerContext must copy request_id into ctx via logctx.WithTraceID")
}

// TestLoggerContext_CopiesTeamID asserts that LoggerContext lifts the
// authenticated team_id Fiber local onto the Go ctx. We don't run real
// auth here — we synthesize the local the same way RequireAuth would.
func TestLoggerContext_CopiesTeamID(t *testing.T) {
	app := fiber.New()
	// Synthetic auth: write LocalKeyTeamID before LoggerContext runs.
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, "team-uuid-abc")
		return c.Next()
	})
	app.Use(middleware.LoggerContext())

	var seen string
	app.Get("/probe", func(c *fiber.Ctx) error {
		seen = logctx.TeamIDFromContext(c.UserContext())
		return c.SendStatus(fiber.StatusNoContent)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/probe", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNoContent, resp.StatusCode)
	require.Equal(t, "team-uuid-abc", seen, "LoggerContext must copy team_id into ctx via logctx.WithTeamID")
}

// TestLoggerContext_NoAuthLeavesTeamIDEmpty covers the anonymous /healthz
// path: the team local is never written so logctx.TeamID should be "".
func TestLoggerContext_NoAuthLeavesTeamIDEmpty(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Use(middleware.LoggerContext())

	var seen string
	app.Get("/probe", func(c *fiber.Ctx) error {
		seen = logctx.TeamIDFromContext(c.UserContext())
		return c.SendStatus(fiber.StatusNoContent)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/probe", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNoContent, resp.StatusCode)
	require.Equal(t, "", seen)
}
