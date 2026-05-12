package middleware_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// TestNewRelic_NilAppNoOps asserts the fail-open contract: when no
// license key is configured the agent init returns nil; the Fiber
// middleware must degrade to a transparent passthrough so the rest of
// the request pipeline runs unchanged.
func TestNewRelic_NilAppNoOps(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.NewRelic(nil))
	app.Get("/probe", func(c *fiber.Ctx) error {
		// GetNRTxn must return nil so handler code can safely test for
		// "agent disabled" without nil-deref'ing.
		require.Nil(t, middleware.GetNRTxn(c))
		return c.SendString("ok")
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/probe", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestRecordProvisionMetrics_NoOpWithoutApp asserts the metric helpers
// don't panic when no NR app has been registered. This is the fail-open
// contract handler code relies on — handlers can call
// RecordProvisionSuccess unconditionally.
func TestRecordProvisionMetrics_NoOpWithoutApp(t *testing.T) {
	// SetNRApp(nil) ensures we start from a known state regardless of
	// test ordering.
	middleware.SetNRApp(nil)

	require.NotPanics(t, func() {
		middleware.RecordProvisionSuccess("postgres")
		middleware.RecordProvisionFail("postgres", "quota")
		middleware.RecordResourceExpired("redis")
	})
}
