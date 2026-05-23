package handlers_test

// respond_provision_failed_final3_test.go — FINAL serial pass #3. Drives both
// arms of respondProvisionFailed (helpers.go):
//   - circuit.ErrOpen → 503 provisioner_unavailable
//   - any other error → 503 provision_failed (fallback)

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/circuit"
	"instant.dev/internal/handlers"
)

func respondProvisionFailedApp(t *testing.T, err error) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			return c.SendStatus(http.StatusTeapot)
		},
	})
	app.Get("/p", func(c *fiber.Ctx) error {
		return handlers.RespondProvisionFailedForTest(c, err, "fallback message")
	})
	return app
}

// TestRespondProvisionFailedFinal3_CircuitOpen — circuit.ErrOpen →
// provisioner_unavailable 503.
func TestRespondProvisionFailedFinal3_CircuitOpen(t *testing.T) {
	app := respondProvisionFailedApp(t, circuit.ErrOpen)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/p", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provisioner_unavailable", decodeErrCode(t, resp))
}

// TestRespondProvisionFailedFinal3_Generic — a non-circuit error →
// provision_failed 503 (fallback arm).
func TestRespondProvisionFailedFinal3_Generic(t *testing.T) {
	app := respondProvisionFailedApp(t, errors.New("boom"))
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/p", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", decodeErrCode(t, resp))
}
