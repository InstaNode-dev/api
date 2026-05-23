package handlers_test

// purefuncs_arms_final3_test.go — FINAL serial pass #3. Pure-function branch
// arms reachable without DB/network:
//   - newAgentActionDeploymentLimitReached: all three tier branches
//     (hobby / hobby_plus / pro-default)                          (agent_action.go:124-138)
//   - requireName + sanitizeNameForRequest: the invalid-UTF-8 arms
//     via a name carrying a raw invalid UTF-8 byte                (provision_helper.go)

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
)

func TestAgentActionDeploymentLimitFinal3_AllTierBranches(t *testing.T) {
	hobby := handlers.NewAgentActionDeploymentLimitReachedForTest("hobby", 1)
	assert.Contains(t, hobby, "Hobby Plus")
	hobbyPlus := handlers.NewAgentActionDeploymentLimitReachedForTest("hobby_plus", 2)
	assert.Contains(t, hobbyPlus, "Pro")
	pro := handlers.NewAgentActionDeploymentLimitReachedForTest("pro", 10)
	assert.Contains(t, pro, "Pro")
	// free / anonymous share the first arm.
	free := handlers.NewAgentActionDeploymentLimitReachedForTest("free", 0)
	assert.Contains(t, free, "Hobby Plus")
}

// invalidUTF8Name is a string with a lone continuation byte — not valid UTF-8.
const invalidUTF8Name = "bad\xffname"

func TestRequireNameFinal3_InvalidUTF8(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			return c.SendStatus(http.StatusTeapot)
		},
	})
	app.Get("/rn", func(c *fiber.Ctx) error {
		_, err := handlers.RequireNameForTest(c, invalidUTF8Name)
		if err != nil {
			return err
		}
		return c.SendString("ok")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/rn", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSanitizeNameForRequestFinal3_InvalidUTF8(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			return c.SendStatus(http.StatusTeapot)
		},
	})
	app.Get("/sn", func(c *fiber.Ctx) error {
		_, err := handlers.SanitizeNameForRequestForTest(c, invalidUTF8Name)
		if err != nil {
			return err
		}
		return c.SendString("ok")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/sn", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
