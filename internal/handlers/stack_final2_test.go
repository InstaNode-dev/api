package handlers_test

// stack_final2_test.go — FINAL SERIAL PASS #2 coverage for the mid-handler
// DB-error arms of stack.go's UpdateEnv / Get / Family handlers that the
// happy-path + closed-DB suites leave uncovered. The closed-DB suite fails the
// FIRST query (team lookup); these arms only run when an EARLY query succeeds
// and a LATER one errors, so we seed a team-owned stack on the pooled DB and
// run the handler over a fault DB sharing the same postgres DSN.
//
//   * UpdateEnv GetStackEnvVars error → fetch_failed   (stack.go L1185-1188, failAfter=2)
//   * UpdateEnv UpdateStackEnvVars error → persist_failed (L1216-1219, failAfter=3)
//   * Family GetStackBySlug error → fetch_failed         (L1885, failAfter=1)

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func stackFaultApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:                      testhelpers.TestJWTSecret,
		AESKey:                         testhelpers.TestAESKeyHex,
		ComputeProvider:                "noop",
		DeletionConfirmationTTLMinutes: 30,
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	sh.SetEmailClient(email.NewNoop())
	app.Use(middleware.RequestID())
	app.Patch("/stacks/:slug/env", middleware.RequireAuth(cfg), sh.UpdateEnv)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/stacks/:slug/family", sh.Family)
	return app
}

func stackNeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

func patchStackEnvF2(t *testing.T, app *fiber.App, slug, jwt, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var raw [2048]byte
	n, _ := resp.Body.Read(raw[:])
	return resp.StatusCode, string(raw[:n])
}

func TestStackFinal2_UpdateEnv_FetchEnvFailed(t *testing.T) {
	stackNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, seedDB, &teamID, "healthy")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stkf2@example.com")

	// team(1)+GetStackBySlug(2) ok, GetStackEnvVars(3) errors.
	app := stackFaultApp(t, openFaultDB(t, 2))
	status, body := patchStackEnvF2(t, app, slug, jwt, `{"env":{"FOO":"bar"}}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "fetch_failed")
}

func TestStackFinal2_UpdateEnv_PersistFailed(t *testing.T) {
	stackNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, seedDB, &teamID, "healthy")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stkf2@example.com")

	// team(1)+slug(2)+GetStackEnvVars(3) ok, UpdateStackEnvVars(4) errors.
	app := stackFaultApp(t, openFaultDB(t, 3))
	status, body := patchStackEnvF2(t, app, slug, jwt, `{"env":{"FOO":"bar"}}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "persist_failed")
}

// Family GetStackBySlug errors (non-NotFound) → fetch_failed 503. failAfter=1
// (team lookup ok, the slug lookup errors).
func TestStackFinal2_Family_FetchFailed(t *testing.T) {
	stackNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stkf2@example.com")

	app := stackFaultApp(t, openFaultDB(t, 1))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks/some-slug/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
