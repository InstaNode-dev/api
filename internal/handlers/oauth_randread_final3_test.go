package handlers_test

// oauth_randread_final3_test.go — FINAL serial pass #3. Uses the randRead seam
// to drive the generateOAuthState / generateSessionID error arms in the
// browser OAuth-start handlers and the CLI create-session handler:
//   - GitHubStart  generateOAuthState error → renderAuthError 500   (auth.go:972)
//   - GoogleStart  generateOAuthState error → renderAuthError 500   (auth.go:1059)
//   - CreateCLISession generateSessionID error → 500                (cli_auth.go:83)

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func TestOAuthStartFinal3_RandReadError(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	restore := handlers.SetRandReadForTest(func([]byte) (int, error) {
		return 0, errors.New("forced rand error")
	})
	defer restore()

	t.Run("github_start", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/github/start", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("google_start", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/google/start", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// TestCreateCLISessionFinal3_RandReadError — randRead errors → generateSessionID
// fails inside CreateCLISession → 500 (cli_auth.go:83).
func TestCreateCLISessionFinal3_RandReadError(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	cfg := &config.Config{
		JWTSecret:        testhelpers.TestJWTSecret,
		AESKey:           testhelpers.TestAESKeyHex,
		DashboardBaseURL: "http://localhost:5173",
		Environment:      "test",
	}
	h := handlers.NewCLIAuthHandler(nil, rdb, cfg, plans.Default())
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Post("/auth/cli", h.CreateCLISession)

	restore := handlers.SetRandReadForTest(func([]byte) (int, error) {
		return 0, errors.New("forced rand error")
	})
	defer restore()

	req := httptest.NewRequest(http.MethodPost, "/auth/cli", nil)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
