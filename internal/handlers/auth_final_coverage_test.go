package handlers_test

// auth_final_coverage_test.go — final push to ≥95% on auth.go / cli_auth.go /
// magic_link.go. Targets the last reachable branches:
//   * CLI PollSession missing-id (400) + broken-redis fail-open (202).
//   * CLI CreateSession redis-set failure (500).
//   * CLI GetCurrentUser: bad-team-id / bad-user-id (401) + db_error (503) +
//     impersonation (read_only + impersonated_by).
//   * magic-link Start: CreateMagicLink DB error (202) + checkEmailRateLimit
//     nil-rdb short-circuit.
//   * magic-link Callback: set-verified-already + upsert-failure success paths.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// brokenRedis returns a client pointed at a dead address (fast timeouts).
func brokenRedis(t *testing.T) *redis.Client {
	t.Helper()
	c := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
		ReadTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func cliErrApp(h *handlers.CLIAuthHandler) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Post("/auth/cli", h.CreateCLISession)
	app.Get("/auth/cli/:id", h.PollCLISession)
	return app
}

// PollSession with a "%20"-only id is non-empty; the empty-id 400 branch is
// reached by routing a blank segment. Fiber routes /auth/cli/ to a 404, so we
// hit the empty-id branch by registering a route that yields an empty :id.
func TestCLI_PollSession_MissingIDBranch(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, Environment: "test"}
	h := handlers.NewCLIAuthHandler(nil, brokenRedis(t), cfg, plans.Default())

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	app.Use(middleware.RequestID())
	// Register a wildcard so an empty trailing segment still dispatches to the
	// handler with an empty :id param.
	app.Get("/poll/:id?", h.PollCLISession)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/poll/", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Broken Redis on Poll → fail-open 202.
func TestCLI_PollSession_BrokenRedisFailOpen(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, Environment: "test"}
	h := handlers.NewCLIAuthHandler(nil, brokenRedis(t), cfg, plans.Default())
	app := cliErrApp(h)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/auth/cli/some-id", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// Broken Redis on CreateSession → redis-set failure → 500.
func TestCLI_CreateSession_RedisSetFailure(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, Environment: "test", DashboardBaseURL: "http://localhost:5173"}
	h := handlers.NewCLIAuthHandler(nil, brokenRedis(t), cfg, plans.Default())
	app := cliErrApp(h)

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/auth/cli", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// --- GetCurrentUser unauthorized + db_error + impersonation ---

func meAppFor(t *testing.T, cfg *config.Config, h *handlers.CLIAuthHandler) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Get("/auth/me", middleware.RequireAuth(cfg), h.GetCurrentUser)
	return app
}

// signMe mints a session JWT with optional read_only/impersonated_by claims.
func signMe(t *testing.T, userID, teamID, email, impersonatedBy string) string {
	t.Helper()
	type cl struct {
		UserID         string `json:"uid"`
		TeamID         string `json:"tid"`
		Email          string `json:"email"`
		ReadOnly       bool   `json:"read_only,omitempty"`
		ImpersonatedBy string `json:"impersonated_by,omitempty"`
		jwt.RegisteredClaims
	}
	c := cl{
		UserID: userID, TeamID: teamID, Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}
	if impersonatedBy != "" {
		c.ReadOnly = true
		c.ImpersonatedBy = impersonatedBy
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	s, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)
	return s
}

func TestCLI_GetCurrentUser_BadTeamIDUnauthorized(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, Environment: "test"}
	h := handlers.NewCLIAuthHandler(nil, brokenRedis(t), cfg, plans.Default())
	app := meAppFor(t, cfg, h)

	// team id is a non-UUID string → uuid.Parse fails → 401.
	tok := signMe(t, uuid.NewString(), "not-a-uuid", "u@example.com", "")
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// GetCurrentUser mounted WITHOUT RequireAuth → middleware.GetUserID returns ""
// → the unauthorized-no-uid guard (cli_auth.go) fires with 401.
func TestCLI_GetCurrentUser_NoAuthContextUnauthorized(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, Environment: "test"}
	h := handlers.NewCLIAuthHandler(nil, brokenRedis(t), cfg, plans.Default())

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	app.Use(middleware.RequestID())
	// No RequireAuth → no uid in locals.
	app.Get("/auth/me", h.GetCurrentUser)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/auth/me", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestCLI_GetCurrentUser_DBErrorAndBadUserID(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, Environment: "test"}

	// db_error on team lookup: closed DB.
	bh := handlers.NewCLIAuthHandler(brokenDB(t), brokenRedis(t), cfg, plans.Default())
	bapp := meAppFor(t, cfg, bh)
	tok := signMe(t, uuid.NewString(), uuid.NewString(), "u@example.com", "")
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := bapp.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	// bad user-id: real team exists, but uid is not a UUID → 401 after team OK.
	h := handlers.NewCLIAuthHandler(db, brokenRedis(t), cfg, plans.Default())
	app := meAppFor(t, cfg, h)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	tok2 := signMe(t, "not-a-uuid", teamID, "u@example.com", "")
	req2 := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req2.Header.Set("Authorization", "Bearer "+tok2)
	resp2, err := app.Test(req2, 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestCLI_GetCurrentUser_Impersonation(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, Environment: "test"}
	h := handlers.NewCLIAuthHandler(db, brokenRedis(t), cfg, plans.Default())
	app := meAppFor(t, cfg, h)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))

	tok := signMe(t, userID, teamID, email, "admin@instanode.dev")
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := readJSON(t, resp)
	assert.Equal(t, true, body["read_only"])
	assert.Equal(t, "admin@instanode.dev", body["impersonated_by"])
}

// --- magic-link Start CreateMagicLink DB error ---

func TestMagicLink_Start_CreateMagicLinkDBError(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	bdb := brokenDB(t)
	authH := handlers.NewAuthHandler(bdb, cfg)
	// nil rdb → checkEmailRateLimit short-circuits (nil-rdb branch), then the
	// closed DB makes CreateMagicLink error → still 202.
	mlH := handlers.NewMagicLinkHandlerWithMailerAndRedis(bdb, cfg, failingMailer{}, authH, nil)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	app.Use(middleware.RequestID())
	app.Post("/auth/email/start", mlH.Start)

	req := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader(`{"email":"new@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// --- magic-link Callback success when the user is already verified ---
// (covers the "already verified → skip SetEmailVerified" branch of Callback)

func TestMagicLink_Callback_AlreadyVerifiedUser(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	authH := handlers.NewAuthHandler(db, cfg)

	// Pre-create a verified user so the Callback's verified branch is taken.
	email := testhelpers.UniqueEmail(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email, email_verified) VALUES ($1::uuid, $2, true)`, teamID, email)
	require.NoError(t, err)

	mailer := &capturingMailer{}
	mlH := handlers.NewMagicLinkHandlerWithMailerAndRedis(db, cfg, mailer, authH, rdb)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	app.Use(middleware.RequestID())
	app.Post("/auth/email/start", mlH.Start)
	app.Get("/auth/email/callback", mlH.Callback)

	startReq := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader(`{"email":"`+email+`","return_to":"https://instanode.dev/x"}`))
	startReq.Header.Set("Content-Type", "application/json")
	sresp, err := app.Test(startReq, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, sresp.StatusCode)
	sresp.Body.Close()
	require.Equal(t, 1, mailer.calls)

	idx := strings.Index(mailer.link, "?t=")
	require.Greater(t, idx, -1)
	plaintext := mailer.link[idx+3:]

	cb := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t="+plaintext, nil)
	resp, err := app.Test(cb, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	// 2026-05-29 AUTH-004: the session JWT is now set in a Secure
	// HttpOnly SameSite=Lax cookie; the Location header carries only a
	// non-secret ?signed_in=1 marker so the dashboard SPA knows to call
	// /auth/me. The full session-leak rationale lives on the AUTH-004
	// regression test in auth_callback_nojwt_authp0_test.go.
	loc := resp.Header.Get("Location")
	assert.NotContains(t, loc, "session_token=", "AUTH-004: JWT must not appear in Location")
	assert.Contains(t, loc, "signed_in=1")
	assert.Contains(t, strings.Join(resp.Header.Values("Set-Cookie"), "\n"), "instanode_session_exchange=",
		"AUTH-004: session JWT must be set as the instanode_session cookie")
}

// capturingMailer records the magic link so the callback test can replay it.
type capturingMailer struct {
	calls int
	link  string
}

func (m *capturingMailer) SendMagicLink(ctx context.Context, to, link string) error {
	m.calls++
	m.link = link
	return nil
}

func readJSON(t *testing.T, resp *http.Response) (map[string]any, error) {
	t.Helper()
	var m map[string]any
	err := json.NewDecoder(resp.Body).Decode(&m)
	return m, err
}
