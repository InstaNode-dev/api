package handlers_test

// magic_link_extra_test.go — handlers_test (external) coverage that
// requires the full test-DB rig (and therefore can't live in the
// internal `package handlers` file).
//
// Drives:
//   * Start happy-path with a real DB → 202 + magic_links row visible
//   * Start callback with missing/invalid token → renders auth_error
//   * Start fail-open when Redis is broken (DB ok)

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// stubMailer records the most recent (to, link) so the happy-path test
// can verify the handler actually invoked it.
type stubMailer struct {
	to, link string
	calls    int
	nextErr  error
}

func (s *stubMailer) SendMagicLink(ctx context.Context, to, link string) error {
	s.calls++
	s.to = to
	s.link = link
	return s.nextErr
}

// mlExtraApp wires Start onto a Fiber app with the production-style
// ErrorHandler so respondError sentinel reaches the response.
func mlExtraApp(t *testing.T, db *sql.DB, rdb *redis.Client, mailer *stubMailer) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret,
		AESKey:    testhelpers.TestAESKeyHex,
	}
	authH := handlers.NewAuthHandler(db, cfg)
	mlH := handlers.NewMagicLinkHandlerWithMailerAndRedis(db, cfg, mailer, authH, rdb)
	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
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
	app.Post("/auth/email/start", mlH.Start)
	app.Get("/auth/email/callback", mlH.Callback)
	return app
}

func TestMagicLinkStart_HappyPath_InsertsRow(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	mailer := &stubMailer{}
	app := mlExtraApp(t, db, rdb, mailer)

	emailAddr := testhelpers.UniqueEmail(t)
	body := fmt.Sprintf(`{"email":%q,"return_to":"https://instanode.dev/dashboard"}`, emailAddr)
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusAccepted, resp.StatusCode)

	// The mailer must have been invoked exactly once with the requested email.
	assert.Equal(t, 1, mailer.calls)
	assert.Equal(t, emailAddr, mailer.to)
	assert.Contains(t, mailer.link, "/auth/email/callback?t=")

	// And the DB row must exist (the persistence path lands inside Start).
	var found int
	err = db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM magic_links WHERE email = $1`, emailAddr).Scan(&found)
	require.NoError(t, err)
	assert.Equal(t, 1, found, "magic_links row must be inserted")
}

func TestMagicLinkStart_FailOpenOnBrokenRedis(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	rdbBroken := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
		ReadTimeout: 50 * time.Millisecond,
	})
	defer rdbBroken.Close()

	mailer := &stubMailer{}
	app := mlExtraApp(t, db, rdbBroken, mailer)

	emailAddr := testhelpers.UniqueEmail(t)
	body := fmt.Sprintf(`{"email":%q}`, emailAddr)
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Even with broken Redis, the enumeration-defence contract says 202.
	assert.Equal(t, fiber.StatusAccepted, resp.StatusCode)
	assert.Equal(t, 1, mailer.calls, "fail-open path still invokes the mailer")
}

func TestMagicLinkCallback_MissingTokenReturns400HTML(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	mailer := &stubMailer{}
	app := mlExtraApp(t, db, rdb, mailer)

	req := httptest.NewRequest(http.MethodGet, "/auth/email/callback", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	// renderAuthError produces text/html — assert the content-type.
	ct := resp.Header.Get("Content-Type")
	assert.Contains(t, ct, "text/html")
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyBytes), "Sign-in link is missing")
}

func TestMagicLinkCallback_InvalidTokenReturns400HTML(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	mailer := &stubMailer{}
	app := mlExtraApp(t, db, rdb, mailer)

	// A random plaintext that has no matching row.
	req := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t=not-a-real-token", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	ct := resp.Header.Get("Content-Type")
	assert.Contains(t, ct, "text/html")
}

// TestMagicLinkCallback_HappyPath_ConsumesAndRedirects walks the full
// success flow: Start inserts a row, we extract the plaintext from the
// stub mailer's recorded link, hit Callback, expect a 302 to
// <return_to>?signed_in=1 plus a Secure HttpOnly session cookie. The
// previous "session_token=<jwt>" Location pattern was retired in
// AUTH-004 (2026-05-29) — see auth_callback_nojwt_authp0_test.go for
// the standalone regression test.
func TestMagicLinkCallback_HappyPath_ConsumesAndRedirects(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	mailer := &stubMailer{}
	app := mlExtraApp(t, db, rdb, mailer)

	emailAddr := testhelpers.UniqueEmail(t)
	body := fmt.Sprintf(`{"email":%q,"return_to":"https://instanode.dev/login/callback"}`, emailAddr)
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusAccepted, resp.StatusCode)
	require.Equal(t, 1, mailer.calls)

	// Extract the plaintext token from the link the mailer received.
	idx := strings.Index(mailer.link, "?t=")
	require.Greater(t, idx, -1)
	plaintext := mailer.link[idx+3:]

	req2 := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t="+plaintext, nil)
	resp2, err := app.Test(req2, 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, fiber.StatusFound, resp2.StatusCode)
	loc := resp2.Header.Get("Location")
	// AUTH-004: JWT in cookie, NOT in Location. The dashboard SPA gets
	// a signed_in=1 marker and reads the cookie via /auth/me.
	assert.NotContains(t, loc, "session_token=", "AUTH-004: JWT must not appear in Location")
	assert.Contains(t, loc, "signed_in=1")
	assert.Contains(t, strings.Join(resp2.Header.Values("Set-Cookie"), "\n"), "instanode_session_exchange=",
		"AUTH-004: session JWT must be set as the instanode_session cookie")

	// Replay must fail — the row has been consumed.
	req3 := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t="+plaintext, nil)
	resp3, err := app.Test(req3, 5000)
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, fiber.StatusBadRequest, resp3.StatusCode,
		"replay of a consumed magic-link token must surface as 400")
}
