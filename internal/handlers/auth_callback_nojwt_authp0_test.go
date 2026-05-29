package handlers_test

// auth_callback_nojwt_authp0_test.go — regression test for AUTH-004
// shipped 2026-05-29.
//
// Lives in handlers_test because it needs testhelpers.SetupTestDB, and
// testhelpers imports handlers (using it from inside `package handlers`
// would cycle).

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestAuthCallback_DoesNotPutJWTInLocation — AUTH-004 regression.
//
// Original exploit: GET /auth/email/callback?t=<plaintext> →
// 302 Location: https://instanode.dev/login/callback?session_token=<24h-JWT>.
// The full 24h-TTL JWT leaks into browser history, CDN logs, ingress
// logs, Referer headers on every subsequent navigation.
//
// Fix: callback sets the JWT in a Secure HttpOnly SameSite=Lax cookie,
// redirect URL carries only ?signed_in=1.
//
// Assertions:
//   - Location header MUST NOT contain "session_token" or a JWT-shape token
//     (any string starting with "eyJ" is a base64url JOSE header).
//   - Set-Cookie header MUST carry instanode_session=<jwt>; HttpOnly; SameSite=Lax.
func TestAuthCallback_DoesNotPutJWTInLocation(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	authH := handlers.NewAuthHandler(db, cfg)
	mailer := &nojwtRecordingMailer{}
	h := handlers.NewMagicLinkHandlerWithMailer(db, cfg, mailer, authH)
	app := fiber.New(fiber.Config{
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
	app.Get("/auth/email/callback", h.Callback)

	plaintext := mustPlantMagicLinkAuthP0(t, db, "qa+returnto@example.com",
		"https://instanode.dev/login/callback")

	req := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t="+plaintext, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode,
		"successful magic-link consumption must 302")

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "302 must carry a Location header")
	assert.NotContains(t, location, "session_token=",
		"AUTH-004: Location MUST NOT contain ?session_token=<jwt>")
	assert.NotContains(t, location, "eyJ",
		"AUTH-004: Location MUST NOT contain a JWT (base64-url 'eyJ' header)")
	assert.Contains(t, location, "signed_in=1",
		"the dashboard marker tells the SPA the cookie is set — it must be present")

	// Use Header.Values — Set-Cookie can have multiple entries (oauth_state
	// clear + the new session cookie) and Header.Get returns only the first.
	setCookies := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
	require.NotEmpty(t, setCookies, "callback must set a session cookie")
	assert.Contains(t, setCookies, "instanode_session=",
		"the session cookie name must be set")
	setCookie := setCookies // alias for downstream attribute checks
	assert.True(t,
		strings.Contains(setCookie, "HttpOnly") || strings.Contains(setCookie, "httponly"),
		"session cookie must be HttpOnly to block AUTH-003 XSS exfil")
	assert.True(t,
		strings.Contains(setCookie, "SameSite=Lax") || strings.Contains(setCookie, "samesite=lax"),
		"session cookie must be SameSite=Lax")
}

// nojwtRecordingMailer satisfies the magicLinkMailer interface for the
// callback test. The Callback path never actually invokes SendMagicLink
// (that happens in Start), but the interface is required by the
// constructor.
type nojwtRecordingMailer struct{}

func (n *nojwtRecordingMailer) SendMagicLink(ctx context.Context, to, link string) error {
	return nil
}

// mustPlantMagicLinkAuthP0 inserts a pre-baked magic-link row and returns
// the plaintext token. Mirrors models.CreateMagicLink without rate-limit.
func mustPlantMagicLinkAuthP0(t *testing.T, db *sql.DB, emailAddr, returnTo string) string {
	t.Helper()
	plaintext, err := models.GenerateMagicLinkPlaintext()
	require.NoError(t, err)
	// magicLinkTTL is a package-private constant (15m); pick a generous
	// TTL inline so this test doesn't depend on its current value.
	_, err = models.CreateMagicLink(context.Background(), db, emailAddr, plaintext, returnTo, 15*time.Minute)
	require.NoError(t, err)
	return plaintext
}
