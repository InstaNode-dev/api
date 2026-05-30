package handlers_test

// auth_me_no_store_test.go — AUTH-146 (QA 2026-05-29).
//
// /auth/me returns the caller's session-bound identity (user_id, team_id,
// email, tier, experiments-bucket, admin flags, impersonation state).
// None of those values are safe to cache — a service worker, browser
// back-cache after logout, or an intermediate proxy that respects the
// default heuristic-cache rules could re-serve them to a subsequent
// session. The handler MUST emit `Cache-Control: no-store` on every 200.
//
// This test exercises the production wiring (RequireAuth + a real
// session JWT against the test database) so the no-store header is
// asserted in the real response path, not a unit-test fixture that
// could drift from the live handler shape.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// TestAuthMe_CacheControlNoStore pins the no-store header. The pre-fix
// /auth/me handler emitted no Cache-Control at all — RFC 9111 default
// heuristic-cache rules let an intermediate cache hold the body and
// re-serve it to a subsequent session on the same machine. The
// post-fix handler stamps `Cache-Control: no-store` on every 200.
func TestAuthMe_CacheControlNoStore(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	email := testhelpers.UniqueEmail(t)
	cfg := &config.Config{
		Port:            "8080",
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "redis",
		Environment:     "test",
	}
	planReg := plans.Default()
	cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planReg)

	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// AUTH-146: `Cache-Control: no-store` is the unconditional opt-out
	// from caching (RFC 9111 §5.2.2.5). The handler must emit exactly
	// this value — `private` alone is insufficient (it still permits a
	// browser cache to retain the body across sessions on the same
	// machine), and `max-age=0` permits revalidated reuse of stale
	// entries (`must-revalidate` is the no-store-equivalent only when
	// the upstream is reachable). The literal "no-store" closes both.
	cacheControl := resp.Header.Get("Cache-Control")
	require.NotEmpty(t, cacheControl,
		"AUTH-146: /auth/me must emit a Cache-Control header so default heuristic caching cannot retain the session-bound identity payload")
	// Allow forward-compat directive lists ("no-store, no-cache, private")
	// — just require no-store to be present.
	tokens := strings.Split(cacheControl, ",")
	hasNoStore := false
	for _, tok := range tokens {
		if strings.TrimSpace(tok) == "no-store" {
			hasNoStore = true
			break
		}
	}
	assert.True(t, hasNoStore,
		"AUTH-146: Cache-Control must include `no-store`; got %q (RFC 9111 §5.2.2.5 — the only directive that forbids storing the response at all)", cacheControl)
}
