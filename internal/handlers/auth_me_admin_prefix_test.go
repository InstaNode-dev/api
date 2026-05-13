package handlers_test

// auth_me_admin_prefix_test.go — verifies the /auth/me admin_path_prefix
// contract:
//
//   1. Caller is on ADMIN_EMAILS AND cfg.AdminPathPrefix is set
//      → response body carries the prefix verbatim.
//   2. Caller is NOT on ADMIN_EMAILS
//      → response body does NOT include the field AT ALL. Not "":
//      not present, because the field's mere presence would leak that
//      the surface exists.
//   3. Caller IS on ADMIN_EMAILS but cfg.AdminPathPrefix is empty
//      → response body does NOT include the field. The admin UI then
//      hides the route because the URL builder has nothing to build with.
//
// This pins the leak boundary: a non-admin session can never observe
// `admin_path_prefix` in any /auth/me payload, regardless of how the
// platform is configured.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// Each test below builds its own minimal Fiber app rather than reusing
// testhelpers.NewTestApp because the contract under test requires
// per-case control of cfg.AdminPathPrefix and the ADMIN_EMAILS env var.

// TestAuthMe_AdminPrefix_IncludedForAdminCaller — happy path. Admin
// email on the allowlist + cfg.AdminPathPrefix set → field present and
// equal to the configured prefix.
func TestAuthMe_AdminPrefix_IncludedForAdminCaller(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	const prefix = "abcdefghijklmnopqrstuvwxyz012345" // 32 chars, alnum
	adminEmail := testhelpers.UniqueEmail(t)
	t.Setenv("ADMIN_EMAILS", adminEmail)

	cfg := &config.Config{
		Port:            "8080",
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "redis",
		Environment:     "test",
		AdminPathPrefix: prefix,
	}
	planReg := plans.Default()
	cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planReg)

	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, adminEmail,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, adminEmail)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	got, has := body["admin_path_prefix"]
	require.True(t, has, "admin caller must receive admin_path_prefix")
	assert.Equal(t, prefix, got, "admin_path_prefix must equal cfg.AdminPathPrefix verbatim")
}

// TestAuthMe_AdminPrefix_OmittedForNonAdminCaller — leak-boundary test.
// Even with cfg.AdminPathPrefix set, a non-admin caller must NEVER see
// the field. Not "", not null — absent. Field presence alone is signal.
func TestAuthMe_AdminPrefix_OmittedForNonAdminCaller(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	const prefix = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" // 32 chars
	t.Setenv("ADMIN_EMAILS", "someone-else@instanode.dev")

	cfg := &config.Config{
		Port:            "8080",
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "redis",
		Environment:     "test",
		AdminPathPrefix: prefix,
	}
	planReg := plans.Default()
	cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planReg)

	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	nonAdminEmail := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, nonAdminEmail,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, nonAdminEmail)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	_, has := body["admin_path_prefix"]
	assert.False(t, has, "non-admin caller MUST NOT receive admin_path_prefix — its presence alone leaks that the surface exists")
}

// TestAuthMe_AdminPrefix_OmittedWhenPrefixUnset — closed-by-default at
// the config layer. Admin caller on the allowlist but the operator has
// not configured ADMIN_PATH_PREFIX → field is absent (admin UI hides the
// route accordingly).
func TestAuthMe_AdminPrefix_OmittedWhenPrefixUnset(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	adminEmail := testhelpers.UniqueEmail(t)
	t.Setenv("ADMIN_EMAILS", adminEmail)

	cfg := &config.Config{
		Port:            "8080",
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "redis",
		Environment:     "test",
		AdminPathPrefix: "", // closed by default
	}
	planReg := plans.Default()
	cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planReg)

	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, adminEmail,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, adminEmail)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	_, has := body["admin_path_prefix"]
	assert.False(t, has, "field must be omitted when cfg.AdminPathPrefix is empty even for admin callers")
}

// TestAuthMe_AdminPrefix_NotInOpenAPI — the OpenAPI spec must not mention
// the admin surface (path-prefix gate hinges on its existence being
// unknown). This is a coarse grep on the spec served from the production
// handler; a finer test would parse the JSON, but the spec is a raw
// string literal whose path keys we just want to scan for the literal
// substrings.
func TestAuthMe_AdminPrefix_NotInOpenAPI(t *testing.T) {
	app := fiber.New()
	app.Get("/openapi.json", handlers.ServeOpenAPI)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	spec := string(buf[:n])
	// Drain the rest if any (the spec is bigger than 1MiB? unlikely but
	// keep reading defensively).
	for {
		extra := make([]byte, 1<<20)
		m, _ := resp.Body.Read(extra)
		if m == 0 {
			break
		}
		spec += string(extra[:m])
	}

	forbidden := []string{
		`"/api/v1/admin/customers"`,
		`"/api/v1/admin/customers/{team_id}"`,
		`"/api/v1/admin/customers/{team_id}/tier"`,
		`"/api/v1/admin/customers/{team_id}/promo"`,
	}
	for _, s := range forbidden {
		assert.NotContains(t, spec, s,
			"OpenAPI spec must NOT expose the admin surface — path-prefix gate requires its existence stay unknown to non-admin callers")
	}
}
