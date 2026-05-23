package handlers_test

// auth_faultinject_coverage_test.go — deterministic fault injection for the
// few remaining error branches that need a partial DB failure (one table works,
// another fails). Uses a per-test ISOLATED database (created + dropped here)
// so DROP-ing a table can't disturb the shared test DB or sibling tests.
//
//   * magic-link Callback user_upsert_failed (503): magic_links lookup +
//     consume succeed, then `users` is gone → FindOrCreateUserByEmail errors.

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

// withIsolatedDB creates a throwaway database, points TEST_DATABASE_URL at it
// (auto-restored by t.Setenv), runs the full test migrations into it via
// testhelpers.SetupTestDB, and drops it on cleanup. Returns the *sql.DB.
func withIsolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		base = "postgres://postgres:postgres@127.0.0.1:5432/instant_dev_test?sslmode=disable"
	}
	admin, err := sql.Open("postgres", base)
	require.NoError(t, err)
	if err := admin.Ping(); err != nil {
		t.Skipf("isolated DB unavailable: %v", err)
	}

	dbName := fmt.Sprintf("auth_iso_%d", os.Getpid()) + "_" + strings.ReplaceAll(t.Name(), "/", "_")
	dbName = strings.ToLower(dbName)
	if len(dbName) > 60 {
		dbName = dbName[:60]
	}
	_, _ = admin.Exec("DROP DATABASE IF EXISTS " + dbName)
	if _, err := admin.Exec("CREATE DATABASE " + dbName); err != nil {
		_ = admin.Close()
		t.Skipf("cannot create isolated DB: %v", err)
	}

	// Point TEST_DATABASE_URL at the isolated DB for this test only.
	isoDSN := replaceDBName(base, dbName)
	t.Setenv("TEST_DATABASE_URL", isoDSN)

	db, clean := testhelpers.SetupTestDB(t)
	t.Cleanup(func() {
		clean()
		// Drop the isolated DB; terminate any lingering backends first.
		_, _ = admin.Exec(
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, dbName)
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + dbName)
		_ = admin.Close()
	})
	return db
}

// replaceDBName swaps the database path segment in a postgres DSN.
func replaceDBName(dsn, name string) string {
	q := ""
	if i := strings.IndexByte(dsn, '?'); i >= 0 {
		q = dsn[i:]
		dsn = dsn[:i]
	}
	slash := strings.LastIndexByte(dsn, '/')
	return dsn[:slash+1] + name + q
}

func TestMagicLink_Callback_UpsertFailureAfterConsume(t *testing.T) {
	db := withIsolatedDB(t)

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	authH := handlers.NewAuthHandler(db, cfg)
	mailer := &capturingMailer{}
	mlH := handlers.NewMagicLinkHandlerWithMailerAndRedis(db, cfg, mailer, authH, nil)

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

	// Create a real, consumable magic-link row.
	email := testhelpers.UniqueEmail(t)
	startReq := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"return_to":"https://instanode.dev/x"}`, email)))
	startReq.Header.Set("Content-Type", "application/json")
	sresp, err := app.Test(startReq, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, sresp.StatusCode)
	sresp.Body.Close()
	require.Equal(t, 1, mailer.calls)

	idx := strings.Index(mailer.link, "?t=")
	require.Greater(t, idx, -1)
	plaintext := mailer.link[idx+3:]

	// Now break the users table so the post-consume FindOrCreateUserByEmail
	// errors, while the magic_links lookup + consume still succeed.
	_, err = db.ExecContext(context.Background(), `DROP TABLE users CASCADE`)
	require.NoError(t, err)

	cb := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t="+plaintext, nil)
	resp, err := app.Test(cb, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// user_upsert_failed → 503 HTML error page.
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

// GitHub new-user with the teams table dropped → CreateTeam fails inside
// findOrCreateUserGitHub → user_upsert_failed 503. Covers the create-team
// error branch.
func TestAuth_GitHub_CreateTeamFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(), `DROP TABLE teams CASCADE`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: "newuser@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// Google new-user with the teams table dropped → CreateTeam fails inside
// findOrCreateUserGoogle → user_upsert_failed 503.
func TestAuth_Google_CreateTeamFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(), `DROP TABLE teams CASCADE`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: "newg@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// FindOrCreateUserByEmail CreateTeam failure: new email + teams table dropped.
func TestAuth_FindOrCreateUserByEmail_CreateTeamFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(), `DROP TABLE teams CASCADE`)
	require.NoError(t, err)

	h := handlers.NewAuthHandler(db, oauthCfg())
	_, _, err = h.FindOrCreateUserByEmail(context.Background(), "brandnew@example.com")
	require.Error(t, err)
}

// magic-link Callback SetEmailVerified failure: a CHECK constraint blocks
// email_verified=true, so CreateUser (defaults false) succeeds but the
// post-consume SetEmailVerified UPDATE fails. The login still succeeds (the
// flip is best-effort) → 302. Covers the verr!=nil branch of Callback.
func TestMagicLink_Callback_SetEmailVerifiedFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE users ADD CONSTRAINT no_verify CHECK (email_verified = false)`)
	require.NoError(t, err)

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	authH := handlers.NewAuthHandler(db, cfg)
	mailer := &capturingMailer{}
	mlH := handlers.NewMagicLinkHandlerWithMailerAndRedis(db, cfg, mailer, authH, nil)

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

	email := "verifyfail@example.com"
	startReq := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"return_to":"https://instanode.dev/x"}`, email)))
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
	// SetEmailVerified failure is swallowed → login still 302s.
	assert.Equal(t, http.StatusFound, resp.StatusCode)
}

// GetCurrentUser GetUserByID db_error: team lookup succeeds, then the users
// table is gone so GetUserByID errors (non-NotFound) → db_error 503.
func TestCLI_GetCurrentUser_UserLookupDBError(t *testing.T) {
	db := withIsolatedDB(t)
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, Environment: "test"}

	// Create a team so GetTeamByID succeeds; the JWT's user id need not exist.
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO teams (id, name, plan_tier) VALUES (gen_random_uuid(), 'x', 'pro')`)
	require.NoError(t, err)
	var teamID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM teams LIMIT 1`).Scan(&teamID))

	// Break the users table so GetUserByID errors after the team lookup.
	_, err = db.ExecContext(context.Background(), `ALTER TABLE users RENAME TO users_gone`)
	require.NoError(t, err)

	h := handlers.NewCLIAuthHandler(db, nil, cfg, plans.Default())
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false})
		},
	})
	app.Use(middleware.RequestID())
	app.Get("/auth/me", middleware.RequireAuth(cfg), h.GetCurrentUser)

	tok := faultJWT(t, teamID)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// magic-link Callback ConsumeMagicLink error: a CHECK constraint blocks the
// consumed_at UPDATE, so GetMagicLinkForConsumption succeeds (row is unconsumed)
// but ConsumeMagicLink's UPDATE errors → consume_failed 503.
func TestMagicLink_Callback_ConsumeError(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE magic_links ADD CONSTRAINT no_consume CHECK (consumed_at IS NULL)`)
	require.NoError(t, err)

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	authH := handlers.NewAuthHandler(db, cfg)
	mailer := &capturingMailer{}
	mlH := handlers.NewMagicLinkHandlerWithMailerAndRedis(db, cfg, mailer, authH, nil)

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

	email := "consumefail@example.com"
	startReq := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
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
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// faultJWT signs a minimal session JWT (uid+tid) for the fault tests.
func faultJWT(t *testing.T, teamID string) string {
	t.Helper()
	return testhelpers.MustSignSessionJWT(t,
		"11111111-1111-1111-1111-111111111111", teamID, "fault@example.com")
}

// GitHub new-user CreateUser failure: teams OK, users INSERT broken → the
// create-user error branch of findOrCreateUserGitHub → 503.
func TestAuth_GitHub_CreateUserFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE users ADD COLUMN forced_break TEXT NOT NULL`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: "ghnew@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// GitHub link-by-email team-lookup failure: an email-only user exists, the
// teams table is then dropped → link succeeds but the subsequent GetTeamByID
// errors → findOrCreateUserGitHub teamErr branch → 503.
func TestAuth_GitHub_LinkTeamLookupFailure(t *testing.T) {
	db := withIsolatedDB(t)
	email := "linkme@example.com"
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO teams (id, name, plan_tier) VALUES (gen_random_uuid(), 'x', 'hobby')`)
	require.NoError(t, err)
	var teamID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM teams LIMIT 1`).Scan(&teamID))
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, email)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	// Drop teams AFTER the user/team exist, so GetUserByGitHubID (NotFound) →
	// GetUserByEmail (found) → LinkGitHubID (users intact) → GetTeamByID fails.
	_, err = db.ExecContext(context.Background(), `ALTER TABLE teams RENAME TO teams_gone`)
	require.NoError(t, err)

	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// Google new-user CreateUser failure: teams OK, users INSERT broken.
func TestAuth_Google_CreateUserFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE users ADD COLUMN forced_break TEXT NOT NULL`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: "gnew@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// Google link-by-email team-lookup failure (mirror of the GitHub case): an
// email-only user exists, teams is renamed away → link OK but GetTeamByID
// errors → findOrCreateUserGoogle teamErr branch → 503.
func TestAuth_Google_LinkTeamLookupFailure(t *testing.T) {
	db := withIsolatedDB(t)
	email := "glinkme@example.com"
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO teams (id, name, plan_tier) VALUES (gen_random_uuid(), 'x', 'hobby')`)
	require.NoError(t, err)
	var teamID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM teams LIMIT 1`).Scan(&teamID))
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, email)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	_, err = db.ExecContext(context.Background(), `ALTER TABLE teams RENAME TO teams_gone`)
	require.NoError(t, err)

	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// GitHub existing-user team-lookup failure: same github id logs in twice; teams
// is renamed before the second login so the existing-user GetTeamByID errors
// → findOrCreateUserGitHub existing-user teamErr branch → 503.
func TestAuth_GitHub_ExistingUserTeamLookupFailure(t *testing.T) {
	db := withIsolatedDB(t)
	ghID := uniqueGHID()
	startFakeOAuth(t, &fakeOAuthServer{ghID: ghID, ghEmail: "ghexist@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	// First login creates the user.
	r1 := oauthPostJSON(t, app, "/auth/github", `{"code":"a"}`)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	r1.Body.Close()

	// Rename teams so the second (existing-user) login's GetTeamByID fails.
	_, err := db.ExecContext(context.Background(), `ALTER TABLE teams RENAME TO teams_gone2`)
	require.NoError(t, err)

	r2 := oauthPostJSON(t, app, "/auth/github", `{"code":"b"}`)
	defer r2.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, r2.StatusCode)
}

// Google existing-user team-lookup failure (mirror of the GitHub case).
func TestAuth_Google_ExistingUserTeamLookupFailure(t *testing.T) {
	db := withIsolatedDB(t)
	sub := uniqueGHID()
	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: sub, gEmail: "gexist@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	r1 := oauthPostJSON(t, app, "/auth/google", `{"id_token":"a"}`)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	r1.Body.Close()

	_, err := db.ExecContext(context.Background(), `ALTER TABLE teams RENAME TO teams_gone3`)
	require.NoError(t, err)

	r2 := oauthPostJSON(t, app, "/auth/google", `{"id_token":"b"}`)
	defer r2.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, r2.StatusCode)
}

// FindOrCreateUserByEmail existing-user team-lookup failure: a user exists, the
// teams table is renamed away → GetUserByEmail OK but GetTeamByID errors →
// the existing-user teamErr branch.
func TestAuth_FindOrCreateUserByEmail_ExistingUserTeamLookupFailure(t *testing.T) {
	db := withIsolatedDB(t)
	email := "existingteamfail@example.com"
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO teams (id, name, plan_tier) VALUES (gen_random_uuid(), 'x', 'hobby')`)
	require.NoError(t, err)
	var teamID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM teams LIMIT 1`).Scan(&teamID))
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, email)
	require.NoError(t, err)

	_, err = db.ExecContext(context.Background(), `ALTER TABLE teams RENAME TO teams_gone4`)
	require.NoError(t, err)

	h := handlers.NewAuthHandler(db, oauthCfg())
	_, _, err = h.FindOrCreateUserByEmail(context.Background(), email)
	require.Error(t, err)
}

// FindOrCreateUserByEmail CreateUser failure: GetUserByEmail returns NotFound
// (table intact, no row), CreateTeam succeeds, but a NOT-NULL-without-default
// column added to users makes the INSERT fail → CreateUser error branch.
func TestAuth_FindOrCreateUserByEmail_CreateUserFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE users ADD COLUMN forced_break TEXT NOT NULL`)
	require.NoError(t, err)

	h := handlers.NewAuthHandler(db, oauthCfg())
	_, _, err = h.FindOrCreateUserByEmail(context.Background(), "brandnew2@example.com")
	require.Error(t, err)
}
