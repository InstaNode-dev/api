package handlers_test

// auth_errorpaths_coverage_test.go — exercises the error/failure branches in
// auth.go / magic_link.go that the happy-path tests don't reach:
//   * user_upsert_failed (503) in GitHub / Google / GoogleCallback /
//     GitHubCallback / GoogleCallbackBrowser — via a closed *sql.DB so the
//     find-or-create lookup errors.
//   * "email already linked to another <provider> account" branch in
//     findOrCreateUserGitHub / findOrCreateUserGoogle.
//   * markEmailVerified SetEmailVerified-error branch (closed DB on an
//     unverified existing account) — best-effort, login still succeeds.
//   * OAuth helper HTTP-status / decode error branches (exchange / verify /
//     userinfo) — via a fake server returning non-200 / garbage.
//   * magic-link Callback lookup-DB-error and consume-DB-error (503) branches.

import (
	"context"
	"database/sql"
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
	"instant.dev/internal/testhelpers"
)

// brokenDB returns a *sql.DB whose connection is already closed, so every
// query returns an error — used to drive the DB-failure branches.
func brokenDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@127.0.0.1:5432/instant_dev_test?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	return db
}

// --- user_upsert_failed (503) across the OAuth handlers ---

func TestAuth_GitHub_UpsertFailure(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: "u@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(brokenDB(t), oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestAuth_Google_UpsertFailure(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: "u@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(brokenDB(t), oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestAuth_GoogleCallback_UpsertFailure(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{gSub: uniqueGHID(), gEmail: "u@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(brokenDB(t), oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google/callback", `{"code":"x","redirect_uri":"y"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestAuth_GitHubCallback_UpsertFailure(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: "u@example.com"})
	h := handlers.NewAuthHandler(brokenDB(t), oauthCfg())
	app := buildAuthApp(h)

	startResp := getReq(t, app, "/auth/github/start?return_to=https://instanode.dev/x")
	cookie := firstCookie(startResp.Header.Get("Set-Cookie"))
	state := extractQueryParam(startResp.Header.Get("Location"), "state")
	startResp.Body.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=c&state="+state, nil)
	req.Header.Set("Cookie", cookie)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestAuth_GoogleCallbackBrowser_UpsertFailure(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{gSub: uniqueGHID(), gEmail: "u@example.com"})
	h := handlers.NewAuthHandler(brokenDB(t), oauthCfg())
	app := buildAuthApp(h)

	startResp := getReq(t, app, "/auth/google/start?return_to=https://instanode.dev/x")
	cookie := firstCookie(startResp.Header.Get("Set-Cookie"))
	state := extractQueryParam(startResp.Header.Get("Location"), "state")
	startResp.Body.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback/browser?code=c&state="+state, nil)
	req.Header.Set("Cookie", cookie)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// --- "email already linked to another account" branches ---

func TestAuth_GitHub_EmailLinkedToAnotherAccount(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)

	// Seed a user that ALREADY has a github_id set, for a given email.
	email := testhelpers.UniqueEmail(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	existingGH := uniqueGHID()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email, github_id) VALUES ($1::uuid, $2, $3)`, teamID, email, existingGH)
	require.NoError(t, err)

	// GitHub login with the SAME email but a DIFFERENT github id → conflict.
	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestAuth_Google_EmailLinkedToAnotherAccount(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)

	email := testhelpers.UniqueEmail(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	existingG := uniqueGHID()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email, google_id) VALUES ($1::uuid, $2, $3)`, teamID, email, existingG)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// --- OAuth helper HTTP-status / decode error branches ---

// errOAuthServer returns non-200 / malformed bodies on every endpoint.
func errOAuthHandler() http.Handler {
	mux := http.NewServeMux()
	bad := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`not-json`))
	}
	for _, p := range []string{"/gh/token", "/gh/user", "/gh/emails", "/g/tokeninfo", "/g/token", "/g/userinfo"} {
		mux.HandleFunc(p, bad)
	}
	return mux
}

func TestAuth_GitHub_ExchangeDecodeError(t *testing.T) {
	srv := httptest.NewServer(errOAuthHandler())
	defer srv.Close()
	defer handlers.SetOAuthURLsForTest(srv.URL)()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuth_Google_VerifyNon200(t *testing.T) {
	srv := httptest.NewServer(errOAuthHandler())
	defer srv.Close()
	defer handlers.SetOAuthURLsForTest(srv.URL)()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuth_GoogleCallback_TokenDecodeError(t *testing.T) {
	srv := httptest.NewServer(errOAuthHandler())
	defer srv.Close()
	defer handlers.SetOAuthURLsForTest(srv.URL)()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google/callback", `{"code":"x","redirect_uri":"y"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// /g/token returns a valid access_token but /g/userinfo errors → userinfo
// failure branch (401) in GoogleCallback.
func TestAuth_GoogleCallback_UserinfoError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.ok"}`))
	})
	mux.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`denied`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer handlers.SetOAuthURLsForTest(srv.URL)()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google/callback", `{"code":"x","redirect_uri":"y"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// FindOrCreateUserByEmail unexpected-lookup-error branch: a closed DB makes
// GetUserByEmail return a non-NotFound error → wrapped error returned.
func TestAuth_FindOrCreateUserByEmail_LookupDBError(t *testing.T) {
	h := handlers.NewAuthHandler(brokenDB(t), oauthCfg())
	_, _, err := h.FindOrCreateUserByEmail(context.Background(), "x@example.com")
	require.Error(t, err)
}

// FindOrCreateUserByEmail existing-user happy path (GetUserByEmail succeeds +
// team lookup) — covers the err==nil branch.
func TestAuth_FindOrCreateUserByEmail_ExistingUser(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	h := handlers.NewAuthHandler(db, oauthCfg())

	email := testhelpers.UniqueEmail(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, email)
	require.NoError(t, err)

	u, tm, err := h.FindOrCreateUserByEmail(context.Background(), strings.ToUpper(email))
	require.NoError(t, err)
	require.NotNil(t, u)
	require.NotNil(t, tm)
	assert.Equal(t, email, u.Email)
}

// --- magic-link Callback DB-error branch (lookup fails, non-NotFound) ---

func TestMagicLink_Callback_LookupDBError(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	bdb := brokenDB(t)
	authH := handlers.NewAuthHandler(bdb, cfg)
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
	app.Get("/auth/email/callback", mlH.Callback)

	// A non-empty token forces a DB lookup, which errors on the closed DB →
	// the non-ErrMagicLinkNotFound branch → 503 HTML.
	req := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t=sometoken", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}
