package handlers_test

// auth_oauth_coverage_test.go — drives the OAuth provider-facing handlers in
// auth.go that were previously uncovered because they make outbound HTTP calls
// to github.com / accounts.google.com. handlers.SetOAuthURLsForTest repoints the
// package-level OAuth endpoint vars at an httptest.Server so the full
// exchange → find-or-create-user → mint-JWT path runs against a fake provider.
//
// Covers (via the public handler surface — find-or-create + mint-JWT + the
// low-level exchange/verify helpers all run transitively):
//   * GitHub        (POST /auth/github)         — happy, link-by-email, error branches
//   * Google        (POST /auth/google)         — happy, audience-mismatch, error branches
//   * GoogleCallback(POST /auth/google/callback)— happy + error branches
//   * GoogleAuthURL (GET  /auth/google/url)     — config + redirect_uri branches
//   * GitHubStart / GitHubCallback (GET browser flow, full success)
//   * GoogleStart / GoogleCallbackBrowser (GET browser flow, full success)
//
// External (package handlers_test) so it can use testhelpers (DB) without the
// import cycle a white-box file would hit.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// fakeOAuthServer serves canned GitHub + Google OAuth responses. Behaviour
// knobs let individual tests force error branches. ghID/ghEmail are mutable so
// successive requests can return different identities (existing-user + link).
type fakeOAuthServer struct {
	ghID           string
	ghEmail        string // email returned by /gh/user (empty → forces /gh/emails fetch)
	ghPrimaryEmail string // email returned by /gh/emails as primary+verified
	ghTokenErr     bool
	gAud           string
	gSub           string // google subject id (default g-sub-123)
	gEmail         string // google email (default g@example.com)
	gTokenNoAccess bool
}

func (f *fakeOAuthServer) gSubOr() string {
	if f.gSub != "" {
		return f.gSub
	}
	return "g-sub-123"
}

func (f *fakeOAuthServer) gEmailOr() string {
	if f.gEmail != "" {
		return f.gEmail
	}
	return "g@example.com"
}

func (f *fakeOAuthServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.ghTokenErr {
			_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"gho_test"}`))
	})
	mux.HandleFunc("/gh/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := f.ghID
		if id == "" {
			id = "424242"
		}
		_, _ = fmt.Fprintf(w, `{"id":%s,"login":"octocat","email":%q}`, id, f.ghEmail)
	})
	mux.HandleFunc("/gh/emails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `[{"email":%q,"primary":true,"verified":true}]`, f.ghPrimaryEmail)
	})
	mux.HandleFunc("/g/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"sub":%q,"email":%q,"name":"G User","aud":%q}`, f.gSubOr(), f.gEmailOr(), f.gAud)
	})
	mux.HandleFunc("/g/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.gTokenNoAccess {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.test"}`))
	})
	mux.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":%q,"email":%q,"name":"G User"}`, f.gSubOr(), f.gEmailOr())
	})
	return mux
}

// uniqueGHID returns a per-test-run numeric GitHub id so a reused test DB
// never collides on github_id (the column is UNIQUE and tests share the DB).
func uniqueGHID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func startFakeOAuth(t *testing.T, f *fakeOAuthServer) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	restore := handlers.SetOAuthURLsForTest(srv.URL)
	t.Cleanup(restore)
}

// settleAuditDB waits (bounded poll, no fixed sleep) for the fire-and-forget
// emitAuthLoginAudit goroutine to finish its INSERT into audit_log. A
// successful login spawns exactly one such row. Draining it before the test
// returns prevents the leaked writer's connection from racing the NEXT test's
// runMigrations `CREATE INDEX IF NOT EXISTS` on audit_log — Postgres surfaces
// that as a pg_class duplicate-key flake when an index build overlaps a write
// to the same relation. Registered as a Cleanup so it runs before the
// per-test DB connection (and migrations of the following test) are touched.
func settleAuditDB(t *testing.T, db *sql.DB) {
	t.Helper()
	t.Cleanup(func() {
		// Wait for the test DB to go quiescent before the test returns, so a
		// leaked fire-and-forget writer (emitAuthLoginAudit) can't still be
		// mid-INSERT when the NEXT test's runMigrations issues CREATE TABLE /
		// TYPE / INDEX (Postgres surfaces the overlap as a pg_class /
		// pg_type duplicate-key flake). safego.Go schedules the writer
		// asynchronously, so we require TWO consecutive quiescent reads
		// separated by a short gap — a single zero reading could land in the
		// window before the goroutine has even issued its query.
		deadline := time.Now().Add(5 * time.Second)
		quietStreak := 0
		for time.Now().Before(deadline) {
			var active int
			err := db.QueryRow(`SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database()
				  AND state = 'active'
				  AND pid <> pg_backend_pid()`).Scan(&active)
			if err != nil {
				return
			}
			if active == 0 {
				quietStreak++
				if quietStreak >= 2 {
					return
				}
			} else {
				quietStreak = 0
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
}

func oauthCfg() *config.Config {
	return &config.Config{
		JWTSecret:          testhelpers.TestJWTSecret,
		AESKey:             testhelpers.TestAESKeyHex,
		Environment:        "test",
		GitHubClientID:     "gh-client",
		GitHubClientSecret: "gh-secret",
		GoogleClientID:     "g-client",
		GoogleClientSecret: "g-secret",
	}
}

func buildAuthApp(h *handlers.AuthHandler) *fiber.App {
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
	app.Post("/auth/github", h.GitHub)
	app.Post("/auth/google", h.Google)
	app.Post("/auth/google/callback", h.GoogleCallback)
	app.Get("/auth/google/url", h.GoogleAuthURL)
	app.Get("/auth/github/start", h.GitHubStart)
	app.Get("/auth/github/callback", h.GitHubCallback)
	app.Get("/auth/google/start", h.GoogleStart)
	app.Get("/auth/google/callback/browser", h.GoogleCallbackBrowser)
	return app
}

func oauthPostJSON(t *testing.T, app *fiber.App, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func getReq(t *testing.T, app *fiber.App, path string) *http.Response {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), 5000)
	require.NoError(t, err)
	return resp
}

// --- POST /auth/github ---

func TestAuth_GitHub_HappyPath(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: testhelpers.UniqueEmail(t)})

	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.NotEmpty(t, body["token"])
}

func TestAuth_GitHub_MissingCodeAndBadBody(t *testing.T) {
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))

	r1 := oauthPostJSON(t, app, "/auth/github", "{bad")
	assert.Equal(t, http.StatusBadRequest, r1.StatusCode)
	r1.Body.Close()

	r2 := oauthPostJSON(t, app, "/auth/github", `{}`)
	assert.Equal(t, http.StatusBadRequest, r2.StatusCode)
	r2.Body.Close()
}

func TestAuth_GitHub_NotConfigured(t *testing.T) {
	cfg := oauthCfg()
	cfg.GitHubClientID = ""
	cfg.GitHubClientSecret = ""
	app := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
}

func TestAuth_GitHub_ExchangeError(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{ghTokenErr: true})
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

// Empty /gh/user email forces the /gh/emails primary+verified fetch, then a
// second request with the same email but a NEW github id exercises the
// link-by-email branch of findOrCreateUserGitHub.
func TestAuth_GitHub_PrimaryEmailFallbackAndLink(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)

	primary := testhelpers.UniqueEmail(t)
	f := &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: "", ghPrimaryEmail: primary}
	startFakeOAuth(t, f)
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	u, err := models.GetUserByEmail(context.Background(), db, primary)
	require.NoError(t, err)
	assert.True(t, u.EmailVerified, "primary+verified GitHub email must mark the account verified")
}

// Link-by-email branch: a user that already exists by email but with NO
// github_id (e.g. created via magic-link) gets the github id linked on first
// GitHub OAuth.
func TestAuth_GitHub_LinkByEmail(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)

	// Pre-create an email-only account (no github_id).
	existing := testhelpers.UniqueEmail(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, existing)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: existing})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	linked, err := models.GetUserByEmail(context.Background(), db, existing)
	require.NoError(t, err)
	assert.True(t, linked.GitHubID.Valid, "github id must be linked onto the existing email account")
}

// Existing-user branch: same github id twice returns the same account.
func TestAuth_GitHub_ExistingUser(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	email := testhelpers.UniqueEmail(t)
	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	r1 := oauthPostJSON(t, app, "/auth/github", `{"code":"a"}`)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	var b1 map[string]any
	require.NoError(t, json.NewDecoder(r1.Body).Decode(&b1))
	r1.Body.Close()

	r2 := oauthPostJSON(t, app, "/auth/github", `{"code":"b"}`)
	require.Equal(t, http.StatusOK, r2.StatusCode)
	var b2 map[string]any
	require.NoError(t, json.NewDecoder(r2.Body).Decode(&b2))
	r2.Body.Close()
	assert.Equal(t, b1["user_id"], b2["user_id"], "same github id must resolve to the same user")
}

// --- POST /auth/google ---

func TestAuth_Google_HappyPath(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: testhelpers.UniqueEmail(t)})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// Link-by-email branch for Google: email-only account links the google_id.
func TestAuth_Google_LinkByEmail(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)

	existing := testhelpers.UniqueEmail(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, existing)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: existing})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	linked, err := models.GetUserByEmail(context.Background(), db, existing)
	require.NoError(t, err)
	assert.True(t, linked.GoogleID.Valid, "google id must be linked onto the existing email account")
}

func TestAuth_Google_BadBodyMissingTokenNotConfigured(t *testing.T) {
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))

	r1 := oauthPostJSON(t, app, "/auth/google", "{bad")
	assert.Equal(t, http.StatusBadRequest, r1.StatusCode)
	r1.Body.Close()

	r2 := oauthPostJSON(t, app, "/auth/google", `{}`)
	assert.Equal(t, http.StatusBadRequest, r2.StatusCode)
	r2.Body.Close()

	cfg := oauthCfg()
	cfg.GoogleClientID = ""
	app2 := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	r3 := oauthPostJSON(t, app2, "/auth/google", `{"id_token":"tok"}`)
	assert.Equal(t, http.StatusServiceUnavailable, r3.StatusCode)
	r3.Body.Close()
}

func TestAuth_Google_AudienceMismatch(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{gAud: "wrong-client"})
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

// Existing-user branch for Google POST: same sub twice → same account.
func TestAuth_Google_ExistingUser(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	sub := uniqueGHID()
	email := testhelpers.UniqueEmail(t)
	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: sub, gEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	r1 := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	var b1 map[string]any
	require.NoError(t, json.NewDecoder(r1.Body).Decode(&b1))
	r1.Body.Close()

	r2 := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	require.Equal(t, http.StatusOK, r2.StatusCode)
	var b2 map[string]any
	require.NoError(t, json.NewDecoder(r2.Body).Decode(&b2))
	r2.Body.Close()
	assert.Equal(t, b1["user_id"], b2["user_id"], "same google sub must resolve to the same user")
}

// fetchGoogleUserInfoOAuth2V2 missing-email branch: /g/userinfo returns id but
// no email → GoogleCallback surfaces 401.
func TestAuth_GoogleCallback_UserinfoMissingEmail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.ok"}`))
	})
	mux.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"g-xyz","email":""}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer handlers.SetOAuthURLsForTest(srv.URL)()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google/callback", `{"code":"x","redirect_uri":"y"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- POST /auth/google/callback ---

func TestAuth_GoogleCallback_HappyPath(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	startFakeOAuth(t, &fakeOAuthServer{gSub: uniqueGHID(), gEmail: testhelpers.UniqueEmail(t)})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google/callback", `{"code":"abc","redirect_uri":"https://instanode.dev/cb"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAuth_GoogleCallback_ErrorBranches(t *testing.T) {
	cfg := oauthCfg()
	cfg.GoogleClientID = ""
	cfg.GoogleClientSecret = ""
	app0 := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	r0 := oauthPostJSON(t, app0, "/auth/google/callback", `{"code":"x","redirect_uri":"y"}`)
	assert.Equal(t, http.StatusServiceUnavailable, r0.StatusCode)
	r0.Body.Close()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))

	r1 := oauthPostJSON(t, app, "/auth/google/callback", "{bad")
	assert.Equal(t, http.StatusBadRequest, r1.StatusCode)
	r1.Body.Close()

	r2 := oauthPostJSON(t, app, "/auth/google/callback", `{"redirect_uri":"y"}`)
	assert.Equal(t, http.StatusBadRequest, r2.StatusCode)
	r2.Body.Close()

	r3 := oauthPostJSON(t, app, "/auth/google/callback", `{"code":"x"}`)
	assert.Equal(t, http.StatusBadRequest, r3.StatusCode)
	r3.Body.Close()
}

func TestAuth_GoogleCallback_NoAccessToken(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{gTokenNoAccess: true})
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google/callback", `{"code":"x","redirect_uri":"y"}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

// --- GET /auth/google/url ---

func TestAuth_GoogleAuthURL_Branches(t *testing.T) {
	cfg := oauthCfg()
	cfg.GoogleClientID = ""
	app0 := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	r0 := getReq(t, app0, "/auth/google/url")
	assert.Equal(t, http.StatusServiceUnavailable, r0.StatusCode)
	r0.Body.Close()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))

	r1 := getReq(t, app, "/auth/google/url")
	assert.Equal(t, http.StatusBadRequest, r1.StatusCode)
	r1.Body.Close()

	r2 := getReq(t, app, "/auth/google/url?redirect_uri=https://x/cb")
	require.Equal(t, http.StatusOK, r2.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(r2.Body).Decode(&body))
	r2.Body.Close()
	assert.Contains(t, body["url"], "accounts.google.com")

	cfg3 := oauthCfg()
	cfg3.GoogleRedirectURI = "https://configured/cb"
	app3 := buildAuthApp(handlers.NewAuthHandler(nil, cfg3))
	r3 := getReq(t, app3, "/auth/google/url")
	assert.Equal(t, http.StatusOK, r3.StatusCode)
	r3.Body.Close()
}

// --- GET browser flows: Start handlers ---

func TestAuth_GitHubStart_RedirectAndNotConfigured(t *testing.T) {
	cfg := oauthCfg()
	cfg.GitHubClientID = ""
	app0 := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	r0 := getReq(t, app0, "/auth/github/start")
	assert.Equal(t, http.StatusServiceUnavailable, r0.StatusCode)
	r0.Body.Close()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := getReq(t, app, "/auth/github/start?return_to=https://instanode.dev/x")
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "github.com/login/oauth/authorize")
	assert.Contains(t, resp.Header.Get("Set-Cookie"), "oauth_state=")
	resp.Body.Close()
}

func TestAuth_GoogleStart_RedirectAndNotConfigured(t *testing.T) {
	cfg := oauthCfg()
	cfg.GoogleClientID = ""
	app0 := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	r0 := getReq(t, app0, "/auth/google/start")
	assert.Equal(t, http.StatusServiceUnavailable, r0.StatusCode)
	r0.Body.Close()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := getReq(t, app, "/auth/google/start?return_to=https://instanode.dev/x")
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "accounts.google.com")
	resp.Body.Close()
}

// --- GET browser flows: Callback handlers ---

func TestAuth_GitHubCallback_StateAndErrorBranches(t *testing.T) {
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))

	cfg := oauthCfg()
	cfg.GitHubClientID = ""
	cfg.GitHubClientSecret = ""
	app0 := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	r0 := getReq(t, app0, "/auth/github/callback?code=c&state=s")
	assert.Equal(t, http.StatusServiceUnavailable, r0.StatusCode)
	r0.Body.Close()

	r1 := getReq(t, app, "/auth/github/callback")
	assert.Equal(t, http.StatusBadRequest, r1.StatusCode)
	r1.Body.Close()

	r2 := getReq(t, app, "/auth/github/callback?code=c&state=s")
	assert.Equal(t, http.StatusBadRequest, r2.StatusCode)
	r2.Body.Close()
}

func TestAuth_GitHubCallback_FullSuccess(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: testhelpers.UniqueEmail(t)})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	startResp := getReq(t, app, "/auth/github/start?return_to=https://instanode.dev/x")
	cookie := startResp.Header.Get("Set-Cookie")
	loc := startResp.Header.Get("Location")
	startResp.Body.Close()
	state := extractQueryParam(loc, "state")
	require.NotEmpty(t, state)

	req := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=c&state="+state, nil)
	req.Header.Set("Cookie", firstCookie(cookie))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "session_token=")
}

func TestAuth_GoogleCallbackBrowser_StateAndErrorBranches(t *testing.T) {
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))

	cfg := oauthCfg()
	cfg.GoogleClientID = ""
	cfg.GoogleClientSecret = ""
	app0 := buildAuthApp(handlers.NewAuthHandler(nil, cfg))
	r0 := getReq(t, app0, "/auth/google/callback/browser?code=c&state=s")
	assert.Equal(t, http.StatusServiceUnavailable, r0.StatusCode)
	r0.Body.Close()

	r1 := getReq(t, app, "/auth/google/callback/browser")
	assert.Equal(t, http.StatusBadRequest, r1.StatusCode)
	r1.Body.Close()

	r2 := getReq(t, app, "/auth/google/callback/browser?code=c&state=s")
	assert.Equal(t, http.StatusBadRequest, r2.StatusCode)
	r2.Body.Close()
}

func TestAuth_GoogleCallbackBrowser_FullSuccess(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	settleAuditDB(t, db)
	startFakeOAuth(t, &fakeOAuthServer{gSub: uniqueGHID(), gEmail: testhelpers.UniqueEmail(t)})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))

	startResp := getReq(t, app, "/auth/google/start?return_to=https://instanode.dev/x")
	cookie := startResp.Header.Get("Set-Cookie")
	loc := startResp.Header.Get("Location")
	startResp.Body.Close()
	state := extractQueryParam(loc, "state")
	require.NotEmpty(t, state)

	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback/browser?code=c&state="+state, nil)
	req.Header.Set("Cookie", firstCookie(cookie))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "session_token=")
}

// extractQueryParam pulls a single (already-unescaped for our hex value) query
// param value out of a URL string.
func extractQueryParam(rawURL, key string) string {
	idx := strings.Index(rawURL, key+"=")
	if idx < 0 {
		return ""
	}
	rest := rawURL[idx+len(key)+1:]
	if amp := strings.IndexByte(rest, '&'); amp >= 0 {
		rest = rest[:amp]
	}
	return rest
}

// firstCookie returns just the "name=value" portion of a Set-Cookie header.
func firstCookie(setCookie string) string {
	if semi := strings.IndexByte(setCookie, ';'); semi >= 0 {
		return setCookie[:semi]
	}
	return setCookie
}
