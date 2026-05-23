package handlers_test

// auth_final2_test.go — FINAL SERIAL PASS #2 coverage for the few remaining
// reachable error arms in auth.go's OAuth find-or-create helpers:
//
//   * findOrCreateUserGitHub LinkGitHubID error    (L601-603)
//   * findOrCreateUserGitHub email-lookup DB error (L618-620)
//   * findOrCreateUserGoogle LinkGoogleID error     (L1168-1170)
//   * findOrCreateUserGoogle email-lookup DB error  (L1183-1185)
//   * findOrCreateUserGoogle empty-Name teamName fallback (L1189-1191)
//
// Drives the live /auth/github + /auth/google handlers via the existing
// startFakeOAuth / buildAuthApp / oauthPostJSON / oauthCfg / withIsolatedDB
// seams. The link-error arms use a CHECK constraint that blocks the
// github_id/google_id UPDATE; the email-lookup-error arm uses the fault DB
// driver so GetUserByGitHubID (query #1) succeeds-as-NotFound while
// GetUserByEmail (query #2) errors.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
)

// TestAuthFinal2_GitHub_LinkGitHubIDFailure: an email-only user exists, then a
// CHECK constraint blocks any github_id assignment so LinkGitHubID's UPDATE
// errors → findOrCreateUserGitHub link branch → 503. Covers auth.go L601-603.
func TestAuthFinal2_GitHub_LinkGitHubIDFailure(t *testing.T) {
	db := withIsolatedDB(t)
	email := "ghlinkfail-final2@example.com"
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO teams (id, name, plan_tier) VALUES (gen_random_uuid(), 'x', 'hobby')`)
	require.NoError(t, err)
	var teamID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM teams LIMIT 1`).Scan(&teamID))
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, email)
	require.NoError(t, err)

	// Block the LinkGitHubID UPDATE: github_id must stay NULL.
	_, err = db.ExecContext(context.Background(),
		`ALTER TABLE users ADD CONSTRAINT no_gh_link_final2 CHECK (github_id IS NULL)`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestAuthFinal2_Google_LinkGoogleIDFailure mirrors the GitHub case for the
// google_id link path → findOrCreateUserGoogle link branch. Covers L1168-1170.
func TestAuthFinal2_Google_LinkGoogleIDFailure(t *testing.T) {
	db := withIsolatedDB(t)
	email := "glinkfail-final2@example.com"
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO teams (id, name, plan_tier) VALUES (gen_random_uuid(), 'x', 'hobby')`)
	require.NoError(t, err)
	var teamID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM teams LIMIT 1`).Scan(&teamID))
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, email)
	require.NoError(t, err)

	_, err = db.ExecContext(context.Background(),
		`ALTER TABLE users ADD CONSTRAINT no_g_link_final2 CHECK (google_id IS NULL)`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: email})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// faultAuthApp builds an auth app over a fault-injecting DB that fails after
// `failAfter` Query/Exec calls. The first call (GetUserByGitHubID /
// GetUserByGoogleID) succeeds and returns NotFound (no row in the freshly
// migrated faultpq DB), then GetUserByEmail (call #2) hits the injected error.
func faultAuthApp(t *testing.T, failAfter int64) *fiber.App {
	t.Helper()
	db := openFaultDB(t, failAfter)
	cfg := oauthCfg()
	h := handlers.NewAuthHandler(db, cfg)
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
	return app
}

// TestAuthFinal2_GitHub_EmailLookupDBError: GetUserByGitHubID (NotFound) then
// GetUserByEmail errors with a non-NotFound DB error → the email-lookup error
// branch of findOrCreateUserGitHub → 503. Covers auth.go L618-620.
func TestAuthFinal2_GitHub_EmailLookupDBError(t *testing.T) {
	// failAfter=1: the github_id lookup query succeeds (0 rows → NotFound),
	// then the email lookup query errors.
	app := faultAuthApp(t, 1)
	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: "fault-gh-final2@example.com"})
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestAuthFinal2_Google_EmailLookupDBError mirrors the GitHub case for the
// findOrCreateUserGoogle email-lookup error branch. Covers auth.go L1183-1185.
func TestAuthFinal2_Google_EmailLookupDBError(t *testing.T) {
	app := faultAuthApp(t, 1)
	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: "fault-g-final2@example.com"})
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// emptyNameGoogleServer is a fake Google tokeninfo endpoint that returns an
// EMPTY name field, forcing findOrCreateUserGoogle to derive the team name from
// the email local-part (L1189-1191). The shared fakeOAuthServer hardcodes
// "G User", so this needs a bespoke server.
func startEmptyNameGoogleOAuth(t *testing.T, sub, email string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/g/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"sub":%q,"email":%q,"name":"","aud":"g-client"}`, sub, email)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Cleanup(handlers.SetOAuthURLsForTest(srv.URL))
}

// TestAuthFinal2_Google_EmptyName_TeamNameFromEmail: a brand-new Google user
// whose tokeninfo carries an empty name → teamName falls back to the email
// local-part. Covers auth.go L1189-1191.
func TestAuthFinal2_Google_EmptyName_TeamNameFromEmail(t *testing.T) {
	db := withIsolatedDB(t)
	sub := strconv.FormatInt(time.Now().UnixNano(), 10)
	local := "noname" + sub[len(sub)-6:]
	email := local + "@example.com"
	startEmptyNameGoogleOAuth(t, sub, email)

	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The new team's name must be the email local-part (the empty-Name fallback).
	var teamName string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT t.name FROM teams t JOIN users u ON u.team_id = t.id WHERE u.email = $1`, email).Scan(&teamName))
	assert.Equal(t, local, teamName, "empty Google name must fall back to the email local-part")
}
