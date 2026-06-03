package handlers_test

// github_app_integration_test.go — end-to-end coverage for the GitHub App
// install flow (P4.1): flag-off 501, misconfigured 503, install 302, and the
// callback (invalid state / invalid installation_id / happy persist+redirect).
// DB-gated; skips locally without a DB.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// signInstallState mints a valid install state token for the test team using
// the same secret + claim shape the handler verifies (testhelpers.TestJWTSecret).
func signInstallState(t *testing.T, teamID string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"team_id": teamID,
		"purpose": "gh_app_install",
		"iat":     time.Now().Add(-time.Minute).Unix(),
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
	})
	s, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)
	return s
}

func appEnabled(c *config.Config) { c.GitHubAppEnabled = true; c.GitHubAppSlug = "instanode" }
func appNoSlug(c *config.Config)  { c.GitHubAppEnabled = true; c.GitHubAppSlug = "" }

func TestGitHubAppInstall_FlagOff_501(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwtTok := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "gh@example.com")
	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy") // flag default OFF
	defer clean()

	req := httptest.NewRequest(http.MethodGet, "/integrations/github/install", nil)
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}

func TestGitHubAppInstall_Misconfigured_503(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwtTok := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "gh@example.com")
	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appNoSlug)
	defer clean()

	req := httptest.NewRequest(http.MethodGet, "/integrations/github/install", nil)
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestGitHubAppInstall_Redirects(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwtTok := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "gh@example.com")
	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appEnabled)
	defer clean()

	req := httptest.NewRequest(http.MethodGet, "/integrations/github/install", nil)
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(loc, "https://github.com/apps/instanode/installations/new?state="),
		"Location should point at the App install page, got %q", loc)
	assert.Contains(t, loc, "state=", "install must carry an anti-CSRF state")
}

func TestGitHubAppCallback_InvalidState_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appEnabled)
	defer clean()

	req := httptest.NewRequest(http.MethodGet, "/integrations/github/callback?installation_id=99&state=bogus", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestGitHubAppCallback_InvalidInstallationID_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appEnabled)
	defer clean()

	state := signInstallState(t, teamID)
	// installation_id missing/non-numeric → 400.
	req := httptest.NewRequest(http.MethodGet, "/integrations/github/callback?installation_id=abc&state="+state, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// state carries a team_id that isn't a UUID → parseTeamID fails → 400.
func TestGitHubAppCallback_InvalidTeamUUID_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appEnabled)
	defer clean()

	state := signInstallState(t, "not-a-uuid")
	req := httptest.NewRequest(http.MethodGet, "/integrations/github/callback?installation_id=12&state="+state, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// state's team_id is a valid UUID but no such team exists → the upsert hits the
// team_id FK and fails → 503 install_persist_failed.
func TestGitHubAppCallback_PersistError_503(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appEnabled)
	defer clean()

	state := signInstallState(t, uuid.NewString()) // valid UUID, not in teams
	req := httptest.NewRequest(http.MethodGet, "/integrations/github/callback?installation_id=34&state="+state, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// An installation already linked to team A cannot be rebound by team B's
// callback → 409 install_conflict (review HIGH-2 anti-hijack).
func TestGitHubAppCallback_InstallConflict_409(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
	const instID int64 = 556677
	// team A owns the installation first.
	_, err := models.UpsertGitHubInstallation(context.Background(), db, instID, uuid.MustParse(teamA), "acme")
	require.NoError(t, err)

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appEnabled)
	defer clean()

	// team B tries to bind the same installation via a state legitimately signed
	// for team B → must be refused.
	state := signInstallState(t, teamB)
	req := httptest.NewRequest(http.MethodGet,
		"/integrations/github/callback?installation_id=556677&state="+state, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	// team A's row is untouched.
	inst, gerr := models.GetGitHubInstallation(context.Background(), db, instID)
	require.NoError(t, gerr)
	assert.Equal(t, teamA, inst.TeamID.String(), "victim installation must remain bound to team A")
}

func TestGitHubAppCallback_PersistsAndRedirects(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", appEnabled)
	defer clean()

	state := signInstallState(t, teamID)
	req := httptest.NewRequest(http.MethodGet,
		"/integrations/github/callback?installation_id=778899&setup_action=install&state="+state, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/integrations/github?installed=778899")

	// the installation↔team link was persisted.
	var gotTeam string
	row := db.QueryRow(`SELECT team_id::text FROM github_installations WHERE installation_id = $1`, int64(778899))
	require.NoError(t, row.Scan(&gotTeam))
	assert.Equal(t, teamID, gotTeam)
}
