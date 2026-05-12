package handlers_test

// Tests the ?env= query parameter on GET /api/v1/resources and
// GET /api/v1/deployments — the slice-1 behavior change in the env-aware
// deployments work. Verifies:
//  - Omitting ?env= returns all envs (backward compat).
//  - ?env=staging returns only staging rows.
//  - ?env=<bogus> returns 200 + empty array (UI-stable, never 400).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

const (
	envProduction = "production"
	envStaging    = "staging"
)

type listResp struct {
	OK    bool             `json:"ok"`
	Items []map[string]any `json:"items"`
	Total int              `json:"total"`
}

// ── GET /api/v1/resources?env= ───────────────────────────────────────────────

func TestResourceList_NoEnvFilter_ReturnsAllEnvs(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, "user-list-noenv", teamID, "noenv@example.com")

	insertResource(t, db, teamID, "postgres", envProduction)
	insertResource(t, db, teamID, "redis", envStaging)

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	body := callList(t, app, "/api/v1/resources", jwt)
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Total, "no filter must return both envs")
	assert.Len(t, body.Items, 2)
}

func TestResourceList_EnvStaging_ReturnsOnlyStaging(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, "user-list-staging", teamID, "staging@example.com")

	insertResource(t, db, teamID, "postgres", envProduction)
	insertResource(t, db, teamID, "redis", envStaging)
	insertResource(t, db, teamID, "mongodb", envStaging)

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	body := callList(t, app, "/api/v1/resources?env=staging", jwt)
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Total, "env=staging must return 2")
	for _, item := range body.Items {
		assert.Equal(t, envStaging, item["env"], "every item must be staging")
	}
}

func TestResourceList_BogusEnv_ReturnsEmptyOK(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, "user-list-bogus", teamID, "bogus@example.com")

	insertResource(t, db, teamID, "postgres", envProduction)

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Uppercase + a space — fails NormalizeEnv shape. UI-stable: 200 + empty.
	body := callList(t, app, "/api/v1/resources?env=PROD%20", jwt)
	assert.True(t, body.OK)
	assert.Equal(t, 0, body.Total)
	assert.Empty(t, body.Items)
}

// ── GET /api/v1/deployments?env= ─────────────────────────────────────────────

func TestDeployList_NoEnvFilter_ReturnsAllEnvs(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, "deploy-noenv", teamID, "deploy-noenv@example.com")

	insertDeployment(t, db, teamID, "app-prod-noenv", envProduction)
	insertDeployment(t, db, teamID, "app-stage-noenv", envStaging)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body := callList(t, app, "/api/v1/deployments", jwt)
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Total)
}

func TestDeployList_EnvStaging_ReturnsOnlyStaging(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, "deploy-stage", teamID, "deploy-stage@example.com")

	insertDeployment(t, db, teamID, "app-prod-only", envProduction)
	insertDeployment(t, db, teamID, "app-stage-1", envStaging)
	insertDeployment(t, db, teamID, "app-stage-2", envStaging)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body := callList(t, app, "/api/v1/deployments?env=staging", jwt)
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Total)
	// Both items must be staging; the server may use either "env" or "environment"
	// as the env-scope key — accept either to match the dashboard's adapter shim.
	for _, item := range body.Items {
		scope, _ := envScopeFromDeploy(item)
		assert.Equal(t, envStaging, scope, "every item must be staging")
	}
}

func TestDeployList_BogusEnv_ReturnsEmptyOK(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, "deploy-bogus", teamID, "deploy-bogus@example.com")

	insertDeployment(t, db, teamID, "app-prod-bogus", envProduction)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body := callList(t, app, "/api/v1/deployments?env=%20Production%20", jwt)
	assert.True(t, body.OK)
	assert.Equal(t, 0, body.Total)
	assert.Empty(t, body.Items)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func insertResource(t *testing.T, db *sql.DB, teamID, resourceType, env string) {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env)
		VALUES ($1::uuid, $2, 'hobby', $3)
		RETURNING id::text
	`, teamID, resourceType, env).Scan(&id))
}

// insertDeployment inserts a deployment row. appIDSuffix is prefixed with the
// teamID (which is fresh per test via MustCreateTeamDB) so re-runs against
// the shared test DB never collide on the app_id UNIQUE index.
func insertDeployment(t *testing.T, db *sql.DB, teamID, appIDSuffix, env string) {
	t.Helper()
	teamPrefix := strings.ReplaceAll(teamID, "-", "")
	if len(teamPrefix) > 12 {
		teamPrefix = teamPrefix[:12]
	}
	appID := fmt.Sprintf("t%s-%s", teamPrefix, appIDSuffix)
	var id string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO deployments (team_id, app_id, port, tier, status, env)
		VALUES ($1::uuid, $2, 8080, 'hobby', 'healthy', $3)
		RETURNING id::text
	`, teamID, appID, env).Scan(&id))
}

// callList issues a GET to the path with the given JWT and returns the parsed
// {ok, items, total} envelope.
func callList(t *testing.T, app *fiber.App, path, jwt string) listResp {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.99.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var out listResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// envScopeFromDeploy reads the env-scope from a deployment list item. The
// handler returns the env scope under a stable key (`env`), but some shapes
// in the codebase use `environment` — accept either to stay decoupled from
// that adapter detail.
func envScopeFromDeploy(item map[string]any) (string, bool) {
	if v, ok := item["env"].(string); ok && v != "" {
		return v, true
	}
	if v, ok := item["environment"].(string); ok && v != "" {
		return v, true
	}
	return "", false
}
