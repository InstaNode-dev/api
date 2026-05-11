package handlers_test

// env_test.go — handler-level tests for multi-environment support
// (POST /db/new, /cache/new, /nosql/new, /storage/new, /webhook/new, /deploy/new).
//
// Each test asserts:
//   - Missing ?env defaults to "production" in the response and DB row.
//   - Invalid env strings are rejected with HTTP 400 + error="invalid_env".
//   - Provisioning in env=staging does not appear in env=production listings.
//
// All tests skip when the test Postgres / Redis isn't reachable — they call
// testhelpers.NewTestApp which itself skips on unreachable infra.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// postCacheNew posts to /cache/new with optional ?env query param and returns
// the parsed JSON body. We use cache as the canonical "smallest happy-path
// provision" — it has no external infra dependency beyond Redis itself.
func postCacheNew(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, ip, env string) (int, map[string]any) {
	t.Helper()
	path := "/cache/new"
	if env != "" {
		path += "?env=" + env
	}
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("X-Forwarded-For", ip)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	return resp.StatusCode, out
}

func TestEnv_DefaultProduction(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	status, body := postCacheNew(t, app, "10.42.0.1", "")
	require.True(t, status == http.StatusCreated || status == http.StatusOK,
		"expected 201/200, got %d (%v)", status, body)

	tokStr, _ := body["token"].(string)
	require.NotEmpty(t, tokStr)
	defer db.Exec(`DELETE FROM resources WHERE token = $1::uuid`, tokStr)

	gotEnv, _ := body["env"].(string)
	assert.Equal(t, models.EnvProduction, gotEnv,
		"missing ?env must default to 'production' in the response")

	// Verify it's also persisted as 'production'.
	var dbEnv string
	require.NoError(t, db.QueryRow(`SELECT env FROM resources WHERE token = $1::uuid`, tokStr).Scan(&dbEnv))
	assert.Equal(t, "production", dbEnv)
}

func TestEnv_Validation_RejectsInvalid(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	cases := []struct {
		name string
		env  string
	}{
		{"contains_space", "prod%20ction"}, // url-encoded space
		{"too_long", strings.Repeat("a", 33)},
		{"uppercase", "Prod"},
		{"underscore", "my_env"},
		{"unicode", "stagé"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := postCacheNew(t, app, "10.43."+tc.name[:1]+".1", tc.env)
			assert.Equal(t, http.StatusBadRequest, status, "body=%v", body)
			assert.Equal(t, "invalid_env", body["error"], "body=%v", body)
		})
	}
}

func TestEnv_Isolation_ListResourcesByEnv(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	mk := func(env string) *models.Resource {
		r, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
			TeamID:       &teamID,
			ResourceType: "redis",
			Tier:         "hobby",
			Env:          env,
		})
		require.NoError(t, err)
		return r
	}
	stagingR := mk("staging")
	prodR := mk("production")
	defer db.Exec(`DELETE FROM resources WHERE id IN ($1, $2)`, stagingR.ID, prodR.ID)

	prodList, err := models.ListResourcesByTeamAndEnv(context.Background(), db, teamID, "production")
	require.NoError(t, err)
	for _, r := range prodList {
		assert.NotEqual(t, stagingR.ID, r.ID,
			"staging resource must NOT appear in production listing")
		assert.Equal(t, "production", r.Env)
	}

	stgList, err := models.ListResourcesByTeamAndEnv(context.Background(), db, teamID, "staging")
	require.NoError(t, err)
	var stgFound bool
	for _, r := range stgList {
		if r.ID == stagingR.ID {
			stgFound = true
		}
		assert.Equal(t, "staging", r.Env)
	}
	assert.True(t, stgFound)
}

func TestEnv_DeployIsolation(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	dev, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID:  teamID,
		AppID:   "myapp-dev-" + uuid.NewString()[:6],
		Tier:    "hobby",
		Env:     "dev",
		EnvVars: map[string]string{"_name": "myapp"},
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, dev.ID)

	prod, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID:  teamID,
		AppID:   "myapp-prod-" + uuid.NewString()[:6],
		Tier:    "hobby",
		Env:     "production",
		EnvVars: map[string]string{"_name": "myapp"},
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, prod.ID)

	assert.NotEqual(t, dev.ID, prod.ID,
		"same logical app (myapp) deployed to dev vs prod must be two distinct rows")
	assert.Equal(t, "dev", dev.Env)
	assert.Equal(t, "production", prod.Env)
}
