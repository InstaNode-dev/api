package handlers_test

// family_bulk_twin_provarms_test.go — fills the validation + filter branches of
// BulkTwin that the existing family_bulk_twin_test.go suite leaves uncovered:
// missing/invalid source+target env, same-env, all-unsupported-types filter
// (200 + twinned=0), and the unauthenticated path. These reach BulkTwin's early
// returns before any provisioning, so they need no object-store / DB backend
// beyond the platform DB the test app already wires.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func bulkTwinApp(t *testing.T) (app interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}, jwt string) {
	t.Helper()
	db, cleanDB := testhelpers.SetupTestDB(t)
	t.Cleanup(cleanDB)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	t.Cleanup(cleanRedis)
	a, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb")
	t.Cleanup(cleanApp)
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	return a, bulkTwinJWT(t, db, teamID)
}

func TestBulkTwin_MissingSourceEnv_Returns400(t *testing.T) {
	app, jwt := bulkTwinApp(t)
	resp := postBulkTwin(t, app, jwt, map[string]any{"target_env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "missing_source_env", decodeBulkTwinResp(t, resp).Error)
}

func TestBulkTwin_MissingTargetEnv_Returns400(t *testing.T) {
	app, jwt := bulkTwinApp(t)
	resp := postBulkTwin(t, app, jwt, map[string]any{"source_env": "production"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "missing_target_env", decodeBulkTwinResp(t, resp).Error)
}

func TestBulkTwin_InvalidSourceEnv_Returns400(t *testing.T) {
	app, jwt := bulkTwinApp(t)
	resp := postBulkTwin(t, app, jwt, map[string]any{"source_env": "BAD ENV", "target_env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_source_env", decodeBulkTwinResp(t, resp).Error)
}

func TestBulkTwin_InvalidTargetEnv_Returns400(t *testing.T) {
	app, jwt := bulkTwinApp(t)
	resp := postBulkTwin(t, app, jwt, map[string]any{"source_env": "production", "target_env": "BAD ENV"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_target_env", decodeBulkTwinResp(t, resp).Error)
}

func TestBulkTwin_SameEnv_Returns400(t *testing.T) {
	app, jwt := bulkTwinApp(t)
	resp := postBulkTwin(t, app, jwt, map[string]any{"source_env": "production", "target_env": "production"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "same_env", decodeBulkTwinResp(t, resp).Error)
}

// All-unsupported resource_types filter (webhook/queue/storage have no per-env
// infra) → 200 OK + twinned=0, not a 4xx. Lets the caller observe the no-op.
func TestBulkTwin_AllUnsupportedTypes_Returns200Zero(t *testing.T) {
	app, jwt := bulkTwinApp(t)
	resp := postBulkTwin(t, app, jwt, map[string]any{
		"source_env":     "production",
		"target_env":     "staging",
		"resource_types": []string{"webhook", "queue", "storage"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBulkTwinResp(t, resp)
	assert.True(t, body.OK)
	assert.Equal(t, 0, body.Twinned)
	assert.Empty(t, body.Items)
	assert.Empty(t, body.Failures)
}

// Unauthenticated → 401 unauthorized (parseTeamID on empty team id).
func TestBulkTwin_Unauthenticated_Returns401(t *testing.T) {
	app, _ := bulkTwinApp(t)
	resp := postBulkTwin(t, app, "", map[string]any{"source_env": "production", "target_env": "staging"})
	defer resp.Body.Close()
	// RequireAuth middleware rejects before the handler when no JWT is present.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
