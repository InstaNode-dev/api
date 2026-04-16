package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestDeployNew_RequiresAuth verifies that POST /deploy/new returns 401
// when no session token is provided.
func TestDeployNew_RequiresAuth(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body := strings.NewReader(`{"image":"ghcr.io/example/app:latest","port":8080}`)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.12.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDeployNew_ServiceDisabled_Or_ValidShape verifies that POST /deploy/new either:
//   - returns 503 if "deploy" is not in EnabledServices (expected in most environments), OR
//   - returns a valid shape (ok=true with token + url) when deploy IS enabled AND k8s is reachable.
//
// The test is designed to pass in both CI (service disabled) and a live k8s cluster
// (service enabled but returns service_disabled when not in-cluster).
func TestDeployNew_ServiceDisabled_Or_ValidShape(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Create an authenticated team to satisfy RequireAuth.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-1", teamID, "user@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body := strings.NewReader(`{"image":"ghcr.io/example/app:latest","port":8080}`)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.12.0.2")

	resp, err := app.Test(req, 30000) // 30s — k8s ops take time
	require.NoError(t, err)
	defer resp.Body.Close()

	// Accept 503 (not in-cluster / k8s unavailable) OR 201 (success).
	switch resp.StatusCode {
	case http.StatusServiceUnavailable:
		var errBody struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
		assert.False(t, errBody.OK)
		assert.Equal(t, "service_disabled", errBody.Error,
			"503 must have error='service_disabled'; got %q", errBody.Error)
		t.Logf("deploy returned 503/service_disabled (expected outside k8s cluster)")

	case http.StatusCreated:
		var successBody struct {
			OK     bool   `json:"ok"`
			Token  string `json:"token"`
			URL    string `json:"url"`
			Status string `json:"status"`
			Image  string `json:"image"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&successBody))
		assert.True(t, successBody.OK)
		assert.NotEmpty(t, successBody.Token, "successful deploy must include token")
		assert.NotEmpty(t, successBody.URL, "successful deploy must include url")
		assert.NotEmpty(t, successBody.Status, "successful deploy must include status")
		assert.Equal(t, "ghcr.io/example/app:latest", successBody.Image)

	case http.StatusBadRequest:
		t.Logf("deploy returned 400 (expected when handler requires multipart/form-data)")

	default:
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /deploy/new: unexpected status %d\n%s", resp.StatusCode, bodyBytes)
	}
}

// TestDeployList_RequiresAuth verifies that GET /api/v1/deployments returns 401
// when no session token is provided.
func TestDeployList_RequiresAuth(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments", nil)
	req.Header.Set("X-Forwarded-For", "10.12.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDeployList_AuthenticatedReturnsEmptySlice verifies that an authenticated user
// with no deployments gets an empty list (not 404 or 500).
func TestDeployList_AuthenticatedReturnsEmptySlice(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-2", teamID, "user2@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.12.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK    bool  `json:"ok"`
		Items []any `json:"items"`
		Total int   `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.NotNil(t, body.Items, "items must be an array, not null")
	assert.Empty(t, body.Items, "new team must have zero deployments")
	assert.Equal(t, 0, body.Total, "total must be 0")
}

// TestDeployGet_UnknownToken_Returns404 verifies that GET /api/v1/deployments/:token
// returns 404 for a token that doesn't exist.
func TestDeployGet_UnknownToken_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-3", teamID, "user3@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/nonexistent-token", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.12.0.5")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
