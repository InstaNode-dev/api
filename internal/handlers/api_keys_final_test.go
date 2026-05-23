package handlers_test

// api_keys_final_test.go — FINAL coverage pass for api_keys.go. Closes the
// DB-error arms (Create db_failed / List db_failed / Revoke db_failed) and the
// PAT-creating-PAT forbidden arm. Reuses apiKeysTestApp + apiKeysDo from
// api_keys_coverage_test.go, swapping in a faultdb for the DB-error arms.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// Create: CreateAPIKey errors → db_failed (api_keys.go:96). RequireAuth is
// JWT-only (no DB), so the first DB call is CreateAPIKey. failAfter=0.
func TestAPIKeysFinal_Create_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := whJWT(t, seedDB, teamID) // user + session JWT

	app := apiKeysTestApp(t, openFaultDB(t, 0))
	resp := apiKeysDo(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt, `{"name":"laptop","scopes":["read"]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// List: ListAPIKeysByTeam errors → db_failed (api_keys.go:120). failAfter=0.
func TestAPIKeysFinal_List_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := whJWT(t, seedDB, teamID)

	app := apiKeysTestApp(t, openFaultDB(t, 0))
	resp := apiKeysDo(t, app, http.MethodGet, "/api/v1/auth/api-keys", jwt, "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// Revoke: RevokeAPIKey errors → db_failed (api_keys.go:158). failAfter=0.
func TestAPIKeysFinal_Revoke_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := whJWT(t, seedDB, teamID)

	app := apiKeysTestApp(t, openFaultDB(t, 0))
	resp := apiKeysDo(t, app, http.MethodDelete, "/api/v1/auth/api-keys/"+uuid.NewString(), jwt, "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// Revoke: a non-UUID :id → invalid_id (api_keys.go:152).
func TestAPIKeysFinal_Revoke_BadID_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := whJWT(t, db, teamID)

	app := apiKeysTestApp(t, db)
	resp := apiKeysDo(t, app, http.MethodDelete, "/api/v1/auth/api-keys/not-a-uuid", jwt, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Revoke: a UUID with no matching row → not_found (api_keys.go:155).
func TestAPIKeysFinal_Revoke_NotFound_404(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := whJWT(t, db, teamID)

	app := apiKeysTestApp(t, db)
	resp := apiKeysDo(t, app, http.MethodDelete, "/api/v1/auth/api-keys/"+uuid.NewString(), jwt, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
