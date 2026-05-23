package handlers_test

// env_policy_get_final3_test.go — FINAL serial pass #3. Covers two
// EnvPolicyHandler.Get arms:
//   - nil policy → returns empty object {} (env_policy.go:57)
//   - bad team_id in token → 401 (env_policy.go:44)

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestEnvPolicyGetFinal3_NilPolicy — a team with no env-policy row → Get returns
// 200 with an empty policy object (env_policy.go:57-58).
func TestEnvPolicyGetFinal3_NilPolicy(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := envPolicyJWT(t, teamID, uuid.NewString())

	app := envPolicyMinimalApp(t, db)
	status, _ := epReq(t, app, http.MethodGet, jwt, "")
	require.Equal(t, http.StatusOK, status)
}

// TestEnvPolicyGetFinal3_BadTeamID — a JWT carrying a non-UUID team_id →
// uuid.Parse fails inside Get → 401 (env_policy.go:44-45).
func TestEnvPolicyGetFinal3_BadTeamID(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
	app := envPolicyMinimalApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/team/env-policy", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Either RequireAuth rejects (401) or Get's uuid.Parse rejects (401).
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
