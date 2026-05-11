package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestWhoami_NoTokenReturns401 guards the canonical "agent probes token
// validity" path. Friction #9: prior to /whoami, agents reached for arbitrary
// /api/v1/* endpoints and got 404 instead of 401, causing wasted token-mint
// retries. /whoami's whole job is to return 401 when the token is bad.
func TestWhoami_NoTokenReturns401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("X-Forwarded-For", "10.13.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"missing bearer must return 401, not 404 — the friction this endpoint was built to remove")
}

// TestWhoami_ReturnsIdentityForAuthedRequest guards the success-path contract:
// returns the team_id + user_id encoded in the JWT, plus best-effort plan_tier
// enrichment from the DB. Agents read these fields directly without an
// extra hop to /billing.
func TestWhoami_ReturnsIdentityForAuthedRequest(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	const userID = "11111111-1111-1111-1111-111111111111"
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID, teamID, "agent@example.com")

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.13.0.2")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, true, body["ok"])
	assert.Equal(t, userID, body["user_id"], "user_id must be the uid claim from the JWT")
	assert.Equal(t, teamID, body["team_id"], "team_id must be the tid claim from the JWT")
	// plan_tier is best-effort — present when the DB lookup succeeded.
	if planTier, ok := body["plan_tier"]; ok {
		assert.Equal(t, "pro", planTier,
			"plan_tier must match the team's actual tier — best-effort enrichment shouldn't lie")
	}
}
