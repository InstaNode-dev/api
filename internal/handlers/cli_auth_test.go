package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestGetCurrentUser_RequiresAuth verifies that GET /auth/me with no Bearer token
// returns 401 Unauthorized.
func TestGetCurrentUser_RequiresAuth(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	// No Authorization header.

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ok"])
}

// TestGetCurrentUser_ReturnsRealTier verifies that GET /auth/me performs a real DB
// lookup and returns the team's actual plan tier — not the hardcoded "hobby" stub.
func TestGetCurrentUser_ReturnsRealTier(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Create a team with a known tier different from the old hardcoded "hobby".
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")

	// Insert a user in that team.
	email := testhelpers.UniqueEmail(t)
	var userID string
	err := db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID)
	require.NoError(t, err)

	// Sign a session JWT for that user+team.
	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, true, body["ok"], "ok must be true")
	assert.Equal(t, "pro", body["tier"], "tier must come from DB, not be hardcoded")
	assert.Equal(t, email, body["email"], "email must be returned")
	assert.Equal(t, "Pro", body["plan_display_name"], "plan_display_name must be populated from plans registry")
	assert.NotEmpty(t, body["user_id"], "user_id must be present")
	assert.NotEmpty(t, body["team_id"], "team_id must be present")
	// trial_ends_at should be absent for a non-trial team.
	_, hasTrialEndsAt := body["trial_ends_at"]
	assert.False(t, hasTrialEndsAt, "trial_ends_at must not be present when not in trial")
}

// TestGetCurrentUser_TrialEndsAt_PresentWhenInTrial verifies that trial_ends_at is
// included in the response when the team has an active trial.
func TestGetCurrentUser_TrialEndsAt_PresentWhenInTrial(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Create a team and start its trial.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, err := db.ExecContext(context.Background(),
		`UPDATE teams SET trial_ends_at = now() + interval '14 days' WHERE id = $1::uuid`,
		teamID,
	)
	require.NoError(t, err)

	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, true, body["ok"])
	_, hasTrialEndsAt := body["trial_ends_at"]
	assert.True(t, hasTrialEndsAt, "trial_ends_at must be present when team is in trial")
}
