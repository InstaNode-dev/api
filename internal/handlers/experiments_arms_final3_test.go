package handlers_test

// experiments_arms_final3_test.go — FINAL serial pass #3. Closes the
// ExperimentsHandler.Converted validation arms the happy-path test leaves open:
//   - missing experiment/variant → invalid_body 400          (experiments.go:95)
//   - action longer than actionMaxLen → truncated (200)       (experiments.go:97-99)
//   - unknown experiment → unknown_experiment 400             (experiments.go:107)
//   - unknown variant → invalid_variant 400                   (experiments.go:121)

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/experiments"
	"instant.dev/internal/testhelpers"
)

func expConvertedReq(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, jwt string, payload map[string]string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/experiments/converted", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func TestExperimentsConvertedFinal3_Arms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	t.Run("missing_fields", func(t *testing.T) {
		resp := expConvertedReq(t, app, jwt, map[string]string{"experiment": "", "variant": ""})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("unknown_experiment", func(t *testing.T) {
		resp := expConvertedReq(t, app, jwt, map[string]string{
			"experiment": "no-such-experiment", "variant": "control"})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid_variant", func(t *testing.T) {
		resp := expConvertedReq(t, app, jwt, map[string]string{
			"experiment": experiments.ExperimentUpgradeButton, "variant": "definitely-not-a-variant"})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("action_truncation", func(t *testing.T) {
		// A valid experiment+variant (server-bucketed) with an over-long action
		// → the truncation arm (experiments.go:97-99) runs; the request still
		// succeeds (200).
		variant := experiments.Pick(experiments.ExperimentUpgradeButton, teamID)
		require.NotEmpty(t, variant)
		resp := expConvertedReq(t, app, jwt, map[string]string{
			"experiment": experiments.ExperimentUpgradeButton,
			"variant":    variant,
			"action":     strings.Repeat("x", 200), // > actionMaxLen (64)
		})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
