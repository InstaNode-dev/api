package handlers_test

// vector_arms_vecwave_test.go — residual coverage for vector.go (the _vecwave
// wave): the validation + auth + 402 error arms of NewVector /
// newVectorAuthenticated that the happy-path tests (vector_test.go,
// vector_authenticated_coverage_test.go) leave uncovered.
//
//   NewVector (anonymous):
//     - empty name        → 400 name_required (requireName arm)
//     - invalid env       → 400 invalid_env   (resolveEnv arm)
//     - parent_resource_id on anon → 402 auth_required
//     - dedicated on anon → 402 auth_required
//   newVectorAuthenticated:
//     - invalid team id in token → 400 invalid_team
//     - dedicated on non-growth tier → 402 upgrade_required (dedicated tier-gate)

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/testhelpers"
)

func vectorPost(t *testing.T, app *fiber.App, ip, jwt, body string) (*http.Response, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/vector/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func TestVectorArms_AnonValidationAnd402_Vecwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,vector,redis")
	defer cleanApp()

	t.Run("empty_name_400", func(t *testing.T) {
		resp, out := vectorPost(t, app, "10.130.0.1", "", `{"name":""}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, []any{"name_required", "invalid_name"}, out["error"])
	})

	t.Run("invalid_env_400", func(t *testing.T) {
		resp, out := vectorPost(t, app, "10.131.0.1", "", `{"name":"vx","env":"NOT VALID ENV!!"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_env", out["error"])
	})

	t.Run("anon_parent_resource_402", func(t *testing.T) {
		resp, out := vectorPost(t, app, "10.132.0.1", "",
			`{"name":"vx","parent_resource_id":"`+uuid.NewString()+`"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
		assert.Equal(t, "auth_required", out["error"])
	})

	t.Run("anon_dedicated_402", func(t *testing.T) {
		resp, out := vectorPost(t, app, "10.133.0.1", "", `{"name":"vx","dedicated":true}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
		assert.Equal(t, "auth_required", out["error"])
	})
}

func TestVectorArms_AuthErrorArms_Vecwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,vector,redis")
	defer cleanApp()

	t.Run("invalid_team_400", func(t *testing.T) {
		// Session JWT carrying a non-UUID team id → parseTeamID fails.
		jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
		resp, out := vectorPost(t, app, "10.134.0.1", jwt, `{"name":"vx"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_team", out["error"])
	})

	t.Run("dedicated_non_growth_402", func(t *testing.T) {
		// A pro team requesting a dedicated vector → 402 upgrade_required
		// (dedicated requires a Growth-class tier).
		teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
		email := testhelpers.UniqueEmail(t)
		var userID string
		require.NoError(t, db.QueryRow(
			`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
			teamID, email).Scan(&userID))
		jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

		resp, out := vectorPost(t, app, "10.135.0.1", jwt, `{"name":"vx","dedicated":true}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
		assert.Equal(t, "upgrade_required", out["error"])
	})
}
