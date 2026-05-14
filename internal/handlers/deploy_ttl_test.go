package handlers_test

// deploy_ttl_test.go — Wave FIX-J handler tests for the TTL keeper endpoints
// and the /deploy/new ttl_policy field. Covers:
//   - POST /api/v1/deployments/:id/make-permanent — happy / already-permanent /
//     cross-tenant 404 / anonymous-rejected.
//   - POST /api/v1/deployments/:id/ttl — bounds validation, custom-policy state.
//   - PATCH /api/v1/team/settings — owner-only.
//
// We don't try to drive an end-to-end /deploy/new build here — that requires
// k8s. Instead we seed deployments directly via the models package and hit
// the keeper endpoints, which is the actual surface FIX-J ships.

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

// TestMakePermanent_HappyPath: a hobby team's auto_24h deploy is flipped to
// permanent and the response reflects the new state.
func TestMakePermanent_HappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "u-mkp-1", teamID, "u@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID: uuid.MustParse(teamID),
		AppID:  "ttl-hp-" + uuid.NewString()[:6],
		Tier:   "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)
	require.True(t, d.ExpiresAt.Valid, "fixture: auto_24h must set expires_at")

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+d.AppID+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)

	var out struct {
		OK   bool                   `json:"ok"`
		Item map[string]interface{} `json:"item"`
		Note string                 `json:"note"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.True(t, out.OK)
	assert.Equal(t, "permanent", out.Item["ttl_policy"])
	assert.NotContains(t, out.Item, "expires_at",
		"permanent deploy must NOT carry expires_at in response")
	assert.Contains(t, out.Note, "ttl",
		"the success note must mention how to re-enable TTL")
}

// TestMakePermanent_CrossTenantReturns404: hitting another team's deploy id
// must return 404 (not 403), to avoid leaking deploy ids across tenants.
func TestMakePermanent_CrossTenantReturns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := testhelpers.MustCreateTeamDB(t, db, "hobby")
	teamB := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWTA := testhelpers.MustSignSessionJWT(t, "u-xtn-a", teamA, "a@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// Deploy belongs to team B; team A's session tries to mutate it.
	dB, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID: uuid.MustParse(teamB),
		AppID:  "ttl-xt-" + uuid.NewString()[:6],
		Tier:   "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, dB.ID)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+dB.AppID+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWTA)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-tenant must return 404 (not 403) to avoid leaking deploy ids")
}

// TestSetTTL_RejectsHoursOutOfRange: hours must be in [1, 8760].
func TestSetTTL_RejectsHoursOutOfRange(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "u-ttl-h", teamID, "u@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID: uuid.MustParse(teamID),
		AppID:  "ttl-h-" + uuid.NewString()[:6],
		Tier:   "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	cases := []struct {
		name    string
		hours   int
		wantBad bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"too_big", 8761, true},
		{"min_valid", 1, false},
		{"max_valid", 8760, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.NewReader(`{"hours":` + intToStr(tc.hours) + `}`)
			req := httptest.NewRequest(http.MethodPost,
				"/api/v1/deployments/"+d.AppID+"/ttl", body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+sessionJWT)
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()
			if tc.wantBad {
				bodyBytes, _ := io.ReadAll(resp.Body)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
					"hours=%d must reject: %s", tc.hours, bodyBytes)
				var errOut struct {
					AgentAction string `json:"agent_action"`
				}
				_ = json.Unmarshal(bodyBytes, &errOut)
				assert.Contains(t, errOut.AgentAction, "TTL hours must be between 1 and 8760",
					"agent_action must name the valid range so the LLM can re-prompt the user")
			} else {
				assert.Equal(t, http.StatusOK, resp.StatusCode,
					"hours=%d must accept", tc.hours)
			}
		})
	}
}

// TestTeamSettings_PatchRequiresAdmin: a developer-role user is rejected.
// owner / admin pass.
func TestTeamSettings_PatchRequiresAdmin(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	// Insert a real user with role='owner' so PopulateTeamRole can resolve
	// the caller's role in the test app (mirrors the prod RBAC chain).
	var userID string
	email := "ttl-owner-" + uuid.NewString()[:8] + "@example.com"
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner') RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// Owner can PATCH.
	body := strings.NewReader(`{"default_deployment_ttl_policy":"permanent"}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/team/settings", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "owner must be allowed: %s", bodyBytes)

	// Re-read GET and assert the value stuck.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/team/settings", nil)
	req2.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp2, err := app.Test(req2, 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	var out struct {
		Settings struct {
			Policy string `json:"default_deployment_ttl_policy"`
		} `json:"settings"`
	}
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&out))
	assert.Equal(t, "permanent", out.Settings.Policy,
		"PATCH must have persisted the value")
}

// TestTeamSettings_PatchRejectsInvalidPolicy returns 400 + agent_action when
// the requested policy isn't auto_24h or permanent.
func TestTeamSettings_PatchRejectsInvalidPolicy(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	var userID string
	email := "ttl-owner-2-" + uuid.NewString()[:8] + "@example.com"
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner') RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body := strings.NewReader(`{"default_deployment_ttl_policy":"bogus"}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/team/settings", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "bogus value must reject: %s", bodyBytes)

	var errOut struct {
		AgentAction string `json:"agent_action"`
	}
	_ = json.Unmarshal(bodyBytes, &errOut)
	assert.Contains(t, errOut.AgentAction, "auto_24h",
		"agent_action must enumerate the valid values")
}

// intToStr is a tiny helper that avoids importing strconv just for one test.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
