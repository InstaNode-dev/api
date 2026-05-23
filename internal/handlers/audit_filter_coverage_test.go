package handlers_test

// audit_filter_coverage_test.go — drives the uncovered filter / tier / CSV /
// masked-email arms of the customer audit-export handler (audit.go). The
// endpoint is wired into NewTestApp and is DB-only; the existing
// audit_export_test.go covers the happy path, but the query-param branches
// (kind / since / until / before / limit clamp, per-tier lookback, CSV
// streaming, masked-email lookup) were only partially exercised under CI.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestAudit_Filters_And_Tiers(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID, jwt := seedUserAndJWT(t, db, teamID)

	now := time.Now().UTC()
	// Three rows with distinct kinds + a user_id so the masked-email lookup runs.
	for i, kind := range []string{"provision", "delete", "rotate_credentials"} {
		_, err := db.Exec(`INSERT INTO audit_log (team_id, user_id, actor, kind, summary, created_at)
			VALUES ($1::uuid, $2::uuid, 'user', $3, 'did a thing', $4)`,
			teamID, userID, kind, now.Add(-time.Duration(i)*time.Hour))
		require.NoError(t, err)
	}

	doGet := func(query string) (*http.Response) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit"+query, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}

	t.Run("kind_filter", func(t *testing.T) {
		resp := doGet("?kind=provision")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			Items []map[string]any `json:"items"`
			Tier  string           `json:"tier"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		resp.Body.Close()
		assert.Equal(t, "pro", body.Tier)
		// Only provision rows.
		for _, it := range body.Items {
			assert.Equal(t, "provision", it["kind"])
		}
	})

	t.Run("since_until_window", func(t *testing.T) {
		since := now.Add(-90 * time.Minute).Format(time.RFC3339)
		until := now.Add(1 * time.Minute).Format(time.RFC3339)
		resp := doGet("?since=" + since + "&until=" + until)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("before_cursor", func(t *testing.T) {
		before := now.Add(1 * time.Hour).Format(time.RFC3339)
		resp := doGet("?before=" + before + "&limit=1")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			NextCursor any `json:"next_cursor"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		resp.Body.Close()
		// limit=1 with 3 rows → page full → next_cursor populated.
		assert.NotNil(t, body.NextCursor)
	})

	t.Run("limit_clamp_huge", func(t *testing.T) {
		resp := doGet("?limit=999999")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("limit_negative_falls_to_default", func(t *testing.T) {
		resp := doGet("?limit=-5")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("invalid_before", func(t *testing.T) {
		resp := doGet("?before=not-a-date")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("invalid_since", func(t *testing.T) {
		resp := doGet("?since=nope")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("invalid_until", func(t *testing.T) {
		resp := doGet("?until=nope")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("csv_export", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv?kind=provision", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAudit_TierGate_FreeRejected(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	_, jwt := seedUserAndJWT(t, db, teamID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	// free tier → upgrade_required (402).
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	resp.Body.Close()
}

func TestAudit_TierLookback_AllTiers(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	for _, tier := range []string{"hobby", "hobby_plus", "pro", "growth", "team"} {
		teamID := testhelpers.MustCreateTeamDB(t, db, tier)
		_, jwt := seedUserAndJWT(t, db, teamID)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "tier=%s", tier)
		var body struct {
			LookbackDays int `json:"lookback_days"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		// growth/team are unlimited (-1); others positive.
		if tier == "growth" || tier == "team" {
			assert.Equal(t, -1, body.LookbackDays, "tier=%s", tier)
		} else {
			assert.Greater(t, body.LookbackDays, 0, "tier=%s", tier)
		}
	}
}

