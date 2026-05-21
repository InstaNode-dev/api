package handlers_test

// webhook_idor_test.go — SRR security-cluster 2026-05-21 / H46 F2.
//
// GET /api/v1/webhooks/:token/requests is intentionally readable with
// just the token (the token IS the credential — agents stash it in
// scripts, the token appears in upstream delivery logs). The IDOR risk
// is the cross-team-session case: an authenticated user from team A
// submitting team B's token. The session is the strong signal that this
// is a poach attempt; reject with 403 cross_team_session.
//
// This file asserts the three branches of the auth gate:
//
//   - Cross-team session (team A's JWT + team B's webhook token) → 403
//     cross_team_session.
//   - Same-team session (team A's JWT + team A's webhook token) → 200.
//   - No session at all (anonymous request with a team-owned token) →
//     200 (token-as-bearer path).
//
// Anonymous-tier webhooks (resource.TeamID not set) are covered by the
// existing happy-path tests in webhook_test.go.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// mintTeamOwnedWebhook inserts a webhook resource owned by teamID and
// returns its token (UUID string).
func mintTeamOwnedWebhook(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	tid := uuid.MustParse(teamID)
	res, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
		TeamID:       &tid,
		ResourceType: models.ResourceTypeWebhook,
		Name:         "webhook-idor-" + uuid.NewString()[:8],
		Tier:         "pro",
		Fingerprint:  "fp-idor-" + uuid.NewString(),
	})
	require.NoError(t, err)
	// MarkResourceActive flips status pending→active; the list-requests
	// handler rejects non-active resources with 410.
	require.NoError(t, models.MarkResourceActive(context.Background(), db, res.ID))
	return res.Token.String()
}

// TestWebhookListRequests_CrossTeamSession_Returns403 asserts the H46-F2
// fix: a session JWT for team A submitting team B's webhook token is
// rejected with 403 cross_team_session, even though the caller is in
// possession of a valid token UUID.
func TestWebhookListRequests_CrossTeamSession_Returns403(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	// Team A owns the webhook. Team B has a valid session but no
	// relation to the webhook.
	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := mintTeamOwnedWebhook(t, db, teamA)
	teamBSession := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB, "ops-b@example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	req.Header.Set("Authorization", "Bearer "+teamBSession)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"team B's session reading team A's webhook must be rejected with 403")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "cross_team_session", body["error"],
		"error code must be cross_team_session so dashboards/agents can branch on it")
}

// TestWebhookListRequests_SameTeamSession_Returns200 asserts that the
// team that owns the webhook can still read with its own session JWT —
// the IDOR fix must not break the legitimate owner-read path.
func TestWebhookListRequests_SameTeamSession_Returns200(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := mintTeamOwnedWebhook(t, db, teamA)
	teamASession := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamA, "ops-a@example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	req.Header.Set("Authorization", "Bearer "+teamASession)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"same-team session reading own webhook must succeed (no IDOR false positive)")
}

// TestWebhookListRequests_NoSession_TokenAsBearer_Returns200 asserts
// the token-as-bearer happy path: an unauthenticated caller in
// possession of a valid token UUID can read. This is by design — the
// token IS the credential; the IDOR fix only adds an extra check when
// a session is also presented.
func TestWebhookListRequests_NoSession_TokenAsBearer_Returns200(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := mintTeamOwnedWebhook(t, db, teamA)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer io.Copy(io.Discard, resp.Body)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"unauthenticated request with valid token must succeed — token IS the credential")
}
