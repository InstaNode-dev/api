package handlers_test

// resource_pause_test.go — covers POST /api/v1/resources/:id/pause and
// /resume. Mirrors the resource_test.go style: each test stands up its own
// DB + Redis + Fiber app, builds a team + user + JWT, inserts a resource row
// directly via SQL (the provisioning pipeline is exercised in db_test.go),
// fires the request, asserts the response shape AND the row's status /
// paused_at columns.
//
// What is NOT covered here (deliberately):
//   - The provider-side REVOKE CONNECT / ACL off / revokeRolesFromUser calls.
//     Those need a live postgres-customers / redis-provision / mongodb pod
//     and live in api/e2e/. The handler short-circuits the provider call
//     when h.cfg.CustomerDatabaseURL / MongoAdminURI is empty (test config),
//     so unit tests exercise the DB-flip + tier-gate path end-to-end without
//     a live backend.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// pauseTestFixture wires up the common test setup: app, DB, Redis, team
// (on the requested plan tier), user, JWT, and a single postgres resource
// row owned by the team. Returns the resource token and the JWT.
type pauseTestFixture struct {
	app           pauseApp
	db            *sql.DB
	resourceToken string
	resourceID    string
	jwt           string
	teamID        string
}

// pauseApp is a tiny interface over *fiber.App that lets us pass either the
// concrete app or a mock from setupPauseFixture without dragging fiber's
// types into the helper signature. Keeps the call sites readable.
type pauseApp interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}

func setupPauseFixture(t *testing.T, planTier string, resourceType string) pauseTestFixture {
	t.Helper()

	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	t.Cleanup(cleanApp)

	teamID := testhelpers.MustCreateTeamDB(t, db, planTier)
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	var resourceToken, resourceID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, $2, $3, 'active')
		RETURNING token::text, id::text
	`, teamID, resourceType, planTier).Scan(&resourceToken, &resourceID))

	return pauseTestFixture{
		app:           app,
		db:            db,
		resourceToken: resourceToken,
		resourceID:    resourceID,
		jwt:           jwt,
		teamID:        teamID,
	}
}

// doPauseOrResume is a tiny wrapper around app.Test for POST /pause | /resume.
func doPauseOrResume(t *testing.T, app pauseApp, jwt, action, token string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+token+"/"+action, nil)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestPauseResource_Pro_Success — a Pro team pauses an active resource. The
// row's status flips to 'paused' and paused_at is set.
func TestPauseResource_Pro_Success(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "postgres")

	resp := doPauseOrResume(t, fix.app, fix.jwt, "pause", fix.resourceToken)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "paused", body["status"])

	var status string
	var pausedAt sql.NullTime
	require.NoError(t, fix.db.QueryRowContext(context.Background(),
		`SELECT status, paused_at FROM resources WHERE id = $1::uuid`,
		fix.resourceID,
	).Scan(&status, &pausedAt))
	assert.Equal(t, "paused", status, "DB row status must be 'paused'")
	assert.True(t, pausedAt.Valid, "paused_at must be set")
	assert.False(t, pausedAt.Time.IsZero(), "paused_at must be a real timestamp")
}

// TestResumeResource_Pro_Success — paused → active flip, paused_at cleared.
func TestResumeResource_Pro_Success(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "postgres")

	// First pause to set up the paused state.
	resp := doPauseOrResume(t, fix.app, fix.jwt, "pause", fix.resourceToken)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now resume.
	resp = doPauseOrResume(t, fix.app, fix.jwt, "resume", fix.resourceToken)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "active", body["status"])

	var status string
	var pausedAt sql.NullTime
	require.NoError(t, fix.db.QueryRowContext(context.Background(),
		`SELECT status, paused_at FROM resources WHERE id = $1::uuid`,
		fix.resourceID,
	).Scan(&status, &pausedAt))
	assert.Equal(t, "active", status)
	assert.False(t, pausedAt.Valid, "paused_at must be NULL after resume")
}

// TestPauseResource_Hobby_402 — pausing on hobby tier returns 402 with the
// upgrade_required code + agent_action. Symmetric with the twin / promote
// tier walls.
func TestPauseResource_Hobby_402(t *testing.T) {
	fix := setupPauseFixture(t, "hobby", "postgres")

	resp := doPauseOrResume(t, fix.app, fix.jwt, "pause", fix.resourceToken)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "upgrade_required", body["error"])

	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action, "402 must carry agent_action")
	assert.Contains(t, action, "Tell the user", "agent_action must satisfy U3 imperative-opening")
	assert.Contains(t, action, "https://instanode.dev/", "agent_action must contain full URL")

	assert.Equal(t, "https://instanode.dev/pricing", body["upgrade_url"])

	// The row must NOT have flipped to paused.
	var status string
	require.NoError(t, fix.db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE id = $1::uuid`,
		fix.resourceID,
	).Scan(&status))
	assert.Equal(t, "active", status, "hobby caller's row must stay active")
}

// TestPauseResource_AlreadyPaused_409 — second pause is an idempotent error
// (409 already_paused). Mirrors the contract spelled out in the task brief.
func TestPauseResource_AlreadyPaused_409(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "redis")

	// First pause.
	resp := doPauseOrResume(t, fix.app, fix.jwt, "pause", fix.resourceToken)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Second pause should 409.
	resp = doPauseOrResume(t, fix.app, fix.jwt, "pause", fix.resourceToken)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "already_paused", body["error"])

	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action, "409 already_paused must carry agent_action")
	assert.Contains(t, action, "Tell the user")
	assert.Contains(t, action, "https://instanode.dev/")
}

// TestResumeResource_NotPaused_409 — resume on an active row is 409 not_paused.
func TestResumeResource_NotPaused_409(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "mongodb")

	// Row is freshly created in active state; resume should 409.
	resp := doPauseOrResume(t, fix.app, fix.jwt, "resume", fix.resourceToken)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "not_paused", body["error"])

	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action)
	assert.Contains(t, action, "Tell the user")
}

// TestPauseResource_CrossTeam_404 — Team B cannot pause Team A's resource.
// Returns 404 (not 403) — cross-team access must not leak existence.
func TestPauseResource_CrossTeam_404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamAID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "pro")
	emailB := testhelpers.UniqueEmail(t)
	var userBID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamBID, emailB,
	).Scan(&userBID))
	jwtB := testhelpers.MustSignSessionJWT(t, userBID, teamBID, emailB)

	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING token::text
	`, teamAID).Scan(&resourceToken))

	resp := doPauseOrResume(t, app, jwtB, "pause", resourceToken)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "not_found", body["error"])
}

// TestPauseResource_Unauthenticated_401 — no JWT → 401.
func TestPauseResource_Unauthenticated_401(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "postgres")
	resp := doPauseOrResume(t, fix.app, "", "pause", fix.resourceToken)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestPauseResource_InvalidUUID_400 — bad :id param → 400 invalid_id.
func TestPauseResource_InvalidUUID_400(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "postgres")
	resp := doPauseOrResume(t, fix.app, fix.jwt, "pause", "not-a-uuid")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_id", body["error"])
}

// TestPauseResource_NotFound_404 — unknown UUID → 404.
func TestPauseResource_NotFound_404(t *testing.T) {
	fix := setupPauseFixture(t, "pro", "postgres")
	resp := doPauseOrResume(t, fix.app, fix.jwt, "pause",
		"00000000-0000-0000-0000-000000000001")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestPausedStorageStillCountsTowardQuota — the iron rule: a paused resource's
// storage_bytes STILL counts toward the per-team storage cap. Otherwise
// "pause + bloat + resume" would be a free quota bypass.
//
// Asserts directly against models.SumStorageBytesByTeamAndType — the function
// quota.CheckStorageQuota calls under the hood — so the contract is verified
// at the model layer rather than via an end-to-end provision wall.
func TestPausedStorageStillCountsTowardQuota(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")

	// Two postgres rows: one active (200MB), one paused (300MB). Sum must
	// be 500MB — the paused row contributes.
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, storage_bytes)
		VALUES ($1::uuid, 'postgres', 'pro', 'active', $2),
		       ($1::uuid, 'postgres', 'pro', 'paused', $3)
	`, teamID, 200*1024*1024, 300*1024*1024)
	require.NoError(t, err)

	teamUUID, err := uuid.Parse(teamID)
	require.NoError(t, err)
	total, err := models.SumStorageBytesByTeamAndType(context.Background(), db, teamUUID, "postgres")
	require.NoError(t, err)

	// 500 MB in bytes.
	assert.Equal(t, int64(500*1024*1024), total,
		"paused resource's storage_bytes MUST count toward the storage cap (iron rule)")

	// A deleted row should NOT contribute — sanity-check the SQL filter.
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, storage_bytes)
		VALUES ($1::uuid, 'postgres', 'pro', 'deleted', $2)
	`, teamID, 999*1024*1024)
	require.NoError(t, err)

	total, err = models.SumStorageBytesByTeamAndType(context.Background(), db, teamUUID, "postgres")
	require.NoError(t, err)
	assert.Equal(t, int64(500*1024*1024), total,
		"deleted rows must be excluded from storage sum")
}
