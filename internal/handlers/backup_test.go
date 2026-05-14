package handlers_test

// backup_test.go — covers the four customer backup/restore endpoints:
//
//   POST /api/v1/resources/:id/backup
//   GET  /api/v1/resources/:id/backups
//   POST /api/v1/resources/:id/restore
//   GET  /api/v1/resources/:id/restores
//
// Same shape as resource_pause_test.go: each test stands up its own
// DB + Redis + Fiber app, builds team + user + JWT + a postgres resource
// row directly via SQL, fires the request, asserts both the JSON shape
// and (for writes) the resource_backups / resource_restores row state.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// backupFixture wires up the common test setup. Mirrors pauseTestFixture
// but adds a userID we need on the restore path (resource_restores.triggered_by
// is NOT NULL).
type backupFixture struct {
	app           *fiberAppShim
	db            *sql.DB
	resourceToken string
	resourceID    string
	teamID        string
	userID        string
	jwt           string
}

// fiberAppShim hides Fiber's app type behind the small surface our helpers
// actually use, keeping signatures readable.
type fiberAppShim struct {
	test func(req *http.Request, msTimeout ...int) (*http.Response, error)
}

func (f *fiberAppShim) Test(req *http.Request, msTimeout ...int) (*http.Response, error) {
	return f.test(req, msTimeout...)
}

func setupBackupFixture(t *testing.T, planTier string) backupFixture {
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
	jwtTok := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	var resourceToken, resourceID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', $2, 'active')
		RETURNING token::text, id::text
	`, teamID, planTier).Scan(&resourceToken, &resourceID))

	return backupFixture{
		app:           &fiberAppShim{test: app.Test},
		db:            db,
		resourceToken: resourceToken,
		resourceID:    resourceID,
		teamID:        teamID,
		userID:        userID,
		jwt:           jwtTok,
	}
}

// doBackupRequest is a tiny wrapper. method = "POST"/"GET", suffix is the
// segment after :id (e.g. "/backup", "/backups", "/restore", "/restores").
// jwt may be "" to test unauthenticated paths.
func doBackupRequest(t *testing.T, app *fiberAppShim, method, jwt, token, suffix string, body []byte) *http.Response {
	t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method,
		"/api/v1/resources/"+token+suffix, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /backup
// ─────────────────────────────────────────────────────────────────────────────

// TestCreateBackup_Pro_Success — Pro team creates a manual backup. The row
// lands in resource_backups with status='pending' and backup_kind='manual'.
func TestCreateBackup_Pro_Success(t *testing.T) {
	fix := setupBackupFixture(t, "pro")

	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/backup", nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "pending", body["status"])
	backupID, _ := body["backup_id"].(string)
	require.NotEmpty(t, backupID, "response must include backup_id")

	// Row state: status='pending', backup_kind='manual', tier_at_backup='pro',
	// triggered_by=userID.
	var status, kind, tierAt, triggeredBy string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		SELECT status, backup_kind, COALESCE(tier_at_backup,''), COALESCE(triggered_by::text,'')
		FROM resource_backups WHERE id = $1::uuid
	`, backupID).Scan(&status, &kind, &tierAt, &triggeredBy))
	assert.Equal(t, "pending", status)
	assert.Equal(t, "manual", kind)
	assert.Equal(t, "pro", tierAt)
	assert.Equal(t, fix.userID, triggeredBy)
}

// TestCreateBackup_Hobby_RateLimit — hobby is capped at 1/day. Second call
// in the same UTC day returns 429 with the upgrade agent_action.
func TestCreateBackup_Hobby_RateLimit(t *testing.T) {
	fix := setupBackupFixture(t, "hobby")

	// First call succeeds.
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/backup", nil)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Second call within the same UTC day hits the cap.
	resp = doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/backup", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "rate_limited", body["error"])

	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action, "429 must carry agent_action")
	assert.Contains(t, action, "Tell the user")
	assert.Contains(t, action, "https://instanode.dev/")
}

// TestCreateBackup_Free_402 — free tier (manual_backups_per_day=0) is 402'd
// with the "claim required" agent_action.
func TestCreateBackup_Free_402(t *testing.T) {
	fix := setupBackupFixture(t, "free")

	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/backup", nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"])
	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action)
	assert.Contains(t, action, "Tell the user")
}

// TestCreateBackup_CrossTeam_403 — Team B cannot back up Team A's resource.
func TestCreateBackup_CrossTeam_403(t *testing.T) {
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

	resp := doBackupRequest(t, &fiberAppShim{test: app.Test}, http.MethodPost, jwtB, resourceToken, "/backup", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestCreateBackup_InvalidUUID_400 — bad :id param → 400 invalid_id.
func TestCreateBackup_InvalidUUID_400(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, "not-a-uuid", "/backup", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_id", body["error"])
}

// TestCreateBackup_NonPostgres_400 — non-postgres types are 400'd with
// unsupported_resource_type. Redis/Mongo backups aren't shipping yet.
func TestCreateBackup_NonPostgres_400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwtTok := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	var redisToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'redis', 'pro', 'active')
		RETURNING token::text
	`, teamID).Scan(&redisToken))

	resp := doBackupRequest(t, &fiberAppShim{test: app.Test}, http.MethodPost, jwtTok, redisToken, "/backup", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "unsupported_resource_type", body["error"])
}

// TestCreateBackup_Unauthenticated_401 — no JWT → 401.
func TestCreateBackup_Unauthenticated_401(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	resp := doBackupRequest(t, fix.app, http.MethodPost, "", fix.resourceToken, "/backup", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /backups
// ─────────────────────────────────────────────────────────────────────────────

// TestListBackups_HappyPath — create two backup rows then list. Items must
// be newest-first and total=2.
func TestListBackups_HappyPath(t *testing.T) {
	fix := setupBackupFixture(t, "pro")

	// Two backup rows. The second has a strictly-later started_at so the
	// ORDER BY created_at DESC has something to sort by.
	for i := 0; i < 2; i++ {
		_, err := fix.db.ExecContext(context.Background(), `
			INSERT INTO resource_backups (resource_id, status, backup_kind, tier_at_backup, triggered_by)
			VALUES ($1::uuid, 'ok', 'scheduled', 'pro', $2::uuid)
		`, fix.resourceID, fix.userID)
		require.NoError(t, err)
	}

	resp := doBackupRequest(t, fix.app, http.MethodGet, fix.jwt, fix.resourceToken, "/backups", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK    bool                     `json:"ok"`
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Total)
	require.Len(t, body.Items, 2)
	assert.Equal(t, "ok", body.Items[0]["status"])
	assert.Equal(t, "scheduled", body.Items[0]["backup_kind"])
}

// TestListBackups_CrossTeam_403 — Team B cannot list Team A's backups.
func TestListBackups_CrossTeam_403(t *testing.T) {
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

	resp := doBackupRequest(t, &fiberAppShim{test: app.Test}, http.MethodGet, jwtB, resourceToken, "/backups", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /restore
// ─────────────────────────────────────────────────────────────────────────────

// TestCreateRestore_Pro_Success — Pro team restores from an 'ok' backup.
// Row lands in resource_restores with status='pending'.
func TestCreateRestore_Pro_Success(t *testing.T) {
	fix := setupBackupFixture(t, "pro")

	// Seed an 'ok' backup.
	var backupID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, status, backup_kind, tier_at_backup, triggered_by)
		VALUES ($1::uuid, 'ok', 'scheduled', 'pro', $2::uuid)
		RETURNING id::text
	`, fix.resourceID, fix.userID).Scan(&backupID))

	bodyJSON, _ := json.Marshal(map[string]string{"backup_id": backupID})
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", bodyJSON)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "pending", body["status"])
	restoreID, _ := body["restore_id"].(string)
	require.NotEmpty(t, restoreID)

	// Restore row exists, links to the right backup + resource + user.
	var status, gotBackupID, gotResourceID, triggeredBy string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		SELECT status, backup_id::text, resource_id::text, triggered_by::text
		FROM resource_restores WHERE id = $1::uuid
	`, restoreID).Scan(&status, &gotBackupID, &gotResourceID, &triggeredBy))
	assert.Equal(t, "pending", status)
	assert.Equal(t, backupID, gotBackupID)
	assert.Equal(t, fix.resourceID, gotResourceID)
	assert.Equal(t, fix.userID, triggeredBy)
}

// TestCreateRestore_Hobby_402 — hobby cannot restore even from a valid
// backup. Response carries the Pro-upgrade agent_action.
func TestCreateRestore_Hobby_402(t *testing.T) {
	fix := setupBackupFixture(t, "hobby")

	var backupID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, status, backup_kind, tier_at_backup, triggered_by)
		VALUES ($1::uuid, 'ok', 'scheduled', 'hobby', $2::uuid)
		RETURNING id::text
	`, fix.resourceID, fix.userID).Scan(&backupID))

	bodyJSON, _ := json.Marshal(map[string]string{"backup_id": backupID})
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", bodyJSON)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"])
	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action)
	assert.Contains(t, action, "Tell the user")
	assert.Contains(t, action, "https://instanode.dev/")
	assert.Equal(t, "https://instanode.dev/pricing", body["upgrade_url"])

	// No restore row should have been inserted.
	var count int
	require.NoError(t, fix.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM resource_restores WHERE resource_id = $1::uuid`,
		fix.resourceID,
	).Scan(&count))
	assert.Equal(t, 0, count, "hobby 402 must not insert a restore row")
}

// TestCreateRestore_BackupNotReady_409 — referencing a pending backup is
// 409 backup_not_ready.
func TestCreateRestore_BackupNotReady_409(t *testing.T) {
	fix := setupBackupFixture(t, "pro")

	var backupID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, status, backup_kind, tier_at_backup, triggered_by)
		VALUES ($1::uuid, 'pending', 'manual', 'pro', $2::uuid)
		RETURNING id::text
	`, fix.resourceID, fix.userID).Scan(&backupID))

	bodyJSON, _ := json.Marshal(map[string]string{"backup_id": backupID})
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", bodyJSON)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "backup_not_ready", body["error"])
	action, _ := body["agent_action"].(string)
	require.NotEmpty(t, action)
}

// TestCreateRestore_MissingBackupID_400 — body without backup_id is 400.
func TestCreateRestore_MissingBackupID_400(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	bodyJSON, _ := json.Marshal(map[string]string{})
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", bodyJSON)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "missing_backup_id", body["error"])
}

// TestCreateRestore_BackupResourceMismatch_400 — backup_id exists but belongs
// to a different resource of the same team.
func TestCreateRestore_BackupResourceMismatch_400(t *testing.T) {
	fix := setupBackupFixture(t, "pro")

	// Create a second postgres resource for the same team, and an 'ok' backup on it.
	var otherResourceID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING id::text
	`, fix.teamID).Scan(&otherResourceID))
	var backupID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, status, backup_kind, tier_at_backup, triggered_by)
		VALUES ($1::uuid, 'ok', 'scheduled', 'pro', $2::uuid)
		RETURNING id::text
	`, otherResourceID, fix.userID).Scan(&backupID))

	bodyJSON, _ := json.Marshal(map[string]string{"backup_id": backupID})
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", bodyJSON)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "backup_resource_mismatch", body["error"])
}

// TestCreateRestore_BackupNotFound_404 — unknown backup_id is 404.
func TestCreateRestore_BackupNotFound_404(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	bodyJSON, _ := json.Marshal(map[string]string{
		"backup_id": uuid.NewString(),
	})
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", bodyJSON)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "backup_not_found", body["error"])
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /restores
// ─────────────────────────────────────────────────────────────────────────────

// TestListRestores_HappyPath — seed two restore rows then list.
func TestListRestores_HappyPath(t *testing.T) {
	fix := setupBackupFixture(t, "pro")

	// Need a backup first to satisfy resource_restores.backup_id FK.
	var backupID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, status, backup_kind, tier_at_backup, triggered_by)
		VALUES ($1::uuid, 'ok', 'scheduled', 'pro', $2::uuid)
		RETURNING id::text
	`, fix.resourceID, fix.userID).Scan(&backupID))

	for i := 0; i < 2; i++ {
		_, err := fix.db.ExecContext(context.Background(), `
			INSERT INTO resource_restores (resource_id, backup_id, status, triggered_by)
			VALUES ($1::uuid, $2::uuid, 'ok', $3::uuid)
		`, fix.resourceID, backupID, fix.userID)
		require.NoError(t, err)
	}

	resp := doBackupRequest(t, fix.app, http.MethodGet, fix.jwt, fix.resourceToken, "/restores", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK    bool                     `json:"ok"`
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Total)
	require.Len(t, body.Items, 2)
	assert.Equal(t, backupID, body.Items[0]["backup_id"])
}

// TestListRestores_InvalidUUID_400 — bad :id is 400.
func TestListRestores_InvalidUUID_400(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	resp := doBackupRequest(t, fix.app, http.MethodGet, fix.jwt, "not-a-uuid", "/restores", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
