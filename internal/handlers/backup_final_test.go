package handlers_test

// backup_final_test.go — FINAL coverage pass for backup.go. Closes the
// mid-handler DB-error arms (team_lookup / insert / list / count / restore
// insert) the vecwave/cursor slices leave open. Uses openFaultDB (staged
// failAfter) so the early auth + ownership lookups succeed and the targeted
// query is the one that errors.
//
// Headline: the count-fails-while-list-succeeds arm (backup.go:252) — the
// fault driver fails AFTER the list query so total falls back to len(items)
// while the page still renders 200.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// bkSeedPGResource inserts an active postgres resource owned by teamID and
// returns its token.
func bkSeedPGResource(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING token::text`, teamID).Scan(&token))
	return token
}

func bkDo(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, method, path, body string) *http.Response {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	var req *http.Request
	if r != nil {
		req = httptest.NewRequest(method, path, r)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

func bkErr(t *testing.T, resp *http.Response) string {
	t.Helper()
	var m map[string]any
	_ = decodeJSON(resp, &m)
	if s, ok := m["error"].(string); ok {
		return s
	}
	return ""
}

// CreateBackup: GetTeamByID errors (backup.go:130). requireOwnedResource(1)
// succeeds, team lookup(2) errors. failAfter=1.
func TestBackupFinal_CreateBackup_TeamLookup_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	userID := uuid.NewString()
	token := bkSeedPGResource(t, seedDB, teamID)

	faultDB := openFaultDB(t, 1)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, userID)
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/backup", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "team_lookup_failed", bkErr(t, resp))
}

// CreateBackup: CreateBackupRow errors (backup.go:185). resource(1) + team(2)
// succeed, INSERT(3) errors. failAfter=2. Use a nil rdb so the rate-limit INCR
// is skipped (it would consume a fault-budget call otherwise).
func TestBackupFinal_CreateBackup_InsertFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	userID := uuid.NewString()
	token := bkSeedPGResource(t, seedDB, teamID)

	faultDB := openFaultDB(t, 2)
	h := handlers.NewBackupHandler(faultDB, nil, plans.Default()) // nil rdb → no INCR
	app := newBackupApp(t, h, teamID, userID)
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/backup", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "backup_create_failed", bkErr(t, resp))
}

// ListBackups: ListBackupsByResource errors (backup.go:245). resource(1)
// succeeds, list(2) errors. failAfter=1.
func TestBackupFinal_ListBackups_ListFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)

	faultDB := openFaultDB(t, 1)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	resp := bkDo(t, app, http.MethodGet, "/api/v1/resources/"+token+"/backups", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "list_failed", bkErr(t, resp))
}

// ListBackups: COUNT fails AFTER the list succeeds (backup.go:252) → 200 with
// total = len(items). resource(1) + list(2) succeed, count(3) errors.
// failAfter=2.
func TestBackupFinal_ListBackups_CountFailWhileListSucceeds_200(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)
	// Seed two backup rows so len(items) > 0.
	var resID string
	require.NoError(t, seedDB.QueryRowContext(context.Background(),
		`SELECT id::text FROM resources WHERE token=$1::uuid`, token).Scan(&resID))
	seedBackupRow(t, seedDB, resID, "ok")
	seedBackupRow(t, seedDB, resID, "ok")

	faultDB := openFaultDB(t, 2)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	resp := bkDo(t, app, http.MethodGet, "/api/v1/resources/"+token+"/backups", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	items, _ := m["items"].([]any)
	total, _ := m["total"].(float64)
	assert.Equal(t, float64(len(items)), total,
		"count failure → total falls back to len(items)")
}

// ListRestores: ListRestoresByResource errors (backup.go:572). resource(1)
// succeeds, list(2) errors. failAfter=1.
func TestBackupFinal_ListRestores_ListFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)

	faultDB := openFaultDB(t, 1)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	resp := bkDo(t, app, http.MethodGet, "/api/v1/resources/"+token+"/restores", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// CreateRestore: GetTeamByID errors → team_lookup_failed (backup.go:411). In-
// place restore (no target). resource(1) succeeds, team(2) errors. failAfter=1.
func TestBackupFinal_CreateRestore_TeamLookup_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)
	var resID string
	require.NoError(t, seedDB.QueryRowContext(context.Background(),
		`SELECT id::text FROM resources WHERE token=$1::uuid`, token).Scan(&resID))
	backupID := seedBackupRow(t, seedDB, resID, "ok")

	faultDB := openFaultDB(t, 1)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	body := `{"backup_id":"` + backupID + `","destructive_acknowledgment":true}`
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/restore", body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "team_lookup_failed", bkErr(t, resp))
}

// CreateRestore: GetBackupByIDForTeam errors → backup_lookup_failed
// (backup.go:438). resource(1) + team(2) succeed, backup lookup(3) errors.
// failAfter=2.
func TestBackupFinal_CreateRestore_BackupLookup_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)
	var resID string
	require.NoError(t, seedDB.QueryRowContext(context.Background(),
		`SELECT id::text FROM resources WHERE token=$1::uuid`, token).Scan(&resID))
	backupID := seedBackupRow(t, seedDB, resID, "ok")

	faultDB := openFaultDB(t, 2)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	body := `{"backup_id":"` + backupID + `","destructive_acknowledgment":true}`
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/restore", body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "backup_lookup_failed", bkErr(t, resp))
}

// CreateRestore: HasInflightRestore errors → inflight_check_failed
// (backup.go:464). resource(1) + team(2) + backup(3) succeed, inflight(4)
// errors. failAfter=3.
func TestBackupFinal_CreateRestore_InflightCheck_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)
	var resID string
	require.NoError(t, seedDB.QueryRowContext(context.Background(),
		`SELECT id::text FROM resources WHERE token=$1::uuid`, token).Scan(&resID))
	backupID := seedBackupRow(t, seedDB, resID, "ok")

	faultDB := openFaultDB(t, 3)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	body := `{"backup_id":"` + backupID + `","destructive_acknowledgment":true}`
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/restore", body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "inflight_check_failed", bkErr(t, resp))
}

// Bad team-id in Locals → unauthorized across CreateBackup / ListBackups /
// CreateRestore / ListRestores (parseTeamID arms 104 / 224 / 320 / 550).
func TestBackupFinal_BadTeamID_Unauthorized(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	h := handlers.NewBackupHandler(db, rdb, plans.Default())
	app := newBackupApp(t, h, "not-a-uuid", uuid.NewString())
	tok := uuid.NewString()
	for _, route := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/resources/" + tok + "/backup"},
		{http.MethodGet, "/api/v1/resources/" + tok + "/backups"},
		{http.MethodPost, "/api/v1/resources/" + tok + "/restore"},
		{http.MethodGet, "/api/v1/resources/" + tok + "/restores"},
	} {
		resp := bkDo(t, app, route.method, route.path, "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "route %s %s", route.method, route.path)
		resp.Body.Close()
	}
}

// Non-UUID :id → invalid_id across the four routes (224 / 230 / 332 / 557).
func TestBackupFinal_BadResourceID_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	h := handlers.NewBackupHandler(db, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/resources/not-a-uuid/backup"},
		{http.MethodGet, "/api/v1/resources/not-a-uuid/backups"},
		{http.MethodPost, "/api/v1/resources/not-a-uuid/restore"},
		{http.MethodGet, "/api/v1/resources/not-a-uuid/restores"},
	} {
		resp := bkDo(t, app, route.method, route.path, "")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "route %s", route.path)
		resp.Body.Close()
	}
}

// CreateRestore: in-place without destructive_acknowledgment → 400
// destructive_ack_required (backup.go:404-area).
func TestBackupFinal_CreateRestore_MissingAck_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := bkSeedPGResource(t, db, teamID)
	var resID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM resources WHERE token=$1::uuid`, token).Scan(&resID))
	backupID := seedBackupRow(t, db, resID, "ok")

	h := handlers.NewBackupHandler(db, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	body := `{"backup_id":"` + backupID + `"}` // no destructive_acknowledgment
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/restore", body)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "destructive_ack_required", bkErr(t, resp))
}

// CreateRestore: CreateRestoreRow errors → restore_create_failed (backup.go:508).
// resource(1)+team(2)+backup(3)+inflight(4) succeed, the INSERT(5) errors.
// failAfter=4.
func TestBackupFinal_CreateRestore_InsertFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)
	var resID string
	require.NoError(t, seedDB.QueryRowContext(context.Background(),
		`SELECT id::text FROM resources WHERE token=$1::uuid`, token).Scan(&resID))
	backupID := seedBackupRow(t, seedDB, resID, "ok")

	faultDB := openFaultDB(t, 4)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	body := `{"backup_id":"` + backupID + `","destructive_acknowledgment":true}`
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/restore", body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "restore_create_failed", bkErr(t, resp))
}

// CreateRestore: missing user session → unauthorized (backup.go:325). The
// newBackupApp helper pins a user; pass "" to drop it.
func TestBackupFinal_CreateRestore_NoUser_401(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := bkSeedPGResource(t, db, teamID)
	h := handlers.NewBackupHandler(db, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, "") // no user-id local
	body := `{"backup_id":"` + uuid.NewString() + `","destructive_acknowledgment":true}`
	resp := bkDo(t, app, http.MethodPost, "/api/v1/resources/"+token+"/restore", body)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ListRestores: COUNT fails after list succeeds → 200 with total=len(items)
// (backup.go:579). resource(1)+list(2) succeed, count(3) errors. failAfter=2.
func TestBackupFinal_ListRestores_CountFail_200(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := bkSeedPGResource(t, seedDB, teamID)

	faultDB := openFaultDB(t, 2)
	h := handlers.NewBackupHandler(faultDB, rdb, plans.Default())
	app := newBackupApp(t, h, teamID, uuid.NewString())
	resp := bkDo(t, app, http.MethodGet, "/api/v1/resources/"+token+"/restores", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// decodeJSON reads the response body into v.
func decodeJSON(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}

var _ redis.Client
