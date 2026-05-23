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

// decodeJSON reads the response body into v.
func decodeJSON(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}

var _ redis.Client
