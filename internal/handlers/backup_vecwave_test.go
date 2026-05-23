package handlers_test

// backup_vecwave_test.go — residual coverage for backup.go (the _vecwave wave).
// Targets the CreateRestore target_resource_id arms and the list/map helper
// branches the existing backup_test.go leaves uncovered:
//
//   CreateRestore:
//     - invalid_target_resource_id (400) — non-UUID target.
//     - target_not_found (404) — UUID target that doesn't exist.
//     - target_cross_team (403) — target owned by another team.
//     - target_type_mismatch (400) — target is a different resource_type.
//     - target happy path (200) — restore-into-different-resource: skips the
//       destructive-ack gate and stamps target_resource_id in the response.
//   backupToMap / restoreToMap:
//     - all-optional-fields-valid branch (finished_at, size_bytes,
//       tier_at_backup, error_summary) via a terminal-state row.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// seedBackupRow inserts a resource_backups row in the given status for the
// resource. When status is a terminal one (ok), it also stamps finished_at /
// size_bytes / tier_at_backup / error_summary so backupToMap's optional-field
// branches all run on the list path. Returns the backup id.
func seedBackupRow(t *testing.T, db *sql.DB, resourceID, status string) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups
		  (resource_id, backup_kind, status, tier_at_backup, size_bytes, finished_at, error_summary, sha256)
		VALUES ($1::uuid, 'manual', $2, 'pro', 4096, now(), 'none', 'deadbeef')
		RETURNING id::text
	`, resourceID, status).Scan(&id))
	return id
}

func TestRestore_InvalidTargetResourceID_400_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	backupID := seedBackupRow(t, fix.db, fix.resourceID, "ok")

	body := []byte(`{"backup_id":"` + backupID + `","target_resource_id":"not-a-uuid"}`)
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", body)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "invalid_target_resource_id", out["error"])
}

func TestRestore_TargetNotFound_404_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	backupID := seedBackupRow(t, fix.db, fix.resourceID, "ok")

	body := []byte(`{"backup_id":"` + backupID + `","target_resource_id":"` + uuid.NewString() + `"}`)
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", body)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "target_not_found", out["error"])
}

func TestRestore_TargetCrossTeam_403_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	backupID := seedBackupRow(t, fix.db, fix.resourceID, "ok")

	// A resource owned by a DIFFERENT team.
	otherTeam := testhelpers.MustCreateTeamDB(t, fix.db, "pro")
	var otherToken string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active') RETURNING token::text
	`, otherTeam).Scan(&otherToken))

	body := []byte(`{"backup_id":"` + backupID + `","target_resource_id":"` + otherToken + `"}`)
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", body)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "target_cross_team", out["error"])
}

func TestRestore_TargetTypeMismatch_400_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	backupID := seedBackupRow(t, fix.db, fix.resourceID, "ok")

	// A same-team target of a DIFFERENT resource_type.
	var redisToken string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'redis', 'pro', 'active') RETURNING token::text
	`, fix.teamID).Scan(&redisToken))

	body := []byte(`{"backup_id":"` + backupID + `","target_resource_id":"` + redisToken + `"}`)
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", body)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "target_type_mismatch", out["error"])
}

// TestRestore_TargetHappyPath_NoAck_200_Vecwave drives the restore-into-a-
// different-resource success path: the destructive-ack gate is skipped (the
// agent opted into a clean DB by choosing a target), the row is created, and
// the response carries target_resource_id.
func TestRestore_TargetHappyPath_NoAck_200_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	backupID := seedBackupRow(t, fix.db, fix.resourceID, "ok")

	// Same-team, same-type target.
	var targetToken, targetID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active') RETURNING token::text, id::text
	`, fix.teamID).Scan(&targetToken, &targetID))

	// No destructive_acknowledgment — must still succeed for a target restore.
	body := []byte(`{"backup_id":"` + backupID + `","target_resource_id":"` + targetToken + `"}`)
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", body)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	assert.Equal(t, false, out["in_place"])
	assert.NotEmpty(t, out["restore_id"])
	assert.NotNil(t, out["target_resource_id"])

	// The restore row must point at the TARGET resource, not the source.
	var rowResourceID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(),
		`SELECT resource_id::text FROM resource_restores WHERE id = $1::uuid`,
		out["restore_id"]).Scan(&rowResourceID))
	assert.Equal(t, targetID, rowResourceID)
}

// TestListBackups_AllOptionalFields_Vecwave seeds a terminal-state backup row
// with every optional column populated so backupToMap's valid-branch for
// finished_at / size_bytes / tier_at_backup / error_summary all run.
func TestListBackups_AllOptionalFields_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	_ = seedBackupRow(t, fix.db, fix.resourceID, "ok")

	resp := doBackupRequest(t, fix.app, http.MethodGet, fix.jwt, fix.resourceToken, "/backups", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.True(t, out.OK)
	require.NotEmpty(t, out.Items)
	row := out.Items[0]
	assert.NotNil(t, row["finished_at"])
	assert.NotNil(t, row["size_bytes"])
	assert.Equal(t, "pro", row["tier_at_backup"])
	assert.Equal(t, "none", row["error_summary"])
}

// TestListRestores_AllOptionalFields_Vecwave does the same for restoreToMap.
func TestListRestores_AllOptionalFields_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	backupID := seedBackupRow(t, fix.db, fix.resourceID, "ok")

	// A terminal-state restore row with finished_at + error_summary populated.
	_, err := fix.db.ExecContext(context.Background(), `
		INSERT INTO resource_restores
		  (resource_id, backup_id, triggered_by, status, finished_at, error_summary)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'failed', now(), 'boom')
	`, fix.resourceID, backupID, fix.userID)
	require.NoError(t, err)

	resp := doBackupRequest(t, fix.app, http.MethodGet, fix.jwt, fix.resourceToken, "/restores", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.Items)
	row := out.Items[0]
	assert.NotNil(t, row["finished_at"])
	assert.Equal(t, "boom", row["error_summary"])
}

// TestBackup_RequireOwnedResource_FetchFailed_503_Vecwave drives the
// requireOwnedResource non-not-found DB-error arm (fetch_failed → 503) via a
// broken DB handle.
func TestBackup_RequireOwnedResource_FetchFailed_503_Vecwave(t *testing.T) {
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := uuid.NewString()
	userID := uuid.NewString()
	h := handlers.NewBackupHandler(brokenDB(t), rdb, plans.Default())
	app := newBackupApp(t, h, teamID, userID)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+uuid.NewString()+"/backup", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "fetch_failed", out["error"])
}

// TestBackup_ParseUserIDFromCtx_Malformed_Vecwave drives parseUserIDFromCtx's
// parse-failure arm: a malformed user_id local on a CreateBackup call. Backup
// tolerates uuid.Nil (the triggered_by column is nullable), so the request
// still proceeds — exercising the err!=nil → return uuid.Nil branch.
func TestBackup_ParseUserIDFromCtx_Malformed_Vecwave(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active') RETURNING token::text`,
		teamID).Scan(&resourceToken))

	h := handlers.NewBackupHandler(db, rdb, plans.Default())
	// userID = garbage → parseUserIDFromCtx returns uuid.Nil.
	app := newBackupApp(t, h, teamID, "not-a-uuid")

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+resourceToken+"/backup", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "backup tolerates a Nil user id")
}

// TestBackup_ListCursor_LimitTooLarge_400_Vecwave drives parseIntStrict's
// "too large" ceiling (n > 1<<20) via ?limit=99999999, which parseListCursor
// surfaces as 400 invalid_cursor.
func TestBackup_ListCursor_LimitTooLarge_400_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")
	resp := doBackupRequest(t, fix.app, http.MethodGet, fix.jwt, fix.resourceToken,
		"/backups?limit=99999999", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "invalid_cursor", out["error"])
}

// TestRestore_InPlace_MissingSHA256_Warn_Vecwave drives CreateRestore's
// legacy-fail-open arm: an in-place restore (destructive ack) from a backup row
// whose sha256 is NULL (pre-migration-043). The restore still succeeds (200)
// after logging the "missing_sha256" warning.
func TestRestore_InPlace_MissingSHA256_Warn_Vecwave(t *testing.T) {
	fix := setupBackupFixture(t, "pro")

	// Seed an OK backup with a NULL sha256.
	var backupID string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, backup_kind, status, tier_at_backup)
		VALUES ($1::uuid, 'manual', 'ok', 'pro') RETURNING id::text`,
		fix.resourceID).Scan(&backupID))

	body := []byte(`{"backup_id":"` + backupID + `","destructive_acknowledgment":true}`)
	resp := doBackupRequest(t, fix.app, http.MethodPost, fix.jwt, fix.resourceToken, "/restore", body)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	assert.Equal(t, true, out["in_place"])
}

// newBackupApp wires a fiber app with a fake-auth shim pinning team/user and
// the four backup/restore routes.
func newBackupApp(t *testing.T, h *handlers.BackupHandler, teamID, userID string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		c.Locals(middleware.LocalKeyUserID, userID)
		return c.Next()
	})
	app.Post("/api/v1/resources/:id/backup", h.CreateBackup)
	app.Get("/api/v1/resources/:id/backups", h.ListBackups)
	app.Post("/api/v1/resources/:id/restore", h.CreateRestore)
	app.Get("/api/v1/resources/:id/restores", h.ListRestores)
	return app
}
