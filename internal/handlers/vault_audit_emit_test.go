package handlers_test

// vault_audit_emit_test.go — guards the audit_log emit sites added for
// vault.read and vault.write. The dedicated vault_audit_log table already
// covers the security trail; these tests assert the cross-team audit_log
// (the dashboard-feed + Brevo-forwarder source) also receives a row.
//
// Integration test — needs TEST_DATABASE_URL. Skips cleanly otherwise.

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
)

// waitForVaultAuditCount polls audit_log for (team_id, kind) rows until the
// count is >= want or the timeout elapses. Mirrors countAuditByKind in
// deploy_audit_emit_test.go but lives here too so the file is self-contained
// and the helper name is unambiguous for a future reader.
func waitForVaultAuditCount(t *testing.T, db *sql.DB, teamID uuid.UUID, kind string, want int) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var n int
	for {
		require.NoError(t, db.QueryRow(
			`SELECT COUNT(*) FROM audit_log WHERE team_id = $1 AND kind = $2`,
			teamID, kind,
		).Scan(&n))
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestVault_AuditLogEmits_OnReadAndWrite walks PUT → GET → DELETE and asserts
// each successful op produces exactly one audit_log row of the expected kind.
func TestVault_AuditLogEmits_OnReadAndWrite(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	teamIDStr, _, jwt := makeTeamUser(t, db)
	teamID := uuid.MustParse(teamIDStr)

	const env, key = "production", "AUDIT_EMIT_KEY"

	// PUT (create v1) → must emit one vault.write row (operation=create).
	resp, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt, map[string]string{"value": "v1"}), 5000)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	writes := waitForVaultAuditCount(t, db, teamID, models.AuditKindVaultWrite, 1)
	assert.Equal(t, 1, writes, "PUT (create) must emit exactly one vault.write audit_log row")

	// PUT again (v2) → another vault.write row (operation=update).
	resp2, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt, map[string]string{"value": "v2"}), 5000)
	require.NoError(t, err)
	resp2.Body.Close()
	require.Equal(t, http.StatusCreated, resp2.StatusCode)

	writes = waitForVaultAuditCount(t, db, teamID, models.AuditKindVaultWrite, 2)
	assert.Equal(t, 2, writes, "second PUT (update) must produce a 2nd vault.write row")

	// GET → must emit one vault.read row.
	resp3, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	resp3.Body.Close()
	require.Equal(t, http.StatusOK, resp3.StatusCode)

	reads := waitForVaultAuditCount(t, db, teamID, models.AuditKindVaultRead, 1)
	assert.Equal(t, 1, reads, "successful GET must emit exactly one vault.read audit_log row")

	// DELETE → 3rd vault.write row (operation=delete).
	resp4, err := app.Test(jsonReq(t, http.MethodDelete, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	resp4.Body.Close()
	require.Equal(t, http.StatusNoContent, resp4.StatusCode)

	writes = waitForVaultAuditCount(t, db, teamID, models.AuditKindVaultWrite, 3)
	assert.Equal(t, 3, writes, "DELETE must produce a 3rd vault.write row (operation=delete)")
}

// TestVault_AuditLog_NotEmittedOn404 confirms the negative path: a GET that
// returns 404 (missing key) must NOT emit a vault.read row.
func TestVault_AuditLog_NotEmittedOn404(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	teamIDStr, _, jwt := makeTeamUser(t, db)
	teamID := uuid.MustParse(teamIDStr)

	resp, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/production/DOES_NOT_EXIST", jwt, nil), 5000)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Give a misbehaving emit a chance to land before we read the count.
	time.Sleep(200 * time.Millisecond)

	rows, err := models.ListAuditEventsByTeam(context.Background(), db, teamID, 20, models.AuditKindVaultRead)
	require.NoError(t, err)
	assert.Empty(t, rows, "404 read must NOT emit vault.read — got %d row(s)", len(rows))
}
