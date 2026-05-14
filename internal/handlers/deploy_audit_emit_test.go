package handlers_test

// deploy_audit_emit_test.go — guards the audit_log emit sites added by the
// audit-emit-vault-login-deploy slice. Each test asserts that a deploy event
// produces the expected audit_log row(s) with the correct kind + team_id.
//
// The emit helpers in deploy.go fire goroutines so we poll up to ~2s for the
// rows to appear; this matches the existing pattern in webhook tests.
//
// SCHEMA NOTE: testhelpers.runMigrations is currently behind production for
// the deployments table (missing migration 020's private / allowed_ips and
// 026's notify_* columns). We patch those columns inline at the start of
// each test rather than relying on testhelpers — keeps this file's tests
// hermetic and avoids cross-contamination with other deploy_*_test.go files
// that have the same problem.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// patchDeploymentsSchema applies the column adds that runMigrations is
// missing. Idempotent — every ADD COLUMN guard uses IF NOT EXISTS.
func patchDeploymentsSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS private BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS allowed_ips TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_webhook TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_webhook_secret TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_state TEXT NOT NULL DEFAULT 'unset'`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_attempts INT NOT NULL DEFAULT 0`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("patchDeploymentsSchema: %v\n  SQL: %s", err, s)
		}
	}
}

// auditWaitTimeout is the upper bound on how long we wait for a goroutine-
// emitted audit_log row to land. Slower than a sync write but bounded so a
// regression that drops the emit entirely fails the test instead of hanging.
const auditWaitTimeout = 2 * time.Second

// countAuditByKind polls the audit_log table for rows matching (team_id, kind)
// until the count is >= want or the timeout elapses. Returns the final count
// observed so the assertion gets a useful message on miss.
func countAuditByKind(t *testing.T, db *sql.DB, teamID, kind string, want int) int {
	t.Helper()
	deadline := time.Now().Add(auditWaitTimeout)
	var n int
	for {
		require.NoError(t, db.QueryRow(
			`SELECT COUNT(*) FROM audit_log WHERE team_id = $1::uuid AND kind = $2`,
			teamID, kind,
		).Scan(&n))
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestDeployNew_EmitsDeployCreatedAudit asserts that POST /deploy/new with
// the noop compute provider produces a deploy.created audit_log row keyed on
// the requesting team. The noop provider also reports "healthy" status, so
// runDeploy emits deploy.healthy as the terminal state — assert both kinds.
func TestDeployNew_EmitsDeployCreatedAudit(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	patchDeploymentsSchema(t, db)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", teamID, "audit@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"port": "8080"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.14.5.1")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"deploy.created emit depends on the 202 happy-path INSERT — got %d", resp.StatusCode)
	resp.Body.Close()

	// deploy.created is emitted from the request goroutine immediately after
	// CreateDeployment; deploy.healthy is emitted from runDeploy once the
	// noop compute provider returns. Both should land within auditWaitTimeout.
	got := countAuditByKind(t, db, teamID, models.AuditKindDeployCreated, 1)
	assert.GreaterOrEqual(t, got, 1,
		"expected at least one deploy.created audit_log row for team %s; got %d", teamID, got)

	gotHealthy := countAuditByKind(t, db, teamID, models.AuditKindDeployHealthy, 1)
	assert.GreaterOrEqual(t, gotHealthy, 1,
		"noop compute provider returns healthy, so runDeploy must emit deploy.healthy; got %d", gotHealthy)

	// deploy.failed must NOT appear on the success path.
	var failedCount int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE team_id = $1::uuid AND kind = $2`,
		teamID, models.AuditKindDeployFailed,
	).Scan(&failedCount))
	assert.Equal(t, 0, failedCount,
		"deploy.failed must not appear on a successful deploy")
}

// TestDeployNew_AtLimit_NoAuditEmitted asserts the negative case: when the
// tier-limit check rejects the deploy with 402, NO audit_log row is written.
// Catches a regression where deploy.created moves above the limit check.
func TestDeployNew_AtLimit_NoAuditEmitted(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	patchDeploymentsSchema(t, db)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", teamID, "atlimit-audit@example.com")

	// Seed the team at its hobby cap (1). Suffix with the team id so this
	// test is stable across re-runs against the same DB (idx_deployments_app_id
	// is unique).
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'hobby', 'healthy')
	`, teamID, "audit-seed-"+teamID[:8])
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"port": "8080"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.14.5.2")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	resp.Body.Close()

	// Give any incorrectly-placed goroutine a chance to land — we want a
	// failure here to be visible, not flaky.
	time.Sleep(200 * time.Millisecond)

	var n int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE team_id = $1::uuid AND kind = $2`,
		teamID, models.AuditKindDeployCreated,
	).Scan(&n))
	assert.Equal(t, 0, n,
		"deploy.created must not emit when the limit check rejects the call before CreateDeployment runs")
}
