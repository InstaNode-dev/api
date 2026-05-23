package handlers_test

// deploy_teardown_reconciler_final2_test.go — FINAL SERIAL PASS #2 coverage for
// the DB-error arms of RunTeardownSweep the happy-path reconciler suite leaves
// uncovered (the file sat at ~69%):
//
//   * begin_tx_failed   (L118-121) — closed DB so BeginTx errors
//   * list_failed       (L130-133) — fault DB fails the SELECT
//   * empty-tx commit   (L134-142) — real DB, no expired rows → commit empty tx
//   * mark_failed       (L161-170) — fault DB: SELECT ok, MarkDeploymentTornDown errors
//
// Reuses newReconcilerHandler / seedExpiredDeploy / fakeTeardownProvider /
// reconcilerRequireDB + openFaultDB. The fault DB shares the pooled DB's DSN so
// the seeded expired row is visible to the SELECT before the injected failure.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// begin_tx_failed: a CLOSED DB makes BeginTx error → the sweep returns early.
func TestTeardownFinal2_BeginTxFailed(t *testing.T) {
	reconcilerRequireDB(t)
	closed, err := sql.Open("postgres", testDSN())
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	h := newReconcilerHandler(t, closed, &fakeTeardownProvider{})
	// Must not panic; just returns after begin_tx_failed.
	h.RunTeardownSweep(context.Background())
}

// list_failed: BeginTx ok, the GetExpiredDeploymentsAwaitingTeardown SELECT
// errors (failAfter=0).
func TestTeardownFinal2_ListFailed(t *testing.T) {
	reconcilerRequireDB(t)
	faultDB := openFaultDB(t, 0)
	h := newReconcilerHandler(t, faultDB, &fakeTeardownProvider{})
	h.RunTeardownSweep(context.Background())
}

// empty-tx commit: a real DB with no expired+provider rows → the sweep takes
// the len(expired)==0 commit path.
func TestTeardownFinal2_EmptyCommit(t *testing.T) {
	reconcilerRequireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	// Ensure no expired+provider rows exist for an isolated team — the global
	// table may have rows from other tests, so use a fresh team and assert no
	// teardown happens for it (the empty-path is exercised when the SELECT
	// returns nothing FOR THIS process's lock window; to make it deterministic
	// we clear any expired+provider rows we can see).
	_, _ = db.Exec(`UPDATE deployments SET status = 'deleted' WHERE status = 'expired' AND provider_id <> ''`)
	fake := &fakeTeardownProvider{}
	h := newReconcilerHandler(t, db, fake)
	h.RunTeardownSweep(context.Background())
	assert.Equal(t, 0, fake.teardownCount())
}

// mark_failed: seed an expired+provider row, then run the sweep on a fault DB
// where the SELECT succeeds (sees the seeded row) and Teardown succeeds (fake)
// but MarkDeploymentTornDown errors → the mark_failed arm + DeployTeardownMarkFailed
// counter. failAfter=1 (SELECT is query 1 inside the tx, the mark UPDATE is 2).
func TestTeardownFinal2_MarkFailed(t *testing.T) {
	reconcilerRequireDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, seedDB, "hobby"))
	defer seedDB.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer seedDB.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)
	// Clear other expired rows so our seeded row is the only candidate.
	_, _ = seedDB.Exec(`UPDATE deployments SET status = 'deleted' WHERE status = 'expired' AND provider_id <> '' AND team_id <> $1`, teamID)

	pid := "app-markfail-final2-" + uuid.NewString()[:8]
	seedExpiredDeploy(t, seedDB, teamID, models.DeployStatusExpired, pid)

	faultDB := openFaultDB(t, 1)
	fake := &fakeTeardownProvider{}
	h := newReconcilerHandler(t, faultDB, fake)
	// Should not panic; the mark failure is logged + counted, then the sweep
	// continues and the (rolled-back) commit leaves the row 'expired'.
	h.RunTeardownSweep(context.Background())
}
