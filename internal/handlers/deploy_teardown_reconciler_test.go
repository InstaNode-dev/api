package handlers_test

// deploy_teardown_reconciler_test.go — P3 coverage: the api teardown
// reconciler that destroys the compute behind auto-expired deployments.
//
// Before P3 the worker's DeploymentExpirer flipped deploys to
// status='expired' and nothing ever tore down the k8s namespace / pod /
// Ingress / cert — leaked, billed infra forever. RunTeardownSweep is the
// fix. These tests assert it (a) calls compute.Teardown for every expired
// row carrying a provider_id, (b) advances the row to the terminal
// 'deleted' status, (c) leaves a row alone when Teardown fails so it is
// retried, and (d) never double-tears-down an already-'deleted' row.
//
// The reconciler's compute backend is injected via SetComputeProvider so
// the test can use a recording fake. Skips when TEST_DATABASE_URL is unset.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/providers/compute"
	"instant.dev/internal/testhelpers"
)

// fakeTeardownProvider is a compute.Provider double that records every
// Teardown call and can be told to fail teardown for a specific provider_id.
type fakeTeardownProvider struct {
	mu       sync.Mutex
	tornDown []string
	failFor  map[string]bool
}

func (f *fakeTeardownProvider) Teardown(_ context.Context, providerID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFor[providerID] {
		return errors.New("simulated teardown failure")
	}
	f.tornDown = append(f.tornDown, providerID)
	return nil
}

func (f *fakeTeardownProvider) teardownCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tornDown)
}

// The reconciler only calls Teardown; the rest of the compute.Provider
// surface is stubbed to satisfy the interface.
func (f *fakeTeardownProvider) Deploy(context.Context, compute.DeployOptions) (*compute.AppDeployment, error) {
	return nil, nil
}
func (f *fakeTeardownProvider) Status(context.Context, string) (*compute.AppDeployment, error) {
	return nil, nil
}
func (f *fakeTeardownProvider) Logs(context.Context, string, bool) (io.ReadCloser, error) {
	return nil, nil
}
func (f *fakeTeardownProvider) Redeploy(context.Context, string, []byte, map[string]string) (*compute.AppDeployment, error) {
	return nil, nil
}
func (f *fakeTeardownProvider) UpdateAccessControl(context.Context, string, bool, []string) error {
	return nil
}

func reconcilerRequireDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping teardown reconciler integration test")
	}
}

// newReconcilerHandler builds a DeployHandler against the test DB with the
// supplied compute double injected.
func newReconcilerHandler(t *testing.T, db *sql.DB, fake compute.Provider) *handlers.DeployHandler {
	t.Helper()
	h := handlers.NewDeployHandler(db, nil, &config.Config{}, nil)
	h.SetComputeProvider(fake)
	return h
}

func seedExpiredDeploy(t *testing.T, db *sql.DB, teamID uuid.UUID, status, providerID string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`
		INSERT INTO deployments (team_id, app_id, provider_id, status, tier)
		VALUES ($1, $2, $3, $4, 'hobby')
		RETURNING id
	`, teamID, "app-"+uuid.NewString()[:10], providerID, status).Scan(&id)
	require.NoError(t, err)
	return id
}

func deployRowStatus(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var s string
	require.NoError(t, db.QueryRow(`SELECT status FROM deployments WHERE id = $1`, id).Scan(&s))
	return s
}

// TestRunTeardownSweep_TearsDownAndMarksDeleted is the core P3 test: an
// expired deploy with a provider_id gets a Teardown call and is advanced
// to the terminal 'deleted' status.
func TestRunTeardownSweep_TearsDownAndMarksDeleted(t *testing.T) {
	reconcilerRequireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	pid := "app-tear-" + uuid.NewString()[:8]
	expiredID := seedExpiredDeploy(t, db, teamID, models.DeployStatusExpired, pid)

	fake := &fakeTeardownProvider{}
	h := newReconcilerHandler(t, db, fake)
	h.RunTeardownSweep(context.Background())

	assert.Equal(t, []string{pid}, fake.tornDown,
		"the expired deploy's compute must be torn down")
	assert.Equal(t, models.DeployStatusDeleted, deployRowStatus(t, db, expiredID),
		"the row must advance to the terminal 'deleted' status")
}

// TestRunTeardownSweep_SkipsHealthyAndProviderlessRows: only expired rows
// WITH a provider_id are processed.
func TestRunTeardownSweep_SkipsHealthyAndProviderlessRows(t *testing.T) {
	reconcilerRequireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	healthyID := seedExpiredDeploy(t, db, teamID, "healthy", "app-healthy-"+uuid.NewString()[:8])
	noProviderID := seedExpiredDeploy(t, db, teamID, models.DeployStatusExpired, "")

	fake := &fakeTeardownProvider{}
	h := newReconcilerHandler(t, db, fake)
	h.RunTeardownSweep(context.Background())

	assert.Equal(t, 0, fake.teardownCount(),
		"no Teardown call for healthy rows or expired-but-providerless rows")
	assert.Equal(t, "healthy", deployRowStatus(t, db, healthyID), "healthy row untouched")
	assert.Equal(t, models.DeployStatusExpired, deployRowStatus(t, db, noProviderID),
		"expired-but-providerless row left alone")
}

// TestRunTeardownSweep_FailedTeardownLeavesRowForRetry: when Teardown
// fails, the row stays 'expired' so the next sweep retries.
func TestRunTeardownSweep_FailedTeardownLeavesRowForRetry(t *testing.T) {
	reconcilerRequireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	pid := "app-fail-" + uuid.NewString()[:8]
	failID := seedExpiredDeploy(t, db, teamID, models.DeployStatusExpired, pid)

	fake := &fakeTeardownProvider{failFor: map[string]bool{pid: true}}
	h := newReconcilerHandler(t, db, fake)
	h.RunTeardownSweep(context.Background())

	assert.Equal(t, models.DeployStatusExpired, deployRowStatus(t, db, failID),
		"a failed teardown must leave the row 'expired' so the next sweep retries it")

	// Second sweep with teardown now succeeding completes the teardown.
	fake.mu.Lock()
	fake.failFor = nil
	fake.mu.Unlock()
	h.RunTeardownSweep(context.Background())
	assert.Equal(t, models.DeployStatusDeleted, deployRowStatus(t, db, failID),
		"the retry sweep must complete the teardown")
}

// TestRunTeardownSweep_ConcurrentSweepsNoDoubleTeardown is the P1-W5-17
// regression: the api runs replicas:2 and StartTeardownReconciler sweeps in
// every pod. Before the fix, GetExpiredDeploymentsAwaitingTeardown was a plain
// SELECT, so both pods picked the same expired rows and double-invoked
// compute.Teardown on the same namespace. The fix adds FOR UPDATE SKIP LOCKED
// inside a per-sweep transaction. This test runs two sweeps concurrently
// (the two-pod scenario) against a shared pool of expired deployments and
// asserts every provider_id is torn down EXACTLY once across both sweeps.
func TestRunTeardownSweep_ConcurrentSweepsNoDoubleTeardown(t *testing.T) {
	reconcilerRequireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	// Seed a batch of expired deployments — enough that a race window exists.
	const n = 12
	pids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		pid := "app-conc-" + uuid.NewString()[:8]
		pids = append(pids, pid)
		seedExpiredDeploy(t, db, teamID, models.DeployStatusExpired, pid)
	}

	// Two pods share ONE recording fake so we can assert the global count.
	fake := &fakeTeardownProvider{}
	podA := newReconcilerHandler(t, db, fake)
	podB := newReconcilerHandler(t, db, fake)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); podA.RunTeardownSweep(context.Background()) }()
	go func() { defer wg.Done(); podB.RunTeardownSweep(context.Background()) }()
	wg.Wait()

	// Every expired deployment must be torn down exactly once — no provider_id
	// appears twice in the recorded teardown calls.
	seen := make(map[string]int)
	for _, p := range fake.tornDown {
		seen[p]++
	}
	for _, p := range pids {
		assert.Equal(t, 1, seen[p],
			"provider_id %s must be torn down exactly once across both pods (FOR UPDATE SKIP LOCKED)", p)
	}
	assert.Equal(t, n, fake.teardownCount(),
		"exactly n teardown calls — no double-pickup between the two concurrent sweeps")
}

// TestRunTeardownSweep_DoesNotReprocessDeletedRows: a row already 'deleted'
// is never picked up again — no double Teardown.
func TestRunTeardownSweep_DoesNotReprocessDeletedRows(t *testing.T) {
	reconcilerRequireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	seedExpiredDeploy(t, db, teamID, models.DeployStatusDeleted, "app-gone-"+uuid.NewString()[:8])

	fake := &fakeTeardownProvider{}
	h := newReconcilerHandler(t, db, fake)
	h.RunTeardownSweep(context.Background())

	assert.Equal(t, 0, fake.teardownCount(),
		"an already-'deleted' row must never be torn down again")
}
