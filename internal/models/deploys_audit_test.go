package models_test

// deploys_audit_test.go — integration coverage for InsertSelfReport +
// ListDeploys. Drives the real Postgres table created by migration 022
// (mirrored into testhelpers.runMigrations).
//
// Skips when TEST_DATABASE_URL is unset, mirroring the pattern in
// resource_env_test.go's requireDB. The handler-level test
// (handlers/deploys_audit_test.go) covers the HTTP surface; this file
// pins the SQL contract — the unique-index dedup, the nullable-column
// behavior, the timestamp parsing, and the ORDER BY / LIMIT shape of
// ListDeploys.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// requireDBDeploys is a local copy of resource_env_test.go's requireDB —
// duplicated rather than imported because Go's _test.go files cannot
// share helpers across files unless they live in the same test binary
// with the same identifier visibility, and the existing helper in
// resource_env_test.go is package-local with a name that's already in
// use within this test binary (different file, same package). The
// behavior is identical.
func requireDBDeploys(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

// TestInsertSelfReport_BasicInsert — the happy path: a fresh row is
// written, all fields land in the DB, and the row is queryable via
// ListDeploys. This is the precondition for every dedup / filter test
// below.
func TestInsertSelfReport_BasicInsert(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	_, _ = db.ExecContext(ctx, `DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM deploys_audit`) })

	err := models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service:     models.DeployServiceAPI,
		CommitID:    "abc1234",
		ImageDigest: "sha256:deadbeef",
		Version:     "v5.1.0",
		BuildTime:   "2026-05-12T16:00:00Z",
	})
	require.NoError(t, err, "self-report on a fresh tuple must succeed")

	rows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{
		Service: models.DeployServiceAPI,
	})
	require.NoError(t, err)
	require.Len(t, rows, 1, "exactly one row must come back for the inserted tuple")
	got := rows[0]
	assert.Equal(t, models.DeployServiceAPI, got.Service)
	assert.Equal(t, "abc1234", got.CommitID)
	assert.Equal(t, "sha256:deadbeef", got.ImageDigest)
	require.True(t, got.Version.Valid)
	assert.Equal(t, "v5.1.0", got.Version.String)
	require.True(t, got.BuildTime.Valid)
	assert.Equal(t, models.DeployNoticedBySelfReport, got.NoticedBy)
}

// TestInsertSelfReport_IdempotentSameTuple — the central correctness
// property of the table: two startups of the same image produce exactly
// one row. This is what makes the table grow with deploys, not with
// pod-restarts.
func TestInsertSelfReport_IdempotentSameTuple(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	_, _ = db.ExecContext(ctx, `DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM deploys_audit`) })

	p := models.SelfReportParams{
		Service:     models.DeployServiceAPI,
		CommitID:    "samecommit",
		ImageDigest: "sha256:samedigest",
		Version:     "v1.0.0",
		BuildTime:   "2026-05-12T16:00:00Z",
	}
	for i := 0; i < 3; i++ {
		require.NoError(t, models.InsertSelfReport(ctx, db, p),
			"insert %d must succeed — ON CONFLICT DO NOTHING is not an error", i)
	}

	rows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{
		Service: models.DeployServiceAPI,
	})
	require.NoError(t, err)
	assert.Len(t, rows, 1,
		"three boots of the same image must collapse to one row via the unique index")
}

// TestInsertSelfReport_DifferentDigestsDifferentRows — the dual of
// IdempotentSameTuple: when the digest changes (a new deploy), a new
// row appears. Same commit, different digest = two rows (the operator
// may have rebuilt without re-tagging; we still want to log it).
func TestInsertSelfReport_DifferentDigestsDifferentRows(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	_, _ = db.ExecContext(ctx, `DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM deploys_audit`) })

	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service:     models.DeployServiceAPI,
		CommitID:    "commit-A",
		ImageDigest: "sha256:digestA",
	}))
	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service:     models.DeployServiceAPI,
		CommitID:    "commit-B",
		ImageDigest: "sha256:digestB",
	}))

	rows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{
		Service: models.DeployServiceAPI,
	})
	require.NoError(t, err)
	assert.Len(t, rows, 2, "two distinct (commit, digest) tuples = two rows")
}

// TestInsertSelfReport_BuildinfoSentinelsBecomeNull — buildinfo emits
// "dev" / "unknown" for un-ldflagged builds. The model parses these as
// NULL so the JSON response surfaces `null` rather than the literal
// sentinel — operators reading the dashboard should see "no version
// recorded" instead of being misled into thinking "dev" is a real
// release.
func TestInsertSelfReport_BuildinfoSentinelsBecomeNull(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	_, _ = db.ExecContext(ctx, `DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM deploys_audit`) })

	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service:     models.DeployServiceAPI,
		CommitID:    "dev-commit",
		ImageDigest: "local-build",
		Version:     "dev",       // buildinfo default → NULL
		BuildTime:   "unknown",   // buildinfo default → NULL
	}))

	rows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{Service: models.DeployServiceAPI})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.False(t, rows[0].Version.Valid, `"dev" must be stored as NULL, not the literal string`)
	assert.False(t, rows[0].BuildTime.Valid, `"unknown" must be stored as NULL, not as a parse error`)
}

// TestInsertSelfReport_RequiresIdentityFields — the three columns that
// back the unique index must be non-empty. Empty inputs are a caller
// bug (the startup hook should always have at least a service name and
// the buildinfo-stamped commit) — surface them as model errors rather
// than letting a row with empty strings sneak into the table.
func TestInsertSelfReport_RequiresIdentityFields(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()

	cases := []struct {
		name string
		p    models.SelfReportParams
	}{
		{"empty service", models.SelfReportParams{CommitID: "c", ImageDigest: "d"}},
		{"empty commit", models.SelfReportParams{Service: "api", ImageDigest: "d"}},
		{"empty digest", models.SelfReportParams{Service: "api", CommitID: "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := models.InsertSelfReport(ctx, db, tc.p)
			assert.Error(t, err, "%s must reject", tc.name)
		})
	}
}

// TestListDeploys_FilterByService — multi-service rows in one table
// must not bleed into each other. An admin asking for ?service=worker
// gets only the worker's rows; the API's rows stay hidden.
func TestListDeploys_FilterByService(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	_, _ = db.ExecContext(ctx, `DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM deploys_audit`) })

	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service: models.DeployServiceAPI, CommitID: "c1", ImageDigest: "d1",
	}))
	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service: models.DeployServiceWorker, CommitID: "c2", ImageDigest: "d2",
	}))
	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service: models.DeployServiceProvisioner, CommitID: "c3", ImageDigest: "d3",
	}))

	apiRows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{Service: models.DeployServiceAPI})
	require.NoError(t, err)
	require.Len(t, apiRows, 1)
	assert.Equal(t, models.DeployServiceAPI, apiRows[0].Service)

	allRows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{})
	require.NoError(t, err)
	assert.Len(t, allRows, 3, "no filter = all services")
}

// TestListDeploys_OrderByAppliedAtDesc — the read shape the admin
// endpoint depends on: newest first. We force two rows with known
// applied_at by post-update so the in-process clock skew doesn't make
// the assertion flaky.
func TestListDeploys_OrderByAppliedAtDesc(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	_, _ = db.ExecContext(ctx, `DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM deploys_audit`) })

	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service: models.DeployServiceAPI, CommitID: "old", ImageDigest: "old-digest",
	}))
	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service: models.DeployServiceAPI, CommitID: "new", ImageDigest: "new-digest",
	}))

	// Force a deterministic gap: backdate "old" by an hour. Otherwise
	// both inserts hit `now()` in the same millisecond and the ORDER
	// BY is non-deterministic.
	_, err := db.ExecContext(ctx,
		`UPDATE deploys_audit SET applied_at = $1 WHERE commit_id = 'old'`,
		time.Now().Add(-1*time.Hour).UTC(),
	)
	require.NoError(t, err)

	rows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{Service: models.DeployServiceAPI})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "new", rows[0].CommitID, "newest row must come first")
	assert.Equal(t, "old", rows[1].CommitID)
}

// TestListDeploys_SinceFilter — operators ask "what was running after
// 14:00 yesterday?" The since filter pushes the cutoff into the WHERE
// clause so the response is bounded by SQL, not the read-side limit.
func TestListDeploys_SinceFilter(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	_, _ = db.ExecContext(ctx, `DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM deploys_audit`) })

	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service: models.DeployServiceAPI, CommitID: "old", ImageDigest: "old-digest",
	}))
	require.NoError(t, models.InsertSelfReport(ctx, db, models.SelfReportParams{
		Service: models.DeployServiceAPI, CommitID: "new", ImageDigest: "new-digest",
	}))
	_, err := db.ExecContext(ctx,
		`UPDATE deploys_audit SET applied_at = $1 WHERE commit_id = 'old'`,
		time.Now().Add(-2*time.Hour).UTC(),
	)
	require.NoError(t, err)

	rows, err := models.ListDeploys(ctx, db, models.ListDeploysParams{
		Service: models.DeployServiceAPI,
		Since:   time.Now().Add(-1 * time.Hour),
	})
	require.NoError(t, err)
	require.Len(t, rows, 1, "since=now-1h must exclude the 2h-old row")
	assert.Equal(t, "new", rows[0].CommitID)
}

// TestListDeploys_RejectsInvalidService — the admin endpoint's input
// validator hands a service value through to the model. Anything not
// in ValidDeployServices is a 400, not a SQL injection.
func TestListDeploys_RejectsInvalidService(t *testing.T) {
	requireDBDeploys(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	_, err := models.ListDeploys(context.Background(), db, models.ListDeploysParams{
		Service: "not-a-real-service",
	})
	assert.Error(t, err, "unknown service must be rejected before reaching SQL")
}
