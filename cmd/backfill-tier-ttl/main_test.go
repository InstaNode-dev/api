package main

// main_test.go — coverage for the backfill-tier-ttl operator tool. Mirrors
// the cmd/openapi-snapshot pattern: main() forwards os.Exit through a
// swappable exitFn, and the real run() body is driven directly with an
// injected sqlmock-backed *sql.DB plus an injected promoteFn so every
// exit-code branch is reachable without standing up a real platform DB.
//
// The tool itself is one-off operator surgery; the test discipline here
// matches the 100% patch-coverage rule from CLAUDE.md (rule 25's sibling
// in feedback_coverage_95_floor_100_patch.md). Each branch in run() —
// usage errors, db-open error, ping error, query/scan errors, dry-run
// summary, apply with mixed ok/error per-team — has a named test.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
)

// withPromoteFn swaps the model call so the apply-loop's success and error
// branches are driveable from the unit-test layer.
func withPromoteFn(t *testing.T, fn func(context.Context, *sql.DB, uuid.UUID) (models.PromoteDeploymentTTLsResult, error)) {
	t.Helper()
	orig := promoteFn
	promoteFn = fn
	t.Cleanup(func() { promoteFn = orig })
}

func TestRun_MissingDBURL_ReturnsUsage(t *testing.T) {
	// Clear DATABASE_URL so the flag default is the empty string.
	t.Setenv("DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != backfillExitUsage {
		t.Fatalf("expected exit %d for missing DATABASE_URL, got %d", backfillExitUsage, code)
	}
	if !strings.Contains(stderr.String(), "DATABASE_URL is unset") {
		t.Errorf("expected stderr to mention 'DATABASE_URL is unset', got: %q", stderr.String())
	}
}

func TestRun_BadFlag_ReturnsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--no-such-flag"}, &stdout, &stderr)
	if code != backfillExitUsage {
		t.Errorf("expected exit %d for unknown flag, got %d", backfillExitUsage, code)
	}
}

func TestRun_OpenDBError_ReturnsUsage(t *testing.T) {
	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return nil, errors.New("simulated open failure") }
	t.Cleanup(func() { openDB = origOpen })

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored"}, &stdout, &stderr)
	if code != backfillExitUsage {
		t.Fatalf("expected exit %d on open failure, got %d", backfillExitUsage, code)
	}
	if !strings.Contains(stderr.String(), "open db") {
		t.Errorf("expected stderr to wrap 'open db' error, got: %q", stderr.String())
	}
}

func TestRun_PingError_ReturnsUsage(t *testing.T) {
	// sqlmock's ExpectPing only fires when MonitorPingsOption is set —
	// otherwise db.PingContext returns nil without consulting the mock.
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing().WillReturnError(errors.New("simulated ping failure"))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored"}, &stdout, &stderr)
	if code != backfillExitUsage {
		t.Fatalf("expected exit %d on ping failure, got %d (stderr: %s)", backfillExitUsage, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "ping db") {
		t.Errorf("expected stderr to mention 'ping db', got: %q", stderr.String())
	}
}

func TestRun_QueryError_ReturnsUsage(t *testing.T) {
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing()
	mock.ExpectQuery(`FROM teams t`).WillReturnError(errors.New("simulated list failure"))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored"}, &stdout, &stderr)
	if code != backfillExitUsage {
		t.Fatalf("expected exit %d on query failure, got %d (stderr: %s)", backfillExitUsage, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "list candidates") {
		t.Errorf("expected stderr to mention 'list candidates', got: %q", stderr.String())
	}
}

func TestRun_ScanError_ReturnsUsage(t *testing.T) {
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing()
	// One row that's malformed for Scan(uuid,string,string,int): drop the int.
	mock.ExpectQuery(`FROM teams t`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "plan_tier", "team_default"}).
			AddRow(uuid.New(), "hobby", "auto_24h"))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored"}, &stdout, &stderr)
	if code != backfillExitUsage {
		t.Fatalf("expected exit %d on scan failure, got %d (stderr: %s)", backfillExitUsage, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "backfill-tier-ttl: scan") {
		t.Errorf("expected stderr to mention 'scan', got: %q", stderr.String())
	}
}

func TestRun_RowsErr_ReturnsUsage(t *testing.T) {
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing()
	cols := []string{"id", "plan_tier", "team_default", "auto_deploy_count"}
	mock.ExpectQuery(`FROM teams t`).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow(uuid.New(), "hobby", "auto_24h", 1).
			RowError(0, errors.New("simulated rows.Err")))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored"}, &stdout, &stderr)
	if code != backfillExitUsage {
		t.Fatalf("expected exit %d on rows.Err, got %d (stderr: %s)", backfillExitUsage, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "backfill-tier-ttl: rows") {
		t.Errorf("expected stderr to mention 'rows', got: %q", stderr.String())
	}
}

func TestRun_DryRunMode_PrintsSummaryAndSkipsApply(t *testing.T) {
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing()
	cols := []string{"id", "plan_tier", "team_default", "auto_deploy_count"}
	candidateA := uuid.New()
	candidateB := uuid.New()
	mock.ExpectQuery(`FROM teams t`).
		WillReturnRows(sqlmock.NewRows(cols).
			// candidate A: team default still auto_24h, no auto deploys
			AddRow(candidateA, "hobby", "auto_24h", 0).
			// candidate B: team default permanent, 2 auto deploys (still a candidate)
			AddRow(candidateB, "pro", "permanent", 2).
			// skipped row: team default permanent AND 0 auto deploys → excluded
			AddRow(uuid.New(), "team", "permanent", 0))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	// Sentinel: dry-run must NOT call promoteFn.
	called := false
	withPromoteFn(t, func(context.Context, *sql.DB, uuid.UUID) (models.PromoteDeploymentTTLsResult, error) {
		called = true
		return models.PromoteDeploymentTTLsResult{}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored"}, &stdout, &stderr)
	if code != backfillExitOK {
		t.Fatalf("expected exit %d on dry-run, got %d (stderr: %s)", backfillExitOK, code, stderr.String())
	}
	if called {
		t.Errorf("dry-run mode MUST NOT call promoteFn — it would mutate the DB")
	}
	out := stdout.String()
	if !strings.Contains(out, "mode=DRY-RUN") {
		t.Errorf("expected dry-run banner in stdout, got: %q", out)
	}
	if !strings.Contains(out, "candidates=2") {
		t.Errorf("expected 2 candidates (third skipped — already promoted), got: %q", out)
	}
	if !strings.Contains(out, "dry-run complete") {
		t.Errorf("expected dry-run completion message, got: %q", out)
	}
}

func TestRun_ApplyMode_MixedOkAndError_ReturnsPartial(t *testing.T) {
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing()
	cols := []string{"id", "plan_tier", "team_default", "auto_deploy_count"}
	candidateOK := uuid.New()
	candidateErr := uuid.New()
	mock.ExpectQuery(`FROM teams t`).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow(candidateOK, "hobby", "auto_24h", 3).
			AddRow(candidateErr, "pro", "auto_24h", 1))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	withPromoteFn(t, func(_ context.Context, _ *sql.DB, id uuid.UUID) (models.PromoteDeploymentTTLsResult, error) {
		if id == candidateErr {
			return models.PromoteDeploymentTTLsResult{}, errors.New("simulated tx failure")
		}
		return models.PromoteDeploymentTTLsResult{DeploysPromoted: 3, TeamDefaultFlipped: true}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored", "-apply"}, &stdout, &stderr)
	if code != backfillExitPartial {
		t.Fatalf("expected exit %d when at least one team errored, got %d (stderr: %s)", backfillExitPartial, code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "mode=APPLY") {
		t.Errorf("expected APPLY banner in stdout, got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "ok=1 errored=1") {
		t.Errorf("expected 'ok=1 errored=1' tally in stdout, got: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "simulated tx failure") {
		t.Errorf("expected per-team error stderr, got: %q", stderr.String())
	}
}

func TestRun_ApplyMode_AllOK_ReturnsOK(t *testing.T) {
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing()
	cols := []string{"id", "plan_tier", "team_default", "auto_deploy_count"}
	mock.ExpectQuery(`FROM teams t`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow(uuid.New(), "hobby", "auto_24h", 1))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	withPromoteFn(t, func(context.Context, *sql.DB, uuid.UUID) (models.PromoteDeploymentTTLsResult, error) {
		return models.PromoteDeploymentTTLsResult{DeploysPromoted: 1, TeamDefaultFlipped: true}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"-database-url", "postgres://ignored", "-apply"}, &stdout, &stderr)
	if code != backfillExitOK {
		t.Fatalf("expected exit %d on clean apply, got %d (stderr: %s)", backfillExitOK, code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok=1 errored=0") {
		t.Errorf("expected 'ok=1 errored=0' in stdout, got: %q", stdout.String())
	}
}

// TestMain_DispatchesViaExitFn covers the main() entry-point line by swapping
// exitFn for a capture closure. os.Args[1:] when invoked under `go test`
// includes test-framework flags, which flag.Parse rejects → run returns the
// usage code. We assert exitFn was invoked (proving main forwards run's exit
// code), not the specific value.
func TestMain_DispatchesViaExitFn(t *testing.T) {
	captured := -1
	orig := exitFn
	exitFn = func(code int) { captured = code }
	t.Cleanup(func() { exitFn = orig })
	main()
	if captured < 0 {
		t.Errorf("expected exitFn to be invoked, got captured=%d", captured)
	}
}

// TestRun_DBURLFromEnv exercises the os.Getenv fallback for the
// -database-url flag default. We point openDB at a sqlmock handle and
// assert we made it past the empty-URL guard.
func TestRun_DBURLFromEnv(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://from-env-only")

	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp),
		sqlmock.MonitorPingsOption(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing()
	mock.ExpectQuery(`FROM teams t`).WillReturnRows(sqlmock.NewRows(
		[]string{"id", "plan_tier", "team_default", "auto_deploy_count"}))

	origOpen := openDB
	openDB = func(_ string) (*sql.DB, error) { return db, nil }
	t.Cleanup(func() { openDB = origOpen })

	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != backfillExitOK {
		t.Fatalf("expected exit %d on empty dry-run, got %d (stderr: %s)", backfillExitOK, code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "candidates=0") {
		t.Errorf("expected 0 candidates banner, got: %q", stdout.String())
	}
}

// Compile-time guard: the os package import in main.go must still be live
// even if a future refactor stops using os.Stdout/os.Stderr directly.
var _ = os.Stdout
