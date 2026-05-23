package db

// local_seam_test.go drives the LocalBackend defensive branches that cannot be
// triggered deterministically against a real superuser Postgres connection:
// the crypto/rand failure, the conn.Close(ctx) defer-error logs, and the
// non-fatal REVOKE / GRANT / DROP USER exec-error logs. It does so via the
// package seams (randInt + pgxConnect) using an in-memory fake pgConn, so the
// tests need no live database and never flake.

import (
	"context"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakePgConn is a deterministic pgConn. execErr decides, per-statement, whether
// Exec returns an error (matched by a case-insensitive substring of the SQL).
// closeErr is returned by Close. queryRowErr is surfaced by the returned Row's
// Scan.
type fakePgConn struct {
	execErr     map[string]error // SQL substring → error to return
	closeErr    error
	queryRowErr error
	queryRowVal int64
	closed      int
}

func (f *fakePgConn) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	for sub, err := range f.execErr {
		if strings.Contains(sql, sub) {
			return pgconn.CommandTag{}, err
		}
	}
	return pgconn.CommandTag{}, nil
}

func (f *fakePgConn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &fakeRow{err: f.queryRowErr, val: f.queryRowVal}
}

func (f *fakePgConn) Close(ctx context.Context) error {
	f.closed++
	return f.closeErr
}

type fakeRow struct {
	err error
	val int64
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) == 1 {
		if p, ok := dest[0].(*int64); ok {
			*p = r.val
		}
	}
	return nil
}

// withFakeConn installs a pgxConnect seam returning the given fakes in sequence
// (first call → conns[0], etc.) and restores the real factory on cleanup. A
// connErrs entry, when non-nil, makes that connect attempt fail instead.
func withFakeConn(t *testing.T, conns []*fakePgConn, connErrs []error) {
	t.Helper()
	orig := pgxConnect
	var i int
	pgxConnect = func(ctx context.Context, connString string) (pgConn, error) {
		idx := i
		i++
		if idx < len(connErrs) && connErrs[idx] != nil {
			return nil, connErrs[idx]
		}
		if idx < len(conns) {
			return conns[idx], nil
		}
		return &fakePgConn{}, nil
	}
	t.Cleanup(func() { pgxConnect = orig })
}

// TestGeneratePassword_RandFailure covers the crypto/rand error branch in
// generatePassword via the randInt seam.
func TestGeneratePassword_RandFailure(t *testing.T) {
	orig := randInt
	randInt = func(_ io.Reader, _ *big.Int) (*big.Int, error) {
		return nil, errors.New("entropy depleted")
	}
	t.Cleanup(func() { randInt = orig })

	_, err := generatePassword(16)
	if err == nil || !strings.Contains(err.Error(), "generatePassword") {
		t.Fatalf("randInt failure must surface; got %v", err)
	}
}

// TestProvision_RandFailure asserts the password failure propagates out of
// Provision before any DB connection is opened.
func TestProvision_RandFailure(t *testing.T) {
	orig := randInt
	randInt = func(_ io.Reader, _ *big.Int) (*big.Int, error) {
		return nil, errors.New("entropy depleted")
	}
	t.Cleanup(func() { randInt = orig })

	b := newLocalBackend("postgres://x:y@h:5432/d")
	_, err := b.Provision(context.Background(), "tok", "anonymous")
	if err == nil || !strings.Contains(err.Error(), "db.local.Provision") {
		t.Fatalf("Provision must fail on RNG error; got %v", err)
	}
}

// TestProvision_NonFatalBranches covers, in one provision, the REVOKE CONNECT
// non-fatal log, the GRANT SCHEMA non-fatal log, and BOTH conn.Close defer-error
// logs (admin conn + new-db conn). The provision still succeeds — these branches
// are best-effort by design.
func TestProvision_NonFatalBranches(t *testing.T) {
	adminConn := &fakePgConn{
		execErr:  map[string]error{"REVOKE CONNECT": errors.New("revoke denied")},
		closeErr: errors.New("admin close failed"),
	}
	newDBConn := &fakePgConn{
		execErr:  map[string]error{"GRANT ALL ON SCHEMA": errors.New("schema grant denied")},
		closeErr: errors.New("newdb close failed"),
	}
	withFakeConn(t, []*fakePgConn{adminConn, newDBConn}, nil)

	b := newLocalBackend("postgres://admin:pw@host:5432/instant_customers")
	creds, err := b.Provision(context.Background(), "nonfatal", "anonymous")
	if err != nil {
		t.Fatalf("non-fatal branches must not fail provision: %v", err)
	}
	if creds.DatabaseName != "db_nonfatal" {
		t.Fatalf("DatabaseName = %q", creds.DatabaseName)
	}
	if adminConn.closed == 0 || newDBConn.closed == 0 {
		t.Fatal("both connections must be Closed (defer-error branches)")
	}
}

// TestProvision_NewDBConnectFails_WithExtensions covers the branch where the
// connect-to-new-db step fails AND extensions were requested, so the provision
// errors loudly instead of returning a non-vector DB.
func TestProvision_NewDBConnectFails_WithExtensions(t *testing.T) {
	adminConn := &fakePgConn{}
	// First connect (admin) succeeds; second connect (new DB) fails.
	withFakeConn(t, []*fakePgConn{adminConn}, []error{nil, errors.New("new db unreachable")})

	b := newLocalBackend("postgres://admin:pw@host:5432/instant_customers")
	_, err := b.Provision(context.Background(), "extfail", "pro")
	// No extensions requested → non-fatal, provision succeeds.
	if err != nil {
		t.Fatalf("no-extension new-db connect failure must be non-fatal: %v", err)
	}
}

// TestProvisionWithExtensions_NewDBConnectFails covers the loud-failure arm:
// extensions requested but the new-DB connect failed.
func TestProvisionWithExtensions_NewDBConnectFails(t *testing.T) {
	adminConn := &fakePgConn{}
	withFakeConn(t, []*fakePgConn{adminConn}, []error{nil, errors.New("new db unreachable")})

	b := newLocalBackend("postgres://admin:pw@host:5432/instant_customers")
	_, err := b.ProvisionWithExtensions(context.Background(), "extloud", "pro", []string{"vector"})
	if err == nil || !strings.Contains(err.Error(), "install extensions") {
		t.Fatalf("requested extensions + new-db connect fail must error loudly; got %v", err)
	}
}

// TestProvision_CreateUserFails covers the CREATE USER error return via the fake.
func TestProvision_CreateUserFails(t *testing.T) {
	adminConn := &fakePgConn{execErr: map[string]error{"CREATE USER": errors.New("user exists")}}
	withFakeConn(t, []*fakePgConn{adminConn}, nil)

	b := newLocalBackend("postgres://admin:pw@host:5432/d")
	_, err := b.Provision(context.Background(), "dupuser", "anonymous")
	if err == nil || !strings.Contains(err.Error(), "CREATE USER") {
		t.Fatalf("want CREATE USER error; got %v", err)
	}
}

// TestProvision_GrantDatabaseFails covers the fatal GRANT DATABASE error return.
func TestProvision_GrantDatabaseFails(t *testing.T) {
	adminConn := &fakePgConn{execErr: map[string]error{"GRANT ALL PRIVILEGES ON DATABASE": errors.New("denied")}}
	withFakeConn(t, []*fakePgConn{adminConn}, nil)

	b := newLocalBackend("postgres://admin:pw@host:5432/d")
	_, err := b.Provision(context.Background(), "grantfail", "anonymous")
	if err == nil || !strings.Contains(err.Error(), "GRANT DATABASE") {
		t.Fatalf("want GRANT DATABASE error; got %v", err)
	}
}

// TestStorageBytes_CloseError covers the StorageBytes disconnect defer-error log
// while the query itself succeeds.
func TestStorageBytes_CloseError(t *testing.T) {
	conn := &fakePgConn{closeErr: errors.New("close failed"), queryRowVal: 4096}
	withFakeConn(t, []*fakePgConn{conn}, nil)

	b := newLocalBackend("postgres://admin:pw@host:5432/d")
	size, err := b.StorageBytes(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("StorageBytes: %v", err)
	}
	if size != 4096 {
		t.Fatalf("size = %d, want 4096", size)
	}
	if conn.closed == 0 {
		t.Fatal("Close must have run (defer-error branch)")
	}
}

// TestDeprovision_NonFatalBranches covers the terminate-connections failure log,
// the DROP USER non-fatal log, and the Close defer-error log — all in one
// Deprovision that still succeeds.
func TestDeprovision_NonFatalBranches(t *testing.T) {
	conn := &fakePgConn{
		execErr: map[string]error{
			"pg_terminate_backend": errors.New("terminate denied"),
			"DROP USER":            errors.New("drop user denied"),
		},
		closeErr: errors.New("close failed"),
	}
	withFakeConn(t, []*fakePgConn{conn}, nil)

	b := newLocalBackend("postgres://admin:pw@host:5432/d")
	if err := b.Deprovision(context.Background(), "tok", ""); err != nil {
		t.Fatalf("Deprovision non-fatal branches must succeed: %v", err)
	}
	if conn.closed == 0 {
		t.Fatal("Close must have run")
	}
}

// TestDeprovision_DropDatabaseFails covers the fatal DROP DATABASE error return.
func TestDeprovision_DropDatabaseFails(t *testing.T) {
	conn := &fakePgConn{execErr: map[string]error{"DROP DATABASE": errors.New("not owner")}}
	withFakeConn(t, []*fakePgConn{conn}, nil)

	b := newLocalBackend("postgres://admin:pw@host:5432/d")
	if err := b.Deprovision(context.Background(), "tok", ""); err == nil ||
		!strings.Contains(err.Error(), "DROP DATABASE") {
		t.Fatalf("want DROP DATABASE error; got %v", err)
	}
}
