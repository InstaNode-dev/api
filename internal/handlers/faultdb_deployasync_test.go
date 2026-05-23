package handlers_test

// faultdb_deployasync_test.go — a fault-injecting database/sql driver that
// proxies the real lib/pq driver but forces query/exec failures after the
// Nth call. This lets the deploy/stack coverage slice reach the mid-handler
// "first query succeeds → a LATER query errors → 503" arms that a plain
// closed-DB handle (which fails the FIRST query) can't.
//
// Owned by the deploy/stack async-pipeline coverage slice (suffix
// `_deployasync`). Used only by stack_faultdb_deployasync_test.go +
// deploy_faultdb_deployasync_test.go.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lib/pq"
)

// errFaultInjected is returned once the fault driver's call budget is exhausted.
var errFaultInjected = errors.New("faultdb: injected failure")

// faultConfig is a per-DB shared counter. failAfter is the number of
// successful Query/Exec calls allowed before injection begins; -1 disables
// injection (pass-through).
type faultConfig struct {
	calls    atomic.Int64
	failAfter int64
}

func (f *faultConfig) shouldFail() bool {
	if f.failAfter < 0 {
		return false
	}
	n := f.calls.Add(1)
	return n > f.failAfter
}

// faultDriver wraps pq for a single *sql.DB instance. Registered once with a
// unique name per test so the failAfter budget is isolated.
type faultDriver struct {
	dsn string
	cfg *faultConfig
}

func (d *faultDriver) Open(_ string) (driver.Conn, error) {
	inner, err := pq.Open(d.dsn)
	if err != nil {
		return nil, err
	}
	return &faultConn{inner: inner, cfg: d.cfg}, nil
}

type faultConn struct {
	inner driver.Conn
	cfg   *faultConfig
}

func (c *faultConn) Prepare(query string) (driver.Stmt, error) { return c.inner.Prepare(query) }
func (c *faultConn) Close() error                              { return c.inner.Close() }
func (c *faultConn) Begin() (driver.Tx, error)                 { return c.inner.Begin() } //nolint:staticcheck

func (c *faultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.cfg.shouldFail() {
		return nil, errFaultInjected
	}
	if qc, ok := c.inner.(driver.QueryerContext); ok {
		return qc.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *faultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.cfg.shouldFail() {
		return nil, errFaultInjected
	}
	if ec, ok := c.inner.(driver.ExecerContext); ok {
		return ec.ExecContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *faultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if bt, ok := c.inner.(driver.ConnBeginTx); ok {
		return bt.BeginTx(ctx, opts)
	}
	return c.inner.Begin() //nolint:staticcheck
}

func (c *faultConn) Ping(ctx context.Context) error {
	if p, ok := c.inner.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

// compile-time interface checks.
var (
	_ driver.QueryerContext = (*faultConn)(nil)
	_ driver.ExecerContext  = (*faultConn)(nil)
	_ driver.ConnBeginTx    = (*faultConn)(nil)
	_ driver.Pinger         = (*faultConn)(nil)
	_ io.Closer             = (*faultConn)(nil)
)

var faultRegMu sync.Mutex
var faultRegN int

// openFaultDB returns a *sql.DB backed by the fault driver. It succeeds on the
// first `failAfter` Query/Exec calls then injects errFaultInjected on every
// subsequent call. Pass failAfter=-1 to disable injection.
//
// Skips the test when TEST_DATABASE_URL is unset.
func openFaultDB(t *testing.T, failAfter int64) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping fault-db coverage")
	}
	faultRegMu.Lock()
	faultRegN++
	name := "faultpq_" + itoaFault(faultRegN)
	sql.Register(name, &faultDriver{dsn: dsn, cfg: &faultConfig{failAfter: failAfter}})
	faultRegMu.Unlock()

	db, err := sql.Open(name, dsn)
	if err != nil {
		t.Fatalf("openFaultDB: %v", err)
	}
	// Single conn so the call counter is deterministic across the request.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func itoaFault(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
