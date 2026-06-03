package handlers_test

// stack_final2_test.go — FINAL SERIAL PASS #2 coverage for the mid-handler
// DB-error arms of stack.go's UpdateEnv / Get / Family handlers that the
// happy-path + closed-DB suites leave uncovered. The closed-DB suite fails the
// FIRST query (team lookup); these arms only run when an EARLY query succeeds
// and a LATER one errors, so we seed a team-owned stack on the pooled DB and
// run the handler over a fault DB sharing the same postgres DSN.
//
//   * UpdateEnv MergeStackEnvVars error → persist_failed (bug-bash #10)
//   * Family GetStackBySlug error → fetch_failed         (failAfter=1)
//
// bug-bash #10 (2026-06-04): UpdateEnv's old GetStackEnvVars → merge-in-Go →
// UpdateStackEnvVars sequence was a non-atomic read-modify-write that lost keys
// under concurrency. It was replaced by a single atomic models.MergeStackEnvVars
// call (one row-locked transaction). That collapsed the two distinct DB-error
// arms (fetch_failed for the read, persist_failed for the write) into ONE
// surface: any error out of MergeStackEnvVars — including the tx's internal
// SELECT ... FOR UPDATE and the UPDATE — maps to persist_failed 503. (Note the
// merge's tx-internal queries DO fault through the shared faultConn: lib/pq's
// driver.Tx has no QueryerContext, so sql.Tx.QueryContext/ExecContext fall back
// to the conn-level faultConn.QueryContext/ExecContext, which honor the
// failAfter budget.) Both former tests now assert the single persist_failed
// surface at the two query depths (the in-tx SELECT and the in-tx UPDATE).

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func stackFaultApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:                      testhelpers.TestJWTSecret,
		AESKey:                         testhelpers.TestAESKeyHex,
		ComputeProvider:                "noop",
		DeletionConfirmationTTLMinutes: 30,
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	sh.SetEmailClient(email.NewNoop())
	app.Use(middleware.RequestID())
	app.Patch("/stacks/:slug/env", middleware.RequireAuth(cfg), sh.UpdateEnv)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/stacks/:slug/family", sh.Family)
	return app
}

func stackNeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

func patchStackEnvF2(t *testing.T, app *fiber.App, slug, jwt, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var raw [2048]byte
	n, _ := resp.Body.Read(raw[:])
	return resp.StatusCode, string(raw[:n])
}

// TestStackFinal2_UpdateEnv_MergeSelectFailed faults the merge tx's internal
// SELECT ... FOR UPDATE. team(1)+GetStackBySlug(2) ok, then MergeStackEnvVars
// begins a tx and its SELECT (3rd conn-level query) errors → persist_failed.
// (Pre-bug-bash-#10 this depth was the GetStackEnvVars "fetch_failed" arm; the
// atomic merge collapsed it into the single persist_failed surface.)
func TestStackFinal2_UpdateEnv_MergeSelectFailed(t *testing.T) {
	stackNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, seedDB, &teamID, "healthy")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stkf2@example.com")

	// team(1)+GetStackBySlug(2) ok, merge tx SELECT ... FOR UPDATE(3) errors.
	app := stackFaultApp(t, openFaultDB(t, 2))
	status, body := patchStackEnvF2(t, app, slug, jwt, `{"env":{"FOO":"bar"}}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "persist_failed")
}

// TestStackFinal2_UpdateEnv_PersistFailed faults the merge tx's internal UPDATE.
// team(1)+slug(2)+merge SELECT(3) ok, the merge tx UPDATE(4) errors →
// persist_failed.
func TestStackFinal2_UpdateEnv_PersistFailed(t *testing.T) {
	stackNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, seedDB, &teamID, "healthy")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stkf2@example.com")

	// team(1)+slug(2)+merge SELECT FOR UPDATE(3) ok, merge UPDATE(4) errors.
	app := stackFaultApp(t, openFaultDB(t, 3))
	status, body := patchStackEnvF2(t, app, slug, jwt, `{"env":{"FOO":"bar"}}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "persist_failed")
}

// Family GetStackBySlug errors (non-NotFound) → fetch_failed 503. failAfter=1
// (team lookup ok, the slug lookup errors).
func TestStackFinal2_Family_FetchFailed(t *testing.T) {
	stackNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stkf2@example.com")

	app := stackFaultApp(t, openFaultDB(t, 1))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks/some-slug/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// ── merge-NotFound (TOCTOU) arm coverage ──────────────────────────────────────
//
// The UpdateEnv handler maps a models.ErrStackNotFound out of MergeStackEnvVars
// to a 404 — the row vanished between GetStackBySlug and the merge tx's
// SELECT ... FOR UPDATE (a genuine TOCTOU that can't be timed deterministically
// against a live row). To exercise that handler arm deterministically we proxy
// the real pq driver and return ZERO rows ONLY for the merge's
// `SELECT ... FOR UPDATE` query: GetStackBySlug (no FOR UPDATE) still finds the
// row, so the handler reaches the merge, whose SELECT then sees no rows →
// ErrStackNotFound → 404 not_found.

type forUpdateVanishConn struct{ inner driver.Conn }

func (c *forUpdateVanishConn) Prepare(q string) (driver.Stmt, error) { return c.inner.Prepare(q) }
func (c *forUpdateVanishConn) Close() error                          { return c.inner.Close() }
func (c *forUpdateVanishConn) Begin() (driver.Tx, error)             { return c.inner.Begin() } //nolint:staticcheck

func (c *forUpdateVanishConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if bt, ok := c.inner.(driver.ConnBeginTx); ok {
		return bt.BeginTx(ctx, opts)
	}
	return c.inner.Begin() //nolint:staticcheck
}

func (c *forUpdateVanishConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "FOR UPDATE") {
		// Simulate the row vanishing: return an empty result set so
		// MergeStackEnvVars' Scan yields sql.ErrNoRows → ErrStackNotFound.
		return &emptyRows{}, nil
	}
	if qc, ok := c.inner.(driver.QueryerContext); ok {
		return qc.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *forUpdateVanishConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if ec, ok := c.inner.(driver.ExecerContext); ok {
		return ec.ExecContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

// emptyRows is a zero-row driver.Rows for the single env_vars column.
type emptyRows struct{}

func (*emptyRows) Columns() []string           { return []string{"coalesce"} }
func (*emptyRows) Close() error                { return nil }
func (*emptyRows) Next(_ []driver.Value) error { return io.EOF }

type forUpdateVanishDriver struct{ dsn string }

func (d *forUpdateVanishDriver) Open(_ string) (driver.Conn, error) {
	inner, err := pq.Open(d.dsn)
	if err != nil {
		return nil, err
	}
	return &forUpdateVanishConn{inner: inner}, nil
}

var fuvRegMu sync.Mutex
var fuvRegN int

func openForUpdateVanishDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	fuvRegMu.Lock()
	fuvRegN++
	name := "fuvpq_" + itoaFault(fuvRegN)
	sql.Register(name, &forUpdateVanishDriver{dsn: dsn})
	fuvRegMu.Unlock()
	db, err := sql.Open(name, dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestStackFinal2_UpdateEnv_MergeRowVanished_404 covers the handler's
// ErrStackNotFound→404 mapping on the atomic merge: GetStackBySlug finds the
// row, but the merge tx's SELECT ... FOR UPDATE sees none (simulated vanish).
func TestStackFinal2_UpdateEnv_MergeRowVanished_404(t *testing.T) {
	stackNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, seedDB, &teamID, "healthy")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "vanish@example.com")

	app := stackFaultApp(t, openForUpdateVanishDB(t))
	status, body := patchStackEnvF2(t, app, slug, jwt, `{"env":{"FOO":"bar"}}`)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Contains(t, body, "not_found")
}
