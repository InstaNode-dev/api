package handlers_test

// admin_impersonate_residual_test.go — residual coverage for
// admin_impersonate.go (83.3% → ≥95%). Targets:
//
//   - resolveTargetUser non-NoRows error → 503 db_failed (lines 155-156, 256).
//   - signImpersonationToken failure → 503 sign_failed (185-188), via the
//     SetSignImpersonationTokenForTest seam.
//   - audit-insert failure → still 200 (best-effort, 209-211), via sqlmock.

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// impersonateAppWithDB wires the impersonate route against an arbitrary DB
// (e.g. sqlmock-backed) behind the fake-auth + RequireAdmin chain.
func impersonateAppWithDB(t *testing.T, db *sql.DB, callerEmail string) *fiber.App {
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
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	fakeAuth := func(c *fiber.Ctx) error {
		if callerEmail != "" {
			c.Locals(middleware.LocalKeyEmail, callerEmail)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	}
	impH := handlers.NewAdminImpersonateHandler(db, cfg)
	g := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	g.Post("/customers/:team_id/impersonate", impH.Impersonate)
	return app
}

// impTeamRow mirrors GetTeamByID's 6-column SELECT.
func impTeamRow(tid uuid.UUID) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "name", "plan_tier",
		"stripe_customer_id", "created_at", "default_deployment_ttl_policy"}).
		AddRow(tid, "", "pro", nil, time.Now(), "auto_24h")
}

// impUserRow mirrors resolveTargetUser's SELECT id,email.
func impUserRow(uid uuid.UUID, email string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "email"}).AddRow(uid, email)
}

// TestImpersonate_ResolveUserDBError_503 drives the resolveTargetUser
// non-NoRows error arm (155-156 + 256). GetTeamByID succeeds; the user
// lookup errors with a generic DB error → 503 db_failed.
func TestImpersonate_ResolveUserDBError_503(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(impTeamRow(tid))
	mock.ExpectQuery(`FROM users`).WithArgs(tid).WillReturnError(errors.New("users boom"))

	app := impersonateAppWithDB(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+tid.String()+"/impersonate", nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestImpersonate_SignFailed_503 drives the signImpersonationToken-failed arm
// (185-188) via the seam. GetTeamByID + resolveTargetUser succeed (sqlmock),
// then the swapped signer returns an error → 503 sign_failed.
func TestImpersonate_SignFailed_503(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	restore := handlers.SetSignImpersonationTokenForTest(
		func(*jwt.Token, []byte) (string, error) { return "", errors.New("sign boom") })
	defer restore()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	uid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(impTeamRow(tid))
	mock.ExpectQuery(`FROM users`).WithArgs(tid).WillReturnRows(impUserRow(uid, "u@x.com"))

	app := impersonateAppWithDB(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+tid.String()+"/impersonate", nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "sign_failed", body["error"])
}

// TestImpersonate_AuditInsertFails_StillReturns200 drives the
// audit_insert_failed best-effort arm (209-211). Team + user + sign succeed;
// the audit INSERT errors. The admin still gets a 200 with a token.
func TestImpersonate_AuditInsertFails_StillReturns200(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	uid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(impTeamRow(tid))
	mock.ExpectQuery(`FROM users`).WithArgs(tid).WillReturnRows(impUserRow(uid, "u@x.com"))
	// InsertAuditEvent uses ExecContext — error so the warn arm runs; the
	// response is still 200.
	mock.ExpectExec(`INSERT INTO audit_log`).WillReturnError(errors.New("audit boom"))

	app := impersonateAppWithDB(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+tid.String()+"/impersonate", nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.NotEmpty(t, body["token"], "token must be minted even when audit insert fails")
}
