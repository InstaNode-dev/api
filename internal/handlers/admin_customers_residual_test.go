package handlers_test

// admin_customers_residual_test.go — residual coverage for admin_customers.go,
// pushing the file from 78.2% → ≥95%. Targets the branches the prior slice
// left uncovered:
//
//   - NewAdminCustomersHandler's default CancelSubscription closure (returns
//     errBillingNotConfigured) — exercised by demoting a team via the default
//     handler (no injected cancelFn).
//   - List: single-tier exact-match filter, query-failed (brokenDB), and the
//     scan/rows-err arms (sqlmock).
//   - Detail: invalid-uuid 400, db_failed (brokenDB), the razorpay-sub-present
//     branch, the users/resources/audit query-failed arms (brokenDB), and the
//     audit-rows-present + metadata branch.
//   - ChangeTier: invalid-uuid 400, invalid-body 400, team-query db_failed
//     (brokenDB), update-failed (sqlmock).
//   - IssuePromo: invalid-uuid 400, invalid-body 400, amount_off value 400,
//     valid_for_days 400, team-query db_failed (brokenDB), insert-failed
//     (brokenDB).
//
// All test files in this slice carry the _residual suffix so they never
// collide with the prior slice's files.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// adminPostRawJSON POSTs a raw (possibly malformed) JSON string so the
// BodyParser-error arms can be exercised. Distinct from adminDoJSON, which
// always sends well-formed JSON.
func adminPostRawJSON(t *testing.T, app *fiber.App, path, raw string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// adminAppAllRoutes wires every admin-customers route against the supplied DB
// (which may be a brokenDB or sqlmock-backed *sql.DB) so the residual tests can
// drive each handler's DB-failure arm. callerEmail is pinned admin so
// RequireAdmin passes.
func adminAppAllRoutes(t *testing.T, db *sql.DB, callerEmail string) *fiber.App {
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
	fakeAuth := func(c *fiber.Ctx) error {
		if callerEmail != "" {
			c.Locals(middleware.LocalKeyEmail, callerEmail)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	}
	adminH := handlers.NewAdminCustomersHandler(db, plans.Default())
	g := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	g.Get("/customers", adminH.List)
	g.Get("/customers/:team_id", adminH.Detail)
	g.Post("/customers/:team_id/tier", adminH.ChangeTier)
	g.Post("/customers/:team_id/promo", adminH.IssuePromo)
	return app
}

// ── NewAdminCustomersHandler default CancelSubscription closure ──────────────

// TestAdminTierChange_DefaultCancelClosure_StillReturns200 demotes a team
// using the DEFAULT handler (no injected cancelFn). The default
// CancelSubscription returns errBillingNotConfigured, exercising the
// closure body in NewAdminCustomersHandler (lines 137-139) and the
// cancel-failed audit arm. The admin still gets a 200.
func TestAdminTierChange_DefaultCancelClosure_StillReturns200(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	teamID, _ := adminSeedTeamWithSub(t, db, "pro")
	app := adminAppAllRoutes(t, db, adminCallerEmail) // uses default CancelSubscription

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "hobby", "reason": "default-closure path"})
	require.Equal(t, http.StatusOK, status, "demote must still 200 even when cancel errors: %v", body)

	// The default CancelSubscription returns an error, so the audit row
	// records cancel_attempted=true + cancel_succeeded=false.
	meta := adminLatestAuditMeta(t, db, teamID, models.AuditKindSubscriptionCanceledByAdmin)
	assert.Equal(t, true, meta["cancel_attempted"])
	assert.Equal(t, false, meta["cancel_succeeded"])
	assert.NotEmpty(t, meta["cancel_error"], "default closure error string must be recorded")
}

// ── List ─────────────────────────────────────────────────────────────────────

// TestAdminList_SingleTierFilter_ExactMatch hits the len(tiers)==1 branch
// (the single-tier exact-match `t.plan_tier = $N` path, lines 241-247).
func TestAdminList_SingleTierFilter_ExactMatch(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)

	hobbyID, _ := adminSeedTeam(t, db, "hobby")
	_, _ = adminSeedTeam(t, db, "pro")

	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers?tier=hobby", nil)
	require.Equal(t, http.StatusOK, status)
	customers, _ := body["customers"].([]any)
	found := false
	for _, c := range customers {
		m, _ := c.(map[string]any)
		if m["team_id"] == hobbyID.String() {
			found = true
		}
		assert.Equal(t, "hobby", m["tier"], "single-tier filter must only return hobby teams")
	}
	assert.True(t, found, "seeded hobby team must appear in tier=hobby filter")
}

// TestAdminList_QueryFailed_BrokenDB drives the query-failed arm (lines
// 324-328) via a closed DB.
func TestAdminList_QueryFailed_BrokenDB(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, brokenDB(t), adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers", nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminList_ScanFailed_Sqlmock drives the scan-failed arm (lines
// 344-349): a row whose first column can't scan into uuid.UUID.
func TestAdminList_ScanFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// 9 columns in the SELECT; return a non-UUID for the first column so
	// Scan into uuid.UUID fails.
	cols := []string{"id", "plan_tier", "name", "created_at", "primary_email",
		"storage_bytes", "deployments_active", "last_active", "total_count"}
	rows := sqlmock.NewRows(cols).AddRow("not-a-uuid", "hobby", "", nil, "", 0, 0, nil, 1)
	mock.ExpectQuery(".*").WillReturnRows(rows)

	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers", nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminList_RowsErr_Sqlmock drives the rows.Err() arm (lines 370-374)
// by injecting a row-level error after a successful row.
func TestAdminList_RowsErr_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	cols := []string{"id", "plan_tier", "name", "created_at", "primary_email",
		"storage_bytes", "deployments_active", "last_active", "total_count"}
	rows := sqlmock.NewRows(cols).
		AddRow(uuid.New().String(), "hobby", "", nil, "", int64(0), 0, nil, 1).
		RowError(0, errors.New("injected row error"))
	mock.ExpectQuery(".*").WillReturnRows(rows)

	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers", nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// ── Detail ─────────────────────────────────────────────────────────────────

// TestAdminDetail_InvalidUUID_400 hits lines 439-441.
func TestAdminDetail_InvalidUUID_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/not-a-uuid", nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_team_id", body["error"])
}

// TestAdminDetail_TeamQueryFailed_BrokenDB hits the db_failed arm (449-450).
func TestAdminDetail_TeamQueryFailed_BrokenDB(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, brokenDB(t), adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+uuid.NewString(), nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminDetail_RazorpaySubAndAuditRows covers the razorpay-sub-present
// branch (464-466) and the audit-rows-present + metadata branch (534-546):
// seed a team with a subscription_id + an audit row carrying metadata.
func TestAdminDetail_RazorpaySubAndAuditRows(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)

	teamID, subID := adminSeedTeamWithSub(t, db, "pro")
	// Emit an audit row with non-empty metadata so the meta.Valid branch runs.
	require.NoError(t, models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "admin",
		Kind:     "test.detail",
		Summary:  "residual detail coverage",
		Metadata: []byte(`{"k":"v"}`),
	}))

	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+teamID.String(), nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	cust, _ := body["customer"].(map[string]any)
	assert.Equal(t, subID, cust["razorpay_subscription_id"], "subscription_id must surface")
	audit, _ := cust["recent_audit"].([]any)
	assert.NotEmpty(t, audit, "recent_audit must include the seeded row")
}

// ── ChangeTier ───────────────────────────────────────────────────────────────

// TestAdminTierChange_InvalidUUID_400 hits lines 629-631.
func TestAdminTierChange_InvalidUUID_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/not-a-uuid/tier",
		map[string]any{"tier": "pro", "reason": "x"})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_team_id", body["error"])
}

// TestAdminTierChange_InvalidBody_400 hits lines 634-636 (BodyParser error).
func TestAdminTierChange_InvalidBody_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminPostRawJSON(t, app, "/api/v1/admin/customers/"+uuid.NewString()+"/tier", `{bad json`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_body", body["error"])
}

// TestAdminTierChange_TeamQueryFailed_BrokenDB hits the db_failed arm
// (654-655): a valid body but a broken DB on GetTeamByID.
func TestAdminTierChange_TeamQueryFailed_BrokenDB(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, brokenDB(t), adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+uuid.NewString()+"/tier",
		map[string]any{"tier": "pro", "reason": "valid reason"})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminTierChange_UpdateFailed_Sqlmock hits the UpdatePlanTier-failed arm
// (663-666): GetTeamByID succeeds (mocked) on a different tier, then
// UpdatePlanTier errors.
func TestAdminTierChange_UpdateFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	tid := uuid.New()
	// GetTeamByID selects 6 columns: id, name, plan_tier,
	// stripe_customer_id, created_at, default_deployment_ttl_policy.
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "plan_tier",
			"stripe_customer_id", "created_at", "default_deployment_ttl_policy"}).
			AddRow(tid, "", "hobby", nil, time.Now(), "auto_24h"))
	// UpdatePlanTier — fail.
	mock.ExpectExec(`UPDATE teams SET plan_tier`).
		WillReturnError(errors.New("update boom"))

	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+tid.String()+"/tier",
		map[string]any{"tier": "pro", "reason": "valid reason"})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// ── IssuePromo ───────────────────────────────────────────────────────────────

// TestAdminIssuePromo_InvalidUUID_400 hits 829-831.
func TestAdminIssuePromo_InvalidUUID_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/not-a-uuid/promo",
		map[string]any{"kind": "first_month_free", "valid_for_days": 30})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_team_id", body["error"])
}

// TestAdminIssuePromo_InvalidBody_400 hits 834-836.
func TestAdminIssuePromo_InvalidBody_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminPostRawJSON(t, app, "/api/v1/admin/customers/"+uuid.NewString()+"/promo", `{bad`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_body", body["error"])
}

// TestAdminIssuePromo_ValidForDays_400 hits 843-846.
func TestAdminIssuePromo_ValidForDays_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+uuid.NewString()+"/promo",
		map[string]any{"kind": "first_month_free", "valid_for_days": 0})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_valid_for_days", body["error"])
}

// TestAdminIssuePromo_AmountOffValue_400 hits 851-854.
func TestAdminIssuePromo_AmountOffValue_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+uuid.NewString()+"/promo",
		map[string]any{"kind": "amount_off", "value": 0, "valid_for_days": 30})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_value", body["error"])
}

// TestAdminIssuePromo_TeamQueryFailed_BrokenDB hits the db_failed arm at 861.
func TestAdminIssuePromo_TeamQueryFailed_BrokenDB(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, brokenDB(t), adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+uuid.NewString()+"/promo",
		map[string]any{"kind": "first_month_free", "valid_for_days": 30})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminIssuePromo_InsertFailed_Sqlmock hits the insert db_failed arm
// (879-880): team lookup succeeds (mocked), promo insert errors with a
// non-validation error.
func TestAdminIssuePromo_InsertFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "plan_tier",
			"stripe_customer_id", "created_at", "default_deployment_ttl_policy"}).
			AddRow(tid, "", "hobby", nil, time.Now(), "auto_24h"))
	// IssueAdminPromoCode runs a QueryRow INSERT...RETURNING — fail it with a
	// generic (non-unique) error so the handler's db_failed arm runs.
	mock.ExpectQuery(`INSERT INTO admin_promo_codes`).
		WillReturnError(errors.New("insert boom"))

	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+tid.String()+"/promo",
		map[string]any{"kind": "first_month_free", "valid_for_days": 30})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminTierChange_UnknownTeam_404 hits the team_not_found arm (651-653):
// a valid tier+reason body but a team id that doesn't exist.
func TestAdminTierChange_UnknownTeam_404(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+uuid.NewString()+"/tier",
		map[string]any{"tier": "pro", "reason": "valid reason"})
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "team_not_found", body["error"])
}

// TestAdminIssuePromo_ModelRejectsValue_400 hits the model-validation
// sentinel arm (874-878): first_month_free passes handler validation
// (value isn't range-checked for that kind) but a negative value makes the
// model return ErrInvalidPromoValue → 400 invalid_promo.
func TestAdminIssuePromo_ModelRejectsValue_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/promo",
		map[string]any{"kind": "first_month_free", "value": -5, "valid_for_days": 30})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_promo", body["error"])
}

// adminTeamSelectCols / adminTeamRow build a GetTeamByID-shaped mocked row.
func adminTeamRow(tid uuid.UUID, tier string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "name", "plan_tier",
		"stripe_customer_id", "created_at", "default_deployment_ttl_policy"}).
		AddRow(tid, "", tier, nil, time.Now(), "auto_24h")
}

// TestAdminTierChange_PromoteElevateFailures_StillReturns200 drives the
// best-effort elevate-failed WARN arms on a promote (681-689). GetTeamByID
// returns hobby, UpdatePlanTier succeeds, then each Elevate* call errors —
// the handler logs at WARN and still returns 200.
func TestAdminTierChange_PromoteElevateFailures_StillReturns200(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(adminTeamRow(tid, "hobby"))
	mock.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	// All three Elevate* calls fail — best-effort, must not change the 200.
	mock.ExpectExec(`UPDATE resources`).WillReturnError(errors.New("elev res boom"))
	mock.ExpectExec(`UPDATE deployments`).WillReturnError(errors.New("elev dep boom"))
	mock.ExpectExec(`UPDATE stacks`).WillReturnError(errors.New("elev stk boom"))
	// Audit insert — accept either Exec or Query shape.
	mock.ExpectExec(`INSERT INTO audit_log`).WillReturnResult(sqlmock.NewResult(0, 1))

	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+tid.String()+"/tier",
		map[string]any{"tier": "pro", "reason": "promote with failing elevates"})
	assert.Equal(t, http.StatusOK, status, "promote must still 200 even when elevates fail: %v", body)
	assert.Equal(t, "pro", body["to"])
}

// TestAdminDetail_UsersScanFailed_Sqlmock drives the Detail users-scan-failed
// arm (483-486): GetTeamByID succeeds, then the users query returns a row
// whose id column can't scan into uuid.UUID.
func TestAdminDetail_UsersScanFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(adminTeamRow(tid, "hobby"))
	// users query — bad uuid in first column.
	mock.ExpectQuery(`FROM users`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "created_at"}).
			AddRow("not-a-uuid", "u@x.com", "member", time.Now()))
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+tid.String(), nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminDetail_UsersQueryFailed_Sqlmock drives the users-query-failed arm
// (476-479): GetTeamByID succeeds, the users query itself errors.
func TestAdminDetail_UsersQueryFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(adminTeamRow(tid, "hobby"))
	mock.ExpectQuery(`FROM users`).WithArgs(tid).WillReturnError(errors.New("users boom"))
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+tid.String(), nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminDetail_ResourcesQueryFailed_Sqlmock drives the resources-query
// arm (500-503): team + users succeed, resources query errors.
func TestAdminDetail_ResourcesQueryFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(adminTeamRow(tid, "hobby"))
	mock.ExpectQuery(`FROM users`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "created_at"})) // empty
	mock.ExpectQuery(`FROM resources`).WithArgs(tid).WillReturnError(errors.New("res boom"))
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+tid.String(), nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminDetail_ResourcesScanFailed_Sqlmock drives the resources-scan arm
// (506-509): a resources row whose count column can't scan into int.
func TestAdminDetail_ResourcesScanFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(adminTeamRow(tid, "hobby"))
	mock.ExpectQuery(`FROM users`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "created_at"}))
	mock.ExpectQuery(`FROM resources`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"resource_type", "count", "storage_bytes"}).
			AddRow("redis", "not-an-int", 0))
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+tid.String(), nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestAdminDetail_AuditScanFailed_Sqlmock drives the audit-scan arm
// (538-541): team+users+resources+deploycount succeed, audit row's id
// column can't scan into uuid.UUID.
func TestAdminDetail_AuditScanFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(adminTeamRow(tid, "hobby"))
	mock.ExpectQuery(`FROM users`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "created_at"}))
	mock.ExpectQuery(`FROM resources`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"resource_type", "count", "storage_bytes"}))
	// CountActiveDeploymentsByTeam — return a count.
	mock.ExpectQuery(`FROM deployments`).WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// audit query — bad uuid id.
	mock.ExpectQuery(`FROM audit_log`).WithArgs(tid, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "actor", "kind", "summary", "metadata", "created_at"}).
			AddRow("not-a-uuid", "admin", "k", "s", nil, time.Now()))
	app := adminAppAllRoutes(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+tid.String(), nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}
