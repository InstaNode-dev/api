package handlers_test

// stack_promote_approval_preflight_test.go — regression coverage for sweep
// finding #11 (P2): a promote approval used to be burned to 'executed' BEFORE
// the promote preflight ran, so a preflight failure (412/503/400/402) left the
// single-use approval consumed and non-retryable, forcing a fresh email
// round-trip.
//
// The fix splits validateApprovedPromote (read-only checks, runs before
// preflight) from markApprovedPromoteExecuted (the 'executed' flip, runs only
// after preflight succeeds, immediately before runStackDeploy). These tests
// pin both halves:
//
//   - preflight-fails  → approval stays 'approved' (retryable)
//   - happy path       → approval is 'executed' exactly once
//
// Scope: stack.go ONLY. Skips cleanly when TEST_DATABASE_URL is unset.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// approvalStatus reads the current status column of a promote_approvals row.
func approvalStatus(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM promote_approvals WHERE id = $1`, id).Scan(&status))
	return status
}

// TestStackPromote_ApprovalID_PreflightFails_StaysApproved is the #11
// regression: a source stack whose service has NO image_ref makes the promote
// preflight fail with 412 missing_image_ref. The approval was validated (it is
// approved + matches from/to/kind), but because the flip is deferred to AFTER
// preflight, a preflight failure must leave the approval 'approved' — the
// operator can retry the same approval once the source has a real image_ref.
func TestStackPromote_ApprovalID_PreflightFails_StaysApproved(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "preflightfail@example.com")

	// Source stack with a service that has NO image_ref → preflight 412.
	slug, srcID := seedPromoteSourceStackNoImageRef(t, db, teamIDStr, "staging", "preflight-fail-src")
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO stack_services (stack_id, name, expose, port, image_ref, status)
		VALUES ($1::uuid, 'api', true, 8080, '', 'building')
	`, srcID)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	id := mustSeedApprovedPromote(t, db, teamID, "staging", "production")

	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from":        "staging",
		"to":          "production",
		"approval_id": id,
	})
	defer resp.Body.Close()

	// Preflight rejects the empty image_ref before the deploy launch.
	require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode,
		"a service with no image_ref must fail promote preflight with 412")
	assert.Equal(t, "missing_image_ref", decodeErrCode(t, resp))

	// The crux of #11: the single-use approval must NOT have been burned.
	assert.Equal(t, models.PromoteApprovalStatusApproved, approvalStatus(t, db, id),
		"a preflight failure must leave the approval 'approved' and retryable, not 'executed'")
}

// TestStackPromote_ApprovalID_NoServices_StaysApproved is the sibling #11
// regression for the OTHER early preflight exit: a source stack with zero
// service rows fails with 412 no_services. The approval must survive that
// failure 'approved' too.
func TestStackPromote_ApprovalID_NoServices_StaysApproved(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "noservices@example.com")

	// Source stack with NO service rows at all → preflight 412 no_services.
	slug, _ := seedPromoteSourceStackNoImageRef(t, db, teamIDStr, "staging", "no-services-src")

	app := newStackTestApp(t, db)
	id := mustSeedApprovedPromote(t, db, teamID, "staging", "production")

	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from":        "staging",
		"to":          "production",
		"approval_id": id,
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode,
		"a source with no services must fail promote preflight with 412")
	assert.Equal(t, "no_services", decodeErrCode(t, resp))

	assert.Equal(t, models.PromoteApprovalStatusApproved, approvalStatus(t, db, id),
		"a no_services preflight failure must leave the approval 'approved' and retryable")
}

// TestMarkApprovedPromoteExecuted_AlreadyExecuted_409 drives the CAS-miss arm
// of markApprovedPromoteExecuted directly: an approval row that was flipped to
// 'executed' between validate and the deferred execute (a concurrent
// double-consume race in prod) makes MarkPromoteApprovalExecuted return 0 rows
// (ok=false). The handler must 409 approval_already_executed. Exercised via a
// white-box seam + pre-seeded executed row because the serial HTTP path can't
// interpose a second consumer between validate and execute.
func TestMarkApprovedPromoteExecuted_AlreadyExecuted_409(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)

	// Seed approved, then flip to 'executed' (simulating the racing consumer
	// that won between our validate and execute).
	idStr := mustSeedApprovedPromote(t, db, teamID, "staging", "production")
	id := uuid.MustParse(idStr)
	row, err := models.GetPromoteApprovalByID(context.Background(), db, id)
	require.NoError(t, err)
	ok, err := models.MarkPromoteApprovalExecuted(context.Background(), db, id)
	require.NoError(t, err)
	require.True(t, ok, "first flip must succeed (approved -> executed)")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Get("/t", func(c *fiber.Ctx) error {
		// row is the stale 'approved' snapshot we captured BEFORE the flip —
		// exactly what validateApprovedPromote would hand to markApprovedPromoteExecuted.
		return h.MarkApprovedPromoteExecutedForTest(c, row, "staging", "production")
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "approval_already_executed", decodeErrCode(t, resp))
}

// TestStackPromote_ApprovalID_HappyPath_ExecutesOnce pins the other half of the
// split: a promote whose preflight fully succeeds must flip the approval to
// 'executed' exactly once. This proves markApprovedPromoteExecuted still runs
// on the success path (the fix didn't accidentally drop the flip).
func TestStackPromote_ApprovalID_HappyPath_ExecutesOnce(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "happyexec@example.com")

	// Source WITH an image_ref so preflight passes end-to-end.
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "happy-exec-src")

	app := newStackTestApp(t, db)
	id := mustSeedApprovedPromote(t, db, teamID, "staging", "production")

	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from":        "staging",
		"to":          "production",
		"approval_id": id,
	})
	defer resp.Body.Close()

	require.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp.StatusCode,
		"a fully-valid promote must proceed past the approval gate; got %d", resp.StatusCode)

	// The approval is now consumed — flipped to 'executed' exactly once.
	assert.Equal(t, models.PromoteApprovalStatusExecuted, approvalStatus(t, db, id),
		"a successful promote must flip the approval to 'executed'")

	// Retry the SAME approval — now 'executed', so the status gate rejects it
	// (proving single-use semantics survive the split).
	resp2 := postPromote(t, app, jwt, slug, map[string]any{
		"from":        "staging",
		"to":          "production",
		"approval_id": id,
	})
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode,
		"re-using an executed approval must 409")
	assert.Equal(t, "approval_not_approved", decodeErrCode(t, resp2))
}
