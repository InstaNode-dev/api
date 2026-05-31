package handlers

// billing_ttl_promote_error_test.go — coverage for the two ttl-promote
// branches in billing.go that the existing integration-style tests in
// billing_ttl_promote_test.go cannot reach against a real Postgres:
//
//   - the promoteErr != nil arm of the switch (lines 1908-1916), where
//     PromoteDeploymentTTLsForTeam errored AFTER the upgrade tx already
//     committed (fail-open: the webhook MUST still return 200 and emit
//     a slog.Error + the "error" outcome metric).
//   - the if db == nil { return } early-out of emitTTLPoliciesPromotedAudit
//     (lines 3550-3551), the defensive guard for misconfigured handlers.
//
// White-box (package handlers) so we can reach the promoteDeploymentTTLsForTeamFn
// seam and call emitTTLPoliciesPromotedAudit directly. Mirrors the
// billingPortalFactory seam pattern: prod default is the real models call,
// tests swap a fake before exercising the handler and restore on cleanup.
//
// Why a seam (and not a real-DB error injection)? The promote call runs
// AFTER UpgradeTeamAllTiersWithSubscription's tx has committed. To force
// promote to error from the postgres side without sabotaging the prior tx
// you'd need mid-request DDL — impossible to do from a black-box test, and
// fragile. The seam keeps the production path identical (a no-op var
// pointing at the real models call) and gives the test a deterministic
// failure injection point that maps 1-1 to the slog.Error branch.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// localTestJWTSecret mirrors localTestJWTSecret. Inlined because
// internal/testhelpers imports internal/handlers and an import cycle is
// not allowed in white-box test files.
const localTestJWTSecret = "test-secret-that-is-at-least-32-bytes-long!!"

// openLocalTestDB connects to TEST_DATABASE_URL using the same driver as
// the integration suite. The caller must Skip when the env var is unset.
func openLocalTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err, "openLocalTestDB: sql.Open")
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Ping(), "openLocalTestDB: ping")
	return db
}

// mustInsertTeam inserts a teams row with the supplied plan_tier and returns
// its UUID as a string. Mirrors testhelpers.MustCreateTeamDB but without the
// cyclic import.
func mustInsertTeam(t *testing.T, db *sql.DB, planTier string) string {
	t.Helper()
	var id string
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO teams (name, plan_tier) VALUES ($1, $2)
		RETURNING id::text
	`, "promote-err-team-"+uuid.NewString()[:8], planTier).Scan(&id)
	require.NoError(t, err, "mustInsertTeam: insert")
	return id
}

// promoteErrTestWebhookSecret is the per-file shared secret used to sign
// Razorpay webhook payloads. Distinct from billing_test.go's package-level
// const so this white-box file doesn't depend on _test package symbols.
const promoteErrTestWebhookSecret = "promote-err-webhook-secret"

// signPromoteErrPayload returns the hex HMAC-SHA256 of the payload using
// the shared secret. Same shape as signRazorpayPayload in billing_test.go.
func signPromoteErrPayload(t *testing.T, payload []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(promoteErrTestWebhookSecret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// newPromoteErrSignedRequest builds a signed /razorpay/webhook request.
func newPromoteErrSignedRequest(t *testing.T, payload []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", signPromoteErrPayload(t, payload))
	return req
}

// newPromoteErrChargedPayload builds a minimal subscription.charged event
// carrying a notes.team_id (so the handler resolves the team without
// hitting the by-subscription-id fallback) and the supplied plan_id (so
// the handler classifies the upgrade as a paid-tier transition that
// reaches the promote-block guard).
func newPromoteErrChargedPayload(t *testing.T, teamID, subID, planID string) []byte {
	t.Helper()
	subEntity, _ := json.Marshal(map[string]any{
		"id":      subID,
		"entity":  "subscription",
		"plan_id": planID,
		"status":  "active",
		"notes":   map[string]any{"team_id": teamID},
	})
	event := map[string]any{
		"entity": "event",
		"event":  "subscription.charged",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
	out, err := json.Marshal(event)
	require.NoError(t, err)
	return out
}

// newPromoteErrApp builds the Fiber app + config used by the promote-error
// test. Matches billingWebhookDBApp in billing_test.go but uses the local
// secret + lives in package handlers so we can reach the seam.
func newPromoteErrApp(t *testing.T, db *sql.DB) (*fiber.App, *config.Config) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:             localTestJWTSecret,
		RazorpayWebhookSecret: promoteErrTestWebhookSecret,
		RazorpayPlanIDHobby:   "plan_test_hobby_promote_err",
		RazorpayPlanIDPro:     "plan_test_pro_promote_err",
		RazorpayPlanIDTeam:    "plan_test_team_promote_err",
	}
	bh := NewBillingHandler(db, cfg, email.NewNoop())

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", bh.RazorpayWebhook)
	return app, cfg
}

// withPromoteFn swaps promoteDeploymentTTLsForTeamFn to the supplied stub
// for the duration of the test. Cleanup restores the production default.
func withPromoteFn(t *testing.T, fn func(context.Context, *sql.DB, uuid.UUID) (models.PromoteDeploymentTTLsResult, error)) {
	t.Helper()
	orig := promoteDeploymentTTLsForTeamFn
	promoteDeploymentTTLsForTeamFn = fn
	t.Cleanup(func() { promoteDeploymentTTLsForTeamFn = orig })
}

// TestEmitTTLPoliciesPromotedAudit_NilDB_EarlyReturns pins the defensive
// guard that the audit helper bails when handed a nil *sql.DB. The fail-
// open contract documents "missed audit must NOT fail the webhook"; nil-db
// is the worst input the helper could see, so the guard MUST not panic
// and MUST not attempt the InsertAuditEvent call.
func TestEmitTTLPoliciesPromotedAudit_NilDB_EarlyReturns(t *testing.T) {
	// If the nil guard regresses, this call panics on dereference inside
	// models.InsertAuditEvent. The test passes by not panicking + by
	// returning from the helper at all (no observable side effect to assert
	// beyond the absence of a panic).
	require.NotPanics(t, func() {
		emitTTLPoliciesPromotedAudit(
			context.Background(),
			nil,
			uuid.New(),
			models.PromoteDeploymentTTLsResult{DeploysPromoted: 5, TeamDefaultFlipped: true},
			"tier_upgrade",
		)
	})
}

// TestBillingWebhook_ChargedPromoteError_LogsAndReturnsOK pins the
// fail-open contract for the promote-error branch (lines 1908-1916). When
// PromoteDeploymentTTLsForTeam returns an error AFTER the upgrade tx
// already committed, the handler MUST:
//
//   - return 200 (Razorpay redelivery cannot help — the tier flip landed)
//   - NOT emit a team.ttl_policies_promoted audit row (the promote failed
//     so there's nothing to record; the existing subscription.upgraded
//     audit covers the customer-visible change)
//   - leave the underlying tier upgrade observable (plan_tier flipped in
//     the teams row by the prior UpgradeTeamAllTiersWithSubscription tx)
//
// Drives the real /razorpay/webhook endpoint against the real test DB but
// with promoteDeploymentTTLsForTeamFn swapped for a stub that returns an
// error. Skips when TEST_DATABASE_URL is unset.
func TestBillingWebhook_ChargedPromoteError_LogsAndReturnsOK(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed promote-error test")
	}

	db := openLocalTestDB(t)

	app, cfg := newPromoteErrApp(t, db)

	teamID := mustInsertTeam(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// Swap the seam: every call returns the same simulated tx failure.
	// promoteCalls counts to confirm the handler actually reached the seam
	// rather than skipping the block for an unrelated reason (e.g. plan
	// classification missing tier metadata, or the rank guard tripping).
	var promoteCalls int
	withPromoteFn(t, func(context.Context, *sql.DB, uuid.UUID) (models.PromoteDeploymentTTLsResult, error) {
		promoteCalls++
		return models.PromoteDeploymentTTLsResult{}, errors.New("simulated promote failure (tx rolled back)")
	})

	subID := "sub_promote_err_" + uuid.NewString()
	payload := newPromoteErrChargedPayload(t, teamID, subID, cfg.RazorpayPlanIDPro)

	resp, err := app.Test(newPromoteErrSignedRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a promote failure MUST NOT 500 the webhook — the tier upgrade tx already committed")

	assert.Equal(t, 1, promoteCalls,
		"handler MUST reach the promote seam exactly once on a paid-tier subscription.charged")

	// Tier upgrade still observable — the upgrade tx commits before promote runs.
	var newTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&newTier))
	assert.Equal(t, "pro", newTier,
		"prior upgrade tx must remain committed even if the later promote step errors")

	// No team.ttl_policies_promoted audit row — the error arm of the switch
	// does NOT call emitTTLPoliciesPromotedAudit (only the success arm does).
	var auditCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
	`, teamID, models.AuditKindTeamTTLPoliciesPromoted).Scan(&auditCount))
	assert.Equal(t, 0, auditCount,
		"promote-error branch MUST NOT emit a team.ttl_policies_promoted audit row — only the success branch does")
}
