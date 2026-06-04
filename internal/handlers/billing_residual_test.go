package handlers_test

// billing_residual_test.go — residual coverage for billing.go (93.1% → ≥95%).
// Targets the cleanly-reachable ChangePlanAPI validation + Razorpay-error arms
// that the prior slice left uncovered. All use billingAppNoAuth (pins team_id
// in Locals) + a live DB seeded with a verified user so the requireVerifiedEmail
// gate passes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// changePlanPost posts a change-plan body and returns (status, parsed).
func changePlanPost(t *testing.T, app *fiber.App, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestResidualChangePlan_MissingTarget_400 hits missing_target_plan.
func TestResidualChangePlan_MissingTarget_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "hobby")
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":""}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "missing_target_plan", body["error"])
}

// TestResidualChangePlan_Yearly_400 hits yearly_change_plan_unsupported.
func TestResidualChangePlan_Yearly_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "hobby")
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":"pro","plan_frequency":"yearly"}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "yearly_change_plan_unsupported", body["error"])
}

// TestResidualChangePlan_InvalidFrequency_400 hits invalid_frequency.
func TestResidualChangePlan_InvalidFrequency_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "hobby")
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":"pro","plan_frequency":"weekly"}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_frequency", body["error"])
}

// TestResidualChangePlan_SamePlan_400 hits same_plan (target == current tier).
func TestResidualChangePlan_SamePlan_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "pro")
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":"pro"}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "same_plan", body["error"])
}

// TestResidualChangePlan_Downgrade_400 hits downgrade_not_self_serve
// (pro → hobby is a downgrade).
func TestResidualChangePlan_Downgrade_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "pro")
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret",
		RazorpayPlanIDHobby: "plan_hobby_test", RazorpayPlanIDPro: "plan_pro_test"}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":"hobby"}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "downgrade_not_self_serve", body["error"])
}

// TestResidualChangePlan_TeamTier_Rejected locks the 2026-06-04 CEO re-gate
// at the change-plan surface: a Pro team requesting target_plan=team is
// rejected with 400 tier_not_yet_available — the Team plan is gated out of
// self-serve until its unlimited-resource delivery is proven built. This
// REVERSES the 2026-05-29 (BIZ-1) enablement; the rejection fires before the
// downstream no_subscription guard and regardless of RAZORPAY_PLAN_ID_TEAM.
func TestResidualChangePlan_TeamTier_Rejected(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "pro")
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret",
		RazorpayPlanIDTeam: "plan_team_test"}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":"team"}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "tier_not_yet_available", body["error"],
		"target_plan=team must return tier_not_yet_available — Team is gated out of self-serve (2026-06-04 CEO directive)")
}

// TestResidualChangePlan_NoSubscription_400 hits no_subscription: a valid
// upgrade target but the team has no Razorpay subscription_id on file.
func TestResidualChangePlan_NoSubscription_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "hobby")
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret",
		RazorpayPlanIDPro: "plan_pro_test", RazorpayPlanIDHobby: "plan_hobby_test"}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":"pro"}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "no_subscription", body["error"])
}

// TestResidualPaymentFailed_NoPrimaryUser_DropsEmail drives the
// primary_user_lookup_failed arm (2062-2071): a payment.failed event whose
// subscription resolves to a team that has NO users → dunning email dropped,
// webhook still 200s. Uses the cov2 webhook harness.
func TestResidualPaymentFailed_NoPrimaryUser_DropsEmail(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	// Team with NO users on file.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	subID := "sub_" + uuid.NewString()
	require.NoError(t, models.UpdateRazorpaySubscriptionID(context.Background(), db,
		uuid.MustParse(teamID), subID))

	subEntity, _ := json.Marshal(map[string]any{
		"id": subID, "entity": "subscription", "notes": map[string]any{"team_id": teamID},
	})
	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
		"subscription_id": subID,
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{
			"payment":      map[string]any{"entity": json.RawMessage(payEntity)},
			"subscription": map[string]any{"entity": json.RawMessage(subEntity)},
		},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code, "payment.failed with no primary user must still 200 (email dropped)")
}

// TestResidualBuildPaymentMethod_Nil drives buildPaymentMethod's nil-input arm
// (2780-2782): returns nil when no SubscriptionDetails is present.
func TestResidualBuildPaymentMethod_Nil(t *testing.T) {
	assert.Nil(t, handlers.BuildPaymentMethodForTest())
}

// TestResidualChargedReceipt_NilEmail drives sendPaymentReceipt's nil-email
// early-return (3131-3133): a charged event processed by a handler whose
// emailer is nil. The webhook still 200s.
func TestResidualChargedReceipt_NilEmail(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, nil) // nil mailer
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)
	defer db.Exec(`DELETE FROM email_send_dedup WHERE 1=1`)

	paid := 1
	payload := cov2SubEvent(t, "subscription.charged", teamID, "sub_"+uuid.NewString(),
		cfg.RazorpayPlanIDPro, "active", &paid, 490000)
	code, _ := cov2Run(t, app, payload)
	assert.Equal(t, http.StatusOK, code)
}

// TestResidualChangePlan_RazorpayError_502 drives the ChangePlan-failed arm
// (2980-2981): a valid upgrade (hobby→pro) on a team WITH a subscription_id but
// garbage Razorpay creds → portal.ChangePlan errors (non-circuit) → 502.
func TestResidualChangePlan_RazorpayError_502(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := mkVerifiedTeam(t, db, "hobby")
	require.NoError(t, models.UpdateRazorpaySubscriptionID(context.Background(), db,
		uuid.MustParse(teamID), "sub_"+uuid.NewString()))
	cfg := &config.Config{
		RazorpayKeyID: "rzp_test_garbage", RazorpayKeySecret: "garbage_secret",
		RazorpayPlanIDHobby: "plan_hobby_test", RazorpayPlanIDPro: "plan_pro_test",
	}
	app := billingAppNoAuth(t, db, cfg, teamID)
	status, body := changePlanPost(t, app, `{"target_plan":"pro"}`)
	// Razorpay call fails (bad creds) → 502 razorpay_error (or 503 if the
	// circuit opened first — both are the failure surface we want).
	assert.Contains(t, []int{http.StatusBadGateway, http.StatusServiceUnavailable}, status,
		"change-plan against bad Razorpay creds must surface a 5xx: %v", body)
}

// mkVerifiedTeam creates a team at planTier with a verified owner user.
func mkVerifiedTeam(t *testing.T, db *sql.DB, planTier string) string {
	t.Helper()
	teamID := testhelpers.MustCreateTeamDB(t, db, planTier)
	u, err := models.CreateUser(context.Background(), db, uuid.MustParse(teamID),
		testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	require.NoError(t, models.SetEmailVerified(context.Background(), db, u.ID))
	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	})
	return teamID
}
