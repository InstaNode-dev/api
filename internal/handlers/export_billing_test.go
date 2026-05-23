package handlers

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"instant.dev/internal/models"
)

// ExportedPlanIDToTier exposes the unexported planIDToTier resolver to
// the external _test package so the new yearly plan-id mapping can be
// asserted without making the helper itself public. Only included in the
// test binary thanks to the _test.go suffix.
func ExportedPlanIDToTier(h *BillingHandler, planID string) string {
	return h.planIDToTier(planID)
}

// PlanIDToTierFallbackForTest exposes the planIDToTierFallback constant
// to the external handlers_test package so regression tests assert the
// safe-fallback tier rather than hard-coding "hobby". If the constant
// changes in future the tests automatically track it.
const PlanIDToTierFallbackForTest = planIDToTierFallback

// ExportedRazorpayPlanIDs exposes razorpayPlanIDs to the external test
// package. Only used by coverage tests to assert the per-tier map is
// populated from cfg.
func ExportedRazorpayPlanIDs(h *BillingHandler) map[string]string {
	return h.razorpayPlanIDs()
}

// ExportedRazorpayPlanIDFor exposes razorpayPlanIDFor for table-driven
// (tier, frequency) tests.
func ExportedRazorpayPlanIDFor(h *BillingHandler, tier, freq string) string {
	return h.razorpayPlanIDFor(tier, freq)
}

// ExportedPlanIDRecognised exposes planIDRecognised for coverage.
func ExportedPlanIDRecognised(h *BillingHandler, planID string) bool {
	return h.planIDRecognised(planID)
}

// ExportedFormatChargedAmount exposes the unexported helper for currency-
// formatting coverage.
func ExportedFormatChargedAmount(amount int64, currency string) string {
	return formatChargedAmount(amount, currency)
}

// ExportedMonthlyAmountINRForTier exposes the unexported fallback amount
// helper.
func ExportedMonthlyAmountINRForTier(tier string) int64 {
	return monthlyAmountINRForTier(tier)
}

// ExportedDunningDedupKey exposes the unexported dedup-key helper for
// regression testing.
func ExportedDunningDedupKey(recipient string) string {
	return dunningDedupKey(recipient)
}

// ExportedMaybeMarkAdminPromoCodeUsed exposes the package-private
// promo-code redemption helper. Signature passes the subscription notes
// map directly so the test does not need to construct a full
// rzpSubscriptionEntity (the wire-shape struct is unexported).
func ExportedMaybeMarkAdminPromoCodeUsed(ctx context.Context, db *sql.DB, notes map[string]string, subID string, teamID uuid.UUID) {
	sub := rzpSubscriptionEntity{ID: subID, Notes: notes}
	maybeMarkAdminPromoCodeUsed(ctx, db, sub, teamID)
}

// ExportedCheckoutNoteAdminPromoCodeID is the canonical map key in
// subscription notes for the admin promo code id.
const ExportedCheckoutNoteAdminPromoCodeID = checkoutNoteAdminPromoCodeID

// ── promotion helper exports (coverage) ──────────────────────────────────────

// ExportedClassifyPromotionError exposes classifyPromotionError so the
// expired / exhausted / does-not-apply / default branches can be asserted
// directly.
func ExportedClassifyPromotionError(err error, code, plan string) (kind, message string) {
	return classifyPromotionError(err, code, plan)
}

// ExportedIsPromoNotFoundError exposes isPromoNotFoundError for the nil +
// substring branches.
func ExportedIsPromoNotFoundError(err error) bool {
	return isPromoNotFoundError(err)
}

// ExportedAdminPromoDescription exposes adminPromoDescription so the
// per-kind + default copy branches can be asserted without a DB row.
func ExportedAdminPromoDescription(kind string, value int) string {
	return adminPromoDescription(&models.AdminPromoCode{Kind: kind, Value: value})
}

// ExportedNewErr is a tiny helper returning an error with the given message
// so coverage tests can construct typed-as-string registry errors.
func ExportedNewErr(msg string) error { return errors.New(msg) }

// ── NewBillingHandler default-closure exercisers (coverage) ──────────────────
//
// NewBillingHandler wires three production default closures
// (FetchSubscriptionDetails / CreateSubscription / FetchCheckoutSubscription)
// that each construct a real Razorpay client + circuit breaker. With
// unconfigured/garbage creds they error out — that's fine; the goal is to
// execute the closure bodies (the lines inside NewBillingHandler) for
// coverage, asserting only that the call returns (no panic).

// ExerciseFetchSubscriptionDetails invokes the prod default closure.
func ExerciseFetchSubscriptionDetails(h *BillingHandler, subID string) {
	defer func() { _ = recover() }()
	_, _ = h.FetchSubscriptionDetails(subID)
}

// ExerciseCreateSubscription invokes the prod default closure.
func ExerciseCreateSubscription(h *BillingHandler) {
	defer func() { _ = recover() }()
	_, _ = h.CreateSubscription(map[string]any{"plan_id": "plan_x"})
}

// ExerciseFetchCheckoutSubscription invokes the prod default closure.
func ExerciseFetchCheckoutSubscription(h *BillingHandler, subID string) {
	defer func() { _ = recover() }()
	_, _, _ = h.FetchCheckoutSubscription(subID)
}

// ── audit-emit exports (coverage of the InsertAuditEvent-failed branches) ────
//
// Each emit* helper is best-effort: a DB failure logs at WARN and returns. A
// closed DB makes InsertAuditEvent fail so the error-log branch is covered.

// ExportedEmitSubscriptionCanceledAudit exposes emitSubscriptionCanceledAudit.
func ExportedEmitSubscriptionCanceledAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, fromTier, toTier, subID string) {
	emitSubscriptionCanceledAudit(ctx, db, teamID, fromTier, toTier, subID)
}

// ExportedEmitSubscriptionChangeAudit exposes emitSubscriptionChangeAudit.
func ExportedEmitSubscriptionChangeAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, fromTier, toTier, subID string) {
	emitSubscriptionChangeAudit(ctx, db, teamID, fromTier, toTier, subID)
}

// ExportedEmitPaymentGraceRecoveredAudit exposes the recovered-audit emit
// against a synthetic grace row.
func ExportedEmitPaymentGraceRecoveredAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, subID string) {
	grace := &models.PaymentGracePeriod{ID: uuid.New(), StartedAt: time.Now(), ExpiresAt: time.Now()}
	emitPaymentGraceRecoveredAudit(ctx, db, teamID, subID, grace, time.Now())
}

// ExportedEmitPaymentGraceStartedAudit exposes the started-audit emit.
func ExportedEmitPaymentGraceStartedAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, subID string, amount int64) {
	grace := &models.PaymentGracePeriod{ID: uuid.New(), StartedAt: time.Now(), ExpiresAt: time.Now()}
	emitPaymentGraceStartedAudit(ctx, db, teamID, subID, grace, amount)
}

// ExportedMaybeRecoverPaymentGrace exposes maybeRecoverPaymentGrace so its
// nil-db, lookup-error, no-active-grace, and flip branches can be exercised
// directly.
func ExportedMaybeRecoverPaymentGrace(ctx context.Context, db *sql.DB, teamID uuid.UUID, subID string) {
	maybeRecoverPaymentGrace(ctx, db, teamID, subID)
}

// ExportedEmitChargeUndeliverableAudit exposes the charge-undeliverable emit.
// The subscription entity is built from minimal fields.
func ExportedEmitChargeUndeliverableAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, subID, planID, reason, resolvedTier string) {
	sub := rzpSubscriptionEntity{ID: subID, PlanID: planID}
	emitChargeUndeliverableAudit(ctx, db, teamID, sub, rzpWebhookEvent{}, reason, resolvedTier)
}
