package models

// pending_checkouts.go — payment-failure notification coverage.
//
// WHY THIS EXISTS
// ---------------
// The payment-failure email only fires on an inbound Razorpay payment.failed /
// subscription.charged_failed webhook. A pre-authorization failure on
// Razorpay's hosted checkout page ("seller does not support recurring
// payments", a declined mandate, an abandoned page) creates NO payment object,
// so Razorpay sends NO webhook — and the customer gets NO email.
//
// pending_checkouts records every subscription /api/v1/billing/checkout
// creates. The billing webhook marks a row resolved the moment the
// subscription activates or charges. The worker's checkout reconciler scans
// for rows still unresolved after a grace window, sends the payment-failure
// notification, and stamps failure_notified_at so a row is only ever notified
// once.
//
// State transitions (enforced by the application, not the DB):
//
//   <none> ──── InsertPendingCheckout ──────────► unresolved
//   unresolved ─ ResolvePendingCheckout ────────► resolved   (resolved_at set)
//   unresolved ─ worker MarkFailureNotified ────► notified   (failure_notified_at set)
//
// See migration 053_pending_checkouts.sql for the schema.

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// InsertPendingCheckout records a freshly-created Razorpay subscription so the
// worker reconciler can detect a checkout that never completed.
//
// ON CONFLICT (subscription_id) DO NOTHING makes the call idempotent — a retried
// checkout (same subscription_id) is a no-op. Best-effort by contract: the
// caller logs and proceeds on error; a missed row only costs a missed
// payment-failure email, never a blocked checkout.
func InsertPendingCheckout(ctx context.Context, db *sql.DB, subscriptionID string, teamID uuid.UUID, customerEmail, planTier string) error {
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO pending_checkouts (subscription_id, team_id, customer_email, plan_tier)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (subscription_id) DO NOTHING`,
		subscriptionID, teamID, customerEmail, planTier,
	)
	return err
}

// PendingCheckout is one unresolved row from pending_checkouts — a Razorpay
// subscription a /api/v1/billing/checkout call created whose outcome (activate
// / charge / abandon) is not yet known.
type PendingCheckout struct {
	SubscriptionID    string
	PlanTier          string
	FailureNotifiedAt sql.NullTime
}

// FindUnresolvedPendingCheckouts returns every pending_checkouts row for the
// team that is still unresolved (resolved_at IS NULL), newest first.
//
// Audit finding F7: CreateCheckoutAPI uses this to detect that the team
// already has a checkout in flight before minting a SECOND Razorpay
// subscription against the customer's card. The newest-first ordering means
// the caller probes the most-recently-created subscription first — the one
// the customer most likely still has open.
//
// failure_notified_at is returned (not filtered) so the caller can apply its
// own policy: a row the worker already emailed a failure notice for is a
// weaker reuse candidate, but the caller still verifies against Razorpay
// rather than assuming the subscription is dead.
func FindUnresolvedPendingCheckouts(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]PendingCheckout, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT subscription_id, plan_tier, failure_notified_at
		   FROM pending_checkouts
		  WHERE team_id = $1 AND resolved_at IS NULL
		  ORDER BY created_at DESC`,
		teamID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PendingCheckout
	for rows.Next() {
		var pc PendingCheckout
		if scanErr := rows.Scan(&pc.SubscriptionID, &pc.PlanTier, &pc.FailureNotifiedAt); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}

// ResolvePendingCheckout marks a pending checkout resolved once its
// subscription activates or charges — the checkout completed, so the worker
// reconciler must not later notify it as a failure.
//
// The `WHERE resolved_at IS NULL` predicate makes the call idempotent: a
// webhook redelivery (or both subscription.activated AND subscription.charged
// firing for the same subscription) resolves the row exactly once. A
// no-such-row UPDATE is a harmless no-op — the checkout simply predates this
// table, or was created on another path.
func ResolvePendingCheckout(ctx context.Context, db *sql.DB, subscriptionID string) error {
	if db == nil || subscriptionID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`UPDATE pending_checkouts SET resolved_at = now()
		 WHERE subscription_id = $1 AND resolved_at IS NULL`,
		subscriptionID,
	)
	return err
}
