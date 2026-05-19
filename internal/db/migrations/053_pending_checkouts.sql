-- 053_pending_checkouts — payment-failure notification coverage gap.
--
-- WHY THIS EXISTS
-- ---------------
-- The payment-failure email (handlePaymentFailed → SendPaymentFailed) only
-- fires on an inbound Razorpay payment.failed / subscription.charged_failed
-- webhook. A *pre-authorization* failure on Razorpay's hosted checkout page
-- ("seller does not support recurring payments", a declined mandate, an
-- abandoned page) creates NO payment object, so Razorpay sends NO webhook —
-- and the customer gets NO email. A live Pro upgrade test hit exactly this.
--
-- pending_checkouts records every subscription the /api/v1/billing/checkout
-- handler creates. The webhook marks a row resolved_at the moment the
-- subscription activates/charges. The worker's checkout reconciler scans for
-- rows that are still unresolved after a grace window, sends the existing
-- payment-failure notification, and stamps failure_notified_at so the row is
-- only ever notified once. This table is the cross-repo contract the worker
-- reconciler consumes.
--
-- The migration number is 053 (not 034) because 034_drop_trial_ends_at.sql
-- already occupies 034; 053 is the next free slot.
CREATE TABLE IF NOT EXISTS pending_checkouts (
  subscription_id      TEXT PRIMARY KEY,
  team_id              UUID NOT NULL REFERENCES teams(id),
  customer_email       TEXT NOT NULL,
  plan_tier            TEXT NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at          TIMESTAMPTZ,
  failure_notified_at  TIMESTAMPTZ
);

-- Partial index over the worker reconciler's exact scan predicate: rows that
-- are neither resolved nor yet notified. Ordered by created_at so the
-- reconciler can apply its grace-window cutoff cheaply.
CREATE INDEX IF NOT EXISTS idx_pending_checkouts_unresolved
  ON pending_checkouts (created_at) WHERE resolved_at IS NULL AND failure_notified_at IS NULL;
