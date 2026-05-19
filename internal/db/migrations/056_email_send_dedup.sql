-- Migration: 056_email_send_dedup — per-billing-cycle dedup ledger for
-- api-side transactional emails (EMAIL-BUGBASH C4/C5).
--
-- WHY: Razorpay fires multiple DISTINCT events for one real billing cycle:
--   • subscription.activated + subscription.charged  → BOTH route into
--     sendPaymentReceipt, so a single upgrade could send TWO receipts.
--   • payment.failed + subscription.pending          → BOTH call
--     SendPaymentFailed, so one failed cycle could send TWO dunning emails.
-- Each event has its own event_id, so the existing razorpay_webhook_events
-- replay guard (which keys on event_id) does NOT dedup them — they are not
-- replays, they are genuinely distinct events describing the same cycle.
--
-- This table is a claim ledger keyed on a caller-built dedup_key that
-- collapses both events of a cycle to one string (e.g.
-- "receipt:<team>:<sub>:<cycle>" / "dunning:<team>:<sub>:<cycle>"). The
-- email send path does INSERT ... ON CONFLICT DO NOTHING and only sends
-- when it inserted the row — so one cycle yields exactly one receipt and
-- one dunning email regardless of how many Razorpay events arrive.
--
-- Idempotent: a webhook redelivery re-attempts the same key, the INSERT is
-- a no-op, and no duplicate email is sent.

CREATE TABLE IF NOT EXISTS email_send_dedup (
    dedup_key   TEXT PRIMARY KEY,
    email_kind  TEXT NOT NULL,            -- 'receipt' | 'dunning' | ...
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cheap pruning index — rows older than 90 days are safe to drop (a billing
-- cycle plus Razorpay's redelivery window is far shorter). A periodic worker
-- can DELETE WHERE created_at < now() - interval '90 days'.
CREATE INDEX IF NOT EXISTS idx_email_send_dedup_created_at
    ON email_send_dedup(created_at);
