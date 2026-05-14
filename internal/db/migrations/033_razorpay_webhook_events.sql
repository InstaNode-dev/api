-- Migration: 028_razorpay_webhook_events
--
-- Razorpay webhook replay protection. The handler at billing.RazorpayWebhook
-- verifies the HMAC-SHA256 signature on every incoming POST — good — but
-- does NOT dedup against the event id. An attacker who captures one signed
-- `subscription.charged` payload (via leaked logs, MITM on a misconfigured
-- proxy, or a compromised Razorpay merchant account) can replay it
-- indefinitely. Each replay re-fires the state machine:
--
--   • `subscription.charged`        → re-upgrades the tier (no-op if same,
--                                      but emits another audit row and
--                                      resets internal expectations)
--   • `subscription.charged_failed` → opens / extends the 7-day grace
--                                      period, sends a dunning email
--   • `payment.failed`              → spurious grace period
--
-- This table records the (event_id, event_type) of every accepted webhook.
-- The handler does INSERT ... ON CONFLICT DO NOTHING and treats a
-- zero-rows-affected as "already processed → 200 OK noop".

CREATE TABLE IF NOT EXISTS razorpay_webhook_events (
    event_id     TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cheap pruning index — older than 30 days are safe to drop (Razorpay
-- doesn't replay that far back; this just keeps the table from growing
-- unbounded). A periodic worker can DELETE WHERE received_at < now() - '30 days'.
CREATE INDEX IF NOT EXISTS idx_razorpay_webhook_events_received_at
    ON razorpay_webhook_events(received_at);
