-- 041_magic_link_send_status.sql — reconciliation columns for magic_links.
--
-- Adds the four columns the worker's magic_link_reconciler needs to detect,
-- retry, and abandon failed email-send attempts. The 2026-05-14
-- RESEND_API_KEY=CHANGE_ME outage went undetected for an unknown duration
-- because the handler had no per-row record of whether the send actually
-- succeeded — it only logged. With these columns the worker can scan for
-- pending / failed rows inside the 15-minute TTL window and re-drive the
-- send via POST /internal/email/resend-magic-link.
--
-- Idempotent: every column add and the index use IF NOT EXISTS so a re-run
-- against a partial deploy is a no-op.
--
-- Status state machine:
--
--   pending → sent           (handler success path)
--          → send_failed     (handler error path; worker may retry)
--          → send_abandoned  (worker after the 3rd attempt)
--
-- A row only flips to send_abandoned via worker action; the handler never
-- writes that value directly.

ALTER TABLE magic_links
    ADD COLUMN IF NOT EXISTS email_send_status TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS email_send_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS email_send_last_error TEXT,
    ADD COLUMN IF NOT EXISTS email_send_last_attempted_at TIMESTAMPTZ;

-- Partial index for the worker's reconciliation query: only pending or
-- failed rows within the 15-minute TTL window. The WHERE clause keeps the
-- index tiny by skipping the bulk of the table (sent rows + expired rows
-- aged out of the TTL window). created_at is the leading column so the
-- worker can prune the time window with an index range scan.
CREATE INDEX IF NOT EXISTS idx_magic_links_reconcile
    ON magic_links (created_at, email_send_status)
    WHERE email_send_status IN ('pending', 'send_failed');
