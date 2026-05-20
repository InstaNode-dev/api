-- 061_forwarder_sent_delivery.sql — extend the worker-side send ledger
-- with Brevo transactional-webhook delivery feedback. Closes the
-- "201 ≠ delivered" gap: Brevo returns 201 the instant it accepts the
-- POST, but the actual SMTP relay happens async — so the existing
-- `classification='success'` row reflects only API-acceptance, NOT
-- delivery. The new columns capture what actually happened downstream.
--
-- WHY (2026-05-20 production incident):
-- Every email since launch was silently rejected at Brevo's relay because
-- the sender domain wasn't validated. The forwarder logged
-- classification=success (200/201 from the API), the audit_log advanced
-- past the row, and zero users heard from us. The ledger lied because
-- it stamped success on API-acceptance instead of relay-delivery.
--
-- This file is the canonical worker-side definition. `api/internal/db/migrations/061_forwarder_sent_delivery.sql`
-- is a verbatim copy so the api migration runner applies it on a fresh
-- platform DB. Keep both in sync.
--
-- Receiver-side machinery (the actual webhook handler) lives in
-- `api/internal/handlers/brevo_webhook.go`. Brevo POSTs to
-- `POST /webhooks/brevo/:secret` for every transactional event
-- (`delivered`, `soft_bounce`, `hard_bounce`, `blocked`, `complaint`,
-- `error`, `deferred`, `unsubscribed`). The handler looks up the
-- matching row by provider_id (Brevo's messageId, persisted by the
-- worker at send time) and updates classification + delivered_at to
-- reflect the actual outcome.
--
-- Columns:
--   * delivered_at — first time we saw a terminal positive event
--                    ('delivered') from Brevo's webhook. NULL while we
--                    only have an API-acceptance row. NOT updated for
--                    non-delivery terminals (bounces, complaints) —
--                    those land in classification instead.
--
-- Classification value extensions (free-form TEXT column today, so this
-- migration is comment-only at the DB level — the api handler writes
-- the new values, the worker keeps writing 'success' on API-acceptance
-- and gets overwritten when the webhook arrives):
--
--   PRE-EXISTING (migration 059):
--     'success'         — Brevo API returned 2xx (API-acceptance, NOT delivery)
--     'permanent_drop'  — F4 missing_renderer / provider Permanent
--     'transient_retry' — reserved, not used today
--
--   ADDED HERE (written by api Brevo webhook handler):
--     'delivered'       — Brevo's SMTP relay confirmed delivery to the recipient MX
--     'bounced_hard'    — Brevo's 'hard_bounce' event — permanent address failure
--     'bounced_soft'    — Brevo's 'soft_bounce' event — transient delivery problem
--     'rejected'        — Brevo's 'blocked' event — sender / domain blocked at relay
--     'complaint'       — Brevo's 'complaint' / 'spam' event — recipient marked as spam
--     'deferred'        — Brevo's 'deferred' event — relay holding the message
--     'unsubscribed'    — Brevo's 'unsubscribed' event — recipient pressed unsubscribe
--
-- Enumeration recipe (CLAUDE.md rule 17): every consumer of
-- forwarder_sent.classification must be updated when a new value is
-- introduced. As of this migration the consumers are:
--   1. `api/internal/handlers/brevo_webhook.go`           — writer (this PR adds it)
--   2. `worker/internal/jobs/event_email_forwarder.go`    — writer (success/permanent_drop)
--   3. `api/internal/handlers/admin_customer_notes.go`    — reader (support panel, free-form display)
-- New values surface in support queries as-is — the column stays TEXT so
-- a future provider (SES delivery notifications, SendGrid event-webhook)
-- can extend the alphabet without a schema migration.

-- Add the delivered_at timestamp. NULL until the webhook says delivered.
-- Idempotent so a re-run of the migration runner is safe.
ALTER TABLE forwarder_sent
    ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ NULL;

-- Index on delivered_at for the "send/delivery ratio" dashboard query
-- (count distinct audit_id where classification='success' vs where
-- delivered_at IS NOT NULL, bucketed by sent_at). Partial — only
-- materialise rows that have actually been confirmed delivered.
CREATE INDEX IF NOT EXISTS idx_forwarder_sent_delivered_at
    ON forwarder_sent (delivered_at DESC)
    WHERE delivered_at IS NOT NULL;

-- Index on (provider, provider_id) for the receiver-side lookup. The api
-- webhook handler matches the inbound `message-id` against this. The
-- index is non-unique because (a) provider_id was DEFAULT '' before
-- migration 059 (legacy rows share empty string), (b) Brevo retries
-- carry the same messageId, and (c) two rows could theoretically share
-- a messageId across providers. The lookup query carries
-- `WHERE provider = 'brevo' AND provider_id = $1` so even the empty-
-- string rows are partitioned by provider.
CREATE INDEX IF NOT EXISTS idx_forwarder_sent_provider_provider_id
    ON forwarder_sent (provider, provider_id);
