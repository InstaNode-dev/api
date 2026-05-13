-- Migration: 022_email_events — provider-side delivery feedback (bounces,
-- unsubscribes, spam complaints, soft bounces) normalized into a single
-- table so the worker's email forwarder can suppress sends to addresses
-- that have already told us "stop".
--
-- WHY: every email we send to a known-bouncing address erodes sender
-- reputation; every nudge to someone who unsubscribed is a CAN-SPAM /
-- GDPR risk. Today instanode has zero surface for provider feedback —
-- this table is the ingestion point.
--
-- Sources: Brevo + SES (SNS) webhooks today, SendGrid stub for parity.
-- Schema is provider-shaped enough to add columns later (e.g. bounce
-- subtype) without breaking existing readers.
--
-- Idempotency: providers retry on slow responses, so the same delivery
-- event can arrive twice. We dedupe on the four-tuple
-- (provider, event_type, email, raw->>'message_id') via a partial UNIQUE
-- index so retries are silent no-ops. The "message_id" key is what every
-- supported provider stamps on the raw payload — see the parser in
-- handlers/email_webhooks.go for the per-provider extraction.
CREATE TABLE IF NOT EXISTS email_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider    TEXT NOT NULL,           -- 'brevo' | 'ses' | 'sendgrid'
    event_type  TEXT NOT NULL,           -- 'bounce' | 'unsubscribe' | 'spam_complaint' | 'soft_bounce'
    email       TEXT NOT NULL,
    reason      TEXT,                    -- provider-specific text, optional
    raw         JSONB NOT NULL,          -- full provider payload, for audit
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Suppression-query index: the worker forwarder reads
--   WHERE email = $1 AND event_type IN (...) AND created_at > now() - interval '365 days'
-- before every send. The composite (email, event_type, created_at DESC)
-- means the worker's lookup is a single index range scan even when the
-- table grows to millions of rows.
CREATE INDEX IF NOT EXISTS idx_email_events_email_type
    ON email_events(email, event_type, created_at DESC);

-- Idempotency / dedupe index. message_id is the provider-stamped delivery
-- id (Brevo: "message-id"; SES: "mail.messageId"; SendGrid: "sg_message_id").
-- Partial index — only when message_id is present in the payload, so the
-- table still accepts events from any future provider that omits it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_email_events_dedupe
    ON email_events(provider, event_type, email, (raw->>'message_id'))
    WHERE raw->>'message_id' IS NOT NULL;
