-- 055_forwarder_sent.sql — worker-side send ledger for the event-email
-- forwarder (worker/internal/jobs/event_email_forwarder.go).
--
-- This file is a verbatim copy of worker/sql/055_forwarder_sent.sql (the
-- canonical source — the worker repo owns this table). Keep the two in
-- sync; the api repo carries the copy so the api migration runner and the
-- auto-deploy gate apply it on a fresh platform DB.
--
-- WHY (BugBash 2026-05-19, P1-3):
-- The forwarder's only idempotency mechanism was the Brevo X-Mailin-Custom
-- header, which is free-form metadata — NOT a delivery-dedup guarantee.
-- Every cursor reset / cursor_corrupt reset / crash-mid-batch recovery
-- re-sent real duplicate email. forwarder_sent is a true worker-side
-- ledger: the forwarder INSERTs (audit_id) ON CONFLICT DO NOTHING before
-- each send and skips when the insert affects 0 rows.

CREATE TABLE IF NOT EXISTS forwarder_sent (
    audit_id TEXT PRIMARY KEY,
    sent_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
