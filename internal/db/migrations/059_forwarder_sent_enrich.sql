-- 059_forwarder_sent_enrich.sql — enrich the worker-side send ledger with
-- audit columns so support staff can answer "which audit_log row was
-- forwarded to which provider, when, to what masked recipient, with what
-- terminal classification" without grepping pod logs.
--
-- This file is a verbatim copy of worker/sql/059_forwarder_sent_enrich.sql
-- (the canonical source — the worker repo owns this table). Keep the two
-- in sync; the api repo carries the copy so the api migration runner and
-- the auto-deploy gate apply it on a fresh platform DB.
--
-- WHY (BugBash 2026-05-20, P1-3 enrichment):
-- Migration 055 introduced forwarder_sent (audit_id, sent_at) as a minimal
-- idempotency ledger. That stopped duplicate sends across cursor resets,
-- but it did NOT give support a way to answer "what happened to email X?"
-- without log-spelunking — and the F4 missing-renderer path (next door
-- in this PR) needs a place to record permanent drops so an operator
-- can grep `classification='permanent_drop'` to find them.
--
-- The columns are appended via ALTER TABLE so a fresh deploy and an
-- already-populated prod DB both converge cleanly. Existing rows
-- backfill to provider='legacy' / classification='success' (the only
-- state a pre-059 row could have been in — markSent was only called on
-- a confirmed 2xx or terminal class).
--
-- Columns:
--   * provider       — 'brevo' | 'ses' | 'noop' | 'none' (used by the
--                      F4 permanent_drop path when no provider was called)
--   * provider_id    — Brevo X-Mailin-Custom value / Resend id /
--                      EventEmail.IdempotencyKey ('audit-<row-id>') when
--                      the provider doesn't surface a message id.
--                      For F4 permanent drops: 'missing_renderer'.
--   * recipient      — MASKED address ("a***@example.com") via the same
--                      algorithm api/internal/email/email.go:maskEmail uses.
--                      NEVER store the raw recipient — PII discipline
--                      (CLAUDE memory feedback_no_hardcoded_strings +
--                      mask-email-in-logs).
--   * template_kind  — audit_log.kind verbatim (e.g. 'anon.expiry_warning').
--                      The same value as the joined audit_log.kind, but
--                      denormalized so a support query against this single
--                      table is index-only.
--   * classification — 'success' | 'transient_retry' | 'permanent_drop'.
--                      success: a 2xx return from the provider.
--                      transient_retry: NOT used today (the ledger only
--                        ever sees a row AFTER a terminal outcome — a
--                        Transient send leaves the row absent so the
--                        next tick retries; this enum value is reserved
--                        for a future per-attempt audit if we add one).
--                      permanent_drop: F4 missing_renderer + the existing
--                        Permanent/SkippedNoTemplate provider classes.

ALTER TABLE forwarder_sent
    ADD COLUMN IF NOT EXISTS provider       TEXT NOT NULL DEFAULT 'legacy',
    ADD COLUMN IF NOT EXISTS provider_id    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS recipient      TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS template_kind  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS classification TEXT NOT NULL DEFAULT 'success';

-- Indexes for the two support-query shapes that motivated this table:
--   1. "Recent activity for one recipient" — SELECT * FROM forwarder_sent
--      WHERE recipient = $1 ORDER BY sent_at DESC LIMIT 50.
--   2. "How many of <kind> went out this week" — SELECT count(*) FROM
--      forwarder_sent WHERE template_kind = $1 AND sent_at > now() - '7 days'.
CREATE INDEX IF NOT EXISTS idx_forwarder_sent_sent_at
    ON forwarder_sent (sent_at DESC);

CREATE INDEX IF NOT EXISTS idx_forwarder_sent_template_kind_sent_at
    ON forwarder_sent (template_kind, sent_at DESC);

-- Partial index for the "find permanent drops" support query. Tiny in
-- normal operation (only F4 missing_renderer rows + provider permanent
-- failures land here) but unindexed scans of a multi-million-row ledger
-- would be slow when the operator does want it.
CREATE INDEX IF NOT EXISTS idx_forwarder_sent_perm_drop
    ON forwarder_sent (sent_at DESC)
    WHERE classification = 'permanent_drop';
