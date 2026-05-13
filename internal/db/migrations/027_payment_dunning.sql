-- Migration: 027_payment_dunning — failed-charge grace period state machine.
--
-- Why this table exists: today's billing flow assumes the happy path. A
-- Razorpay subscription.charged webhook elevates the team's tier; a
-- subscription.cancelled webhook drops it. There is no in-between for a
-- card that declines while the customer is otherwise in good standing.
-- Razorpay's own retry schedule eventually fires subscription.cancelled
-- after N failed attempts, but during the retry window we send the
-- customer nothing — they discover their account is gone only when the
-- dashboard surfaces "free" tier on their next visit.
--
-- This table is the dunning state machine: one active row per team
-- between the first failed charge and either (a) a successful recharge
-- (status = 'recovered') or (b) the 7-day grace period elapsing
-- (status = 'terminated'). The worker drives email reminders every 6
-- hours off this table (up to 28 reminders over 7 days) and the
-- terminator job sweeps expires_at < now() rows on the hourly schedule.
--
-- Status enum is unconstrained TEXT for forward-compat — if we later
-- introduce 'paused' / 'admin_extended' we don't need a DB migration to
-- accept the value. The application code is the source of truth for
-- valid transitions; readers MUST treat unknown statuses as
-- "don't touch."
--
-- One-active-row invariant: a single team can have at most one
-- status='active' row at a time. This is enforced by the partial unique
-- index uq_payment_grace_team_active — a redelivery of the same
-- subscription.charged_failed webhook hits the constraint, the INSERT
-- fails with a unique-violation, and the handler treats that as a
-- no-op (the grace clock has already started). Historical 'recovered' /
-- 'terminated' rows for the same team are unconstrained — a customer
-- who recovers, pays for two more months, then fails again should get a
-- fresh grace row, not a reactivation of the prior one.
CREATE TABLE IF NOT EXISTS payment_grace_periods (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id          UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    subscription_id  TEXT NOT NULL,                       -- Razorpay sub_<...> snapshot at grace-start time
    status           TEXT NOT NULL DEFAULT 'active',      -- active | recovered | terminated
    started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,                -- started_at + 7 days; terminator job sweeps when now() > this
    reminders_sent   INTEGER NOT NULL DEFAULT 0,          -- monotonic counter; up to 28 (every 6h over 7d)
    last_reminder_at TIMESTAMPTZ,                         -- NULL until the first reminder fires; drives the 6h cadence query
    recovered_at     TIMESTAMPTZ,                         -- non-NULL iff status='recovered'
    terminated_at    TIMESTAMPTZ                          -- non-NULL iff status='terminated'
);

-- Backs the worker's two sweep queries:
--   1. payment_grace_reminder job:
--      WHERE status='active' AND expires_at > now()
--        AND (last_reminder_at IS NULL OR last_reminder_at < now() - interval '6 hours')
--   2. payment_grace_terminator job:
--      WHERE status='active' AND expires_at < now()
-- Both filter on (status, expires_at) so a composite index covers both
-- — the terminator can stop after the expires_at < now() index range,
-- and the reminder job's residual filter on last_reminder_at is a cheap
-- in-memory check on the much smaller status='active' subset.
CREATE INDEX IF NOT EXISTS idx_payment_grace_active
    ON payment_grace_periods(status, expires_at);

-- One-active-row invariant. Razorpay webhook redeliveries are common —
-- a delayed network ack causes Razorpay to fire the same
-- subscription.charged_failed event twice within a few seconds. Without
-- this index the handler would write two grace rows for the same team,
-- the worker would send two parallel email streams, and the customer
-- would receive doubled reminders. The partial predicate
-- WHERE status='active' lets historical recovered/terminated rows
-- coexist with a new active row when the customer recovers, pays for a
-- while, then fails again later.
CREATE UNIQUE INDEX IF NOT EXISTS uq_payment_grace_team_active
    ON payment_grace_periods(team_id) WHERE status = 'active';
