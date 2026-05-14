-- 044_pending_deletions.sql — email-confirmed two-step deletion table.
--
-- Powers Wave FIX-I: when a paid-tier team calls DELETE on a deploy or
-- stack, the API does NOT immediately tear down the resource. Instead it
-- inserts a row here with a hashed confirmation token + 15-min expiry,
-- emails the link to the team's primary user, and returns 202. The user
-- (NOT the agent) clicks the link, which routes back through POST
-- /api/v1/<kind>/:id/confirm-deletion?token=<plaintext>. The handler
-- validates against confirmation_token_hash, flips status='confirmed',
-- and only then calls the actual deprovision path.
--
-- Why a separate table (not a flag on deployments/stacks):
--
--   1. Same shape covers BOTH deploys and stacks (resource_type
--      discriminator) without forking the model layer.
--   2. The confirmation_token_hash is high-churn write-mostly state that
--      doesn't belong on the resource row itself.
--   3. A team can have multiple pending deletions across resources; a
--      column-level flag would force a per-resource lookup pattern.
--
-- Idempotent CREATE: TABLE IF NOT EXISTS so a re-run against a partial
-- deploy is a no-op. Forward-only — no DROP TABLE in the down path
-- because pending_deletions is the source of truth for in-flight
-- destructive ops; rolling back the migration would orphan tokens.
--
-- Status state machine (writes serialised by atomic CAS on status):
--
--   pending → confirmed   (user clicked the email link in time)
--          → cancelled    (user changed mind via DELETE on the confirm endpoint)
--          → expired      (worker periodic job after expires_at < now())
--
-- The terminal states (confirmed/cancelled/expired) are never re-entered;
-- a fresh deletion request creates a NEW row with a fresh token.

CREATE TABLE IF NOT EXISTS pending_deletions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id             UUID NOT NULL,
    resource_type           TEXT NOT NULL CHECK (resource_type IN ('deploy', 'stack')),
    team_id                 UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    requested_by_user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,
    confirmation_token_hash TEXT NOT NULL UNIQUE,
    status                  TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'cancelled', 'expired')),
    confirmed_at            TIMESTAMPTZ,
    cancelled_at            TIMESTAMPTZ,
    email_sent_to           TEXT NOT NULL
);

-- Per-team index — drives "is there a pending deletion for this
-- resource?" lookups on the DELETE path and the dashboard banner.
CREATE INDEX IF NOT EXISTS idx_pending_deletions_team
    ON pending_deletions (team_id, status);

-- Per-resource lookup — used by the handler to short-circuit "already
-- pending" on a second DELETE of the same id. Partial because we only
-- ever query for the pending subset.
CREATE INDEX IF NOT EXISTS idx_pending_deletions_resource_pending
    ON pending_deletions (resource_id, resource_type)
    WHERE status = 'pending';

-- Expiry sweeper index — the worker's pending_deletion_expirer scans
-- this every 60s. Partial keeps it tiny because expired/confirmed/
-- cancelled rows are not interesting to the sweeper.
CREATE INDEX IF NOT EXISTS idx_pending_deletions_expires
    ON pending_deletions (expires_at)
    WHERE status = 'pending';
