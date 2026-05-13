-- Migration: 026_promote_approvals — email-link approval workflow for env
-- promotions targeting non-development environments.
--
-- Why this table exists: today POST /api/v1/stacks/:slug/promote and POST
-- /api/v1/resources/:id/provision-twin execute immediately when an admin or
-- operator calls them. Product directive: promotions to staging / preprod /
-- production / etc. must require an explicit human approval via email link
-- before they execute. Dev-env promotes are unchanged — they bypass this
-- table entirely so the inner-loop developer experience stays one-call.
--
-- Lifecycle of a row:
--
--   1. API creates a row with status='pending', a 32-byte URL-safe random
--      token, and expires_at = now() + 24h.
--   2. The Brevo forwarder (worker side) picks up the audit_log row of kind
--      'promote.approval_requested' and emails the operator a clickable
--      https://api.instanode.dev/approve/<token> link.
--   3. Operator clicks → GET /approve/<token> atomically flips status to
--      'approved' (single-use: ON UPDATE WHERE status='pending') and
--      records approved_at. Already-clicked links report "already used";
--      expired links report "link expired" and flip status to 'expired'.
--   4. A worker (separate PR) polls for status='approved' AND
--      executed_at IS NULL, runs the original promote with the cached
--      promote_payload, and stamps executed_at. Out of scope for this PR.
--   5. Admins can mark a row 'rejected' via POST /api/v1/promotions/:id/reject.
--
-- The promote_payload column carries the original POST body so the worker
-- can replay the request without re-fetching state that may have changed.
-- promote_kind is 'stack' or 'resource_twin' so the worker knows which
-- code path to call.

CREATE TABLE IF NOT EXISTS promote_approvals (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token              TEXT UNIQUE NOT NULL,
  team_id            UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  requested_by_email TEXT NOT NULL,
  promote_kind       TEXT NOT NULL,                          -- 'stack' | 'resource_twin'
  promote_payload    JSONB NOT NULL,                         -- the original POST body
  from_env           TEXT NOT NULL,
  to_env             TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'pending',        -- pending | approved | rejected | expired | executed
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  approved_at        TIMESTAMPTZ,
  executed_at        TIMESTAMPTZ,
  rejected_at        TIMESTAMPTZ
);

-- Backs the GET /approve/:token lookup. Partial index on status='pending' so
-- the hot lookup path scans only live rows; expired / approved / rejected
-- tokens degrade to a full-scan miss (which returns ErrNotFound).
CREATE INDEX IF NOT EXISTS idx_promote_approvals_token
    ON promote_approvals(token) WHERE status = 'pending';

-- Backs the worker's pending-execution poll: "find rows that are approved
-- but not yet executed." Partial index keeps it tiny — most rows are either
-- pending (waiting for click) or executed (already run, dead weight in this
-- index but never matched).
CREATE INDEX IF NOT EXISTS idx_promote_approvals_pending_exec
    ON promote_approvals(status) WHERE status = 'approved' AND executed_at IS NULL;
