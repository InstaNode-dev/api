-- Migration: 022_deploys_audit — append-only audit trail of every distinct
-- (service, commit_id, image_digest) tuple that has actually run on this
-- platform.
--
-- Why this table exists: /healthz returns the live pod's commit_id +
-- version + build_time, but the moment a Deployment rolls the pod is gone
-- and the previous identity is unrecoverable. `kubectl rollout history`
-- is namespace-scoped, ephemeral, and tells you what was *configured*,
-- not what actually started serving traffic. There is no answer today
-- for "which image was serving /api/v1/resources at 14:00 UTC last
-- Tuesday?". This table answers that question — every binary that boots
-- writes one row the first time it sees itself, and the row stays
-- forever.
--
-- Self-report contract: on pod startup each service inserts a row keyed
-- on (service, commit_id, image_digest). ON CONFLICT DO NOTHING means
-- the second-and-subsequent boots of the same image are no-ops; the
-- table grows once per *unique* deploy, not once per pod restart. A
-- normal autoscale event that spawns 10 replicas of one image still
-- writes a single row.
--
-- The unique index backing ON CONFLICT also doubles as the safety belt
-- against a misbehaving probe that calls the insert path more than once
-- per process — duplicates collapse silently rather than bloating the
-- table.
--
-- Read path: GET /api/v1/<admin-prefix>/deploys (admin-only — same
-- prefix-obscurity + email-allowlist gates as /api/v1/<admin-prefix>/customers).
-- Founders answer support tickets with this view; the dashboard does not
-- consume it.

CREATE TABLE IF NOT EXISTS deploys_audit (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service           TEXT NOT NULL,           -- 'api' | 'worker' | 'provisioner'
    commit_id         TEXT NOT NULL,           -- short Git SHA from buildinfo
    image_digest      TEXT NOT NULL,           -- 'sha256:abc...' from k8s status.containerStatuses[].imageID
    version           TEXT,                    -- semver / release tag from buildinfo (nullable for un-ldflagged dev builds)
    build_time        TIMESTAMPTZ,             -- RFC-3339 build timestamp from buildinfo (nullable when "unknown")
    applied_at        TIMESTAMPTZ NOT NULL DEFAULT now(),  -- first time this tuple was observed running
    migration_version TEXT,                    -- highest migration filename present at startup (e.g. '022_deploys_audit.sql')
    noticed_by        TEXT NOT NULL DEFAULT 'self-report'  -- 'self-report' (binary inserted on its own startup) | 'admin-import' (operator backfill)
);

-- Backs the ON CONFLICT clause on the self-report INSERT path. The
-- (service, commit_id, image_digest) triple is the natural identity of
-- "what is running" — same binary on different services is two rows;
-- same binary re-tagged but identical bits (same digest) is one row.
CREATE UNIQUE INDEX IF NOT EXISTS uq_deploys_audit_identity
    ON deploys_audit(service, commit_id, image_digest);

-- Supports the primary read pattern: "show me the last N deploys of
-- service X, newest first." Used by the admin endpoint's default sort.
CREATE INDEX IF NOT EXISTS idx_deploys_audit_service_time
    ON deploys_audit(service, applied_at DESC);
