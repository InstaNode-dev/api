-- 031_backups.sql — customer-facing Postgres backups + restore.
--
-- Adds two append-only tables that record each backup attempt (manual or
-- scheduled, taken by the worker) and each restore attempt. The worker
-- (sibling repo, /tmp/wt-customer-backups-worker) polls rows in status
-- 'pending', flips to 'running', performs pg_dump → S3 (or pg_restore from
-- S3), and writes the terminal status + size_bytes + error_summary.
--
-- The API only WRITES 'pending' rows (one per POST /backup or /restore)
-- and READS rows for the list endpoints. Status transitions and S3 keys
-- are owned by the worker.
--
-- backup_kind:
--   'scheduled' — fired by the worker's daily backup job.
--   'manual'    — fired by a customer POST /api/v1/resources/:id/backup.
--
-- tier_at_backup snapshots the customer's plan tier at the time the backup
-- was taken so that retention enforcement (worker) can reason about a row
-- in isolation — e.g. a row taken while Pro stays for 30 days even after
-- the team downgrades. Mirrors resources.tier semantics.
--
-- Restores ALWAYS require an authenticated user (triggered_by NOT NULL)
-- — there is no anonymous restore path. Backups CAN have NULL triggered_by
-- when produced by the scheduled job (no human in the loop).

CREATE TABLE IF NOT EXISTS resource_backups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id     UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    status          TEXT NOT NULL CHECK (status IN ('pending','running','ok','failed')) DEFAULT 'pending',
    backup_kind     TEXT NOT NULL CHECK (backup_kind IN ('scheduled','manual')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    s3_key          TEXT,
    size_bytes      BIGINT,
    tier_at_backup  TEXT,
    error_summary   TEXT,
    triggered_by    UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_backups_resource ON resource_backups(resource_id);
CREATE INDEX IF NOT EXISTS idx_backups_pending  ON resource_backups(status) WHERE status IN ('pending','running');

CREATE TABLE IF NOT EXISTS resource_restores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id     UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    backup_id       UUID NOT NULL REFERENCES resource_backups(id),
    status          TEXT NOT NULL CHECK (status IN ('pending','running','ok','failed')) DEFAULT 'pending',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    error_summary   TEXT,
    triggered_by    UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_restores_resource ON resource_restores(resource_id);
CREATE INDEX IF NOT EXISTS idx_restores_pending  ON resource_restores(status) WHERE status IN ('pending','running');
