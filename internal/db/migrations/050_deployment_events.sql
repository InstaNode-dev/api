-- 050_deployment_events.sql
--
-- Stores post-mortem autopsy records for failed deployments.
--
-- When a deployment transitions into a failure state (failed / crashloop /
-- evicted / image-pull-error / build-error), the worker captures one row here
-- containing the structured cause (reason + exit_code + k8s event message +
-- last ~200 log lines + a plain-language hint). The api's GET /deploy/:id and
-- GET /api/v1/deployments/:id handlers read the latest row and emit it as a
-- top-level "failure" object.
--
-- Design decisions:
--   - Separate table (not audit_log) — audit_log is append-only lifecycle
--     events, each carrying a team_id FK and sent to downstream email
--     forwarders. Autopsy rows are technical debugging artefacts without an
--     email surface, and the last_lines payload is large (up to 200 lines of
--     log text), which would bloat the audit_log JSONB column.
--   - kind column — extensible hook for future row types beyond
--     'failure_autopsy' (e.g. 'build_log_snapshot', 'oom_profile').
--   - exit_code nullable — kaniko builds and evicted pods may not have a
--     clean process exit code.
--   - last_lines as JSONB text[] — Postgres array of text with efficient JSONB
--     storage; oldest-first, up to 200 entries.
--   - One autopsy per failure via the partial unique index on
--     (deployment_id, kind) WHERE kind = 'failure_autopsy'. The worker uses
--     INSERT ... ON CONFLICT DO UPDATE (upsert) to stay idempotent across
--     reconcile ticks — it won't insert a second row if the pod state hasn't
--     changed since the last tick.
--   - FK to deployments with ON DELETE CASCADE — when a deployment is
--     hard-deleted (DELETE /deploy/:id) all autopsy rows disappear automatically.
--     Soft-deleted ('expired') rows keep their autopsy for the dashboard's
--     "why did this fail?" view.

CREATE TABLE IF NOT EXISTS deployment_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id   UUID        NOT NULL
                                REFERENCES deployments(id)
                                ON DELETE CASCADE,
    kind            TEXT        NOT NULL,  -- 'failure_autopsy'
    reason          TEXT        NOT NULL,  -- OOMKilled | Evicted | ImagePullBackOff | CrashLoopBackOff | BuildFailed | DeadlineExceeded | Error | Unknown
    exit_code       INT,                   -- nullable; container exit code when available
    event           TEXT        NOT NULL DEFAULT '',  -- k8s Event message or build error string
    last_lines      JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- text[], oldest-first, up to 200 entries
    hint            TEXT        NOT NULL DEFAULT '',  -- plain-language "likely cause + what to do"
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Primary lookup: "give me the latest autopsy for deployment X".
CREATE INDEX IF NOT EXISTS deployment_events_deployment_id_idx
    ON deployment_events (deployment_id, created_at DESC);

-- Idempotency: at most one failure_autopsy row per deployment. The worker
-- upserts into this; a re-queued reconcile tick for the same failure writes
-- the same reason/exit_code/event/last_lines/hint rather than appending rows.
CREATE UNIQUE INDEX IF NOT EXISTS deployment_events_autopsy_uniq
    ON deployment_events (deployment_id, kind)
    WHERE kind = 'failure_autopsy';
