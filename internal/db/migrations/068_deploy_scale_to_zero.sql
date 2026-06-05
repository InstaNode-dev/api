-- 068_deploy_scale_to_zero.sql — scale-to-zero (idle descheduling) state columns.
--
-- WHY: a deployed-but-idle app costs a full pod's worth of compute even when it
-- serves zero requests. Scale-to-zero (Task #54) lets the worker patch an idle
-- Deployment to replicas=0 (~$0 compute) and wake it back to replicas=1 on
-- demand. This migration adds the per-deployment state the idle-scaler and the
-- wake path read/write. The whole feature is gated behind the
-- DEPLOY_SCALE_TO_ZERO_ENABLED worker env flag (default OFF), so these columns
-- are inert — populated at create-time but acted upon only when an operator
-- enables the flag.
--
-- Columns:
--   last_activity_at  TIMESTAMPTZ — floor "last known activity" marker. Set to
--                                   now() at create-time, bumped on every wake
--                                   and on redeploy. The idle-scaler descheduals
--                                   a Deployment only when
--                                   now() - last_activity_at > idle_threshold.
--
--                                   v1 NOTE: the api is NOT in the request path
--                                   (apps are served by k8s Ingress straight to
--                                   the per-app Service), and no nginx-ingress
--                                   request-total scrape is wired yet, so the
--                                   honest "activity" signal v1 captures is
--                                   deploy / redeploy / explicit-wake events —
--                                   NOT per-HTTP-request traffic. A follow-up
--                                   (documented in the worker job header) will
--                                   wire an ingress request-counter to bump this
--                                   column on real traffic for true
--                                   traffic-based idle detection.
--
--   scaled_to_zero    BOOLEAN     — true while the app is currently descheduled
--                                   (replicas=0). The wake path reads this to
--                                   decide whether a scale-up is needed; the
--                                   dashboard/agent reads it to show "sleeping".
--                                   The idle-scaler sets it true on scale-down,
--                                   the wake path sets it false on scale-up.
--
--   always_on         BOOLEAN     — per-app opt-out. A pinned app (an operator
--                                   or Pro+ user who wants zero cold-starts) is
--                                   never descheduled by the idle-scaler. Default
--                                   false → eligible for scale-to-zero.
--
-- Idempotent + forward-only. Existing rows get last_activity_at backfilled from
-- updated_at (their most recent known activity) so the idle-scaler does not
-- immediately deschedule every pre-existing deploy the first time the flag is
-- turned on; scaled_to_zero / always_on default to false.

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS scaled_to_zero   BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS always_on        BOOLEAN NOT NULL DEFAULT false;

-- Backfill: seed last_activity_at from updated_at for every pre-existing row so
-- the very first idle-scaler tick after the flag is enabled treats existing
-- deploys as "recently active" rather than immediately idle. New rows set
-- last_activity_at = now() at INSERT time (see CreateDeployment).
UPDATE deployments
SET    last_activity_at = COALESCE(updated_at, created_at, now())
WHERE  last_activity_at IS NULL;

-- Partial index: the idle-scaler scans for healthy, eligible, not-yet-zeroed
-- deployments ordered by activity. Excluding always_on + already-zeroed +
-- terminal rows keeps the index narrow and the scan cheap.
CREATE INDEX IF NOT EXISTS idx_deployments_idle_candidates
    ON deployments (last_activity_at)
    WHERE status = 'healthy'
      AND scaled_to_zero = false
      AND always_on = false;
