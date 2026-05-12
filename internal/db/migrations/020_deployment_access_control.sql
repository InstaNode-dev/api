-- 020_deployment_access_control.sql — Private deploy access control on deployments.
--
-- Track A of the private-deploys feature. Adds two columns:
--
--   private:     true → the Ingress carries
--                nginx.ingress.kubernetes.io/whitelist-source-range so only
--                allowed IPs can reach the app.
--   allowed_ips: comma-joined list of CIDRs / IPs. NOT a JSONB array — these
--                are surfaced into the Ingress annotation as a comma-joined
--                string anyway, and the existing string-handling code paths
--                (scanDeployment, deploymentToMap) keep their shape with a
--                plain TEXT field. Validation (net.ParseCIDR / net.ParseIP,
--                max 32 entries, non-empty when private=true) lives in the
--                handler — the column is just storage.
--
-- Default false / '' is the critical backward-compat guarantee: existing
-- deployments stay public exactly as they were. The Ingress annotation is
-- only set when private=true, so the legacy code path produces byte-identical
-- Ingress objects.
--
-- Tier gating (Pro / Team / Growth only) is enforced in the handler before
-- the row is inserted — no DB-level constraint required.
--
-- Rollback (NOT executed — kept for runbook only):
--   ALTER TABLE deployments
--     DROP COLUMN IF EXISTS allowed_ips,
--     DROP COLUMN IF EXISTS private;

ALTER TABLE deployments
  ADD COLUMN IF NOT EXISTS private BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS allowed_ips TEXT NOT NULL DEFAULT '';
