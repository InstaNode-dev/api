-- Migration: 026_deploy_webhook — optional notify_webhook on a deployment so
-- the user's external URL gets POST'd when the deploy reaches a terminal
-- state (healthy / failed). Today agents poll GET /deploy/:id to discover
-- success/failure; this lets them subscribe instead.
--
-- Columns:
--   notify_webhook         TEXT — user-supplied URL (https only, SSRF-checked
--                          on write). Stored verbatim; not encrypted because
--                          it's a hostname-bearing URL that the worker needs
--                          to read on every retry.
--   notify_webhook_secret  TEXT — optional HMAC signing key. AES-256-GCM
--                          encrypted at rest with the platform AES_KEY (same
--                          path as resources.connection_url). Worker decrypts
--                          before computing the X-InstaNode-Signature header.
--   notify_state           TEXT — lifecycle: 'unset' (default, no webhook),
--                          'pending' (terminal-state reached, awaiting POST),
--                          'sent' (2xx received), 'failed' (4xx received, or
--                          5xx/network after max retries). The worker's job
--                          scans WHERE notify_state='pending' AND status IN
--                          ('healthy','failed').
--   notify_attempts        INTEGER — count of dispatch attempts. Worker
--                          caps at 3 for transient 5xx/network errors;
--                          4xx is permanent (don't retry — the URL is
--                          broken from the user's side).
--
-- Index: partial on (notify_state, status) WHERE notify_state='pending' keeps
-- the worker scan cheap as the deployments table grows. Anything not pending
-- is invisible to the scan, so the index stays small.

ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_webhook TEXT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_webhook_secret TEXT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_state TEXT NOT NULL DEFAULT 'unset';
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notify_attempts INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_deployments_notify_pending
  ON deployments(notify_state, status)
  WHERE notify_state = 'pending';
