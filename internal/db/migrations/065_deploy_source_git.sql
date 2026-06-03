-- 065_deploy_source_git.sql — multi-source deploys, P3 (source=git / pull-by-URL).
--
-- WHY: P2 (#221, mig 064) added source='image' (deploy a prebuilt ref). P3 adds
-- source='git': the caller passes a repo URL (+ optional ref + token) and the
-- platform points Kaniko at the repo directly (git context build), so large
-- projects that exceed the 10 MB tarball cap can ship without an upload or a
-- pre-built image. source='git' is already permitted by the 064
-- deployments_source_check, so no constraint change is needed here.
--
-- All columns are ADDITIVE with safe defaults — every existing row + tarball
-- and image deploy keeps working unchanged:
--
--   git_url       — clone URL (https://host/owner/repo[.git]) for source='git';
--                   '' otherwise.
--   git_ref       — branch / tag / commit SHA to build; '' = provider default
--                   branch.
--   git_token_enc — AES-256-GCM ciphertext of an optional read-only access
--                   token for a PRIVATE repo (same whole-object encryption as
--                   registry_creds_enc / notify_webhook_secret). '' for public
--                   repos. NEVER returned to the client (deploymentToMap emits
--                   only git_token_set: bool).

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS git_url       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS git_ref       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS git_token_enc TEXT NOT NULL DEFAULT '';
