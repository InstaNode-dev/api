-- 064_deploy_source_image.sql — multi-source deploys, P2 (source=image / BYO image).
--
-- WHY: P1 (#220) capped /deploy/new uploads at 10 MB and nudges large projects
-- to "deploy a prebuilt image instead of uploading source". This migration adds
-- the columns that let a deployment record where its image came from, so a
-- caller can skip the tarball+Kaniko build entirely and have the platform
-- deploy a prebuilt image (e.g. one their GitHub CI already pushed to GHCR).
--
-- All columns are ADDITIVE with safe defaults, so every existing row + every
-- existing tarball deploy keeps working unchanged:
--
--   source            — 'tarball' (default, the only mode before P2) | 'image'.
--                       Future P3 adds 'git'. CHECK keeps it to known modes.
--   image_ref         — fully-qualified registry ref (host/path[:tag][@digest])
--                       for source='image'; '' for tarball deploys.
--   registry_creds_enc — AES-256-GCM ciphertext of the optional pull-only
--                       registry credential JSON (whole-object encryption,
--                       same posture as notify_webhook_secret). '' when the
--                       image is public / uses the platform's ghcr-pull secret.
--                       NEVER returned to the client (deploymentToMap emits
--                       only registry_creds_set: bool).

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS source             TEXT NOT NULL DEFAULT 'tarball',
    ADD COLUMN IF NOT EXISTS image_ref          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS registry_creds_enc TEXT NOT NULL DEFAULT '';

-- Constrain source to the modes the code understands. 'git' is reserved for P3
-- so adding it here now is forward-safe and avoids a follow-up migration.
ALTER TABLE deployments
    DROP CONSTRAINT IF EXISTS deployments_source_check;
ALTER TABLE deployments
    ADD CONSTRAINT deployments_source_check
    CHECK (source IN ('tarball', 'image', 'git'));
