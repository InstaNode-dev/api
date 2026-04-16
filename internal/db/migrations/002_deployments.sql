-- 002_deployments.sql — App hosting deployments table (Phase 6)
-- Tracks each user app deployed via POST /deploy/new.

CREATE TABLE IF NOT EXISTS deployments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id       UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    resource_id   UUID REFERENCES resources(id) ON DELETE SET NULL,
    app_id        TEXT UNIQUE NOT NULL,   -- short slug used for subdomain: {app_id}.instant.dev
    provider_id   TEXT,                  -- k8s Deployment name (e.g. "app-{app_id}")
    status        TEXT NOT NULL DEFAULT 'building',
                  -- building | deploying | healthy | failed | stopped
    app_url       TEXT,                  -- https://{app_id}.instant.dev or NodePort URL (local)
    env_vars      JSONB NOT NULL DEFAULT '{}',   -- non-infra env vars set by user via PATCH
    port          INT NOT NULL DEFAULT 8080,
    tier          TEXT NOT NULL DEFAULT 'hobby',
    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_deployments_team_id    ON deployments(team_id);
CREATE INDEX IF NOT EXISTS idx_deployments_resource_id ON deployments(resource_id);
CREATE INDEX IF NOT EXISTS idx_deployments_status     ON deployments(status);
