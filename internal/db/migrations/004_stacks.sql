-- 004_stacks.sql — Multi-service stack hosting (Phase 6)

CREATE TABLE IF NOT EXISTS stacks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        TEXT,                                -- human-readable name (optional)
    slug        TEXT UNIQUE NOT NULL,               -- short ID used in namespace, URLs
    namespace   TEXT UNIQUE NOT NULL,               -- "instant-stack-{slug}"
    status      TEXT NOT NULL DEFAULT 'building',   -- building|deploying|healthy|failed|stopped|deleting
    tier        TEXT NOT NULL DEFAULT 'hobby',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stack_services (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stack_id    UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,                      -- matches service key in instant.yaml
    image_tag   TEXT,                               -- docker image tag used for this deploy
    status      TEXT NOT NULL DEFAULT 'building',   -- building|deploying|healthy|failed|stopped
    expose      BOOLEAN NOT NULL DEFAULT FALSE,
    port        INT NOT NULL DEFAULT 8080,
    app_url     TEXT,                               -- Ingress URL if expose=true
    error_msg   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(stack_id, name)
);

CREATE INDEX IF NOT EXISTS idx_stacks_team_id    ON stacks(team_id);
CREATE INDEX IF NOT EXISTS idx_stacks_slug       ON stacks(slug);
CREATE INDEX IF NOT EXISTS idx_stack_services_stack ON stack_services(stack_id);
