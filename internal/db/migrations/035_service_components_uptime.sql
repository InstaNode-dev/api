-- 035_service_components_uptime.sql — real status backend (W11).
--
-- Before this migration the dashboard's /status page ran client-side
-- probes from the browser. That has a fatal failure mode caught by
-- persona-3: if instanode's edge is down, the probe is also down, so the
-- page either fails to load or reports green-on-green from a single
-- happy-path browser. Worse, /incidents 404'd until W7-A.
--
-- This migration introduces the storage tables the worker fills via the
-- new `uptime_prober` job (one probe per component per minute) and the
-- API reads via GET /api/v1/status (cached 60s in Redis).
--
-- Two append-only tables (no per-row UPDATE):
--
--   service_components — the set of probeable subsystems. Seeded with
--     the five we have today; future additions are inserts not migrations.
--     The `slug` column is the join key on uptime_samples — short,
--     stable, lowercase, no spaces. `category` groups rows on the public
--     /status page; `description` shows under each row.
--
--   uptime_samples — one row per probe attempt. BIGSERIAL because at
--     ~5 probes/min × 90d retention = ~650k rows steady-state; UUIDs
--     would be overkill. `latency_ms` is nullable so a connection
--     failure (no measurable RTT) stores a clean row without a sentinel.
--     The (component_slug, sampled_at DESC) index serves both the
--     "last 24h samples" read and the daily prune sweep.
--
-- Retention: the worker prunes rows older than 90 days via a daily job
-- (see worker/internal/jobs/uptime_retention.go). 90d is the longest
-- window the API computes; older rows have no consumer.

CREATE TABLE IF NOT EXISTS service_components (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug         TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    category     TEXT NOT NULL,
    description  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS uptime_samples (
    id             BIGSERIAL PRIMARY KEY,
    component_slug TEXT NOT NULL REFERENCES service_components(slug),
    sampled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    healthy        BOOLEAN NOT NULL,
    latency_ms     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_uptime_samples_recent
    ON uptime_samples(component_slug, sampled_at DESC);

-- Seed five components. ON CONFLICT lets the migration re-run cleanly
-- if an operator has already inserted via a manual prune job (see
-- /tmp/wt-w11-status-worker/ops notes).
INSERT INTO service_components(slug, display_name, category, description) VALUES
    ('api',         'API',         'core',    'instanode.dev provisioning + management API'),
    ('provisioner', 'Provisioner', 'core',    'gRPC service that mints customer databases'),
    ('worker',      'Worker',      'core',    'Background jobs (backups, expiry, heartbeats)'),
    ('deploys',     'Deploys',     'compute', 'Kaniko build + Kubernetes deploy infrastructure'),
    ('marketing',   'Marketing',   'edge',    'instanode.dev marketing site + dashboard')
ON CONFLICT (slug) DO NOTHING;
