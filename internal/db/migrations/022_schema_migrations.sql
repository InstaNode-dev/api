-- Migration: 022_schema_migrations — record which migration files have been
-- applied, so GET /healthz can surface the highest-applied filename + count.
--
-- The runner (db.RunMigrations in internal/db/postgres.go) applies every
-- embedded .sql file in lex order on every startup using IF NOT EXISTS
-- guards, so the DB is always at or ahead of the binary. This table makes
-- "what did the running binary actually apply?" inspectable at runtime
-- without scraping startup logs.
--
-- One row per filename. applied_at is the first time this binary saw it;
-- migrations that ran before this table existed are backfilled with the
-- current timestamp the first time the new binary boots (filename ordering
-- is still preserved). The runner inserts with ON CONFLICT DO NOTHING so
-- subsequent startups are no-ops.
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Read path for /healthz hits the index implicitly via PRIMARY KEY scan +
-- ORDER BY filename DESC LIMIT 1, which costs a single page read. No
-- additional index needed.
