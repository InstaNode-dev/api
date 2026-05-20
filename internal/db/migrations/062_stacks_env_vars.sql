-- 062_stacks_env_vars.sql — make `PATCH /stacks/:slug/env` persist.
--
-- WHY (B7-P0-1, 2026-05-20): the handler at internal/handlers/stack.go::UpdateEnv
-- logged `stack.env.noted`, returned 200, but never persisted. The next
-- POST /stacks/:slug/redeploy then rebuilt with the original env, silently
-- dropping the user's update. The user-visible failure surface was the
-- redeployed pod's environment — no error, just stale values — which is
-- the worst possible failure mode (silent data loss).
--
-- Two choices for "where do env vars live":
--
--   (a) one JSONB column on `stacks`           — env applies to ALL services
--   (b) one JSONB column on `stack_services`   — env applies per-service
--
-- This migration ships (a). Rationale: the handler body shape today is
-- `{"env": {"KEY": "VALUE"}}` — a single flat map with no service-name
-- routing. The wire contract treats env as stack-scoped, so the storage
-- shape matches. If a future PR introduces `{"env": {"<svc>": {...}}}`
-- per-service routing, migration 063 adds the column on stack_services
-- and the model layer prefers it when populated; this row's column
-- remains the stack-wide fallback. No data-shape lock-in.
--
-- Default '{}'::jsonb so existing stacks read as empty (the handler's
-- `len(env) == 0` branch returns the same 400 it did before — no
-- behaviour change for callers who never set env).
--
-- Idempotent for the runner's re-apply path.

ALTER TABLE stacks
    ADD COLUMN IF NOT EXISTS env_vars JSONB NOT NULL DEFAULT '{}'::jsonb;

-- No index — env_vars is only read alongside the row in single-stack
-- lookups (GetStackBySlug, GetStackByID, ListStacksForTeam). No query
-- filters or aggregates on the column's contents. A GIN index would
-- pay write-amplification cost for no read win.

COMMENT ON COLUMN stacks.env_vars IS
    'Stack-scoped env vars applied at next redeploy. Set via PATCH /stacks/:slug/env. JSON object {KEY: VALUE}; keys validated by isValidEnvKey (POSIX [A-Z_][A-Z0-9_]*).';
