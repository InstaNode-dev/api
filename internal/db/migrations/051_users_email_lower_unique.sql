-- Migration: 051_users_email_lower_unique
--
-- P7 (bug-hunt 2026-05-17): the /claim account-takeover guard does an
-- exact-match GetUserByEmail. migration 023 added idx_users_email_lower
-- but it is a PLAIN index — not UNIQUE — so the database itself never
-- prevented "Victim@X.com" and "victim@x.com" from both existing as
-- separate user rows. The handler-layer fix (NormalizeEmail in
-- GetUserByEmail + CreateUser) closes the application path; this
-- migration closes the data-integrity path so a future caller bypassing
-- the model layer still cannot create a case-variant duplicate identity.
--
-- DUPLICATE-DATA RISK
--
-- CREATE UNIQUE INDEX fails outright if two rows already collide on
-- lower(email). The platform's CreateUser has always taken its email
-- from a verified magic-link / OAuth identity (both already lowercased
-- in handlers/auth.go), and /claim is the only path that wrote an
-- un-normalised email — and only ever for a brand-new email (the P0-1
-- guard refuses pre-existing ones). A genuine lower(email) collision is
-- therefore expected to be empty in prod, but we MUST NOT ship a
-- migration that can crash-loop the api pod on apply.
--
-- This migration is defensive: a PL/pgSQL block first probes for any
-- lower(email) collision. If one exists it RAISEs a descriptive
-- EXCEPTION naming the offending address and the required operator
-- action (dedup the colliding users rows, then re-run) instead of
-- letting Postgres emit an opaque "could not create unique index"
-- error. If none exists it creates the unique index. The whole block
-- is idempotent — re-running after the index exists is a no-op via the
-- pg_class existence check.
--
-- OPERATOR REMEDIATION (only if the RAISE fires):
--   1. SELECT lower(email), count(*), array_agg(id)
--        FROM users GROUP BY lower(email) HAVING count(*) > 1;
--   2. For each colliding group, merge the duplicate user rows into the
--      canonical (oldest created_at) row — re-point team membership and
--      foreign keys, then DELETE the redundant rows.
--   3. Re-run migrations.

DO $$
DECLARE
    dup RECORD;
BEGIN
    -- Already applied? Nothing to do.
    IF EXISTS (
        SELECT 1 FROM pg_class WHERE relname = 'uq_users_email_lower'
    ) THEN
        RETURN;
    END IF;

    -- Probe for case/whitespace-variant duplicate identities.
    SELECT lower(email) AS norm, count(*) AS n
      INTO dup
      FROM users
     GROUP BY lower(email)
    HAVING count(*) > 1
     LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
          'migration 051: cannot create unique index on lower(email) — % rows collide on "%". Dedup the colliding users rows (see migration header for the remediation query) then re-run.',
          dup.n, dup.norm;
    END IF;

    -- Safe: build the unique functional index. This SUPERSEDES the plain
    -- idx_users_email_lower from migration 023 (a unique index also
    -- serves the case-insensitive lookup planner path), but we leave 023's
    -- index in place — dropping it is a separate, non-urgent cleanup.
    CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email));
END $$;
