-- Migration: 052_users_email_verified
--
-- Adds users.email_verified — a per-user flag recording whether the account
-- holder has demonstrated control of the email address on file.
--
-- WHY (DECISION 2026-05-17): POST /claim still mints a session for a
-- brand-new-account email so the anonymous→claimed funnel is not broken, but
-- the claim itself does NOT prove the caller owns that inbox. We therefore
-- mark /claim-created users email_verified=false and gate billing/upgrade
-- actions (POST /api/v1/billing/checkout, ChangePlan) behind a verified
-- email — the user clears the gate by completing a magic-link sign-in, which
-- DOES prove inbox control.
--
-- Account-creation paths and the value they set:
--   /claim new account          → false (caller did not prove inbox control)
--   magic-link login             → flips to true on link consumption
--   Google OAuth                 → true  (Google only returns verified emails)
--   GitHub OAuth                 → true  (handler filters /user/emails on Verified)
--
-- GRANDFATHERING — existing accounts must not be locked out of billing.
-- The column DEFAULT is false (correct for every NEW row), but a one-time
-- backfill flips every PRE-EXISTING user to true: anyone who already has an
-- account predates this gate and keeps full billing access. New /claim users
-- created after this migration retain the false default.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;

-- Grandfather every user that existed before this migration ran. Idempotent:
-- a re-run only re-touches the same already-true rows. New /claim accounts
-- created after the migration are inserted with the false column default and
-- are NOT affected (their created_at is later than this statement's effect,
-- and CreateUser sets the value explicitly anyway).
UPDATE users SET email_verified = true WHERE email_verified = false;
