-- Migration: 014_custom_domains — Pro+ custom hostnames for stacks.
--
-- A row is created when a customer requests POST /api/v1/stacks/<slug>/domains
-- with a hostname they own. The row carries a verification_token; the customer
-- proves DNS ownership by adding a TXT record at "_instanode.<hostname>" whose
-- value contains "instanode-verify-<verification_token>".
--
-- Once verified, the API creates a k8s Ingress + cert-manager Certificate so
-- the custom hostname routes to the stack's primary service over HTTPS. The
-- customer's final step is a CNAME to "<stack-slug>.deployment.instanode.dev".
--
-- Lifecycle:  pending_verification → verified → ingress_ready → cert_ready → live
-- "failed" is reserved for terminal errors (e.g. ingress conflict).
--
-- Hostname uniqueness is enforced at the DB layer — two teams cannot bind
-- the same hostname even by racing the request.

CREATE TABLE IF NOT EXISTS custom_domains (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    stack_id        UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    hostname        TEXT NOT NULL UNIQUE,
    -- TXT challenge value the customer must add at _instanode.<hostname>
    verification_token TEXT NOT NULL,
    -- Lifecycle:  pending_verification → verified → ingress_ready → cert_ready → live
    status          TEXT NOT NULL DEFAULT 'pending_verification',
    -- Set when the TXT lookup first matched.
    verified_at     TIMESTAMPTZ,
    -- Set when cert-manager Certificate goes Ready=True.
    cert_ready_at   TIMESTAMPTZ,
    last_check_at   TIMESTAMPTZ,
    last_check_err  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cdom_team ON custom_domains (team_id);
CREATE INDEX IF NOT EXISTS idx_cdom_stack ON custom_domains (stack_id);
