-- 042_webhook_hmac_secret.sql — optional HMAC verification secret for
-- /webhook/receive/:token.
--
-- BugBash findings: #119 / #S7 / #122 (B25). The receiver had no way for a
-- caller to lock down who is allowed to POST payloads — anyone with the
-- receive URL could inject (and read) arbitrary requests. This column adds
-- an opt-in shared secret. When a `resources.hmac_secret` row is non-NULL
-- and the resource_type is 'webhook', the Receive handler verifies the
-- caller's X-Hub-Signature-256 header against the request body before
-- storing the payload. When NULL the receiver accepts unsigned traffic
-- (back-compat for every existing token).
--
-- Idempotent: the ADD COLUMN uses IF NOT EXISTS so a re-run against a
-- partial deploy is a no-op. Only rows where type='webhook' will populate
-- this column in practice; for every other resource_type it stays NULL.

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS hmac_secret TEXT;
