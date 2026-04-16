-- 002: add provider_resource_id to resources
ALTER TABLE resources ADD COLUMN IF NOT EXISTS provider_resource_id TEXT;
