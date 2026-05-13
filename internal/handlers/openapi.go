package handlers

// openapi.go — serves GET /openapi.json with an OpenAPI 3.1 description of the live API.

import "github.com/gofiber/fiber/v2"

// ServeOpenAPI handles GET /openapi.json.
func ServeOpenAPI(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json; charset=utf-8")
	return c.SendString(openAPISpec)
}

// openAPISpec is embedded at build time. It covers all stable, agent-facing endpoints.
// Generated credentials and tier limits are documented here so AI agents can
// consume instant.dev programmatically without reading the source code.
//
// ─────────────────────────────────────────────────────────────────────────────
// INTENTIONAL OMISSION: the founder-only customer-management endpoints
// (list customers, customer detail, set tier, issue promo) are NOT
// documented here. They register at runtime under an unguessable URL
// prefix (cfg.AdminPathPrefix, sourced from the ADMIN_PATH_PREFIX env
// var) — see internal/router/router.go for the wiring. Adding their
// paths to this spec would defeat the obscurity gate.
//
// The prefix is delivered only to allowlisted admin callers via the
// admin_path_prefix field on GET /auth/me. The dashboard's admin UI
// builds URLs from that response; curl + the docs in INTERNAL-OPS.md
// (private) are the supported paths for off-dashboard use.
//
// DO NOT add /api/v1/<prefix>/customers/... or /api/v1/admin/customers
// entries to the spec below. If you need a new admin route, append it
// to the same Group in router.go and document it in INTERNAL-OPS.md.
// ─────────────────────────────────────────────────────────────────────────────
const openAPISpec = `{
  "openapi": "3.1.0",
  "info": {
    "title": "instant.dev API",
    "version": "1.0.0",
    "description": "Zero-friction developer infrastructure. Provision real databases, caches, and queues with a single HTTP call — no account, no Docker, no setup."
  },
  "servers": [{ "url": "https://instant.dev", "description": "Production" }],
  "paths": {
    "/healthz": {
      "get": {
        "summary": "Health check",
        "responses": {
          "200": { "description": "Service is healthy", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HealthResponse" } } } }
        }
      }
    },
    "/db/new": {
      "post": {
        "summary": "Provision a Postgres database",
        "description": "Returns a real postgres:// connection string with pgvector pre-installed. Anonymous tier: 10MB, 2 connections, 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Database provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DBProvisionResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim — anonymous fingerprint that previously provisioned must claim with email before re-provisioning). Includes agent_action with copy the calling agent can show the user, plus upgrade_url and (for the recycle gate) claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/cache/new": {
      "post": {
        "summary": "Provision a Redis cache",
        "description": "Returns a real redis:// connection string with ACL namespace isolation. Anonymous tier: 5MB memory, 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Cache provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CacheProvisionResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/nosql/new": {
      "post": {
        "summary": "Provision a MongoDB database",
        "description": "Returns a real mongodb:// connection string scoped to a per-token database. Anonymous tier: 5MB, 2 connections, 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "MongoDB database provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/NoSQLProvisionResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/queue/new": {
      "post": {
        "summary": "Provision a NATS JetStream queue",
        "description": "Returns a real nats:// connection string with per-account subject isolation. Anonymous tier: 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Queue provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/QueueProvisionResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/webhook/new": {
      "post": {
        "summary": "Provision a webhook receiver",
        "description": "Returns a public receive_url that accepts any HTTP method and stores the payload (headers + body) in Redis for 24h.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Webhook receiver provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/WebhookProvisionResponse" } } } },
          "402": { "description": "Quota exceeded OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/webhook/receive/{token}": {
      "post": {
        "summary": "Receive a webhook payload",
        "description": "Accepts any HTTP method. Stores headers + body in Redis with a 24h TTL. Returns the stored request ID.",
        "parameters": [{ "name": "token", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "requestBody": { "content": { "application/json": {}, "application/x-www-form-urlencoded": {}, "text/plain": {} } },
        "responses": {
          "200": { "description": "Payload stored", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "id": { "type": "string" } } } } } }
        }
      }
    },
    "/.well-known/oauth-protected-resource": {
      "get": {
        "summary": "OAuth 2.0 Protected Resource Metadata (RFC 9728)",
        "description": "Discovery document used by MCP clients to obtain authorization metadata. Public, no auth required.",
        "responses": {
          "200": { "description": "Metadata document", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OAuthProtectedResourceMetadata" } } } }
        }
      }
    },
    "/stacks/new": {
      "post": {
        "summary": "Deploy a multi-service stack",
        "description": "Like POST /deploy/new but for an instant.yaml manifest declaring multiple services. Each service has its own build context (tarball), port, optional Ingress (expose:true), and optional list of resource tokens (needs:). Cross-service references use service://<name> in env values — these resolve to cluster-internal http://<name>:<port> URLs at deploy time, so service A can call service B without knowing its public hostname. OptionalAuth: anonymous stacks are supported (24h TTL, rate-limited by fingerprint).",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "multipart/form-data": {
              "schema": { "$ref": "#/components/schemas/StackRequest" }
            }
          }
        },
        "responses": {
          "202": { "description": "Stack accepted, building", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StackResponse" } } } },
          "400": { "description": "Invalid manifest, missing tarball for a declared service, or unresolved service:// reference" },
          "429": { "description": "Anonymous rate limit exceeded" },
          "503": { "description": "Compute backend unavailable" }
        }
      }
    },
    "/stacks/{slug}": {
      "get": {
        "summary": "Get stack status",
        "description": "Returns per-service status. The overall stack status is 'healthy' only when every service is healthy.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Stack record", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StackResponse" } } } },
          "404": { "description": "Stack not found" }
        }
      },
      "delete": {
        "summary": "Tear down and delete a stack",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Deletion enqueued" },
          "404": { "description": "Stack not found" }
        }
      }
    },
    "/stacks/{slug}/redeploy": {
      "post": {
        "summary": "Rebuild + rolling update for one or more services in the stack",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "202": { "description": "Redeploy accepted" },
          "401": { "description": "Unauthorized — redeploy mutates the stack and requires a session" },
          "404": { "description": "Stack not found" }
        }
      }
    },
    "/api/v1/stacks/{slug}/promote": {
      "post": {
        "summary": "Promote a stack from one env to another (Pro+)",
        "description": "Copies the stack's config (image binding, resource bindings, name) to a sibling stack in the target env. If the target env already has a sibling, its status is bumped back to 'building' (in-place re-promote); otherwise a new stack row is created with parent_stack_id pointing at the family root. Pro / Team / Growth tiers only — returns 402 with agent_action otherwise. Compute redeploy is plumbed-but-waiting on Phase-1 POST /deploy/new; the row + parent linkage is the durable contract that future deploy hooks read from.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Source stack slug (the env you are promoting FROM)" }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["to"],
                "properties": {
                  "from": { "type": "string", "description": "Source env — defaults to source stack's env. Must match if provided." },
                  "to":   { "type": "string", "description": "Target env (production, staging, dev, ...) — required." },
                  "name": { "type": "string", "description": "Optional display name override for the new stack." }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Re-promoted into existing sibling stack — same slug, status reset to building" },
          "202": { "description": "Created a new stack in the target env (parent_stack_id points at family root)" },
          "400": { "description": "Invalid body, missing 'to', from==to, or invalid env name" },
          "401": { "description": "Unauthorized — session required" },
          "402": { "description": "Upgrade required — team is not on pro/team/growth. Response carries upgrade_url + agent_action." },
          "403": { "description": "Blocked by team env_policy. Body: { error: 'env_policy_denied', env, action, role, allowed_roles, agent_action }." },
          "404": { "description": "Source stack not found or not owned by this team" },
          "409": { "description": "Source env did not match the asserted 'from'" }
        }
      }
    },
    "/api/v1/vault/copy": {
      "post": {
        "summary": "Bulk-copy vault secrets from one env to another (Pro+)",
        "description": "Copies vault entries from a source env to a target env, optionally filtered by an explicit key allowlist. dry_run=true returns the full plan without persisting. Pro / Team / Growth tiers only — returns 402 with agent_action otherwise.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["from", "to"],
                "properties": {
                  "from":      { "type": "string", "description": "Source env name. Required." },
                  "to":        { "type": "string", "description": "Target env name. Required. Must differ from 'from'." },
                  "keys":      { "type": "array", "items": { "type": "string" }, "description": "Optional allowlist of key names. Empty/omitted → copy all keys at source." },
                  "dry_run":   { "type": "boolean", "description": "When true, returns the per-key plan but persists nothing." },
                  "overwrite": { "type": "boolean", "description": "When true, keys already in the target env are bumped to a new version. Default false." }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Plan + counts. Per-key actions are one of: copy, overwrite, skip, missing, quota_exceeded.",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":      { "type": "boolean" },
                    "dry_run": { "type": "boolean" },
                    "from":    { "type": "string" },
                    "to":      { "type": "string" },
                    "plan":    { "type": "array", "items": { "type": "object", "properties": { "key": { "type": "string" }, "action": { "type": "string" } } } },
                    "copied":  { "type": "integer" },
                    "skipped": { "type": "integer" },
                    "missing": { "type": "integer" },
                    "blocked": { "type": "integer" }
                  }
                }
              }
            }
          },
          "400": { "description": "Invalid body, missing from/to, from==to, or invalid env/key name" },
          "401": { "description": "Unauthorized — session required" },
          "402": { "description": "Upgrade required — team is not on pro/team/growth. Response carries upgrade_url + agent_action." },
          "403": { "description": "Blocked by team env_policy. Body: { error: 'env_policy_denied', env, action, role, allowed_roles, agent_action }." }
        }
      }
    },
    "/deploy/new": {
      "post": {
        "summary": "Deploy a container application",
        "description": "Builds a Docker image from the supplied tarball (or pulls an existing image) and rolls it out behind a public HTTPS URL on *.deployment.instanode.dev. Env vars may use the value 'vault://KEY' to reference a secret stored via /api/v1/vault — the plaintext is resolved at deploy time and never persisted in plaintext. The separate 'resource_bindings' field accepts 'family:<family_root_id>' values that resolve at submit time to the connection URL of the family member matching the deploy's env — so one manifest works across staging / production / dev. Raw resource-token UUIDs are also accepted for backward compatibility.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "multipart/form-data": { "schema": { "$ref": "#/components/schemas/DeployRequest" } } } },
        "responses": {
          "202": { "description": "Deployment accepted, building", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "400": { "description": "Bad request — invalid env_vars JSON, invalid_resource_binding (resource_bindings value is not a UUID or family:<uuid>), private_deploy_requires_allowed_ips (private=true with no IPs), invalid_allowed_ip (bad CIDR/IP literal), too_many_allowed_ips (>32 entries), or invalid_notify_webhook (URL is not https, unresolvable, or resolves to a private/loopback/link-local IP)" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "deployment_limit_reached OR private_deploy_requires_pro — hobby/anonymous/free trying to set private=true. agent_action points to https://instanode.dev/pricing." },
          "403": { "description": "Blocked by team env_policy, OR resource_binding_forbidden (binding references a resource owned by a different team)" },
          "404": { "description": "resource_binding_not_found — the resource or family root id supplied in resource_bindings does not exist" },
          "409": { "description": "no_env_twin — resource_bindings used family:<id> but the family has no member in the deploy's env. agent_action tells the user to call POST /api/v1/resources/:id/provision-twin first." },
          "503": { "description": "Compute backend unavailable or service disabled, OR resource_binding_lookup_failed (transient DB error during binding resolution)" }
        }
      }
    },
    "/deploy/{id}": {
      "get": {
        "summary": "Get deployment status",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Deployment record", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" },
          "404": { "description": "Not found" }
        }
      },
      "delete": {
        "summary": "Tear down and delete a deployment",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Deletion enqueued" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" }
        }
      }
    },
    "/deploy/{id}/env": {
      "patch": {
        "summary": "Update env vars (redeploy required to apply)",
        "description": "Merges the supplied env vars with the existing ones. Values prefixed with 'vault://' are stored verbatim and resolved at the next redeploy. Plaintext is never logged.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "env": { "type": "object", "additionalProperties": { "type": "string" } } } } } } },
        "responses": {
          "200": { "description": "Env vars updated", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } }
        }
      }
    },
    "/deploy/{id}/logs": {
      "get": {
        "summary": "Stream deployment logs (Server-Sent Events)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "text/event-stream of log lines, terminated by 'data: [end]'" },
          "409": { "description": "Deployment still building" }
        }
      }
    },
    "/deploy/{id}/redeploy": {
      "post": {
        "summary": "Redeploy with the latest stored env vars",
        "description": "Re-resolves any vault:// references and rolls out a new revision. Use after PATCH /deploy/{id}/env or after rotating a vault secret.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "202": { "description": "Redeploy accepted" }
        }
      }
    },
    "/api/v1/vault/{env}/{key}": {
      "put": {
        "summary": "Store an encrypted secret",
        "description": "Encrypts the supplied value with AES-256-GCM and stores it as a new version. Subsequent PUTs of the same key create v2, v3, ... — old versions remain queryable until DELETE.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "env", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Environment scope (production, staging, dev, ...)" },
          { "name": "key", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Secret key (e.g. RAZORPAY_KEY_SECRET)" }
        ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["value"], "properties": { "value": { "type": "string" } } } } } },
        "responses": {
          "201": { "description": "Secret stored", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/VaultPutResponse" } } } },
          "401": { "description": "Unauthorized" }
        }
      },
      "get": {
        "summary": "Read a secret (decrypted)",
        "description": "Returns the latest version's plaintext. Pass ?version=N to read a specific historical version. Every read writes a row to vault_audit_log.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "env", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "key", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "version", "in": "query", "required": false, "schema": { "type": "integer" } }
        ],
        "responses": {
          "200": { "description": "Secret returned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/VaultGetResponse" } } } },
          "404": { "description": "Secret not found for this team / env / key" }
        }
      },
      "delete": {
        "summary": "Hard delete every version of a secret",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "env", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "key", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "204": { "description": "Deleted" },
          "404": { "description": "Not found (idempotent)" }
        }
      }
    },
    "/api/v1/vault/{env}/{key}/rotate": {
      "post": {
        "summary": "Rotate a secret (new value, version + 1)",
        "description": "Convenience for PUT — preserves history but bumps the version visibly. Existing deployments continue to read v(N-1) until they redeploy.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "env", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "key", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["value"], "properties": { "value": { "type": "string" } } } } } },
        "responses": {
          "200": { "description": "Rotated", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/VaultPutResponse" } } } }
        }
      }
    },
    "/api/v1/vault/{env}": {
      "get": {
        "summary": "List keys stored in an environment",
        "description": "Returns key names only — values are NEVER returned by this endpoint. Use GET /api/v1/vault/{env}/{key} to read a value.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "env", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "List of keys", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "keys": { "type": "array", "items": { "type": "string" } } } } } } }
        }
      }
    },
    "/api/v1/teams/{team_id}/invitations": {
      "post": {
        "summary": "Invite a user to the team (admin or owner only)",
        "description": "Creates a single-use token tied to the invitee's email. The token is delivered out-of-band (email) and exchanged at POST /api/v1/invitations/{token}/accept.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "team_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["email", "role"], "properties": { "email": { "type": "string", "format": "email" }, "role": { "type": "string", "enum": ["admin", "developer", "viewer", "member"] } } } } } },
        "responses": {
          "201": { "description": "Invitation created", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/InvitationResponse" } } } },
          "403": { "description": "Forbidden — admin role required" }
        }
      },
      "get": {
        "summary": "List pending invitations for a team (admin or owner only)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "team_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Invitations", "content": { "application/json": { "schema": { "type": "object", "properties": { "items": { "type": "array", "items": { "$ref": "#/components/schemas/InvitationResponse" } } } } } } }
        }
      }
    },
    "/api/v1/teams/{team_id}/invitations/{id}": {
      "delete": {
        "summary": "Revoke a pending invitation",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "team_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } },
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
        ],
        "responses": {
          "204": { "description": "Revoked" }
        }
      }
    },
    "/api/v1/invitations/{token}/accept": {
      "post": {
        "summary": "Accept an invitation by token (no auth required — token IS the auth)",
        "description": "Public endpoint. The token is single-use and ties the accepting user's session to the invited team and role.",
        "parameters": [{ "name": "token", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Accepted", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "team_id": { "type": "string", "format": "uuid" }, "role": { "type": "string" } } } } } },
          "404": { "description": "Token not found" },
          "410": { "description": "Token already used or expired" }
        }
      }
    },
    "/claim": {
      "post": {
        "summary": "Claim anonymous resources to a permanent account",
        "description": "Converts anonymous resources to hobby tier (no expiry). Sends a magic link to the supplied email; clicking the link sets a session JWT cookie and atomically transfers every resource token in the onboarding JWT to the new team.",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimRequest" } } } },
        "responses": {
          "200": { "description": "Magic link sent to email", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimResponse" } } } },
          "201": { "description": "Account created, resources transferred (legacy direct-claim flow)", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimResponse" } } } },
          "409": { "description": "JWT already used (single-use claim)" }
        }
      }
    },
    "/claim/preview": {
      "get": {
        "summary": "Preview which resources a claim would attach",
        "description": "Decodes the onboarding JWT and returns the list of resources that would be transferred if /claim were posted with this token. Read-only; does not consume the JWT. Useful for showing the user what they're about to claim before they enter their email.",
        "parameters": [{ "name": "t", "in": "query", "required": true, "schema": { "type": "string" }, "description": "Signed onboarding JWT (the upgrade_jwt field from any anonymous provisioning response, or extracted from the upgrade URL)." }],
        "responses": {
          "200": { "description": "Preview of claimable resources", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimPreviewResponse" } } } },
          "400": { "description": "Token missing or malformed" },
          "401": { "description": "Token expired or signature invalid" }
        }
      }
    },
    "/start": {
      "get": {
        "summary": "Pre-filled upgrade landing page",
        "parameters": [{ "name": "t", "in": "query", "required": true, "schema": { "type": "string" }, "description": "Signed onboarding JWT from the note field" }],
        "responses": { "200": { "description": "HTML landing page with resource context" } }
      }
    },
    "/auth/me": {
      "get": {
        "summary": "Get current user info",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "User and team info", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AuthMeResponse" } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/whoami": {
      "get": {
        "summary": "Identity probe — confirms the bearer token is valid and returns the team it grants access to",
        "description": "Lightweight endpoint for agents to verify their bearer token works and discover their team_id / plan_tier without an extra DB hop. Returns 401 on invalid/missing token, 200 with identity on success.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Identity confirmed", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/WhoamiResponse" } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/resources": {
      "get": {
        "summary": "List all resources for the authenticated team",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Resource list", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ResourceListResponse" } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/resources/{id}": {
      "get": {
        "summary": "Get a specific resource",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Resource detail" },
          "403": { "description": "Forbidden — resource belongs to another team" },
          "404": { "description": "Not found" }
        }
      },
      "delete": {
        "summary": "Delete a resource",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Resource deleted" },
          "403": { "description": "Forbidden — not your resource OR blocked by team env_policy. The env_policy variant carries body: { error: 'env_policy_denied', env, action, role, allowed_roles, agent_action }." }
        }
      }
    },
    "/api/v1/team/env-policy": {
      "get": {
        "summary": "Get the team's per-env access policy",
        "description": "Returns the policy JSON. Any authenticated team member may read. An empty policy ({}) means no enforcement — every role can perform every action on every env (the default and backward-compat baseline).",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": {
            "description": "Policy fetched",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":     { "type": "boolean" },
                    "policy": {
                      "type": "object",
                      "description": "Shape: { <env>: { <action>: [<role>, ...] } }. Known actions: deploy, delete_resource, vault_write.",
                      "additionalProperties": {
                        "type": "object",
                        "additionalProperties": { "type": "array", "items": { "type": "string" } }
                      }
                    }
                  }
                }
              }
            }
          },
          "401": { "description": "Unauthorized" }
        }
      },
      "put": {
        "summary": "Replace the team's per-env access policy (owner only)",
        "description": "Writes the supplied policy verbatim, replacing any previous value. Empty {} disables enforcement. Validation: env names match ^[a-z0-9_-]{1,64}$, action names must be one of deploy/delete_resource/vault_write (unknown actions are rejected to catch typos), role names match ^[a-z0-9_]{1,32}$, total body capped at 8 KiB. Owner-only — non-owners receive 403 with agent_action telling them to have an owner run the prompt.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "description": "The policy object itself (NOT wrapped). Example: {\"production\":{\"deploy\":[\"owner\"]}}",
                "additionalProperties": {
                  "type": "object",
                  "additionalProperties": { "type": "array", "items": { "type": "string" } }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Policy persisted; the response echoes the normalised policy." },
          "400": { "description": "Invalid policy shape, unknown action, or malformed JSON. agent_action is populated when applicable." },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Caller is not the team owner. Body: { error: 'owner_required', role, allowed_roles, agent_action }." }
        }
      }
    },
    "/api/v1/resources/{id}/rotate-credentials": {
      "post": {
        "summary": "Rotate credentials for a DB/cache/nosql resource",
        "description": "Generates a new password and returns the updated connection_url. The old URL is immediately revoked.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Credentials rotated", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "connection_url": { "type": "string" } } } } } },
          "403": { "description": "Forbidden" }
        }
      }
    },
    "/api/v1/resources/{id}/pause": {
      "post": {
        "summary": "Pause a resource (suspend without deletion)",
        "description": "Sets status to 'paused' and runs the provider-side revoke (REVOKE CONNECT for postgres, ACL SETUSER off for redis, revokeRolesFromUser for mongodb; queue/storage/webhook are pure status flips). The connection URL is preserved on resume — no re-issuance. Paused resources STOP counting against the per-type resource quota, but storage_bytes STILL counts toward the storage cap so pause-and-bloat is not a valid escape. Tier-gated to Pro+. Idempotent error: a second pause on an already-paused resource returns 409 already_paused.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Resource paused", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "id": { "type": "string", "format": "uuid" }, "token": { "type": "string", "format": "uuid" }, "status": { "type": "string", "enum": ["paused"] }, "message": { "type": "string" } } } } } },
          "400": { "description": "invalid_id — :id is not a valid UUID" },
          "401": { "description": "Unauthorized — session token required" },
          "402": { "description": "upgrade_required — pause/resume requires Pro+. Body: { error: 'upgrade_required', upgrade_url, agent_action }." },
          "403": { "description": "Forbidden — caller doesn't own the resource" },
          "404": { "description": "not_found — resource doesn't exist" },
          "409": { "description": "already_paused — the resource is already paused (idempotent error)" },
          "503": { "description": "provider_failed — the provider-side revoke failed; the DB row is unchanged" }
        }
      }
    },
    "/api/v1/resources/{id}/resume": {
      "post": {
        "summary": "Resume a paused resource (restore from same data)",
        "description": "Flips status from 'paused' back to 'active' and re-grants the provider-side connection (GRANT CONNECT / ACL on / grantRolesToUser). The connection URL is preserved unchanged — no re-issuance, no new password — so any existing client config still works. Tier-gated to Pro+ in symmetry with pause.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Resource resumed", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "id": { "type": "string", "format": "uuid" }, "token": { "type": "string", "format": "uuid" }, "status": { "type": "string", "enum": ["active"] }, "message": { "type": "string" } } } } } },
          "400": { "description": "invalid_id" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "upgrade_required — pause/resume requires Pro+" },
          "403": { "description": "Forbidden" },
          "404": { "description": "not_found" },
          "409": { "description": "not_paused — the resource isn't currently paused" },
          "503": { "description": "provider_failed — the provider-side grant failed; the DB row is unchanged" }
        }
      }
    },
    "/api/v1/resources/families": {
      "get": {
        "summary": "List resource families for the authenticated team",
        "description": "Returns one entry per family root the team owns, with members grouped by env. A family is a set of env-twin resources (prod-db / staging-db / dev-db) linked via parent_resource_id (migration 018). Resources without children or parent appear as single-member families. Sets Cache-Control: private, max-age=30 — narrow freshness window because provisioning + soft-delete both shift family membership. Quota / billing decisions must NOT rely on this aggregate; it's a UX-only optimisation.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": {
            "description": "Family list",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":       { "type": "boolean" },
                    "families": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "family_root_id":  { "type": "string", "format": "uuid", "description": "Stable family identifier — the row's own id when it is its own root." },
                          "resource_type":   { "type": "string", "description": "postgres | redis | mongodb | webhook | queue | storage" },
                          "members_per_env": {
                            "type": "object",
                            "additionalProperties": {
                              "type": "object",
                              "properties": {
                                "id":            { "type": "string", "format": "uuid" },
                                "token":         { "type": "string", "format": "uuid" },
                                "env":           { "type": "string" },
                                "resource_type": { "type": "string" },
                                "tier":          { "type": "string" },
                                "status":        { "type": "string" },
                                "is_root":       { "type": "boolean", "description": "true when this row is the family root (parent_resource_id IS NULL)." },
                                "name":          { "type": "string" }
                              }
                            }
                          }
                        }
                      }
                    },
                    "total":    { "type": "integer" }
                  }
                }
              }
            }
          },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/resources/{id}/family": {
      "get": {
        "summary": "Get the env-twin family for a resource",
        "description": "Returns the root + every sibling for the family containing the given resource. The id can be the family root or any child — the handler walks parent_resource_id up to the root and back down. Cross-team callers get 403 (not 404) so honest mistakes are debuggable. Sensitive fields like connection_url are never returned. Sets Cache-Control: private, max-age=30.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" }, "description": "Any member of the family — root or child. The handler resolves the root by walking parent_resource_id." }],
        "responses": {
          "200": {
            "description": "Family payload",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":             { "type": "boolean" },
                    "family_root_id": { "type": "string", "format": "uuid" },
                    "members": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id":                 { "type": "string", "format": "uuid" },
                          "token":              { "type": "string", "format": "uuid" },
                          "env":                { "type": "string" },
                          "resource_type":      { "type": "string" },
                          "tier":               { "type": "string" },
                          "status":             { "type": "string" },
                          "is_root":            { "type": "boolean" },
                          "parent_resource_id": { "type": "string", "description": "Empty for the root; otherwise the root's id." },
                          "name":               { "type": "string" },
                          "created_at":         { "type": "string", "format": "date-time" }
                        }
                      }
                    },
                    "total":          { "type": "integer" }
                  }
                }
              }
            }
          },
          "400": { "description": "Resource ID is not a valid UUID" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Cross-team — caller does not own this resource" },
          "404": { "description": "Resource not found" }
        }
      }
    },
    "/api/v1/resources/{id}/provision-twin": {
      "post": {
        "summary": "Provision an env-twin of an existing resource (Pro+)",
        "description": "Creates a fresh resource of the same type as the source, in a different env, linked into the same family (parent_resource_id = family root). Tier-gated to Pro/Team/Growth — hobby/free callers get a 402 with agent_action telling them to upgrade. Only supports postgres/redis/mongodb sources (the resource types where env-twin has real per-env infra). The response shape mirrors the corresponding /db/new, /cache/new, /nosql/new endpoint so dashboard + MCP code consuming those needs no branching for twins.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" }, "description": "Token of the source resource (root or any sibling — the handler resolves the family root)." }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["env"],
                "properties": {
                  "env":  { "type": "string", "description": "Target env for the twin (production / staging / dev / ...). Must match ^[a-z0-9-]{1,32}$." },
                  "name": { "type": "string", "description": "Optional human-readable label (max 120 chars). Falls back to the source's name when omitted." }
                }
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Twin provisioned — body carries connection_url + family_root_id (same shape as POST /db/new etc.)" },
          "400": { "description": "invalid_id / missing_env / invalid_env / unsupported_for_twin (source isn't postgres/redis/mongodb)" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "upgrade_required — team is on hobby/free; response carries agent_action + upgrade_url" },
          "403": { "description": "forbidden — caller does not own the source resource" },
          "404": { "description": "Source resource not found" },
          "409": { "description": "twin_exists — family already has a row in the requested env" },
          "503": { "description": "provision_failed — downstream provisioner errored; resource row was soft-deleted" }
        }
      }
    },
    "/api/v1/webhooks/{token}/requests": {
      "get": {
        "summary": "List received webhook payloads",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "token", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "List of stored requests with headers and body" }
        }
      }
    },
    "/api/v1/billing": {
      "get": {
        "summary": "Aggregated billing state for the authenticated team",
        "description": "One-shot fetch that powers the dashboard's billing view: current tier, Razorpay subscription status, next renewal timestamp, monthly amount, and the payment method on file. Returns 200 with sensibly-defaulted nulls for teams without a Razorpay subscription yet — callers can render the 'no subscription' UI without branching on error.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Aggregated billing state", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BillingStateResponse" } } } },
          "401": { "description": "Missing or invalid session token" },
          "404": { "description": "Team not found" }
        }
      }
    },
    "/api/v1/billing/checkout": {
      "post": {
        "summary": "Create a Razorpay subscription and return its hosted-page URL",
        "description": "Mints a Razorpay subscription for the requested plan (hobby or pro) tied to the authenticated team. The dashboard redirects the user to the returned short_url to complete payment; on success Razorpay fires subscription.activated to /razorpay/webhook and the team's plan_tier is elevated atomically. The Team tier currently returns 400 tier_unavailable — only ops can set it via /internal/set-tier. plan_frequency selects monthly (default) vs yearly billing — yearly returns 503 billing_not_configured until the operator creates the yearly Razorpay plan and sets RAZORPAY_PLAN_ID_*_YEARLY.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["plan"], "properties": { "plan": { "type": "string", "enum": ["hobby", "pro"] }, "plan_frequency": { "type": "string", "enum": ["monthly", "yearly"], "default": "monthly", "description": "Billing cycle. Empty = monthly. Yearly variants follow the same canonical-tier mapping on the webhook side — teams.plan_tier still stores the bare tier name." } } } } } },
        "responses": {
          "200": { "description": "Subscription created — redirect user to short_url", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "short_url": { "type": "string", "format": "uri" }, "subscription_id": { "type": "string" } } } } } },
          "400": { "description": "Invalid plan, invalid plan_frequency, or tier_unavailable" },
          "401": { "description": "Missing or invalid session token" },
          "502": { "description": "Razorpay rejected the create-subscription call" },
          "503": { "description": "Razorpay not configured on this environment (incl. yearly plan_id unset)" }
        }
      }
    },
    "/api/v1/billing/cancel": {
      "post": {
        "summary": "Cancel the team's active Razorpay subscription",
        "description": "Triggers a cancellation on Razorpay's side. Razorpay processes the cancellation asynchronously and emits subscription.cancelled to /razorpay/webhook, which downgrades the team to Hobby. The cancel call returns 200 immediately; the dashboard should re-fetch /api/v1/billing after a few seconds to see the updated state.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Cancel request accepted by Razorpay" },
          "401": { "description": "Missing or invalid session token" },
          "404": { "description": "No active subscription to cancel" },
          "502": { "description": "Razorpay rejected the cancel call" },
          "503": { "description": "Razorpay not configured on this environment" }
        }
      }
    },
    "/api/v1/billing/invoices": {
      "get": {
        "summary": "List the team's invoices",
        "description": "Returns up to the last 24 invoices from Razorpay for the team's subscription, newest first. Each entry includes id, amount (paise), currency, and status. Returns an empty array when the team has no subscription yet.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Invoice list", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "invoices": { "type": "array", "items": { "type": "object", "properties": { "id": { "type": "string" }, "amount": { "type": "integer", "description": "Amount in paise (INR×100)" }, "currency": { "type": "string" }, "status": { "type": "string" } } } } } } } } },
          "401": { "description": "Missing or invalid session token" },
          "503": { "description": "Razorpay not configured on this environment" }
        }
      }
    },
    "/api/v1/billing/update-payment": {
      "post": {
        "summary": "Return a Razorpay hosted-page URL the user can use to update their card on file",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Hosted page URL", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "short_url": { "type": "string", "format": "uri" } } } } } },
          "401": { "description": "Missing or invalid session token" },
          "404": { "description": "No active subscription" },
          "503": { "description": "Razorpay not configured" }
        }
      }
    },
    "/api/v1/billing/change-plan": {
      "post": {
        "summary": "Switch the team's subscription to a different tier",
        "description": "Hobby↔Pro on the same Razorpay subscription. Proration is handled by Razorpay; the new plan takes effect at the end of the current billing period. Team tier is currently not customer-changeable — returns 400 tier_unavailable.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["plan"], "properties": { "plan": { "type": "string", "enum": ["hobby", "pro"] } } } } } },
        "responses": {
          "200": { "description": "Plan change accepted by Razorpay" },
          "400": { "description": "Invalid plan or tier_unavailable" },
          "401": { "description": "Missing or invalid session token" },
          "404": { "description": "No active subscription" },
          "503": { "description": "Razorpay not configured" }
        }
      }
    },
    "/api/v1/billing/promotion/validate": {
      "post": {
        "summary": "Validate a promotion code against a target plan",
        "description": "HTTP wrapper around the plans-registry ValidatePromotion check. Accepts {code, plan} and returns either a structured discount payload (200 + ok:true) or a typed rejection (200 + ok:false with error/message/agent_action). Rejections deliberately return 200 — the dashboard's PromoCodePanel can render the red state through its normal success-path parser without a catch on the fetch promise. MCP/CLI agents read agent_action for the LLM-ready copy. Rate-limited at 30 validations/team/hour to make brute-forcing the seed-code namespace impractical; the limiter scopes per team so multiple developers on one team share the bucket. Codes are case-insensitive — the response echoes the canonical uppercase code.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["code", "plan"],
                "properties": {
                  "code": { "type": "string", "description": "Promotion code (case-insensitive)", "example": "LAUNCH50" },
                  "plan": { "type": "string", "enum": ["hobby", "pro", "team"], "description": "Plan tier the discount must apply to" }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Either a valid discount (ok:true) or a typed rejection (ok:false). The dashboard branches on the ok field, not the status code.",
            "content": {
              "application/json": {
                "examples": {
                  "valid": {
                    "summary": "Valid code for the requested plan",
                    "value": {
                      "ok": true,
                      "code": "LAUNCH50",
                      "discount": {
                        "kind": "percent_off",
                        "value": 50,
                        "applies_to": ["pro", "team"],
                        "max_uses": 1000,
                        "description": "50% off Pro or Team for the first 1000 signups"
                      },
                      "valid_until": "2026-12-31T23:59:59Z"
                    }
                  },
                  "invalid": {
                    "summary": "Unknown code or wrong plan",
                    "value": {
                      "ok": false,
                      "error": "promotion_invalid",
                      "message": "Promotion code \"SAVE20\" is not valid for the pro plan.",
                      "agent_action": "Tell the user this promo code isn't valid for the requested plan. Have them try a different code at https://instanode.dev/billing — promotion codes are case-insensitive."
                    }
                  },
                  "expired": {
                    "summary": "Code matched the registry but its expires_at is in the past",
                    "value": {
                      "ok": false,
                      "error": "promotion_expired",
                      "message": "Promotion code \"LAUNCH50\" has expired.",
                      "agent_action": "Tell the user this promo code isn't valid for the requested plan. Have them try a different code at https://instanode.dev/billing — promotion codes are case-insensitive."
                    }
                  }
                }
              }
            }
          },
          "400": { "description": "Empty code, missing plan, or malformed JSON body" },
          "401": { "description": "Missing or invalid session token" },
          "429": { "description": "Team exceeded 30 validations per hour. Wait for the next hourly bucket.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/api/v1/billing/usage": {
      "get": {
        "summary": "Aggregated usage metrics for the authenticated team (cached)",
        "description": "One-shot fetch that powers the dashboard's BillingPage Usage panel. Replaces the prior pattern of summing storage_bytes per type in the browser after pulling the full /resources list. The aggregation runs once per team per 30s cache window and is shared across every surface (BillingPage today, future MCP agent_usage_summary tool). Real-time provisioning paths (POST /db/new etc.) MUST NOT use this aggregate — they read fresh DB state. Response shape: { ok, freshness_seconds, as_of, usage: { postgres, redis, mongodb, deployments, webhooks, vault, members } }. Storage services carry { bytes, limit_bytes }; count services carry { count, limit }. -1 in any limit field means 'unlimited' (matches plans.yaml). Cache-Control: private, max-age=30, stale-while-revalidate=60 — browsers + intermediate proxies honour the same window without hammering the API.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": {
            "description": "Aggregated usage payload",
            "headers": {
              "Cache-Control": {
                "schema": { "type": "string", "example": "private, max-age=30, stale-while-revalidate=60" },
                "description": "Per-team payload — private (no shared proxies). 30s max-age matches the server-side cache; 60s SWR gives the browser a grace window where stale values render while a background refresh runs."
              }
            },
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/BillingUsageResponse" },
                "example": {
                  "ok": true,
                  "freshness_seconds": 30,
                  "as_of": "2026-05-12T00:00:00Z",
                  "usage": {
                    "postgres":    { "bytes": 12582912,  "limit_bytes": 524288000 },
                    "redis":       { "bytes": 0,         "limit_bytes": 26214400 },
                    "mongodb":     { "bytes": 0,         "limit_bytes": 104857600 },
                    "deployments": { "count": 1, "limit": 1 },
                    "webhooks":    { "count": 3, "limit": 1000 },
                    "vault":       { "count": 5, "limit": 50 },
                    "members":     { "count": 1, "limit": 1 }
                  }
                }
              }
            }
          },
          "401": { "description": "Missing or invalid session token. Response includes agent_action pointing the user at https://instanode.dev/login.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "500": { "description": "Failed to compute usage (transient DB error). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/metrics": {
      "get": {
        "summary": "Prometheus metrics scrape endpoint",
        "description": "Exposes the standard Prometheus text-format metrics for the API process (Go runtime, HTTP request counters, provision counters, conversion funnel, Redis errors, etc.). When METRICS_TOKEN is set in config, the request must include 'Authorization: Bearer <METRICS_TOKEN>'. Open without auth in local dev.",
        "responses": {
          "200": { "description": "Prometheus text-format metrics", "content": { "text/plain": {} } },
          "401": { "description": "METRICS_TOKEN is configured and the supplied bearer did not match" }
        }
      }
    },
    "/openapi.json": {
      "get": {
        "summary": "Machine-readable OpenAPI 3.1 description of this API",
        "description": "Returns this very document. Self-describing endpoint that agents can read to discover every other route.",
        "responses": {
          "200": { "description": "OpenAPI 3.1 JSON spec", "content": { "application/json": {} } }
        }
      }
    },
    "/storage/new": {
      "post": {
        "summary": "Provision S3-compatible object storage",
        "description": "Returns S3-compatible credentials (access_key_id + secret_access_key) scoped to a per-token prefix inside a shared MinIO/R2 bucket. Anonymous tier: 1024MB, 24h TTL. Returns 503 service_disabled when MINIO_ENDPOINT / R2_API_TOKEN are not configured on the server.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Storage provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StorageProvisionResponse" } } } },
          "402": { "description": "Storage limit reached. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "429": { "description": "Anonymous fingerprint limit exceeded. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Object storage is not configured on this environment", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/resources/{token}/logs": {
      "get": {
        "summary": "Stream pod logs for an isolated (growth-tier) resource",
        "description": "Server-Sent Events stream of the last N log lines from the per-tenant pod that backs a growth-tier resource (postgres / cache / nosql / queue). The token IS the credential — no Bearer required, identical to /webhook/receive/{token}. Returns 400 not_growth for shared-tier resources (those run on platform pods shared across customers; use external log aggregation instead).",
        "parameters": [
          { "name": "token", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } },
          { "name": "tail", "in": "query", "required": false, "schema": { "type": "integer", "default": 100, "minimum": 1, "maximum": 500 } }
        ],
        "responses": {
          "200": { "description": "text/event-stream of log lines terminated by 'data: [end]'" },
          "400": { "description": "invalid_token, not_growth, or unsupported_type" },
          "404": { "description": "Resource or backing pod not found" },
          "409": { "description": "Resource has no provider namespace yet — still provisioning" },
          "503": { "description": "Log streaming unavailable (no k8s client)" }
        }
      }
    },
    "/stacks/{slug}/logs/{svc}": {
      "get": {
        "summary": "Stream service logs from a stack (Server-Sent Events)",
        "description": "Tails the named service's pod logs as text/event-stream. Anonymous-owned stacks are accessible without auth (token-style by slug); authenticated stacks require Bearer and team ownership.",
        "parameters": [
          { "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "svc", "in": "path", "required": true, "schema": { "type": "string", "description": "Service name from the manifest" } }
        ],
        "responses": {
          "200": { "description": "text/event-stream of log lines terminated by 'data: [end]'" },
          "404": { "description": "Stack not found" },
          "503": { "description": "Compute backend log stream failed" }
        }
      }
    },
    "/stacks/{slug}/env": {
      "patch": {
        "summary": "Note env var overrides for a stack (applied on next redeploy)",
        "description": "Accepts a map of env vars to be applied on the next call to POST /stacks/{slug}/redeploy. MVP: env vars are NOT persisted to the stacks table — the message in the response reminds the caller to issue a redeploy. Auth required: anonymous stacks cannot be mutated after creation.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["env"], "properties": { "env": { "type": "object", "additionalProperties": { "type": "string" } } } } } } },
        "responses": {
          "200": { "description": "Env vars noted" },
          "400": { "description": "Body missing or env is empty" },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Stack not found or not owned by this team" }
        }
      }
    },
    "/auth/github": {
      "post": {
        "summary": "Exchange a GitHub OAuth authorization code for a session JWT",
        "description": "Programmatic / SPA flow. Body: {\"code\":\"<github-oauth-code>\"}. Returns 200 with a 24h session JWT plus user/team ids. Returns 503 oauth_not_configured when GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not set in the environment.",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["code"], "properties": { "code": { "type": "string" } } } } } },
        "responses": {
          "200": { "description": "Session issued", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "token": { "type": "string" }, "user_id": { "type": "string", "format": "uuid" }, "team_id": { "type": "string", "format": "uuid" }, "email": { "type": "string", "format": "email" } } } } } },
          "400": { "description": "Body invalid or missing code" },
          "401": { "description": "GitHub rejected the authorization code" },
          "503": { "description": "GitHub OAuth not configured / user upsert failed / JWT signing failed" }
        }
      }
    },
    "/auth/github/start": {
      "get": {
        "summary": "Browser-driven GitHub OAuth: stash CSRF cookie + 302 to GitHub",
        "description": "Sets an HTTP-only state cookie binding ?return_to and a random state token, then 302-redirects the user agent to https://github.com/login/oauth/authorize. The dashboard's login page links here directly — there is no JSON contract. ?return_to is validated against the allowlist (instanode.dev, www.instanode.dev, http://localhost:5173, http://localhost:3000); off-list values collapse to https://instanode.dev/login/callback.",
        "parameters": [{ "name": "return_to", "in": "query", "required": false, "schema": { "type": "string", "format": "uri" } }],
        "responses": {
          "302": { "description": "Redirect to GitHub authorize URL" },
          "503": { "description": "GitHub OAuth not configured" }
        }
      }
    },
    "/auth/github/callback": {
      "get": {
        "summary": "Browser-driven GitHub OAuth: exchange code + 302 to <return_to>?session_token=<jwt>",
        "description": "Verifies the state cookie matches the ?state query param, exchanges ?code with GitHub, finds-or-creates the user/team, mints a 24h session JWT, and 302-redirects to the validated return_to URL with session_token appended. On any error, renders an HTML error page.",
        "parameters": [
          { "name": "code", "in": "query", "required": true, "schema": { "type": "string" } },
          { "name": "state", "in": "query", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "302": { "description": "Redirect to <return_to>?session_token=<jwt>" },
          "400": { "description": "Missing code/state, or state mismatch / expired" },
          "401": { "description": "GitHub rejected the code" },
          "503": { "description": "OAuth not configured / user upsert / JWT signing failed" }
        }
      }
    },
    "/auth/email/start": {
      "post": {
        "summary": "Send a passwordless magic-link sign-in email",
        "description": "Generates a single-use 15-minute token, stores its SHA-256 hash, emails the link, and returns 202 — always 202, even when the email isn't registered, to defeat user enumeration. The link points to GET /auth/email/callback?t=<token>.",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["email"], "properties": { "email": { "type": "string", "format": "email" }, "return_to": { "type": "string", "format": "uri", "description": "Where to send the user after sign-in. Validated against the allowlist; off-list collapses to the default." } } } } } },
        "responses": {
          "202": { "description": "Magic link sent (or silently dropped — body is invariant by design)" },
          "400": { "description": "Body invalid or email malformed" }
        }
      }
    },
    "/auth/email/callback": {
      "get": {
        "summary": "Consume a magic link, mint a session JWT, 302 to <return_to>",
        "description": "Validates and atomically consumes the magic-link token, finds-or-creates the user/team, mints a 24h session JWT, and redirects to the original return_to with session_token appended. On any error renders an HTML error page (the user is in a browser).",
        "parameters": [{ "name": "t", "in": "query", "required": true, "schema": { "type": "string", "description": "Plaintext magic-link token from the emailed URL" } }],
        "responses": {
          "302": { "description": "Redirect to <return_to>?session_token=<jwt>" },
          "400": { "description": "Token missing, expired, already used, or invalid" },
          "503": { "description": "Database / JWT signing failed" }
        }
      }
    },
    "/auth/cli": {
      "post": {
        "summary": "Start a CLI device-flow login session",
        "description": "Creates a pending Redis-backed login session (10-minute TTL) and returns a browser URL the user must visit to complete OAuth. The CLI then polls GET /auth/cli/{id} for completion. Optional body: anon_tokens — anonymous resource tokens that the server will associate with the user's team once they sign in.",
        "requestBody": { "required": false, "content": { "application/json": { "schema": { "type": "object", "properties": { "anon_tokens": { "type": "array", "items": { "type": "string", "format": "uuid" } } } } } } },
        "responses": {
          "201": { "description": "Session created", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "session_id": { "type": "string" }, "auth_url": { "type": "string", "format": "uri" }, "expires_in": { "type": "integer", "description": "Seconds (600)" } } } } } },
          "500": { "description": "Failed to create login session" }
        }
      }
    },
    "/auth/cli/{id}": {
      "get": {
        "summary": "Poll a CLI device-flow login session for completion",
        "description": "Returns 202 with {pending:true} while the user is still completing OAuth, or 200 with the issued API key and identity once they have. The session is single-use and is deleted on the first 200 response. After Redis expiry (or on lookup failure) the endpoint fails open with pending=true so the CLI keeps polling.",
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Login complete", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "api_key": { "type": "string" }, "email": { "type": "string", "format": "email" }, "tier": { "type": "string" }, "team_name": { "type": "string" }, "claimed_tokens": { "type": "array", "items": { "type": "string", "format": "uuid" } } } } } } },
          "202": { "description": "Still pending" },
          "400": { "description": "Missing session id" },
          "404": { "description": "Session not found or expired" }
        }
      }
    },
    "/billing/checkout": {
      "post": {
        "summary": "Legacy alias for POST /api/v1/billing/checkout",
        "description": "Kept for backward compatibility with older dashboard/SDK clients. Identical contract to POST /api/v1/billing/checkout. New callers should use the /api/v1 path.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["plan"], "properties": { "plan": { "type": "string", "enum": ["hobby", "pro"] } } } } } },
        "responses": {
          "200": { "description": "Subscription created — redirect user to short_url", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "short_url": { "type": "string", "format": "uri" }, "subscription_id": { "type": "string" } } } } } },
          "400": { "description": "Invalid plan or tier_unavailable" },
          "401": { "description": "Missing or invalid session token" },
          "502": { "description": "Razorpay rejected the create-subscription call" },
          "503": { "description": "Razorpay not configured on this environment" }
        }
      }
    },
    "/razorpay/webhook": {
      "post": {
        "summary": "Razorpay subscription event webhook (signature-verified)",
        "description": "Receives Razorpay subscription lifecycle events: subscription.charged (payment confirmed → elevate team tier + elevate all permanent resources + trigger migrations for shared-infra resources), subscription.cancelled (downgrade team to hobby), payment.failed (record). The body's HMAC-SHA256 signature with RAZORPAY_WEBHOOK_SECRET must match the X-Razorpay-Signature header. Always returns 200 on success — Razorpay retries on non-2xx. Returns 400 invalid_signature when the HMAC check fails. NOT for direct caller use — Razorpay POSTs here.",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "description": "Razorpay event payload (event, payload.subscription/payment.entity). See Razorpay webhook docs." } } } },
        "responses": {
          "200": { "description": "Event processed (or ignored for unhandled event types)" },
          "400": { "description": "invalid_signature or invalid_payload" }
        }
      }
    },
    "/api/v1/resources/{id}/credentials": {
      "get": {
        "summary": "Read the decrypted connection_url for a resource",
        "description": "Returns the AES-256-GCM-decrypted connection_url for the resource. The id path parameter is the resource's token (UUID). Mirrors the 'not 403, but 404' pattern: resources owned by other teams return 404, never confirming existence. Returns 400 no_connection_url for resources without a stored URL (e.g. storage resources expose access_key_id + secret_access_key elsewhere, not connection_url).",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Decrypted connection URL", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "id": { "type": "string", "format": "uuid" }, "token": { "type": "string", "format": "uuid" }, "resource_type": { "type": "string" }, "env": { "type": "string" }, "connection_url": { "type": "string" } } } } } },
          "400": { "description": "Resource has no connection_url" },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Resource not found (or owned by another team)" },
          "500": { "description": "Encryption key invalid or decryption failed" }
        }
      }
    },
    "/api/v1/team/summary": {
      "get": {
        "summary": "Aggregated team counts for the dashboard sidebar (cached)",
        "description": "One-shot fetch the dashboard sidebar uses to render SidebarUpgradeCard + per-nav-row badge numbers (Resources · 7, Deployments · 2, etc.). Replaces the prior pattern where every <NavRow> page-load triggered its own /api/v1/resources scan to compute a single number. Aggregation runs once per team per 5-min cache window — long enough that one signed-in user opening every dashboard page across a session triggers ~1 aggregate per surface, short enough that a provision/delete is visible within minutes. Eventual-consistent by design (per the §13 freshness matrix); do NOT use this for quota gate decisions. Response shape: { ok, freshness_seconds, as_of, tier, counts: { resources: { total, postgres, redis, mongodb, webhook, queue, storage, other }, deployments, members, vault_keys } }. Unknown resource_type rows fold into counts.resources.other so the total stays accurate even when the per-type breakdown lags a newly-shipped service. Cache-Control: private, max-age=300.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": {
            "description": "Aggregated team summary",
            "headers": {
              "Cache-Control": {
                "schema": { "type": "string", "example": "private, max-age=300" },
                "description": "Per-team payload — private (no shared proxies). 5-min max-age matches the server-side cache. No stale-while-revalidate because the window is already wide."
              }
            },
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/TeamSummaryResponse" },
                "example": {
                  "ok": true,
                  "freshness_seconds": 300,
                  "as_of": "2026-05-12T00:00:00Z",
                  "tier": "hobby",
                  "counts": {
                    "resources": { "total": 7, "postgres": 2, "redis": 1, "mongodb": 1, "webhook": 2, "queue": 0, "storage": 1, "other": 0 },
                    "deployments": 1,
                    "members": 1,
                    "vault_keys": 5
                  }
                }
              }
            }
          },
          "401": { "description": "Missing or invalid session token. Response includes agent_action pointing the user at https://instanode.dev/login.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "500": { "description": "Failed to compute summary (transient DB error). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/api/v1/team/members": {
      "get": {
        "summary": "List members of the caller's team",
        "description": "Any team member (owner/admin/developer/viewer/legacy member) may list. Returns each member's user_id, email, role, joined_at, plus the tier's member_limit.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Members + limit", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "members": { "type": "array", "items": { "type": "object", "properties": { "user_id": { "type": "string", "format": "uuid" }, "email": { "type": "string", "format": "email" }, "role": { "type": "string" }, "joined_at": { "type": "string", "format": "date-time" } } } }, "member_limit": { "type": "integer" } } } } } },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not a member of this team" }
        }
      }
    },
    "/api/v1/team/members/invite": {
      "post": {
        "summary": "Invite a user to the team (owner or admin)",
        "description": "Two flows under the same endpoint: role='member' uses the legacy owner-controlled seat flow (owner-only, enforces tier seat limit); role='admin'/'developer'/'viewer' uses the RBAC token flow (single-use token emailed out, accepted at POST /api/v1/invitations/{token}/accept).",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["email"], "properties": { "email": { "type": "string", "format": "email" }, "role": { "type": "string", "enum": ["admin", "developer", "viewer", "member"], "default": "member" } } } } } },
        "responses": {
          "201": { "description": "Invitation created" },
          "400": { "description": "Body invalid, missing email, or invalid role" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner/admin role required" },
          "409": { "description": "Member limit reached / duplicate / already-a-member" }
        }
      }
    },
    "/api/v1/team/members/leave": {
      "post": {
        "summary": "Leave the team",
        "description": "Removes the caller from their current team. Owners cannot leave — transfer ownership first.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Left the team" },
          "401": { "description": "Unauthorized" },
          "409": { "description": "Owner cannot leave (failed_precondition)" }
        }
      }
    },
    "/api/v1/team/members/{user_id}": {
      "delete": {
        "summary": "Remove a member from the team (owner only)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "user_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Member removed" },
          "400": { "description": "Invalid user id" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner only" },
          "404": { "description": "User not in team" },
          "409": { "description": "Cannot remove the owner" }
        }
      }
    },
    "/api/v1/team/invitations": {
      "get": {
        "summary": "List pending invitations sent by this team (owner only)",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Invitation list" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner only" }
        }
      }
    },
    "/api/v1/team/invitations/{id}": {
      "delete": {
        "summary": "Revoke a pending invitation (owner only)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Revoked" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner only or invitation belongs to another team" },
          "404": { "description": "Invitation not found" }
        }
      }
    },
    "/api/v1/team/invitations/{id}/accept": {
      "post": {
        "summary": "Accept an invitation by its row id (authenticated user)",
        "description": "Authenticated counterpart to POST /api/v1/invitations/{token}/accept — this one accepts by the invitation row id (UUID) and trusts the caller's session for identity. Use the token-based public endpoint when accepting from a link in an email.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Accepted" },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Invitation not found" },
          "409": { "description": "Expired, already used, or member-limit reached" }
        }
      }
    },
    "/api/v1/deployments": {
      "get": {
        "summary": "List all deployments owned by the caller's team",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Deployment list", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "items": { "type": "array", "items": { "$ref": "#/components/schemas/DeployItem" } }, "total": { "type": "integer" } } } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/deployments/{id}": {
      "get": {
        "summary": "Get a deployment by id (alias of GET /deploy/{id})",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Deployment record", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" },
          "404": { "description": "Not found" }
        }
      },
      "patch": {
        "summary": "Update access-control fields (private + allowed_ips) in place",
        "description": "Edits the private flag and allowed_ips list on an existing deployment without rebuilding the image. The dashboard PrivacyPanel writes here. Body fields are optional: sending only 'allowed_ips' keeps the current private state; sending 'private': false clears the allow-list regardless of allowed_ips. allowed_ips uses REPLACE semantics (the supplied list is the new authoritative list, not merged into the existing one) — matches REST conventions and avoids silent allow-list growth across multiple PATCHes. Validation reuses the POST /deploy/new rule-set: Pro+ tier required (returns 402 with private_deploy_requires_pro), private=true with empty allowed_ips returns 400, invalid IPs/CIDRs surface verbatim, >32 entries returns too_many_allowed_ips. Compute layer patches the live Ingress annotations via the same helper POST uses (no image rebuild, no pod restart).",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "private": { "type": "boolean", "description": "Flip the deploy public ↔ private. When false, the allow-list is cleared regardless of allowed_ips in the same body." },
                  "allowed_ips": { "type": "array", "items": { "type": "string" }, "description": "REPLACE the allow-list with this exact set of IPs/CIDRs. Max 32 entries; each must be a valid IP literal or CIDR." }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Access control updated", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "400": { "description": "Bad request — missing_fields (empty body), private_deploy_requires_allowed_ips, invalid_allowed_ip, too_many_allowed_ips, or invalid_body" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "private_deploy_requires_pro — hobby/anonymous/free trying to flip a deploy private. agent_action points to https://instanode.dev/pricing." },
          "403": { "description": "Not your deployment" },
          "404": { "description": "Not found" },
          "503": { "description": "compute_update_failed (ingress patch failed) or update_failed (DB write failed)" }
        }
      },
      "delete": {
        "summary": "Tear down + delete a deployment (alias of DELETE /deploy/{id})",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Deletion enqueued" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" }
        }
      }
    },
    "/api/v1/stacks": {
      "get": {
        "summary": "List all stacks owned by the caller's team",
        "description": "Returns one row per stack, including its env (production/staging/dev/...) and parent_stack_id linkage so the dashboard can render the Environments grid without an extra round-trip per stack. For grouped env-sibling views call GET /api/v1/stacks/{slug}/family instead.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Stack list", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "items": { "type": "array", "items": { "type": "object", "properties": { "stack_id": { "type": "string", "description": "Slug (same as path /stacks/{slug})" }, "name": { "type": "string" }, "status": { "type": "string" }, "tier": { "type": "string" }, "namespace": { "type": "string" }, "env": { "type": "string", "description": "Deployment env (production / staging / dev / ...). Defaults to 'production' for legacy stacks pre-dating migration 015." }, "parent_stack_id": { "type": "string", "description": "Root stack id when this is a promoted child. Empty string for the root." }, "created_at": { "type": "string", "format": "date-time" } } } }, "total": { "type": "integer" } } } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/stacks/{slug}/family": {
      "get": {
        "summary": "Get every env sibling of a stack (Pro+)",
        "description": "Returns the production / staging / dev variants of the same app as a flat list, with the root first. The 'family' is resolved by walking parent_stack_id up to the root, then collecting every direct child. Pro / Team / Growth only — Hobby callers receive 402 with agent_action because they can't create siblings. Includes a per-env URL derived from the primary exposed service's app_url so the dashboard can render clickable env tiles. Response carries Cache-Control: private, max-age=60 — short enough to stay fresh across promotes/redeploys.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Any member of the family (root or child) — the handler walks up to the root and back down." }],
        "responses": {
          "200": {
            "description": "Family list (root first)",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":    { "type": "boolean" },
                    "slug":  { "type": "string", "description": "Echo of the requested slug." },
                    "family": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "slug":            { "type": "string" },
                          "name":            { "type": "string" },
                          "env":             { "type": "string" },
                          "status":          { "type": "string" },
                          "tier":            { "type": "string" },
                          "url":             { "type": "string", "description": "Best-effort: first exposed service's app_url, else first service URL, else empty." },
                          "is_root":         { "type": "boolean", "description": "True for the family root (parent_stack_id is null)." },
                          "parent_stack_id": { "type": "string", "description": "Empty string for the root; otherwise the root's id." },
                          "last_deploy_at":  { "type": "string", "format": "date-time" },
                          "created_at":      { "type": "string", "format": "date-time" }
                        }
                      }
                    },
                    "total": { "type": "integer" }
                  }
                }
              }
            }
          },
          "401": { "description": "Unauthorized — session required" },
          "402": { "description": "Upgrade required — team is not on pro/team/growth. Response carries upgrade_url + agent_action." },
          "404": { "description": "Stack not found or not owned by this team" }
        }
      }
    },
    "/api/v1/stacks/{slug}/domains": {
      "post": {
        "summary": "Bind a custom hostname to a stack (Pro+)",
        "description": "Pro tier or higher. Records the requested hostname against the caller's stack and emits a TXT-record DNS challenge. Status starts at 'pending_verification' until POST .../verify confirms the challenge. Returns 402 upgrade_required for Hobby/anonymous teams.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["hostname"], "properties": { "hostname": { "type": "string", "description": "Apex or subdomain, e.g. app.example.com" } } } } } },
        "responses": {
          "201": { "description": "Domain row created (pending verification)" },
          "400": { "description": "Body invalid or hostname malformed" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "upgrade_required — Pro plan or higher" },
          "404": { "description": "Stack not found or not owned by this team" },
          "409": { "description": "hostname_taken — bound to another team's stack" }
        }
      },
      "get": {
        "summary": "List custom domains bound to a stack",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Custom-domain list" },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Stack not found or not owned by this team" }
        }
      }
    },
    "/api/v1/stacks/{slug}/domains/{id}/verify": {
      "post": {
        "summary": "Re-poll verification + ingress + certificate state for a custom domain (idempotent)",
        "description": "Drives the state machine forward: pending_verification → verified (TXT check passes) → ingress_ready (Ingress + Certificate created) → cert_ready (cert-manager has issued the TLS cert). Each call advances at most one step; safe to call repeatedly.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
        ],
        "responses": {
          "200": { "description": "Latest state after this call's mutations" },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Stack or domain not found" }
        }
      }
    },
    "/api/v1/stacks/{slug}/domains/{id}": {
      "delete": {
        "summary": "Tear down the Ingress (best-effort) and remove the custom-domain binding",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
        ],
        "responses": {
          "200": { "description": "Custom domain removed" },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Custom domain not found" },
          "503": { "description": "DB delete failed" }
        }
      }
    },
    "/api/v1/auth/api-keys": {
      "post": {
        "summary": "Mint a Personal Access Token (long-lived bearer for agents/CI)",
        "description": "Creates a long-lived bearer token bound to the caller's team. The plaintext key is returned ONCE in the response and never shown again — the DB stores only its SHA-256 hash. PATs cannot mint other PATs (the request fails with 403 when the caller is themselves a PAT, not a user session). Scopes default to full team access; pass scopes:['read','write','admin'] to limit.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["name"], "properties": { "name": { "type": "string", "maxLength": 120, "description": "Human-readable label, e.g. 'laptop' or 'github-actions'" }, "scopes": { "type": "array", "items": { "type": "string", "enum": ["read", "write", "admin"] } } } } } } },
        "responses": {
          "201": { "description": "Key created — plaintext returned exactly once", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "id": { "type": "string", "format": "uuid" }, "name": { "type": "string" }, "scopes": { "type": "array", "items": { "type": "string" } }, "created_at": { "type": "string", "format": "date-time" }, "key": { "type": "string", "description": "Plaintext bearer token — copy now, never shown again" }, "note": { "type": "string" } } } } } },
          "400": { "description": "Body invalid, missing name, name too long, or invalid scope" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "PAT-creating-a-PAT is forbidden — use a user session" },
          "503": { "description": "Token generation or DB write failed" }
        }
      },
      "get": {
        "summary": "List Personal Access Tokens for the team",
        "description": "Returns metadata only — plaintext keys are never echoed back. Each item has id, name, scopes, created_at, last_used_at (nullable), and revoked.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "API key list (metadata only)", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "items": { "type": "array", "items": { "type": "object", "properties": { "id": { "type": "string", "format": "uuid" }, "name": { "type": "string" }, "scopes": { "type": "array", "items": { "type": "string" } }, "created_at": { "type": "string", "format": "date-time" }, "last_used_at": { "type": ["string", "null"], "format": "date-time" }, "revoked": { "type": "boolean" } } } } } } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/auth/api-keys/{id}": {
      "delete": {
        "summary": "Revoke a Personal Access Token",
        "description": "Soft-deletes the key (sets revoked_at = now()). Tokens that have been revoked fail subsequent auth checks immediately.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Revoked", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "id": { "type": "string", "format": "uuid" } } } } } },
          "400": { "description": "Path id is not a UUID" },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Key not found" }
        }
      }
    },
    "/api/v1/audit": {
      "get": {
        "summary": "Per-team audit log (feeds the dashboard's Recent Activity panel)",
        "description": "Returns up to ?limit (default 20, max 200) recent audit events for the caller's team, newest first. Optional ?kind filter (e.g. 'provision', 'delete', 'tier_change'). Each item has id, actor, kind, resource_type, resource_id (nullable), summary (HTML-safe), metadata (arbitrary JSON), at.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 20, "minimum": 1, "maximum": 200 } },
          { "name": "kind", "in": "query", "required": false, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Audit event list", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "items": { "type": "array", "items": { "type": "object", "properties": { "id": { "type": "string", "format": "uuid" }, "actor": { "type": "string" }, "kind": { "type": "string" }, "resource_type": { "type": "string" }, "resource_id": { "type": ["string", "null"], "format": "uuid" }, "summary": { "type": "string", "description": "HTML-safe summary; rendered via dangerouslySetInnerHTML in the dashboard" }, "metadata": { "type": ["object", "null"], "additionalProperties": true }, "at": { "type": "string", "format": "date-time" } } } } } } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/internal/set-tier": {
      "post": {
        "summary": "Internal: forcibly elevate a team's tier (dev only)",
        "description": "Internal-only — only enabled when ENVIRONMENT=development. Bypasses Razorpay entirely and writes the team's plan_tier directly. Also calls ElevateResourceTiersByTeam to bump every active permanent resource to the new tier immediately, and (when configured) fires migrator jobs to move shared-infra resources to isolated infra. Only upgrades are accepted: tier must be one of 'pro', 'team', 'growth'. Downgrades go through the real Razorpay cancellation flow.",
        "x-instanode-internal": true,
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["team_id", "tier"], "properties": { "team_id": { "type": "string", "format": "uuid" }, "tier": { "type": "string", "enum": ["pro", "team", "growth"] } } } } } },
        "responses": {
          "200": { "description": "Tier updated", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "team_id": { "type": "string", "format": "uuid" }, "tier": { "type": "string" } } } } } },
          "400": { "description": "Body invalid, team_id missing/malformed, or tier not an allowed upgrade target" },
          "404": { "description": "Endpoint not registered (ENVIRONMENT != development)" },
          "503": { "description": "DB update failed" }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "description": "Session JWT for authenticated endpoints (deploy, vault, billing, team, custom-domain). Resource provisioning (POST /db/new, /cache/new, /nosql/new, /queue/new, /storage/new, /webhook/new) does NOT require this header — those endpoints are anonymous. How to obtain a JWT from an anonymous agent flow: (1) Call any provisioning endpoint anonymously — the response includes a start_url like https://api.instanode.dev/start?t=<onboarding-jwt>. (2) Visit that URL once (or POST { jti, email } to /claim directly) to attach the anonymous tokens to a real team. Email verification via magic link. (3) /claim returns a session JWT (24h) usable as the Authorization: Bearer header. For unattended agents, prefer POST /api/v1/api-keys (requires an existing session) which mints a long-lived bearer token tied to your team. Claim values: tid (team ID), uid (user ID), email, plus standard RFC 7519 claims. HS256-signed."
      }
    },
    "schemas": {
      "HealthResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "service": { "type": "string" },
          "commit_id": { "type": "string", "description": "Short git SHA of the running binary (compiled via -ldflags). Falls back to 'dev' for un-instrumented builds." },
          "build_time": { "type": "string", "description": "RFC3339 UTC timestamp when the running binary was built. Falls back to 'dev'." },
          "version": { "type": "string", "description": "Build version tag from -ldflags. Falls back to 'dev'." },
          "migration_version": { "type": "string", "description": "Filename of the highest-applied embedded migration recorded in the platform DB's schema_migrations table (e.g. '022_schema_migrations.sql'). Empty when migration_status='unknown'." },
          "migration_count": { "type": "integer", "description": "Total number of migrations recorded as applied in schema_migrations. 0 when migration_status='unknown'." },
          "migration_status": { "type": "string", "enum": ["ok", "unknown"], "description": "'ok' when the read against schema_migrations succeeded; 'unknown' when the DB was unreachable or the table is absent. The service still returns 200 OK in either case — this field surfaces tracking-read health independently of overall service health." }
        }
      },
      "ProvisionRequest": {
        "type": "object",
        "properties": {
          "name": { "type": "string", "description": "Optional human-readable label (max 120 chars)" },
          "env": { "type": "string", "description": "Optional environment scope (production / staging / dev / ...). Anonymous tier is always 'production'.", "default": "production" },
          "parent_resource_id": { "type": "string", "format": "uuid", "description": "Optional. Link the new resource into an existing env-twin family — the new row becomes a sibling of the parent (same family root, different env). Validated against same-team + same-type + no-duplicate-twin before provisioning. Authenticated callers only. Errors: 400 type_mismatch (parent is a different resource_type), 403 forbidden_parent_resource (parent belongs to another team), 404 parent_not_found, 409 twin_exists (family already has a row in this env). See GET /api/v1/resources/{id}/family + /api/v1/resources/families." }
        }
      },
      "DBProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "token": { "type": "string", "format": "uuid" },
          "connection_url": { "type": "string", "description": "postgres:// connection string with pgvector pre-installed. Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal postgres:// URL routed via instant-pg-proxy. Use this when calling from a workload deployed inside the instanode cluster (e.g. an app started by /deploy/new) — the public hostname does not hairpin reliably." },
          "tier": { "type": "string" },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "connections": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "note": { "type": "string" }
        }
      },
      "CacheProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "token": { "type": "string", "format": "uuid" },
          "connection_url": { "type": "string", "description": "redis:// connection string with ACL namespace isolation. Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal redis:// URL routed via instant-redis-proxy. Use this when calling from a workload deployed inside the instanode cluster." },
          "key_prefix": { "type": "string", "description": "All keys must use this prefix for namespace isolation" },
          "tier": { "type": "string" },
          "limits": { "type": "object", "properties": { "memory_mb": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "note": { "type": "string" }
        }
      },
      "NoSQLProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "token": { "type": "string", "format": "uuid" },
          "connection_url": { "type": "string", "description": "mongodb:// connection string scoped to a per-token database. Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal mongodb:// URL routed via instant-mongo-proxy. Use this when calling from a workload deployed inside the instanode cluster." },
          "tier": { "type": "string" },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "connections": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "note": { "type": "string" }
        }
      },
      "QueueProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "token": { "type": "string", "format": "uuid" },
          "connection_url": { "type": "string", "description": "nats:// connection string with per-account subject isolation. Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal nats:// URL routed via instant-nats-proxy. Use this when calling from a workload deployed inside the instanode cluster." },
          "tier": { "type": "string" },
          "limits": { "type": "object" },
          "note": { "type": "string" }
        }
      },
      "WebhookProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "token": { "type": "string", "format": "uuid" },
          "receive_url": { "type": "string", "description": "Public URL that accepts any HTTP method and stores the payload" },
          "tier": { "type": "string" },
          "expires_at": { "type": "string", "format": "date-time" },
          "note": { "type": "string" }
        }
      },
      "StorageProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid", "description": "Resource row id" },
          "token": { "type": "string", "format": "uuid" },
          "name": { "type": "string" },
          "connection_url": { "type": "string", "description": "Public bucket URL scoped to the per-token prefix" },
          "endpoint": { "type": "string", "description": "S3-compatible endpoint host (e.g. minio.instant-data.svc.cluster.local:9000 / r2.instant.dev)" },
          "access_key_id": { "type": "string" },
          "secret_access_key": { "type": "string", "description": "Shown ONCE — store now; rotation requires re-provisioning" },
          "prefix": { "type": "string", "description": "Object-key prefix all writes must use for isolation" },
          "tier": { "type": "string" },
          "env": { "type": "string" },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "expires_in": { "type": "string", "description": "Anonymous-only" } } }
        }
      },
      "DeployItem": {
        "type": "object",
        "description": "Deployment row as returned in the list endpoint. Shape matches DeployResponse.item.",
        "properties": {
          "id": { "type": "string", "format": "uuid" },
          "app_id": { "type": "string", "description": "8-char public identifier used in the URL" },
          "url": { "type": "string" },
          "status": { "type": "string", "enum": ["building", "healthy", "failed", "stopped"] },
          "tier": { "type": "string" },
          "environment": { "type": "string" },
          "env": { "type": "object", "additionalProperties": { "type": "string" } },
          "port": { "type": "integer" },
          "team_id": { "type": "string", "format": "uuid" }
        }
      },
      "ClaimRequest": {
        "type": "object",
        "required": ["jwt", "email"],
        "properties": {
          "jwt": { "type": "string", "description": "Onboarding JWT. Read this directly from the upgrade_jwt field of any anonymous provisioning response — no need to string-parse the upgrade URL." },
          "email": { "type": "string", "format": "email" }
        }
      },
      "ClaimResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "team_id": { "type": "string", "format": "uuid" },
          "user_id": { "type": "string", "format": "uuid" },
          "session_token": { "type": "string", "description": "24h JWT for immediate authenticated API use" },
          "message": { "type": "string" }
        }
      },
      "ClaimPreviewResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "token_valid": { "type": "boolean", "description": "True when the onboarding JWT is well-formed, unexpired, and not yet claimed." },
          "expires_at": { "type": "string", "format": "date-time", "description": "When the onboarding JWT itself expires (typically 7 days from issue). Unrelated to per-resource 24h TTL." },
          "resources": {
            "type": "array",
            "description": "All anonymous resources that this JWT would attach to the new team if /claim were posted.",
            "items": {
              "type": "object",
              "properties": {
                "id": { "type": "string", "format": "uuid" },
                "token": { "type": "string", "format": "uuid" },
                "resource_type": { "type": "string", "enum": ["postgres", "redis", "mongodb", "nats", "webhook", "storage"] },
                "tier": { "type": "string" },
                "status": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" }
              }
            }
          }
        }
      },
      "AuthMeResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "user_id": { "type": "string", "format": "uuid" },
          "team_id": { "type": "string", "format": "uuid" },
          "email": { "type": "string" },
          "tier": { "type": "string", "enum": ["hobby", "pro", "team"] },
          "trial_ends_at": { "type": "string", "format": "date-time", "nullable": true }
        }
      },
      "StackRequest": {
        "type": "object",
        "description": "Multipart form. The 'manifest' field is the YAML instant.yaml text; each service declared under services: must have a matching multipart field named after the service whose content is a gzipped tar archive of that service's build context.",
        "properties": {
          "manifest": { "type": "string", "description": "instant.yaml contents. Example: services:\\n  api:\\n    build: ./api\\n    port: 8080\\n  web:\\n    build: ./web\\n    port: 8080\\n    expose: true\\n    env: { API_URL: service://api }" },
          "<service-name>": { "type": "string", "format": "binary", "description": "One field per service declared in the manifest, named after the service. Value is a gzipped tar archive containing that service's Dockerfile + source. Total request body cap is 200 MB." }
        },
        "required": ["manifest"]
      },
      "StackResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "stack_id": { "type": "string", "description": "Format: stk-<8-char-hex>. Use this for GET /stacks/{slug}." },
          "status": { "type": "string", "enum": ["building", "deploying", "healthy", "failed", "stopped"], "description": "Overall stack status. 'healthy' only when every service is healthy." },
          "tier": { "type": "string" },
          "name": { "type": "string", "description": "Optional human-readable label (from manifest.name)" },
          "services": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "name": { "type": "string", "description": "Service name from the manifest" },
                "status": { "type": "string", "enum": ["building", "deploying", "healthy", "failed", "stopped"] },
                "port": { "type": "integer" },
                "expose": { "type": "boolean" },
                "url": { "type": "string", "description": "Empty unless expose:true. Public HTTPS URL on *.deployment.instanode.dev — only the exposed service gets one; other services are reachable in-cluster only via http://<service-name>:<port>." }
              }
            }
          },
          "expires_in": { "type": "string", "description": "Anonymous stacks have a 24h TTL; authenticated stacks return empty." },
          "note": { "type": "string" }
        }
      },
      "WhoamiResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "user_id": { "type": "string", "format": "uuid" },
          "team_id": { "type": "string", "format": "uuid" },
          "team_name": { "type": "string", "description": "Present only when the team has a non-empty name" },
          "plan_tier": { "type": "string", "enum": ["anonymous", "free", "hobby", "pro", "team"], "description": "Best-effort enrichment from the teams table; absent on DB lookup failure" }
        },
        "required": ["ok", "user_id", "team_id"]
      },
      "ResourceListResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "items": { "type": "array", "items": { "$ref": "#/components/schemas/ResourceItem" } },
          "total": { "type": "integer" }
        }
      },
      "ResourceItem": {
        "type": "object",
        "properties": {
          "id": { "type": "string", "format": "uuid" },
          "token": { "type": "string", "format": "uuid" },
          "resource_type": { "type": "string", "enum": ["postgres", "redis", "mongodb", "nats", "webhook", "storage"] },
          "name": { "type": "string" },
          "env": { "type": "string", "description": "Environment scope (production / staging / dev / ...)" },
          "tier": { "type": "string" },
          "status": { "type": "string" },
          "storage_bytes": { "type": "integer" },
          "expires_at": { "type": "string", "format": "date-time", "nullable": true },
          "created_at": { "type": "string", "format": "date-time" }
        }
      },
      "OAuthProtectedResourceMetadata": {
        "type": "object",
        "properties": {
          "resource": { "type": "string", "description": "Canonical URL of this protected resource" },
          "authorization_servers": { "type": "array", "items": { "type": "string" } },
          "bearer_methods_supported": { "type": "array", "items": { "type": "string", "enum": ["header"] } },
          "resource_documentation": { "type": "string" }
        }
      },
      "VaultPutResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "key": { "type": "string" },
          "env": { "type": "string" },
          "version": { "type": "integer" }
        }
      },
      "VaultGetResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "key": { "type": "string" },
          "env": { "type": "string" },
          "version": { "type": "integer" },
          "value": { "type": "string", "description": "Decrypted plaintext" }
        }
      },
      "DeployRequest": {
        "type": "object",
        "properties": {
          "tarball": { "type": "string", "format": "binary", "description": "gzipped tar archive containing the Dockerfile + source (max 50 MB). When MINIO_ENDPOINT is configured the build context is uploaded to MinIO and kaniko pulls it via the S3 path; otherwise it falls back to a k8s Secret which caps at ~1 MiB." },
          "name": { "type": "string", "description": "Optional human-readable label" },
          "port": { "type": "integer", "description": "Container port (default 8080)" },
          "env": { "type": "string", "description": "Environment scope (production / staging / dev / ...)" },
          "env_vars": { "type": "string", "description": "Optional JSON object of env vars to inject into the deployed pod on the FIRST build — e.g. '{\"DATABASE_URL\":\"postgres://...\",\"REDIS_URL\":\"redis://...\"}'. Avoids the (POST /deploy/new) → (PATCH /env) → (POST /redeploy) round-trip pattern. Values may use 'vault://KEY' refs which resolve at deploy time. Keys starting with underscore are reserved and ignored." },
          "resource_bindings": { "type": "string", "description": "Optional JSON object mapping env-var-name to a resource reference. Values can be either 'family:<family_root_id>' (resolved at submit time to the family member matching the deploy's env — one manifest works across all envs) or a raw resource-token UUID (legacy path; resolves to that specific resource regardless of env). Resolved values are merged into env_vars, with explicit env_vars taking precedence on key collision. Example: '{\"DATABASE_URL\":\"family:7a3f2c91-...\",\"REDIS_URL\":\"family:9bd5f3e0-...\"}'." },
          "private": { "type": "string", "description": "Optional flag (\"true\" / \"1\" / \"yes\") that turns this into a private deploy. When set, the resulting Ingress carries an nginx whitelist-source-range annotation built from allowed_ips. Pro / Team / Growth only — hobby/anonymous/free return 402 with agent_action: \"Tell the user private deploys require Pro tier. Upgrade at https://instanode.dev/pricing — takes 30 seconds.\"" },
          "allowed_ips": { "type": "string", "description": "Comma-separated list of CIDRs or IP literals (e.g. \"1.2.3.4,10.0.0.0/8,2001:db8::/32\"). Required when private=true; max 32 entries. Each entry is validated via Go's net.ParseCIDR / net.ParseIP — invalid entries surface in the 400 message so an agent can fix the literal that broke. Larger allowlists belong in CF Access or a real VPN, not an nginx annotation." },
          "notify_webhook": { "type": "string", "description": "Optional https:// URL fired by POST when the deploy reaches a terminal state (status='healthy' or 'failed'). Lets callers subscribe instead of polling GET /deploy/:id. Rejected with 400 + agent_action if the URL is not https, the hostname is unresolvable, or resolves to a private/loopback/link-local/CGNAT IP (SSRF protection). Payload shape: { event: 'deploy.healthy' | 'deploy.failed', deploy_id, app_id, url, commit_id, build_time, duration_s, error_message? }. 2xx → notify_state='sent'; 4xx → 'failed' (no retry — user URL is broken); 5xx/network → up to 3 retries, then 'failed'." },
          "notify_webhook_secret": { "type": "string", "description": "Optional HMAC-SHA256 signing key. When set, every dispatch includes an X-InstaNode-Signature: sha256=<hex(hmac(secret, body))> header. Stored AES-256-GCM encrypted; plaintext never leaves the request. Omit to dispatch without a signature header." }
        },
        "required": ["tarball"]
      },
      "DeployResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "item": {
            "type": "object",
            "properties": {
              "id": { "type": "string", "format": "uuid" },
              "app_id": { "type": "string", "description": "8-char public identifier used in the URL" },
              "url": { "type": "string", "description": "Live HTTPS URL (set once status=healthy)" },
              "status": { "type": "string", "enum": ["building", "healthy", "failed", "stopped"] },
              "tier": { "type": "string" },
              "environment": { "type": "string", "description": "Env scope (production/staging/dev). Note: 'env' on this object is the env_vars map, not the scope." },
              "env": { "type": "object", "additionalProperties": { "type": "string" }, "description": "Env vars map — vault://KEY references resolve at deploy time" },
              "port": { "type": "integer" },
              "private": { "type": "boolean", "description": "True when the Ingress is locked down via nginx whitelist-source-range. Pro / Team / Growth feature." },
              "allowed_ips": { "type": "array", "items": { "type": "string" }, "description": "CIDRs / IPs whitelisted on the Ingress when private=true. Empty array on a public deploy." },
              "notify_webhook": { "type": "string", "description": "Echoed-back webhook URL when set on POST /deploy/new. Empty string when no webhook was configured for this deployment." },
              "notify_state": { "type": "string", "enum": ["unset", "pending", "sent", "failed"], "description": "Lifecycle of the deploy-notify webhook. 'unset' = no URL configured. 'pending' = URL configured, awaiting terminal state (or worker dispatch). 'sent' = 2xx received. 'failed' = 4xx received OR 5xx/network exhausted retries." },
              "notify_attempts": { "type": "integer", "description": "Count of dispatch attempts made by the worker. Present only when notify_webhook is set. 5xx/network errors retry up to 3 times; 4xx is permanent." },
              "notify_secret_set": { "type": "boolean", "description": "True when an HMAC signing secret was supplied at create time. Present only when notify_webhook is set. The plaintext secret is never returned." },
              "team_id": { "type": "string", "format": "uuid" }
            }
          },
          "note": { "type": "string" }
        }
      },
      "InvitationResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid" },
          "team_id": { "type": "string", "format": "uuid" },
          "email": { "type": "string", "format": "email" },
          "role": { "type": "string", "enum": ["admin", "developer", "viewer", "member"] },
          "expires_at": { "type": "string", "format": "date-time" }
        }
      },
      "BillingPaymentMethod": {
        "type": "object",
        "description": "Payment method on file. null when the team has no Razorpay subscription, or has a subscription but no successful charge yet.",
        "properties": {
          "type": { "type": "string", "enum": ["card", "upi", "netbanking", "wallet"], "description": "Razorpay payment method type" },
          "brand": { "type": ["string", "null"], "description": "Card network (e.g. 'visa', 'mastercard') — present only for type=card" },
          "last4": { "type": ["string", "null"], "description": "Last 4 digits — present only for type=card" },
          "vpa": { "type": ["string", "null"], "description": "UPI VPA (e.g. 'name@hdfc') — present only for type=upi" }
        },
        "required": ["type"]
      },
      "BillingStateResponse": {
        "type": "object",
        "description": "Aggregated billing state served by GET /api/v1/billing.",
        "properties": {
          "ok": { "type": "boolean" },
          "tier": { "type": "string", "enum": ["anonymous", "free", "hobby", "pro", "team"], "description": "Current plan tier from the team record" },
          "subscription_status": { "type": "string", "enum": ["none", "active", "cancelled", "trial"], "description": "'none' when no Razorpay subscription exists; 'trial' when trial_ends_at is in the future; 'cancelled' when Razorpay reports cancelled / completed / expired or cancel_at_cycle_end=true; 'active' otherwise" },
          "next_renewal_at": { "type": ["string", "null"], "format": "date-time", "description": "ISO timestamp for next renewal (Razorpay current_end). null when no active subscription" },
          "amount_inr": { "type": ["integer", "null"], "description": "Monthly subscription amount in INR rupees (not paise). Sourced from the most recent paid invoice when available; falls back to the tier-derived price for brand-new subscriptions. null when no subscription on file" },
          "payment_method": { "oneOf": [{ "$ref": "#/components/schemas/BillingPaymentMethod" }, { "type": "null" }] },
          "billing_email": { "type": "string", "description": "Owner's email — best-effort; empty string when no owner user row exists" },
          "razorpay_subscription_id": { "type": ["string", "null"], "description": "Razorpay subscription id (sub_xxx). null until the team starts a checkout flow. Useful for support tickets" },
          "razorpay_customer_id": { "type": ["string", "null"], "description": "Razorpay customer id. Reserved for future use — always null today (Razorpay subscriptions don't require a pre-created customer record)" }
        },
        "required": ["ok", "tier", "subscription_status", "billing_email"]
      },
      "BillingUsageResponse": {
        "type": "object",
        "description": "Cached aggregate served by GET /api/v1/billing/usage. Replaces the prior client-side summation across /resources. Shared payload type for the cache layer (Redis JSON) and the public HTTP response, so a deploy-time shape change naturally invalidates older cache entries. -1 in any limit_bytes / limit field means 'unlimited' (matches the plans.yaml convention).",
        "properties": {
          "ok":                { "type": "boolean", "enum": [true] },
          "freshness_seconds": { "type": "integer", "description": "Cache TTL window in seconds. Today 30 — matches the §13 freshness target and the Cache-Control max-age. Tune in one place: this field follows the server-side const." },
          "as_of":             { "type": "string", "format": "date-time", "description": "When the aggregation was computed. Useful for stale-while-revalidate displays and for debugging cache-vs-live discrepancies." },
          "usage": {
            "type": "object",
            "description": "Per-service metrics. Storage services carry { bytes, limit_bytes }. Count services carry { count, limit }. Fields are omitempty so the irrelevant one for each kind stays off the wire.",
            "properties": {
              "postgres":    { "$ref": "#/components/schemas/UsageMetric" },
              "redis":       { "$ref": "#/components/schemas/UsageMetric" },
              "mongodb":     { "$ref": "#/components/schemas/UsageMetric" },
              "deployments": { "$ref": "#/components/schemas/UsageMetric" },
              "webhooks":    { "$ref": "#/components/schemas/UsageMetric" },
              "vault":       { "$ref": "#/components/schemas/UsageMetric" },
              "members":     { "$ref": "#/components/schemas/UsageMetric" }
            }
          }
        },
        "required": ["ok", "freshness_seconds", "as_of", "usage"]
      },
      "UsageMetric": {
        "type": "object",
        "description": "One service's slice of the usage aggregate. Either bytes/limit_bytes (storage services) or count/limit (deployments, webhooks, vault, members). -1 in a limit field means 'unlimited'.",
        "properties": {
          "bytes":       { "type": "integer", "format": "int64", "description": "Current storage usage in bytes. Present on postgres/redis/mongodb." },
          "limit_bytes": { "type": "integer", "format": "int64", "description": "Storage cap in bytes (plans.yaml storage_mb × 1024 × 1024). -1 = unlimited." },
          "count":       { "type": "integer", "description": "Current count. Present on deployments/webhooks/vault/members." },
          "limit":       { "type": "integer", "description": "Count cap from plans.yaml. -1 = unlimited." }
        }
      },
      "TeamSummaryResponse": {
        "type": "object",
        "description": "Cached aggregate served by GET /api/v1/team/summary. Powers the dashboard sidebar's SidebarUpgradeCard and per-nav-row badge numbers. Eventual-consistent on purpose (5-min window) — do NOT use for quota gate decisions. Shared payload type for the Redis cache and the public response; a JSON shape change naturally invalidates older cache entries.",
        "properties": {
          "ok":                { "type": "boolean", "enum": [true] },
          "freshness_seconds": { "type": "integer", "description": "Cache TTL window in seconds. Today 300 — matches the server-side const and the Cache-Control max-age." },
          "as_of":             { "type": "string", "format": "date-time", "description": "When the aggregation was computed." },
          "tier":              { "type": "string", "description": "Current plan tier from the team record. Mirrored here so the sidebar doesn't need a second /billing fetch just to render the upgrade card.", "enum": ["anonymous", "free", "hobby", "pro", "team"] },
          "counts": {
            "type": "object",
            "description": "Per-area counts. resources.total is the sum of every typed bucket plus 'other' — saves the dashboard from re-adding.",
            "properties": {
              "resources":   { "$ref": "#/components/schemas/TeamSummaryResourceCounts" },
              "deployments": { "type": "integer", "description": "Active deployments. Excludes status IN ('deleted','stopped') — matches the dashboard's 'active deployments' framing." },
              "members":     { "type": "integer", "description": "Team member count (including the caller)." },
              "vault_keys":  { "type": "integer", "description": "Total vault entries across every env this team owns." }
            },
            "required": ["resources", "deployments", "members", "vault_keys"]
          }
        },
        "required": ["ok", "freshness_seconds", "as_of", "tier", "counts"]
      },
      "TeamSummaryResourceCounts": {
        "type": "object",
        "description": "Per-type breakdown of active resources for one team. Produced by a single SELECT resource_type, COUNT(*) GROUP BY resource_type — cheaper than six separate COUNTs. Unknown resource_type rows fold into 'other' so the total stays accurate when a freshly-shipped service hasn't gotten a typed bucket yet.",
        "properties": {
          "total":    { "type": "integer", "description": "Sum across every bucket (typed + other)." },
          "postgres": { "type": "integer" },
          "redis":    { "type": "integer" },
          "mongodb":  { "type": "integer" },
          "webhook":  { "type": "integer" },
          "queue":    { "type": "integer" },
          "storage":  { "type": "integer" },
          "other":    { "type": "integer", "description": "Catch-all for resource_type values this build doesn't recognise (e.g. a service shipped after the dashboard's TS types were generated). Always included in total." }
        },
        "required": ["total"]
      },
      "ErrorResponse": {
        "type": "object",
        "description": "Canonical JSON shape returned by every 4xx/5xx response. agent_action and upgrade_url are populated for error codes where the calling agent benefits from user-facing copy or a remediation link (quota walls, invalid tokens, expired resources, permission denied, tier gates). Codes without remediation guidance (transient db_error, list_failed, stream_failed, etc.) omit these fields. Backward-compatible: omitempty fields are absent on the wire when empty so existing clients that ignored agent_action/upgrade_url see no change.",
        "properties": {
          "ok": { "type": "boolean", "enum": [false], "description": "Always false on error responses" },
          "error": { "type": "string", "description": "Stable machine-readable error code (e.g. 'quota_exceeded', 'invalid_token', 'forbidden', 'storage_limit_reached'). Programmatic clients should branch on this." },
          "message": { "type": "string", "description": "Human-readable explanation of the error. May contain tier names, resource IDs, or other context. Not stable — use the 'error' code for programmatic decisions." },
          "agent_action": { "type": "string", "description": "Optional. A sentence the calling agent should surface verbatim to the human user — e.g. 'Tell the user they've hit the hobby tier storage limit (500MB). Have them upgrade at https://instanode.dev/pricing to provision more storage.' Present on quota walls, invalid-token errors, permission-denied errors, expired-resource errors, and tier-gate errors. Absent on transient infra failures where the right response is silent retry." },
          "upgrade_url": { "type": "string", "format": "uri", "description": "Optional. Where the user can resolve the error — typically the pricing/upgrade page for quota walls and the login page for token errors. Present whenever following the URL would clear the error." }
        },
        "required": ["ok", "error", "message"]
      }
    }
  }
}`
