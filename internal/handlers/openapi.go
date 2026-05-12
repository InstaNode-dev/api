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
          "402": { "description": "Quota exceeded or feature requires upgrade. Includes agent_action with copy the calling agent can show the user, plus upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
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
          "402": { "description": "Quota exceeded or feature requires upgrade. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
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
          "402": { "description": "Quota exceeded or feature requires upgrade. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
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
          "402": { "description": "Quota exceeded or feature requires upgrade. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
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
          "402": { "description": "Quota exceeded. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
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
          "402": { "description": "Upgrade required — team is not on pro/team/growth. Response carries upgrade_url + agent_action." }
        }
      }
    },
    "/deploy/new": {
      "post": {
        "summary": "Deploy a container application",
        "description": "Builds a Docker image from the supplied tarball (or pulls an existing image) and rolls it out behind a public HTTPS URL on *.deployment.instanode.dev. Env vars may use the value 'vault://KEY' to reference a secret stored via /api/v1/vault — the plaintext is resolved at deploy time and never persisted in plaintext.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "multipart/form-data": { "schema": { "$ref": "#/components/schemas/DeployRequest" } } } },
        "responses": {
          "202": { "description": "Deployment accepted, building", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "401": { "description": "Unauthorized" },
          "503": { "description": "Compute backend unavailable or service disabled" }
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
        "responses": { "200": { "description": "Resource deleted" }, "403": { "description": "Forbidden" } }
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
        "description": "Mints a Razorpay subscription for the requested plan (hobby or pro) tied to the authenticated team. The dashboard redirects the user to the returned short_url to complete payment; on success Razorpay fires subscription.activated to /razorpay/webhook and the team's plan_tier is elevated atomically. The Team tier currently returns 400 tier_unavailable — only ops can set it via /internal/set-tier.",
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
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Stack list", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "items": { "type": "array", "items": { "type": "object", "properties": { "stack_id": { "type": "string", "description": "Slug (same as path /stacks/{slug})" }, "name": { "type": "string" }, "status": { "type": "string" }, "tier": { "type": "string" }, "namespace": { "type": "string" }, "created_at": { "type": "string", "format": "date-time" } } } }, "total": { "type": "integer" } } } } } },
          "401": { "description": "Unauthorized" }
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
        "properties": { "ok": { "type": "boolean" }, "service": { "type": "string" } }
      },
      "ProvisionRequest": {
        "type": "object",
        "properties": {
          "name": { "type": "string", "description": "Optional human-readable label (max 120 chars)" },
          "env": { "type": "string", "description": "Optional environment scope (production / staging / dev / ...). Anonymous tier is always 'production'.", "default": "production" }
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
          "env_vars": { "type": "string", "description": "Optional JSON object of env vars to inject into the deployed pod on the FIRST build — e.g. '{\"DATABASE_URL\":\"postgres://...\",\"REDIS_URL\":\"redis://...\"}'. Avoids the (POST /deploy/new) → (PATCH /env) → (POST /redeploy) round-trip pattern. Values may use 'vault://KEY' refs which resolve at deploy time. Keys starting with underscore are reserved and ignored." }
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
