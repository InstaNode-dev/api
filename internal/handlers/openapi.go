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
          "201": { "description": "Database provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DBProvisionResponse" } } } }
        }
      }
    },
    "/cache/new": {
      "post": {
        "summary": "Provision a Redis cache",
        "description": "Returns a real redis:// connection string with ACL namespace isolation. Anonymous tier: 5MB memory, 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Cache provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CacheProvisionResponse" } } } }
        }
      }
    },
    "/nosql/new": {
      "post": {
        "summary": "Provision a MongoDB database",
        "description": "Returns a real mongodb:// connection string scoped to a per-token database. Anonymous tier: 5MB, 2 connections, 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "MongoDB database provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/NoSQLProvisionResponse" } } } }
        }
      }
    },
    "/queue/new": {
      "post": {
        "summary": "Provision a NATS JetStream queue",
        "description": "Returns a real nats:// connection string with per-account subject isolation. Anonymous tier: 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Queue provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/QueueProvisionResponse" } } } }
        }
      }
    },
    "/webhook/new": {
      "post": {
        "summary": "Provision a webhook receiver",
        "description": "Returns a public receive_url that accepts any HTTP method and stores the payload (headers + body) in Redis for 24h.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Webhook receiver provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/WebhookProvisionResponse" } } } }
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
          "plan_tier": { "type": "string", "enum": ["anonymous", "hobby", "pro", "team"], "description": "Best-effort enrichment from the teams table; absent on DB lookup failure" }
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
          "tier": { "type": "string", "enum": ["anonymous", "hobby", "pro", "team"], "description": "Current plan tier from the team record" },
          "subscription_status": { "type": "string", "enum": ["none", "active", "cancelled", "trial"], "description": "'none' when no Razorpay subscription exists; 'trial' when trial_ends_at is in the future; 'cancelled' when Razorpay reports cancelled / completed / expired or cancel_at_cycle_end=true; 'active' otherwise" },
          "next_renewal_at": { "type": ["string", "null"], "format": "date-time", "description": "ISO timestamp for next renewal (Razorpay current_end). null when no active subscription" },
          "amount_inr": { "type": ["integer", "null"], "description": "Monthly subscription amount in INR rupees (not paise). Sourced from the most recent paid invoice when available; falls back to the tier-derived price for brand-new subscriptions. null when no subscription on file" },
          "payment_method": { "oneOf": [{ "$ref": "#/components/schemas/BillingPaymentMethod" }, { "type": "null" }] },
          "billing_email": { "type": "string", "description": "Owner's email — best-effort; empty string when no owner user row exists" },
          "razorpay_subscription_id": { "type": ["string", "null"], "description": "Razorpay subscription id (sub_xxx). null until the team starts a checkout flow. Useful for support tickets" },
          "razorpay_customer_id": { "type": ["string", "null"], "description": "Razorpay customer id. Reserved for future use — always null today (Razorpay subscriptions don't require a pre-created customer record)" }
        },
        "required": ["ok", "tier", "subscription_status", "billing_email"]
      }
    }
  }
}`
