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
    "/claim": {
      "post": {
        "summary": "Claim anonymous resources to a permanent account",
        "description": "Converts anonymous resources to hobby tier (no expiry). Returns a session_token for immediate authenticated API use.",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimRequest" } } } },
        "responses": {
          "201": { "description": "Account created, resources transferred", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimResponse" } } } },
          "409": { "description": "JWT already used" }
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
    }
  },
  "components": {
    "securitySchemes": {
      "bearerAuth": { "type": "http", "scheme": "bearer", "description": "Session JWT from /claim or /auth/github or /auth/google" }
    },
    "schemas": {
      "HealthResponse": {
        "type": "object",
        "properties": { "ok": { "type": "boolean" }, "service": { "type": "string" } }
      },
      "ProvisionRequest": {
        "type": "object",
        "properties": { "name": { "type": "string", "description": "Optional human-readable label (max 120 chars)" } }
      },
      "DBProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "token": { "type": "string", "format": "uuid" },
          "connection_url": { "type": "string", "description": "postgres:// connection string with pgvector pre-installed" },
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
          "connection_url": { "type": "string", "description": "redis:// connection string with ACL namespace isolation" },
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
          "connection_url": { "type": "string", "description": "mongodb:// connection string scoped to a per-token database" },
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
          "connection_url": { "type": "string", "description": "nats:// connection string with per-account subject isolation" },
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
          "jwt": { "type": "string", "description": "Onboarding JWT from the note field upgrade URL (?t=...)" },
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
          "tier": { "type": "string" },
          "status": { "type": "string" },
          "storage_bytes": { "type": "integer" },
          "expires_at": { "type": "string", "format": "date-time", "nullable": true },
          "created_at": { "type": "string", "format": "date-time" }
        }
      }
    }
  }
}`
