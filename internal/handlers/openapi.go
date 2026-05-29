package handlers

// openapi.go — serves GET /openapi.json with an OpenAPI 3.1 description of the live API.

import (
	"strings"
	"sync"

	"github.com/gofiber/fiber/v2"
)

// openAPIEnvironment is set by router wiring at startup. When the value is
// not "development", ServeOpenAPI strips the /internal/set-tier path entry
// from the served spec — that route is only registered in development
// (router.go), so leaking it in the production spec lies to agents and
// advertises an internal privilege-escalation surface.
//
// T19 P0-1 fix (BugHunt 2026-05-20).
var openAPIEnvironment = "production"

// openAPISpecForEnv caches the per-environment rendered spec so repeat
// requests don't re-slice the string.
var (
	openAPISpecOnce sync.Once
	openAPISpecProd string
)

// SetOpenAPIEnvironment wires the runtime ENVIRONMENT into ServeOpenAPI.
// Called from router.New at startup.
func SetOpenAPIEnvironment(env string) {
	if env != "" {
		openAPIEnvironment = env
	}
}

// stripInternalSetTierPath removes the "/internal/set-tier": { ... } block
// from the spec. The block is a single, self-contained JSON object value
// (no nested "/internal/set-tier" anywhere else in the spec — verified by
// the registry-iterating test below). We scan for the literal key and
// walk balanced braces until the closing one, then trim a trailing comma.
//
// This is text surgery on a const JSON document. It is cheap (runs once
// per process via sync.Once) and avoids the larger refactor of moving
// the spec into a generated struct. If the surgery ever fails (the key
// is absent / brace mismatch), we fall back to the unmodified spec — a
// dev-route in the prod spec is the documented bug, not a regression.
func stripInternalSetTierPath(spec string) string {
	const key = `"/internal/set-tier"`
	keyIdx := strings.Index(spec, key)
	if keyIdx < 0 {
		return spec
	}
	// Find the colon after the key, then the opening brace.
	colon := strings.Index(spec[keyIdx:], ":")
	if colon < 0 {
		return spec
	}
	openIdx := strings.Index(spec[keyIdx+colon:], "{")
	if openIdx < 0 {
		return spec
	}
	openIdx += keyIdx + colon
	// Walk balanced braces, ignoring those inside double-quoted strings.
	depth := 0
	inStr := false
	esc := false
	closeIdx := -1
	for i := openIdx; i < len(spec); i++ {
		ch := spec[i]
		if esc {
			esc = false
			continue
		}
		if inStr {
			if ch == '\\' {
				esc = true
				continue
			}
			if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				closeIdx = i
			}
		}
		if closeIdx >= 0 {
			break
		}
	}
	if closeIdx < 0 {
		return spec
	}
	end := closeIdx + 1
	// Walk past whitespace; eat a trailing comma if present so the
	// "paths" object stays valid JSON. If no comma, we may be the
	// last entry — also eat the *preceding* comma instead.
	for end < len(spec) && (spec[end] == ' ' || spec[end] == '\t' || spec[end] == '\n' || spec[end] == '\r') {
		end++
	}
	if end < len(spec) && spec[end] == ',' {
		end++
		return spec[:keyIdx] + spec[end:]
	}
	// Last entry: trim back to the preceding comma so we don't leave
	// a dangling one before the closing `}` of "paths".
	start := keyIdx
	for start > 0 {
		ch := spec[start-1]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			start--
			continue
		}
		if ch == ',' {
			start--
		}
		break
	}
	return spec[:start] + spec[end:]
}

// ServeOpenAPI handles GET /openapi.json.
func ServeOpenAPI(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json; charset=utf-8")
	if openAPIEnvironment == "development" {
		return c.SendString(openAPISpec)
	}
	openAPISpecOnce.Do(func() {
		openAPISpecProd = stripInternalSetTierPath(openAPISpec)
	})
	return c.SendString(openAPISpecProd)
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
    "title": "InstaNode API",
    "version": "1.0.0",
    "description": "Zero-friction developer infrastructure. Provision real databases, caches, and queues with a single HTTP call — no account, no Docker, no setup.\n\n## Idempotency\n\nEvery POST endpoint that creates a resource is idempotent. Two layered protections cover every retry pattern:\n\n1. Explicit Idempotency-Key header (Stripe-shape, 24h TTL). Pass the same opaque key on each retry of a logical operation and the server replays the first response verbatim. Reusing a key with a different body returns 409.\n2. Body-fingerprint fallback (120s TTL). When the header is absent, the server synthesises a key from sha256(scope, route, canonical-body) and dedups identical retries inside a 120s window. Absorbs double-clicks, mobile double-taps, agent retries on transient 5xx, and reverse-proxy retries on network blips. Use the explicit header for true exactly-once across longer windows.\n\nEvery response from a create endpoint carries:\n- X-Idempotency-Source: explicit | fingerprint | miss — which dedup path matched (explicit = caller passed an Idempotency-Key; fingerprint = the body-fingerprint cache replayed; miss = handler ran fresh).\n- X-Idempotent-Replay: true — present only when the response was served from the cache (either path).\n\n## Rate limit (applies to every route)\n\nA global per-IP rate limit (100 req/min) is applied to EVERY documented endpoint by the router middleware. Exceeding it returns 429 with the standard ErrorResponse envelope (error=rate_limited), a Retry-After HTTP header, and retry_after_seconds in the JSON body. The per-route response maps below may omit 429 for brevity; the canonical 429 shape is documented under components.responses.TooManyRequests and applies to every path. T19 P1-1 (BugHunt 2026-05-20).\n\n## Payload size (applies to every route)\n\nFiber's global BodyLimit is set to 50 MiB — only /deploy/new and /stacks/new (multipart tarballs) and /webhooks/github/* (push payloads) approach that cap; JSON endpoints are bounded to sub-KB bodies by the per-handler shape. Oversized requests return 413 payload_too_large with the standard JSON ErrorResponse envelope (NOT the upstream nginx HTML 502 the older shape returned — T19 P1-2). The canonical 413 shape is documented under components.responses.PayloadTooLarge.\n\n## Security headers (applies to every response)\n\nEvery response from EVERY route — including liveness/readiness probes, OpenAPI document fetch, 4xx error envelopes, 5xx error envelopes, and 404/405 Fiber-default responses — carries the following defense-in-depth response headers, set by the SecurityHeaders middleware ahead of RequestID in the router middleware chain (task #311 wave-3 chaos-verify redo):\n\n- Strict-Transport-Security: max-age=63072000; includeSubDomains — production only (omitted on ENVIRONMENT=development so local http://localhost:8080 doesn't poison the host's HSTS cache). 2-year max-age, includeSubDomains for *.api.instanode.dev.\n- X-Content-Type-Options: nosniff — disables MIME sniffing.\n- X-Frame-Options: SAMEORIGIN — clickjacking defense.\n- Referrer-Policy: strict-origin-when-cross-origin — prevents URL-token leakage across origin downgrades.\n- Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=() — denies powerful browser APIs.\n- Cross-Origin-Resource-Policy: same-origin — blocks no-cors cross-origin fetches.\n\nThese headers are not enumerated in each per-route responses block to keep the spec readable; they apply globally. Coverage test: TestSecurityHeaders_AllEndpoints_AllHeaders_Prod (internal/handlers/security_headers_test.go) iterates 5 representative endpoints (healthz, readyz, openapi.json, db/new, claim) and asserts all 6 headers land on every response."
  },
  "servers": [{ "url": "https://api.instanode.dev", "description": "Production" }],
  "paths": {
    "/livez": {
      "get": {
        "summary": "Liveness probe",
        "description": "Returns 200 unconditionally with body {\"alive\":true}. NO database check, NO migration check, NO auth. Exists purely to distinguish 'process alive' from 'process ready' for k8s liveness/readiness probe split. Mirrored on provisioner-sidecar (:8092), worker-healthz (:8091), and migrator (:8090).",
        "responses": {
          "200": { "description": "Process is alive", "content": { "application/json": { "schema": { "type": "object", "properties": { "alive": { "type": "boolean", "const": true } }, "required": ["alive"] } } } }
        }
      }
    },
    "/healthz": {
      "get": {
        "summary": "Health check (shallow liveness)",
        "description": "Process-level liveness — returns 200 if the api binary is up and can ping its primary platform DB. Wired to Kubernetes livenessProbe. Use /readyz for deep upstream-reachability checks.",
        "responses": {
          "200": { "description": "Service is healthy", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HealthResponse" } } } }
        }
      }
    },
    "/readyz": {
      "get": {
        "summary": "Deep readiness check (multi-component)",
        "description": "Runs component-by-component readiness checks against every critical upstream the api depends on (platform_db, customer_db, provisioner_grpc, brevo, razorpay, redis, do_spaces). Each check has a 10-15s cache to avoid upstream spam. Wired to Kubernetes readinessProbe — a degraded pod is removed from the Service endpoint list (but not restarted). Critical-failed components (platform_db, provisioner_grpc) → 503; everything else → 200 with overall=degraded.",
        "responses": {
          "200": { "description": "Service is ready (overall=ok) or degraded but still serving (overall=degraded). The body's checks[] enumerates per-component status.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ReadinessResponse" } } } },
          "503": { "description": "Critical component failed — pod removed from Service rotation by kubelet. The body's checks[] still enumerates per-component status so an operator can diagnose.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ReadinessResponse" } } } }
        }
      }
    },
    "/db/new": {
      "post": {
        "summary": "Provision a Postgres database",
        "description": "Returns a real postgres:// connection string with pgvector pre-installed. Anonymous tier: 10MB, 2 connections, 24h TTL.\n\nSupports Stripe/AWS-style idempotency via the optional Idempotency-Key request header — see the parameter description below.",
        "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars) that makes this POST safe to retry. The first response is cached for 24h; subsequent calls carrying the same key return the cached response verbatim with X-Idempotent-Replay: true. Reusing a key with a different body returns 409. Replays do NOT consume rate-limit budget — the per-fingerprint daily counter is refunded on every cache hit so an agent retrying transient 5xx with the same key gets the documented replay (FINDING API-1, 2026-05-29). The FIRST call still pays the rate-limit cost; replays are refunded. The per-fingerprint provision-dedup cap (5 fresh resources/day, anti-abuse) is unchanged." }],
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Database provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DBProvisionResponse" } } } },
          "400": { "description": "Bad request — one of: name_required (name field missing/empty), invalid_name (name fails the 1-64-char start-alnum pattern or contains invalid UTF-8), invalid_body (request body is not valid JSON), invalid_env, or an invalid Idempotency-Key (empty, >255 chars, or non-ASCII-printable).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim — anonymous fingerprint that previously provisioned must claim with email before re-provisioning). Includes agent_action with copy the calling agent can show the user, plus upgrade_url and (for the recycle gate) claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "409": { "description": "Idempotency-Key already used with a different request body (error=idempotency_key_conflict). The agent reused a key for a logically different call — generate a new key.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/vector/new": {
      "post": {
        "summary": "Provision a pgvector-enabled Postgres database",
        "description": "Returns a real postgres:// connection string with the pgvector extension pre-installed. Use for embedding stores (OpenAI ada-002 = 1536 dims, text-embedding-3-small = 1536, text-embedding-3-large = 3072). The optional dimensions field is a documentation hint — pgvector lets you pick per-column dimensions at table-create time, so the server stores the declared default but does not enforce it. Tier limits mirror Postgres exactly because the underlying storage IS Postgres. Anonymous tier: 10MB, 2 connections, 24h TTL.",
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/VectorProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Vector database provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/VectorProvisionResponse" } } } },
          "400": { "description": "Bad request — one of: invalid dimensions (must be 1..16000), invalid env, invalid_name (name contains invalid UTF-8), or invalid_body (request body is not valid JSON).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/cache/new": {
      "post": {
        "summary": "Provision a Redis cache",
        "description": "Returns a real redis:// connection string with ACL namespace isolation. Anonymous tier: 5MB memory, 24h TTL.\n\nSupports Stripe/AWS-style idempotency via the optional Idempotency-Key request header.",
        "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars). First response cached for 24h; replays return the cached body with X-Idempotent-Replay: true. Reusing the key with a different body returns 409." }],
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Cache provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CacheProvisionResponse" } } } },
          "400": { "description": "Bad request — one of: name_required (name field missing/empty), invalid_name (name fails the 1-64-char start-alnum pattern or contains invalid UTF-8), invalid_body (request body is not valid JSON), invalid_env, or an invalid Idempotency-Key (empty, >255 chars, or non-ASCII-printable).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "409": { "description": "Idempotency-Key already used with a different body (error=idempotency_key_conflict).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/nosql/new": {
      "post": {
        "summary": "Provision a MongoDB database",
        "description": "Returns a real mongodb:// connection string scoped to a per-token database. Anonymous tier: 5MB, 2 connections, 24h TTL.\n\nSupports Stripe/AWS-style idempotency via the optional Idempotency-Key request header.",
        "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars). First response cached for 24h; replays return the cached body with X-Idempotent-Replay: true. Reusing the key with a different body returns 409." }],
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "MongoDB database provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/NoSQLProvisionResponse" } } } },
          "400": { "description": "Bad request — one of: name_required (name field missing/empty), invalid_name (name fails the 1-64-char start-alnum pattern or contains invalid UTF-8), invalid_body (request body is not valid JSON), invalid_env, or an invalid Idempotency-Key (empty, >255 chars, or non-ASCII-printable).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "409": { "description": "Idempotency-Key already used with a different body (error=idempotency_key_conflict).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/queue/new": {
      "post": {
        "summary": "Provision a NATS JetStream queue",
        "description": "Returns a real nats:// connection string with per-account subject isolation. Anonymous tier: 24h TTL.\n\nSupports Stripe/AWS-style idempotency via the optional Idempotency-Key request header.",
        "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars). First response cached for 24h; replays return the cached body with X-Idempotent-Replay: true. Reusing the key with a different body returns 409." }],
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Queue provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/QueueProvisionResponse" } } } },
          "400": { "description": "Bad request — one of: name_required (name field missing/empty), invalid_name (name fails the 1-64-char start-alnum pattern or contains invalid UTF-8), invalid_body (request body is not valid JSON), invalid_env, or an invalid Idempotency-Key (empty, >255 chars, or non-ASCII-printable).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "402": { "description": "Quota exceeded, feature requires upgrade, OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "409": { "description": "Idempotency-Key already used with a different body (error=idempotency_key_conflict).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/webhook/new": {
      "post": {
        "summary": "Provision a webhook receiver",
        "description": "Returns a public receive_url that accepts any HTTP method and stores the payload (headers + body) in Redis for 24h.\n\nSupports Stripe/AWS-style idempotency via the optional Idempotency-Key request header.",
        "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars). First response cached for 24h; replays return the cached body with X-Idempotent-Replay: true. Reusing the key with a different body returns 409." }],
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Webhook receiver provisioned", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/WebhookProvisionResponse" } } } },
          "400": { "description": "Bad request — one of: name_required (name field missing/empty), invalid_name (name fails the 1-64-char start-alnum pattern or contains invalid UTF-8), invalid_body (request body is not valid JSON), invalid_env, or an invalid Idempotency-Key (empty, >255 chars, or non-ASCII-printable).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "402": { "description": "Quota exceeded OR free-tier recycle requires claim (error=free_tier_recycle_requires_claim). Includes agent_action and upgrade_url; recycle gate also returns claim_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "409": { "description": "Idempotency-Key already used with a different body (error=idempotency_key_conflict).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Provisioning failed (transient). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/webhook/receive/{token}": {
      "post": {
        "summary": "Receive a webhook payload",
        "description": "Accepts ANY HTTP method (GET/POST/PUT/DELETE) so verification-challenge flows like Slack URL verify reach the handler. Stores method, path, query string, all duplicate headers (sensitive ones — Authorization, Cookie, X-Api-Key, X-Auth-Token, Proxy-Authorization, Set-Cookie — are redacted to '[REDACTED]'), and the raw body (capped at 1 MiB) in Redis with a tier-based TTL. The ring buffer per token is capped at the tier's webhook_requests_stored limit; the 101st payload evicts the oldest and sets response header X-Webhook-Rotated: <token>. If the resource has an HMAC secret set, every request must carry a valid X-Hub-Signature-256 header (sha256=<hex of HMAC-SHA256(secret, body)>) or returns 401. Senders may pass X-Idempotency-Key for safe retries — the same key replays the original response without writing a duplicate entry.",
        "parameters": [
          { "name": "token", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } },
          { "name": "X-Hub-Signature-256", "in": "header", "required": false, "schema": { "type": "string" }, "description": "sha256=<hex> — required only when the webhook resource has hmac_secret configured." },
          { "name": "X-Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string" }, "description": "Opaque key (e.g. from Stripe's Idempotency-Key); two requests with the same key replay the original response." }
        ],
        "requestBody": { "description": "Raw body of any content type — the handler stores the bytes verbatim and does not parse by Content-Type. The listed types are the common cases; the wildcard entry documents that any media type is accepted.", "content": { "application/json": {}, "application/x-www-form-urlencoded": {}, "text/plain": {}, "application/octet-stream": {}, "*/*": {} } },
        "responses": {
          "200": { "description": "Payload stored", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "id": { "type": "string" } } } } } },
          "401": { "description": "HMAC signature missing or invalid (when hmac_secret is set on the resource).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "404": { "description": "Token not found.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "410": { "description": "Token exists but resource status != 'active'.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "413": { "description": "Request body exceeds the 1 MiB cap.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
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
        "description": "Copies the stack's config (image binding, resource bindings, name) to a sibling stack in the target env. If the target env already has a sibling, its status is bumped back to 'building' (in-place re-promote); otherwise a new stack row is created with parent_stack_id pointing at the family root. Pro / Team / Growth tiers only — returns 402 with agent_action otherwise.\n\nEmail-link approval gate (migration 026): when 'to' is anything other than 'development', the API does NOT execute the promote immediately. It persists a pending row in promote_approvals, returns 202 with status='pending_approval' + an approval_id + expires_at, and emails the requester a single-use https://api.instanode.dev/approve/<token> link valid for 24h. Dev-env promotes bypass this gate entirely. To run a previously-approved promote manually, pass approval_id in the body — the API verifies status='approved', from/to match, and flips the row to 'executed' before proceeding.",
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
                  "from":        { "type": "string", "description": "Source env — defaults to source stack's env. Must match if provided." },
                  "to":          { "type": "string", "description": "Target env (production, staging, dev, ...) — required. Anything other than 'development' triggers the email-link approval flow." },
                  "name":        { "type": "string", "description": "Optional display name override for the new stack." },
                  "approval_id": { "type": "string", "description": "Optional. Pass the id of an already-approved promote_approvals row to run the promote immediately (skips the email-link wait). The row's (kind,from,to) must match this request." }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Re-promoted into existing sibling stack — same slug, status reset to building" },
          "202": { "description": "Either a new stack was created in the target env (parent_stack_id points at family root), OR — for non-dev target envs without an approval_id — a pending approval was created. The body status field disambiguates: 'building' (executed) vs 'pending_approval' (waiting for email click). The pending shape includes approval_id, expires_at, and an agent_action telling the user to check their inbox." },
          "400": { "description": "Invalid body, missing 'to', from==to, invalid env name, or approval_id mismatched (kind/from/to)." },
          "401": { "description": "Unauthorized — session required" },
          "402": { "description": "Upgrade required — team is not on pro/team/growth. Response carries upgrade_url + agent_action." },
          "403": { "description": "Blocked by team env_policy. Body: { error: 'env_policy_denied', env, action, role, allowed_roles, agent_action }." },
          "404": { "description": "Source stack not found, not owned by this team, OR approval_id does not match any row for this team" },
          "409": { "description": "Source env did not match the asserted 'from', OR approval_id is not in status='approved'" },
          "410": { "description": "approval_id is past its 24h expiry window" }
        }
      }
    },
    "/approve/{token}": {
      "get": {
        "summary": "Click-through endpoint for email-link promote approvals",
        "description": "Public, no-auth endpoint. The operator's email link points here. On a valid pending unexpired token, the row is atomically flipped to status='approved' (single-use) and the response 302-redirects to https://instanode.dev/app/promotions/<id>?approved=1. Otherwise renders an HTML page describing the failure (invalid / expired / already-used). Rate-limited to 10 req/sec per IP — defends the 32-byte token space against brute-force.",
        "parameters": [{ "name": "token", "in": "path", "required": true, "schema": { "type": "string" }, "description": "URL-safe base64 token from the approval email." }],
        "responses": {
          "302": { "description": "Approved — redirect to dashboard" },
          "400": { "description": "Missing token (HTML)" },
          "404": { "description": "Token does not match any row (HTML)" },
          "410": { "description": "Token expired or already used (HTML)" },
          "429": { "description": "Per-IP rate limit hit (HTML)" }
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
        "description": "Builds a Docker image from the supplied tarball (or pulls an existing image) and rolls it out behind a public HTTPS URL on *.deployment.instanode.dev. Env vars may use the value 'vault://KEY' to reference a secret stored via /api/v1/vault — the plaintext is resolved at deploy time and never persisted in plaintext. The separate 'resource_bindings' field accepts 'family:<family_root_id>' values that resolve at submit time to the connection URL of the family member matching the deploy's env — so one manifest works across staging / production / dev. Raw resource-token UUIDs are also accepted for backward compatibility.\n\nSupports Stripe/AWS-style idempotency via the optional Idempotency-Key request header — safe-retry the multipart upload after a transient build failure without creating duplicate apps.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars). First response cached for 24h; replays return the cached body with X-Idempotent-Replay: true. Note: deploy/new is multipart/form-data, so the body-hash compares the raw form payload — a re-uploaded tarball with even one byte different is treated as a different request (returns 409). Generate a fresh key for each distinct build context." }],
        "requestBody": { "required": true, "content": { "multipart/form-data": { "schema": { "$ref": "#/components/schemas/DeployRequest" } } } },
        "responses": {
          "202": { "description": "Deployment accepted, building", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "400": { "description": "Bad request — invalid env_vars JSON, invalid_resource_binding (resource_bindings value is not a UUID or family:<uuid>), private_deploy_requires_allowed_ips (private=true with no IPs), invalid_allowed_ip (bad CIDR/IP literal), too_many_allowed_ips (>32 entries), invalid_notify_webhook (URL is not https, unresolvable, or resolves to a private/loopback/link-local IP), OR invalid_idempotency_key (empty/>255 chars/non-ASCII-printable)" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "deployment_limit_reached OR private_deploy_requires_pro — hobby/anonymous/free trying to set private=true. agent_action points to https://instanode.dev/pricing." },
          "403": { "description": "Blocked by team env_policy, OR resource_binding_forbidden (binding references a resource owned by a different team)" },
          "404": { "description": "resource_binding_not_found — the resource or family root id supplied in resource_bindings does not exist" },
          "409": { "description": "no_env_twin (resource_bindings used family:<id> but the family has no member in the deploy's env — agent_action tells the user to call POST /api/v1/resources/:id/provision-twin first) OR idempotency_key_conflict (the same Idempotency-Key was used with a different request body)" },
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
    "/api/v1/deployments/{id}/make-permanent": {
      "post": {
        "summary": "Opt a deployment out of the auto-24h TTL",
        "description": "Wave FIX-J. Sets expires_at = NULL and ttl_policy = 'permanent' so the deployment never auto-expires. Idempotent — calling twice is a no-op. Anonymous tier is rejected with 402 (anonymous deploys are always 24h; claim the account first). Cross-tenant requests return 404, not 403, so deploy ids belonging to other teams can't be probed. Emits audit kind 'deploy.made_permanent' with source='make_permanent_endpoint'.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Deployment id (UUID or short app_id slug)." }],
        "responses": {
          "200": { "description": "Deployment kept permanently", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "401": { "description": "Unauthorized" },
          "402": { "description": "upgrade_required — anonymous tier. agent_action points at https://api.instanode.dev/start." },
          "404": { "description": "Not found (or owned by another team)" }
        }
      }
    },
    "/api/v1/deployments/{id}/ttl": {
      "post": {
        "summary": "Set a custom TTL for a deployment",
        "description": "Wave FIX-J. Sets expires_at = now() + hours and ttl_policy = 'custom'. hours must be in [1, 8760]. Also resets reminders_sent so a freshly-extended deploy gets the full six-email warning cycle again. Anonymous tier rejected with 402. Cross-tenant 404. Emits 'deploy.ttl_set' audit kind.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "required": ["hours"], "properties": {
            "hours": { "type": "integer", "minimum": 1, "maximum": 8760, "description": "Number of hours from now until the deploy auto-expires. 1..8760 (1 hour to 1 year)." }
          }}}}
        },
        "responses": {
          "200": { "description": "TTL updated", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DeployResponse" } } } },
          "400": { "description": "invalid_hours — outside 1..8760" },
          "402": { "description": "upgrade_required — anonymous tier" },
          "404": { "description": "Not found" }
        }
      }
    },
    "/api/v1/team/settings": {
      "get": {
        "summary": "Read team preferences",
        "description": "Wave FIX-J. Returns the team's preferences. Today the only field is default_deployment_ttl_policy ('auto_24h' or 'permanent') — flipping this changes the default for every future POST /deploy/new. Per-deploy ttl_policy on /deploy/new always overrides this default.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": {
            "description": "Team preferences",
            "content": { "application/json": { "schema": { "type": "object", "properties": {
              "ok": { "type": "boolean" },
              "settings": { "type": "object", "properties": {
                "team_id": { "type": "string" },
                "default_deployment_ttl_policy": { "type": "string", "enum": ["auto_24h", "permanent"] },
                "default_deployment_ttl_hours": { "type": "integer", "description": "Convenience field — 24 for auto_24h, 0 for permanent." }
              }}
            }}}}
          },
          "401": { "description": "Unauthorized" }
        }
      },
      "patch": {
        "summary": "Mutate team preferences (owner/admin only)",
        "description": "Wave FIX-J. Updates one or more team preferences. Only owner/admin may call. Each changed field emits a 'team.settings_changed' audit row.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": {
          "default_deployment_ttl_policy": { "type": "string", "enum": ["auto_24h", "permanent"], "description": "Sets the team-wide default for /deploy/new. 'auto_24h' means every new deploy auto-expires in 24h; 'permanent' means deploys never auto-expire." }
        }}}}},
        "responses": {
          "200": { "description": "Updated" },
          "400": { "description": "invalid_ttl_policy — not 'auto_24h' or 'permanent'" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Insufficient role (owner/admin required)" }
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
        "description": "Convenience for PUT — preserves history but bumps the version visibly. Existing deployments continue to read v(N-1) until they redeploy.\n\nIdempotent: each call inserts a new versioned row in vault_secrets, so double-clicks were producing duplicate versions (BB2-CHROME-3). The Idempotency middleware now dedups retries via either an explicit Idempotency-Key header (24h TTL) or the body-fingerprint fallback (120s TTL). See the top-level Idempotency section in info.description.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "env", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "key", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars). First response cached for 24h; replays return the cached body with X-Idempotent-Replay: true. Reusing the key with a different body returns 409." }
        ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["value"], "properties": { "value": { "type": "string" } } } } } },
        "responses": {
          "200": { "description": "Rotated", "headers": { "X-Idempotent-Replay": { "description": "Set to 'true' when the response was served from the idempotency cache instead of running the handler.", "schema": { "type": "string", "enum": ["true"] } }, "X-Idempotency-Source": { "description": "Which dedup path matched: explicit (Idempotency-Key header), fingerprint (body-fingerprint fallback), or miss (handler ran fresh).", "schema": { "type": "string", "enum": ["explicit", "fingerprint", "miss"] } } }, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/VaultPutResponse" } } } },
          "409": { "description": "Idempotency-Key already used with a different body (error=idempotency_key_conflict).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
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
        "description": "Converts anonymous resources to hobby tier (no expiry). Sends a magic link to the supplied email; clicking the link sets a session JWT cookie and atomically transfers every resource token in the onboarding token to the new team.",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimRequest" } } } },
        "responses": {
          "200": { "description": "Magic link sent to email", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimResponse" } } } },
          "201": { "description": "Account created, resources transferred (legacy direct-claim flow)", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimResponse" } } } },
          "400": { "description": "Validation failure. Possible error codes: missing_token (no token/jwt in body), missing_email (no email), invalid_email_format (email failed RFC 5322 validation), invalid_body (body not valid JSON), invalid_token (token failed signature/expiry check).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "409": { "description": "Onboarding token already used (single-use claim)" }
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
        "summary": "Onboarding bounce — always 302 to the dashboard claim page",
        "description": "Public bounce endpoint baked into the upgrade_url returned by every anonymous provisioning response. Issues a 302 Location redirect to the dashboard's claim page (DASHBOARD_BASE_URL + '/claim?t=<jwt>') — the dashboard then drives the email-claim flow against POST /claim. ALWAYS 302s regardless of token validity (API-5): an invalid/expired/missing token still redirects to /claim where the dashboard renders a friendly error UI. This is the contract because /start URLs land in agents' terminal logs and users copy-paste them into browsers; a raw JSON 400 is hostile UX. Agents that already hold the upgrade_jwt should POST /claim directly instead of following this redirect.",
        "parameters": [{ "name": "t", "in": "query", "required": false, "schema": { "type": "string" }, "description": "Signed onboarding JWT (the upgrade_jwt field from any anonymous provisioning response, or extracted from the upgrade URL). Optional — when missing, the bounce still 302s to /claim with no t= query so the dashboard renders its empty / login state." }],
        "responses": {
          "302": {
            "description": "Redirect to the dashboard claim page (e.g. https://instanode.dev/claim?t=<jwt>). Follow the Location header for the human flow, or POST /claim directly with the JWT to skip the dashboard step.",
            "headers": {
              "Location": { "schema": { "type": "string", "format": "uri" }, "description": "Dashboard claim URL with the JWT echoed in the t= query param (or no t= when omitted by the caller)" }
            }
          }
        }
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
    "/auth/logout": {
      "post": {
        "summary": "Log out — revoke the current session token server-side",
        "description": "Adds the bearer token's JTI to a Redis revocation set (TTL = remaining token lifetime) so the token is rejected by RequireAuth even before it expires. Idempotent; safe to call without a valid token.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Session revoked", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" } } } } } },
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
        "description": "Creates a fresh resource of the same type as the source, in a different env, linked into the same family (parent_resource_id = family root). Tier-gated to Pro/Team/Growth — hobby/free callers get a 402 with agent_action telling them to upgrade. Only supports postgres/redis/mongodb sources (the resource types where env-twin has real per-env infra).\n\nEmail-link approval gate (migration 026): when 'env' is anything other than 'development', the API does NOT execute immediately. It persists a pending row in promote_approvals, returns 202 with status='pending_approval' + an approval_id + expires_at, and emails the requester a single-use https://api.instanode.dev/approve/<token> link valid for 24h. Dev-env twins bypass this gate. Pass approval_id in the body to consume a previously-approved row immediately.",
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
                  "env":         { "type": "string", "description": "Target env for the twin (production / staging / dev / ...). Must match ^[a-z0-9-]{1,32}$. Anything other than 'development' triggers the email-link approval flow." },
                  "name":        { "type": "string", "description": "Optional human-readable label (max 120 chars). Falls back to the source's name when omitted." },
                  "approval_id": { "type": "string", "description": "Optional. Pass an already-approved approval row id to run the twin immediately (skips the email-link wait)." }
                }
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Twin provisioned — body carries connection_url + family_root_id (same shape as POST /db/new etc.)" },
          "202": { "description": "Pending approval — non-dev target env, no approval_id supplied. Body: { status: 'pending_approval', approval_id, expires_at, agent_action, ... }." },
          "400": { "description": "invalid_id / missing_env / invalid_env / unsupported_for_twin (source isn't postgres/redis/mongodb), or approval_id mismatched" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "upgrade_required — team is on hobby/free; response carries agent_action + upgrade_url" },
          "403": { "description": "forbidden — caller does not own the source resource" },
          "404": { "description": "Source resource not found, or approval_id does not match any row for this team" },
          "409": { "description": "twin_exists — family already has a row in the requested env, OR approval_id is not in status='approved'" },
          "410": { "description": "approval_id is past its 24h expiry window" },
          "503": { "description": "provision_failed — downstream provisioner errored; resource row was soft-deleted" }
        }
      }
    },
    "/api/v1/families/bulk-twin": {
      "post": {
        "summary": "Bulk env-twin every parent resource in source_env (Pro+)",
        "description": "One-shot endpoint to twin every family-root resource a team owns in source_env into target_env. Replaces N sequential per-resource /provision-twin calls — the agentic-founder use case for setting up staging in one step.\n\nReturns 200 on full success, 207 Multi-Status when at least one twin failed (the successful rows are NOT rolled back — caller retries just the failed parents). Parents already twinned in target_env count as skipped_already_existed (NOT failures) so retries are idempotent. Tier-gated to Pro/Team/Growth.\n\nConcurrency: per-call semaphore caps in-flight provisions (5 by default) so a team with 30 resources doesn't wait 30× serial provision time. Provisions are NOT rolled back on partial failure — the customer can retry just the failed rows.\n\nQuota gate: if a team's resource-count headroom is exhausted, the remaining parents return failures[] entries with error=quota_exceeded + the upgrade URL in agent_action.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["source_env", "target_env"],
                "properties": {
                  "source_env":     { "type": "string", "description": "Env to copy FROM (e.g. \"production\"). Must match ^[a-z0-9-]{1,32}$. Only resources where parent_resource_id IS NULL — the family roots — are considered." },
                  "target_env":     { "type": "string", "description": "Env to copy TO (e.g. \"staging\"). Must differ from source_env. Same charset rule as source_env." },
                  "resource_types": {
                    "type": "array",
                    "items": { "type": "string", "enum": ["postgres", "redis", "mongodb"] },
                    "description": "Optional whitelist. Empty = all twin-supported types. Unknown types in the filter are silently dropped so old callers don't break when a new supported type lands."
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "All selected parents twinned (or already had a twin). Body: { ok:true, twinned, skipped_already_existed, items[], failures:[] }. Items carry parent_token + twin_token + resource_type + env + (optional) skipped:true for the already-existed rows." },
          "207": { "description": "Multi-Status — at least one parent failed (provision error, quota_exceeded, etc.). Body shape identical to 200 but failures[] is non-empty. Each failure carries parent_token + error code + message + (for quota_exceeded) agent_action + upgrade_url." },
          "400": { "description": "missing_source_env / missing_target_env / invalid_source_env / invalid_target_env / same_env (source and target are identical)." },
          "401": { "description": "Unauthorized — Bearer token required." },
          "402": { "description": "upgrade_required — team is on hobby/free; response carries agent_action + upgrade_url. Multi-env workflows are a Pro+ differentiator." },
          "503": { "description": "team_lookup_failed / list_failed — transient DB error; retry with backoff." }
        }
      }
    },
    "/api/v1/resources/{id}/backup": {
      "post": {
        "summary": "Trigger an ad-hoc Postgres backup",
        "description": "Queues a manual backup of the referenced postgres resource. Tier-gated: anonymous/free callers get 402 + agent_action telling them to claim and upgrade; hobby callers are capped at 1 manual backup per UTC day (Redis-backed counter manual_backup:<team_id>:<YYYY-MM-DD>); pro/growth get 100/day; team gets 1000/day. Only postgres resources are supported today — other types return 400 unsupported_resource_type. The API inserts a pending row in resource_backups and returns immediately; the worker picks it up within 30s, runs pg_dump → S3, and writes the terminal status, size_bytes, and s3_key. Poll GET /api/v1/resources/{id}/backups to watch the row transition pending → running → ok|failed. Audit event: backup.requested with metadata {resource_id, triggered_by, backup_kind}. Retention follows plans.yaml.backup_retention_days (hobby=7, pro/growth=30, team=90). Hobby cannot restore from these — see /restore.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" }, "description": "Resource token UUID — must be a postgres resource owned by the authenticated team." }],
        "responses": {
          "200": { "description": "Backup queued", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "backup_id": { "type": "string", "format": "uuid" }, "status": { "type": "string", "enum": ["pending"] }, "started_at": { "type": "string", "format": "date-time" }, "message": { "type": "string" } } } } } },
          "400": { "description": "invalid_id (resource UUID malformed) or unsupported_resource_type (resource is not postgres)" },
          "401": { "description": "Unauthorized — session token required" },
          "402": { "description": "upgrade_required — anonymous/free tier cannot back up; response carries agent_action + upgrade_url", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "403": { "description": "Forbidden — caller doesn't own the resource" },
          "404": { "description": "not_found — resource doesn't exist" },
          "429": { "description": "rate_limited — team has hit its manual_backups_per_day cap for the current UTC day; response carries agent_action pointing at the Pro upgrade", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "backup_create_failed — transient DB error; retry with backoff" }
        }
      }
    },
    "/api/v1/resources/{id}/backups": {
      "get": {
        "summary": "List backups for a resource",
        "description": "Returns the team's backups for this resource, newest first. Cursor-style pagination via ?before=<RFC3339> — pass the oldest row's created_at to fetch the next page. ?limit caps at 200 (default 50). Each item carries status (pending|running|ok|failed), backup_kind (scheduled|manual), tier_at_backup (the tier in effect when the backup was taken, used by the retention prune job in the worker), size_bytes (NULL until the worker writes the terminal row), and error_summary (only set on failed). 403 on cross-team access. No tier gate on read — even hobby callers can list to verify backups exist, which is part of the Pro-upgrade trust path.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } },
          { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }, "description": "Max rows to return. Capped at 200." },
          { "name": "before", "in": "query", "schema": { "type": "string", "format": "date-time" }, "description": "Cursor — only rows with created_at < before are returned. Pass the oldest item's created_at to paginate backwards." }
        ],
        "responses": {
          "200": {
            "description": "Backup list",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":    { "type": "boolean" },
                    "items": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "backup_id":      { "type": "string", "format": "uuid" },
                          "status":         { "type": "string", "enum": ["pending","running","ok","failed"] },
                          "backup_kind":    { "type": "string", "enum": ["scheduled","manual"] },
                          "started_at":     { "type": "string", "format": "date-time" },
                          "finished_at":    { "type": "string", "format": "date-time", "nullable": true },
                          "size_bytes":     { "type": "integer", "nullable": true, "description": "Size of the pg_dump artifact in bytes. NULL until the worker writes the terminal row." },
                          "tier_at_backup": { "type": "string", "nullable": true, "description": "Snapshot of team.plan_tier when the backup was taken. Used by the retention prune job — a backup taken on Pro stays for 30 days even after the team downgrades." },
                          "error_summary":  { "type": "string", "nullable": true, "description": "Short human-readable failure reason. Only set when status='failed'." },
                          "created_at":     { "type": "string", "format": "date-time" }
                        }
                      }
                    },
                    "total": { "type": "integer", "description": "Total backups for this resource (not just the current page). Used by the dashboard to render pagination affordances." }
                  }
                }
              }
            }
          },
          "400": { "description": "invalid_id or invalid_cursor (?before is not RFC3339)" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Forbidden — caller doesn't own the resource" },
          "404": { "description": "not_found — resource doesn't exist" }
        }
      }
    },
    "/api/v1/resources/{id}/restore": {
      "post": {
        "summary": "Restore a Postgres resource from a backup (Pro+)",
        "description": "Queues a restore from a previously-completed backup. Tier-gated to Pro/Growth/Team via plans.yaml.backup_restore_enabled — hobby/free callers get 402 + agent_action telling them to upgrade ('Pro can restore, Hobby cannot' is the wedge). backup_id must (a) exist, (b) belong to the same resource named in the URL, (c) be in status='ok'. Mismatches return 400/404/409 with distinct error codes so a dashboard can show the right copy. The API writes a pending row in resource_restores; the worker picks it up within 30s and runs pg_restore from S3. Audit event: restore.requested with metadata {resource_id, backup_id, triggered_by} — distinct from backup.requested so a Loops subscriber can filter to 'user clicked Restore' (a high-signal event). The DB column resource_restores.triggered_by is NOT NULL; PAT-only sessions without a user identity get 401.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" }, "description": "Resource token UUID — target of the restore. Must be owned by the authenticated team." }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["backup_id"],
                "properties": {
                  "backup_id": { "type": "string", "format": "uuid", "description": "Id of the resource_backups row to restore from. Must be in status='ok' and belong to the same resource as the URL :id." }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Restore queued", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "restore_id": { "type": "string", "format": "uuid" }, "status": { "type": "string", "enum": ["pending"] }, "started_at": { "type": "string", "format": "date-time" }, "message": { "type": "string" } } } } } },
          "400": { "description": "invalid_id, invalid_body, missing_backup_id, invalid_backup_id, or backup_resource_mismatch (backup_id belongs to a different resource than the one in the URL)" },
          "401": { "description": "Unauthorized — session token required AND must carry a user identity (PAT-only sessions are rejected)" },
          "402": { "description": "upgrade_required — restore is Pro+. Response carries agent_action + upgrade_url to https://instanode.dev/pricing.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "403": { "description": "Forbidden — caller doesn't own the resource" },
          "404": { "description": "not_found (resource doesn't exist) OR backup_not_found (backup_id doesn't exist)" },
          "409": { "description": "backup_not_ready — backup_id is in status pending/running/failed and cannot be restored from. Response carries agent_action telling the user to wait or pick another backup.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "restore_create_failed or backup_lookup_failed — transient DB error; retry" }
        }
      }
    },
    "/api/v1/resources/{id}/restores": {
      "get": {
        "summary": "List restore attempts for a resource",
        "description": "Same shape and pagination as /backups. Items carry status (pending|running|ok|failed), backup_id (the source backup), and error_summary (only on failed). No tier gate — visible to every tier so the dashboard can show 'restore in progress / restore complete' state even on tiers that can't initiate new restores. 403 on cross-team access.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } },
          { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 } },
          { "name": "before", "in": "query", "schema": { "type": "string", "format": "date-time" } }
        ],
        "responses": {
          "200": {
            "description": "Restore list",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":    { "type": "boolean" },
                    "items": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "restore_id":    { "type": "string", "format": "uuid" },
                          "backup_id":     { "type": "string", "format": "uuid", "description": "Source backup the restore was taken from." },
                          "status":        { "type": "string", "enum": ["pending","running","ok","failed"] },
                          "started_at":    { "type": "string", "format": "date-time" },
                          "finished_at":   { "type": "string", "format": "date-time", "nullable": true },
                          "error_summary": { "type": "string", "nullable": true },
                          "created_at":    { "type": "string", "format": "date-time" }
                        }
                      }
                    },
                    "total": { "type": "integer" }
                  }
                }
              }
            }
          },
          "400": { "description": "invalid_id or invalid_cursor" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Forbidden — caller doesn't own the resource" },
          "404": { "description": "not_found" }
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
        "description": "Mints a Razorpay subscription for the requested plan (hobby, hobby_plus, pro, or team) tied to the authenticated team. The dashboard redirects the user to the returned short_url to complete payment; on success Razorpay fires subscription.activated AND subscription.charged to /razorpay/webhook — both trigger the same idempotent tier-elevation path so the team is upgraded as soon as the mandate is authorised, even before the first invoice is collected. Team-tier checkout was enabled 2026-05-29 (CEO BIZ-1) — if RAZORPAY_PLAN_ID_TEAM / _TEAM_ANNUAL is unset on the environment the request returns 503 billing_not_configured (operator signal), not 400 tier_unavailable. plan_frequency selects monthly (default) vs yearly billing — yearly returns 503 billing_not_configured until the operator creates the yearly Razorpay plan and sets RAZORPAY_PLAN_ID_*_YEARLY. promotion_code: admin-issued codes are bookmarked in the subscription notes for future discount wiring (no Razorpay Offer is applied yet — codes are not consumed until a real discount is confirmed). IDEMPOTENT: the endpoint never mints a second subscription for a team that already has a live one — if the team already holds the requested tier (or higher) it returns 400 already_on_plan, and if a prior checkout's subscription is still payable at Razorpay (status created/authenticated/pending) it returns that subscription's short_url with reused:true instead of creating a new one. This prevents a confused re-click from producing two parallel subscriptions that both charge the card.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["plan"], "properties": { "plan": { "type": "string", "enum": ["hobby", "hobby_plus", "pro", "team"] }, "plan_frequency": { "type": "string", "enum": ["monthly", "yearly"], "default": "monthly", "description": "Billing cycle. Empty = monthly. Yearly variants follow the same canonical-tier mapping on the webhook side — teams.plan_tier still stores the bare tier name." } } } } } },
        "responses": {
          "200": { "description": "Subscription created (or an existing live one reused) — redirect user to short_url. reused:true means the short_url belongs to a checkout the team started earlier and no new subscription was minted.", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "short_url": { "type": "string", "format": "uri" }, "subscription_id": { "type": "string" }, "reused": { "type": "boolean", "description": "Present and true only when an existing still-payable subscription was returned instead of minting a new one." } } } } } },
          "400": { "description": "Invalid plan, invalid plan_frequency, or already_on_plan (the team already holds the requested tier or higher)" },
          "401": { "description": "Missing or invalid session token" },
          "502": { "description": "Razorpay rejected the create-subscription call" },
          "503": { "description": "Razorpay not configured on this environment (incl. yearly plan_id unset)" }
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
        "description": "Hobby ↔ Hobby Plus ↔ Pro ↔ Team on the same Razorpay subscription. Proration is handled by Razorpay; the new plan takes effect at the end of the current billing period. Team-tier ChangePlan was enabled 2026-05-29 (CEO BIZ-1) alongside Team checkout.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["plan"], "properties": { "plan": { "type": "string", "enum": ["hobby", "hobby_plus", "pro", "team"] } } } } } },
        "responses": {
          "200": { "description": "Plan change accepted by Razorpay" },
          "400": { "description": "Invalid plan" },
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
                  "plan": { "type": "string", "enum": ["hobby", "hobby_plus", "pro", "team"], "description": "Plan tier the discount must apply to" }
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
        "description": "Provisions an object-storage prefix for the caller. The response shape depends on what isolation the configured backend can ENFORCE (PrefixScopedKeys capability — see STORAGE-ABSTRACTION-DESIGN-2026-05-20.md):\n\n- 'prefix-scoped' / 'prefix-scoped-temporary' (R2, S3, MinIO): returns access_key_id + secret_access_key (and session_token for STS-backed flows) that the backend IAM enforces against <prefix>/*. Use directly with any S3 SDK.\n\n- 'shared-master-key' (legacy DO Spaces rows): returns the platform master key + prefix. Isolation is by convention only; new tenants do NOT land here.\n\n- 'broker' (DO Spaces today for new tenants): NO long-lived credential is returned. Instead the response carries agent_action='use_presign_endpoint' + presign_url pointing to POST /storage/{token}/presign for short-lived signed URLs.\n\nAlways inspect the 'mode' field in the response to pick the right access pattern. Anonymous tier: 10MB, 24h TTL (plans.yaml storage_storage_mb=10). Supports Stripe/AWS-style idempotency via the optional Idempotency-Key request header.",
        "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "maxLength": 255 }, "description": "Opaque client-supplied key (1-255 ASCII printable chars). First response cached for 24h; replays return the cached body with X-Idempotent-Replay: true. Reusing the key with a different body returns 409." }],
        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProvisionRequest" } } } },
        "responses": {
          "201": { "description": "Storage provisioned. Response carries a 'mode' field — one of shared-master-key | prefix-scoped | prefix-scoped-temporary | broker — describing the isolation the tenant has.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StorageProvisionResponse" } } } },
          "400": { "description": "Bad request — one of: name_required (name field missing/empty), invalid_name (name fails the 1-64-char start-alnum pattern or contains invalid UTF-8), invalid_body (request body is not valid JSON), invalid_env, or an invalid Idempotency-Key (empty, >255 chars, or non-ASCII-printable).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "402": { "description": "Storage limit reached. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "409": { "description": "Idempotency-Key already used with a different body (error=idempotency_key_conflict).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "429": { "description": "Anonymous fingerprint limit exceeded. Includes agent_action and upgrade_url.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Object storage is not configured on this environment", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/storage/{token}/presign": {
      "post": {
        "summary": "Mint a short-lived presigned S3 URL (broker-mode access)",
        "description": "Returns a signed URL the caller can use directly with HTTP GET/PUT against the configured object-storage endpoint. Used in BROKER MODE — when the backend (DO Spaces today) cannot enforce per-tenant prefix-scoping at the IAM layer, /storage/new returns no long-lived credential and the caller fetches one signed URL per object operation via this endpoint instead. The token in the URL IS the credential (same token returned by /storage/new); no Authorization header required. expires_in is clamped to a maximum of 3600 seconds. The 'key' field is rooted at the resource's prefix — path-traversal segments ('../', '.') are dropped.",
        "parameters": [
          { "name": "token", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" }, "description": "The storage resource's token (returned by /storage/new)." }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["operation", "key"],
                "properties": {
                  "operation": { "type": "string", "enum": ["GET", "PUT"], "description": "S3 verb to sign for." },
                  "key": { "type": "string", "description": "Object key, relative to the resource's prefix. Leading slashes + '../' components are stripped." },
                  "expires_in": { "type": "integer", "description": "Lifetime of the signed URL in seconds. Default 600, max 3600.", "default": 600, "maximum": 3600 }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Signed URL minted.", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "url": { "type": "string" }, "method": { "type": "string" }, "key": { "type": "string" }, "object_key": { "type": "string" }, "expires_at": { "type": "string", "format": "date-time" } } } } } },
          "400": { "description": "invalid_token, invalid_operation, or invalid_key.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "404": { "description": "resource_not_found", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "410": { "description": "resource_inactive — paused, expired, or deleted.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "service_disabled or sign_failed (object storage not configured).", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
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
        "summary": "Update env vars on a stack (persisted; applied on next redeploy)",
        "description": "PATCH semantics — incoming env map is merged into the stack's existing env_vars (B7-P0-1, migration 062). Setting a key to the empty string deletes it. Keys must match POSIX [A-Z_][A-Z0-9_]* — the same shape /deploy/new and /stacks/new enforce. Total payload after merge is capped at 64KiB. Persisted to stacks.env_vars JSONB; the next POST /stacks/{slug}/redeploy applies them. Auth required: anonymous stacks cannot be mutated after creation.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["env"], "properties": { "env": { "type": "object", "additionalProperties": { "type": "string" }, "description": "Env vars to upsert. Empty-string value deletes a key." } } } } } },
        "responses": {
          "200": { "description": "Env vars persisted; response includes the full merged env map.", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "env": { "type": "object", "additionalProperties": { "type": "string" }, "description": "Full env set on the stack AFTER the merge — caller does not need to re-GET." }, "message": { "type": "string" } } } } } },
          "400": { "description": "Body missing, env is empty, or an env-var key fails the POSIX [A-Z_][A-Z0-9_]* shape (error=invalid_env_key)." },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Stack not found or not owned by this team" },
          "409": { "description": "Stack is mid-teardown and cannot be modified (error=stack_deleting)." },
          "413": { "description": "Merged env_vars payload exceeds 64KiB (error=env_too_large)." }
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
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["plan"], "properties": { "plan": { "type": "string", "enum": ["hobby", "hobby_plus", "pro", "team"] } } } } } },
        "responses": {
          "200": { "description": "Subscription created — redirect user to short_url", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "short_url": { "type": "string", "format": "uri" }, "subscription_id": { "type": "string" } } } } } },
          "400": { "description": "Invalid plan" },
          "401": { "description": "Missing or invalid session token" },
          "502": { "description": "Razorpay rejected the create-subscription call" },
          "503": { "description": "Razorpay not configured on this environment" }
        }
      }
    },
    "/razorpay/webhook": {
      "post": {
        "summary": "Razorpay subscription event webhook (signature-verified)",
        "description": "Receives Razorpay subscription lifecycle events: subscription.activated (card/mandate authorised → elevate team tier immediately, same idempotent path as subscription.charged; closes the activation-before-charge window for Indian payment methods like UPI/NACH where the first charge may be delayed hours after activation), subscription.charged (payment confirmed → elevate team tier + elevate all permanent resources + trigger migrations for shared-infra resources; ALSO recovers any active payment-grace row → emits payment.grace_recovered audit; both activated and charged route to the same idempotent upgrade handler — dedup is per-event_id so no double-upgrade risk), subscription.cancelled (downgrade team to hobby), subscription.charged_failed (opens a 7-day payment-grace window → emits payment.grace_started audit; idempotent via partial-unique index on payment_grace_periods, so webhook redeliveries are silent no-ops; worker side fires the 6h reminder cadence and terminates non-recovered grace rows at expires_at), payment.failed (record + emit grace_started when the failed payment carries a subscription reference). The body's HMAC-SHA256 signature with RAZORPAY_WEBHOOK_SECRET must match the X-Razorpay-Signature header. Always returns 200 on success — Razorpay retries on non-2xx. Returns 400 invalid_signature when the HMAC check fails. NOT for direct caller use — Razorpay POSTs here.",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "description": "Razorpay event payload (event, payload.subscription/payment.entity). See Razorpay webhook docs." } } } },
        "responses": {
          "200": { "description": "Event processed (or ignored for unhandled event types)" },
          "400": { "description": "invalid_signature or invalid_payload" }
        }
      }
    },
    "/api/v1/resources/{id}/metrics": {
      "get": {
        "summary": "Per-resource time-series metrics (p50/p95/p99 latency, connections, storage, error rate)",
        "description": "Returns aggregated metrics for the resource over the requested window. Default window is 1h; max window is tier-gated: hobby=1h, pro=24h, growth/team=7d. Anonymous/free callers get 402 upgrade_required — resource observability is a Pro+ differentiator. Buckets are fixed at 60s; samples_count = window_seconds / 60. The response carries data_source=stub while the W5-A heartbeat prober's per-probe row writer is unshipped — the API SHAPE matches the eventual real-data response so dashboard code does not change when the stub is replaced. Future swap-in is documented in resource_metrics.go (Option A: NerdGraph NRQL; Option C: server-side bucketing of resource_metrics rows).",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } },
          { "name": "window", "in": "query", "required": false, "schema": { "type": "string", "default": "1h", "example": "24h" }, "description": "Duration string (1h, 30m, 24h). Bare integers are interpreted as seconds (3600 == 1h). Capped per tier; over-cap returns 402 with agent_action naming the ceiling instead of silently clamping." }
        ],
        "responses": {
          "200": {
            "description": "Metrics fetched",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":                       { "type": "boolean" },
                    "resource_id":              { "type": "string", "format": "uuid" },
                    "resource_type":            { "type": "string", "description": "postgres | redis | mongodb | webhook | queue | storage" },
                    "window_seconds":           { "type": "integer", "format": "int64", "description": "Resolved window in seconds (post-default, post-cap-rejection)." },
                    "samples_count":            { "type": "integer", "description": "Equals window_seconds / sample_interval_seconds. Capped at 10080 (7d @ 1min)." },
                    "sample_interval_seconds": { "type": "integer", "description": "Fixed at 60. Tier ceilings change window, not bucket width." },
                    "metrics": {
                      "type": "object",
                      "description": "All arrays have length samples_count. Empty during the stub window means awaiting-first-probe-sample, not backend-down.",
                      "properties": {
                        "latency_p50_ms":     { "type": "array", "items": { "type": "number" } },
                        "latency_p95_ms":     { "type": "array", "items": { "type": "number" } },
                        "latency_p99_ms":     { "type": "array", "items": { "type": "number" } },
                        "connections_active": { "type": "array", "items": { "type": "number" } },
                        "storage_bytes":      { "type": "array", "items": { "type": "number" } },
                        "error_rate_pct":     { "type": "array", "items": { "type": "number" } }
                      }
                    },
                    "data_source": { "type": "string", "enum": ["stub", "newrelic", "resource_metrics"], "description": "stub while the W5-A prober is unshipped. resource_metrics once Option C lands, newrelic once Option A lands. Dashboard renders a yellow banner only on stub." }
                  }
                }
              }
            }
          },
          "400": { "description": "invalid_id — :id is not a valid UUID — OR invalid_window — window param unparseable, non-positive, or > 7d hard maximum" },
          "401": { "description": "Unauthorized — session token required" },
          "402": { "description": "upgrade_required — anonymous/free tier hit the wall OR ?window= exceeds tier cap. Body carries agent_action explaining the current ceiling (e.g. Hobby caps metrics windows at 1h; longer windows require Pro) + upgrade_url." },
          "403": { "description": "Forbidden — caller's team doesn't own the resource" },
          "404": { "description": "not_found — resource doesn't exist" },
          "503": { "description": "fetch_failed — DB lookup failed (transient infra error)" }
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
    "/api/v1/team": {
      "get": {
        "summary": "Get the caller's team record",
        "description": "Returns the public-safe subset of the caller's team row: id, name, plan_tier, has_active_subscription (mirror of teams.razorpay_subscription_id IS NOT NULL), and created_at. Distinct from GET /api/v1/team/summary (cached aggregate counts) and GET /api/v1/team/members (member roster). Use this when the dashboard's TeamPage opens or after PATCH /api/v1/team to read back the new name.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Team record", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "team": { "$ref": "#/components/schemas/TeamSelf" } }, "required": ["ok", "team"] } } } },
          "401": { "description": "Missing or invalid session token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "404": { "description": "Team not found", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Lookup failed (transient DB error). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      },
      "patch": {
        "summary": "Rename the caller's team",
        "description": "Updates the team's display name. Only the 'name' field is mutable here — plan_tier, subscription state, and member roster flow through dedicated paths (Razorpay webhook for tier; /api/v1/admin/customers/:id/tier for admin demote; /api/v1/team/members/* for membership). Read-only sessions (admin impersonation) are blocked by the route's RequireWritable gate before this handler runs.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["name"], "properties": { "name": { "type": "string", "minLength": 1, "maxLength": 200, "description": "New display name. Whitespace is trimmed. Must be 1-200 chars after trim." } } } } } },
        "responses": {
          "200": { "description": "Team updated", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "team": { "$ref": "#/components/schemas/TeamSelf" } }, "required": ["ok", "team"] } } } },
          "400": { "description": "Body invalid, name missing, or name longer than 200 chars", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "401": { "description": "Missing or invalid session token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "403": { "description": "Read-only session (admin impersonation) — mutations are blocked", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "503": { "description": "Update failed (transient DB error). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      },
      "delete": {
        "summary": "Request team deletion (GDPR Article 17, owner only, 30-day grace)",
        "description": "Begins right-to-be-forgotten for the caller's team. Owner role required. Body must include confirm_team_slug matching the team's visible slug (defense-in-depth: typo / paste-error short-circuits before any state change). Effect: teams.status flips to deletion_requested, deletion_requested_at = now(), every team resource is paused (status='paused', paused_at=now()), and the active Razorpay subscription is best-effort cancelled. After 30 days the worker's team_deletion_executor hard-destroys customer DBs / S3 backups / PII fields and flips status to tombstoned. Inside the 30-day window the owner can call POST /api/v1/team/restore to halt deletion.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["confirm_team_slug"],
                "properties": {
                  "confirm_team_slug": { "type": "string", "description": "Must match the team's visible slug exactly (case-insensitive). Fetch from GET /api/v1/team/summary if unknown." }
                }
              }
            }
          }
        },
        "responses": {
          "202": { "description": "Deletion request accepted. Response: { ok, deletion_at, grace_window_days, how_to_cancel }. The deletion_at field is the wall-clock instant the worker will tombstone the team." },
          "400": { "description": "Missing or invalid body / confirm_team_slug." },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Caller is not the team owner." },
          "404": { "description": "Team not found." },
          "409": { "description": "slug_mismatch (confirm_team_slug did not match) or already_pending (deletion has already been requested or the team is tombstoned)." }
        }
      }
    },
    "/api/v1/team/restore": {
      "post": {
        "summary": "Cancel a pending team deletion (owner only, inside 30-day grace)",
        "description": "Reverses a prior DELETE /api/v1/team if invoked within the 30-day grace window. Sets teams.status back to active, resumes paused team resources, and emits team.deletion_canceled. Past the 30-day window the worker has begun (or completed) destruction and restoration is no longer possible — the endpoint returns 410 Gone.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Restored. Response: { ok, status, resumed_resource_count, days_remaining_at_cancel }." },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Caller is not the team owner." },
          "404": { "description": "Team not found." },
          "409": { "description": "not_pending — team is not in deletion_requested status." },
          "410": { "description": "grace_expired — 30 days have elapsed; restoration is no longer possible." }
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
        "description": "Two flows under the same endpoint: role='member' uses the legacy owner-controlled seat flow (owner-only); role='admin'/'developer'/'viewer' uses the RBAC token flow (single-use token emailed out, accepted at POST /api/v1/invitations/{token}/accept). BOTH flows enforce the per-tier seat limit. Rate-limited to 10 invites/hour/team via Redis sliding counter; over-cap returns 429. Idempotency-Key header is honored (24h cache, replays carry X-Idempotent-Replay: true).",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string" }, "description": "Optional opaque key (≤255 chars). When present the response is cached for 24h scoped to (team_id, key); subsequent calls with the same key replay the cached response verbatim and set X-Idempotent-Replay: true." }
        ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["email"], "properties": { "email": { "type": "string", "format": "email" }, "role": { "type": "string", "enum": ["admin", "developer", "viewer", "member"], "default": "member" } } } } } },
        "responses": {
          "201": { "description": "Invitation created" },
          "400": { "description": "Body invalid, missing email, or invalid role" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner/admin role required" },
          "409": { "description": "Member limit reached / duplicate / already-a-member" },
          "429": { "description": "Rate limit exceeded (10 invites/hour/team)" }
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
        "description": "Refuses when the target is the team's primary user — every team needs a primary. Promote another member via POST .../promote-to-primary first. On success the removed user is reassigned to a freshly-created personal team; that team's UUID is returned in orphan_team_id so the caller can audit it.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "user_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Member removed; response includes orphan_team_id", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "orphan_team_id": { "type": "string", "format": "uuid", "description": "UUID of the freshly-created personal team the removed user was reassigned to." } } } } } },
          "400": { "description": "Invalid user id, or target is the team's primary user (error code cannot_remove_primary)" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner only" },
          "404": { "description": "User not in team" },
          "409": { "description": "Cannot remove the owner" }
        }
      },
      "patch": {
        "summary": "Change a member's role (owner only)",
        "description": "Updates users.role for the target. Allowed roles: admin, developer, viewer, member (legacy alias of developer). Owner role is NOT assignable here — use POST .../promote-to-primary for an atomic ownership transfer.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "user_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["role"], "properties": { "role": { "type": "string", "enum": ["admin", "developer", "viewer", "member"] } } } } } },
        "responses": {
          "200": { "description": "Role updated", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "user_id": { "type": "string", "format": "uuid" }, "role": { "type": "string" } } } } } },
          "400": { "description": "Invalid user id, invalid role, or attempt to assign owner (error code cannot_assign_owner_role)" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner only" },
          "404": { "description": "User not on this team" }
        }
      }
    },
    "/api/v1/team/members/{user_id}/promote-to-primary": {
      "post": {
        "summary": "Atomically transfer team primary + owner to the target user (owner only)",
        "description": "Owner-only. Demotes the current primary (is_primary=false, role=admin) and promotes the target (is_primary=true, role=owner) inside one transaction so the partial unique index uq_users_one_primary_per_team can never observe a two-primary state. Idempotent: promoting the existing primary is a no-op.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "user_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Primary transferred", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "team_id": { "type": "string", "format": "uuid" }, "primary_user_id": { "type": "string", "format": "uuid" } } } } } },
          "400": { "description": "Invalid user id" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Owner only" },
          "404": { "description": "Target user not on this team" }
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
        "description": "Authenticated counterpart to POST /api/v1/invitations/{token}/accept — this one accepts by the invitation row id (UUID) and trusts the caller's session for identity. Use the token-based public endpoint when accepting from a link in an email. If the invitation requested role=owner but the team already has an owner, the user is silently downgraded to member and the response carries a warning field explaining the demote — use POST /api/v1/team/members/{user_id}/promote-to-primary for an atomic ownership transfer.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": {
          "200": { "description": "Accepted; response includes the granted role and an optional warning when an owner request was silently downgraded.", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "role": { "type": "string" }, "warning": { "type": "string", "description": "Present iff the invitation requested role=owner but a silent downgrade to member occurred." } } } } } },
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
        "summary": "Tear down + delete a deployment (two-step for paid tiers; immediate for anon/free or with bypass header)",
        "description": "Wave FIX-I two-step deletion. PAID TIERS (hobby/pro/team/growth) with a verified owner email: the API does NOT immediately tear down — it queues a pending_deletions row, emails the owner a confirmation link (15-minute TTL by default; configurable via DELETION_CONFIRMATION_TTL_MINUTES), and returns 202 with deletion_status='pending_confirmation'. The agent CANNOT confirm on the user's behalf — only the human can, by either clicking the email link (which 302s through GET /auth/email/confirm-deletion to the dashboard) or by POSTing the token directly to POST /api/v1/deployments/{id}/confirm-deletion?token=<tok>. The deployment slot is NOT freed until the row flips to status='confirmed'. To cancel a pending deletion the user calls DELETE /api/v1/deployments/{id}/confirm-deletion (the same path, DELETE verb). ANONYMOUS / FREE tiers, or callers that set X-Skip-Email-Confirmation: yes, get the back-compat immediate-destruction path with 200 OK.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "X-Skip-Email-Confirmation", "in": "header", "required": false, "schema": { "type": "string", "enum": ["yes"] }, "description": "Set to 'yes' to bypass the two-step email-confirmed flow for paid tiers. Reserved for agents that have already obtained explicit user consent." }
        ],
        "responses": {
          "200": { "description": "Immediate destruction path (anonymous/free tier OR header bypass): deployment torn down synchronously." },
          "202": { "description": "Two-step path (paid tier, email wired, no bypass header): pending_deletions row queued + confirmation email sent. Body carries deletion_status='pending_confirmation', confirmation_sent_to (masked), confirmation_expires_at, agent_action (verbatim LLM copy), cancellation_note." },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" },
          "409": { "description": "deletion_already_pending — a pending email is already in flight for this resource. Cancel it first via DELETE /confirm-deletion, then retry." },
          "422": { "description": "deletion_email_disabled — paid team has no verified owner email on file." },
          "503": { "description": "email_send_failed — transient email-backend failure; safe to retry." }
        }
      }
    },
    "/api/v1/deployments/{id}/confirm-deletion": {
      "post": {
        "summary": "Confirm a pending deletion (paid tiers, Wave FIX-I)",
        "description": "Step 2 of the two-step deletion flow. The user (NOT the agent) clicks the email link, which 302s through /auth/email/confirm-deletion to the dashboard's /app/confirm-deletion page, which POSTs here with the plaintext token. The handler hashes the token, validates against pending_deletions.confirmation_token_hash + status='pending' + expires_at > now(), atomically flips the row to 'confirmed' via CAS, then runs the actual deprovision (compute.Teardown + DELETE FROM deployments). A double-click resolves to 410 on the loser. The handler emits deploy.deletion_confirmed in audit_log.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "token", "in": "query", "required": true, "schema": { "type": "string" }, "description": "Plaintext confirmation token from the email link (starts with 'del_'). Stored only as sha256 hash server-side." }
        ],
        "responses": {
          "200": { "description": "Deletion confirmed. Body: { ok, id, resource_type, deletion_status='confirmed', freed_at, agent_action, note }." },
          "400": { "description": "missing_token — query parameter omitted." },
          "401": { "description": "Unauthorized" },
          "410": { "description": "deletion_token_invalid — token expired, already used, or never existed. agent_action tells the user to call DELETE again to mint a fresh email." },
          "503": { "description": "deletion_lookup_failed / deletion_mark_failed / deletion_email_disabled — transient DB failure or email backend not wired." }
        }
      },
      "delete": {
        "summary": "Cancel a pending deletion (paid tiers, Wave FIX-I)",
        "description": "Cancels an in-flight pending_deletions row without consuming the token. The resource stays active and the slot stays consumed. Caller must own the resource (same team gate as DELETE /api/v1/deployments/{id}). Emits deploy.deletion_cancelled in audit_log.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Cancellation confirmed. Body: { ok, id, resource_type, deletion_status='cancelled', agent_action, note }." },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" },
          "404": { "description": "No pending deletion to cancel for this resource." },
          "410": { "description": "Pending row is already resolved (confirmed/cancelled/expired)." }
        }
      }
    },
    "/api/v1/stacks/{slug}/confirm-deletion": {
      "post": {
        "summary": "Confirm a pending stack deletion (paid tiers, Wave FIX-I)",
        "description": "Stack-side counterpart of POST /api/v1/deployments/{id}/confirm-deletion. Same contract — see that endpoint for the full flow.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "token", "in": "query", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Stack deletion confirmed." },
          "400": { "description": "missing_token" },
          "401": { "description": "Unauthorized" },
          "410": { "description": "deletion_token_invalid" }
        }
      },
      "delete": {
        "summary": "Cancel a pending stack deletion (paid tiers, Wave FIX-I)",
        "description": "Stack-side counterpart of DELETE /api/v1/deployments/{id}/confirm-deletion.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Cancellation confirmed." },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your stack" },
          "404": { "description": "No pending deletion to cancel" }
        }
      }
    },
    "/auth/email/confirm-deletion": {
      "get": {
        "summary": "Email-link 302 redirect to the dashboard confirm page (Wave FIX-I)",
        "description": "The href in deletion-confirm emails. Validates that ?t=<token> is present and 302s to <DASHBOARD_BASE_URL>/app/confirm-deletion?t=<token>. The API does NOT validate the token here — a click is navigation, not action; the dashboard's authenticated POST is the real confirm step.",
        "parameters": [{ "name": "t", "in": "query", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "302": { "description": "Redirect to dashboard confirm page" },
          "400": { "description": "Missing token query parameter" }
        }
      }
    },
    "/api/v1/deployments/{id}/github": {
      "post": {
        "summary": "Connect a deployment to a GitHub repository for auto-deploy",
        "description": "Wires the deployment to a GitHub repo + branch. On every push to the tracked branch, GitHub POSTs to /webhooks/github/{webhook_id}, the API verifies the X-Hub-Signature-256 HMAC, and enqueues a fresh deploy via the worker. The response carries the webhook_url (paste into GitHub → Settings → Webhooks) and the webhook_secret (paste into the same form; this is the ONLY time the plaintext secret is returned — it is AES-256-GCM encrypted at rest). Tier-gated: Hobby and above. Anonymous / free are rejected with 402 because they cannot deploy at all. Hobby teams can have one deployment total (plans.yaml deployments_apps=1); that single deployment may have one GitHub connection. A deployment can have at most one connection at a time — a second POST returns 409 with agent_action telling the caller to DELETE first.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Deployment app_id (short slug, e.g. '6fffcc21')." }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["repo"],
                "properties": {
                  "repo": { "type": "string", "description": "GitHub repository in 'owner/repo' form, e.g. 'octocat/hello-world'.", "example": "octocat/hello-world" },
                  "branch": { "type": "string", "description": "Branch to watch. Defaults to 'main'. Pushes to other branches are ignored at receive time.", "example": "main" },
                  "installation_id": { "type": "integer", "format": "int64", "description": "Optional GitHub App installation id. Reserved for a future private-repo flow; today plain webhooks are used and this field can be omitted." }
                }
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Connection created",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok": { "type": "boolean" },
                    "connection": { "$ref": "#/components/schemas/GitHubConnection" },
                    "webhook_url": { "type": "string", "format": "uri", "description": "Paste into GitHub → Settings → Webhooks → Payload URL." },
                    "webhook_secret": { "type": "string", "description": "Plaintext HMAC signing key. Paste into GitHub → Settings → Webhooks → Secret. Returned ONCE — not surfaced again." },
                    "note": { "type": "string" }
                  }
                }
              }
            }
          },
          "400": { "description": "Bad request — invalid_repo (not owner/repo form), invalid_branch (>250 chars), or invalid_body" },
          "401": { "description": "Unauthorized" },
          "402": { "description": "github_requires_paid_tier — anonymous / free trying to connect. agent_action points to https://instanode.dev/pricing." },
          "403": { "description": "Not your deployment" },
          "404": { "description": "Deployment not found" },
          "409": { "description": "already_connected — deployment already has a GitHub connection. DELETE first to reconnect." },
          "503": { "description": "encryption_unavailable / encryption_failed / create_failed" }
        }
      },
      "get": {
        "summary": "Get the current GitHub connection for a deployment",
        "description": "Returns the current connection (without the webhook secret — that is returned exactly once on POST). Useful for the dashboard's 'connected to <repo>' tile + last-deploy timestamp. When no connection exists, returns connected=false with connection=null.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": {
            "description": "Connection status",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ok":          { "type": "boolean" },
                    "connected":   { "type": "boolean" },
                    "connection":  { "oneOf": [ { "$ref": "#/components/schemas/GitHubConnection" }, { "type": "null" } ] },
                    "webhook_url": { "type": "string", "format": "uri", "description": "Present only when connected=true." }
                  }
                }
              }
            }
          },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" },
          "404": { "description": "Deployment not found" }
        }
      },
      "delete": {
        "summary": "Disconnect a deployment from GitHub auto-deploy",
        "description": "Removes the GitHub connection. The deployment itself stays — only the auto-deploy wiring is removed. Idempotent: calling DELETE when no connection exists returns 200 with deleted=false.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Connection removed (or no-op when none existed)" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Not your deployment" },
          "404": { "description": "Deployment not found" },
          "503": { "description": "delete_failed" }
        }
      }
    },
    "/webhooks/github/{webhook_id}": {
      "post": {
        "summary": "Receive a GitHub push event (PUBLIC, signed)",
        "description": "GitHub POSTs here on every push to the customer's connected repo. Authentication is HMAC-SHA256 over the request body using the per-connection secret — the signature arrives in the X-Hub-Signature-256 header as 'sha256=<hex>'. This endpoint is PUBLIC (no Authorization header — GitHub presents none). Behaviour: ping events return 200 with pong=true; non-push events are accepted as no-ops; push events to a branch other than the tracked branch are accepted as no-ops; pushes to the tracked branch enqueue a pending_github_deploys row that the worker drains within 30s. Idempotency: a duplicate push.event with the same after commit SHA is a no-op (duplicate=true in response). Rate-limit: 10 deploys/hour/repo — exceeding returns 429 with Retry-After=3600. Branch-delete pushes (after=all-zeros) are ignored.",
        "parameters": [
          { "name": "webhook_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" }, "description": "Connection id returned by POST /api/v1/deployments/{id}/github." },
          { "name": "X-Hub-Signature-256", "in": "header", "required": true, "schema": { "type": "string" }, "description": "GitHub-formatted signature: 'sha256=<hex>' where hex is HMAC-SHA256(secret, body)." },
          { "name": "X-GitHub-Event", "in": "header", "required": true, "schema": { "type": "string", "enum": ["push", "ping"] }, "description": "GitHub event type. Only 'push' triggers a deploy; 'ping' acknowledges." }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "description": "GitHub push event payload (subset). See https://docs.github.com/en/webhooks/webhook-events-and-payloads#push.",
                "properties": {
                  "ref":   { "type": "string", "example": "refs/heads/main" },
                  "after": { "type": "string", "description": "Commit SHA after the push (becomes the deploy revision)." },
                  "pusher": { "type": "object", "properties": { "name": { "type": "string" } } },
                  "repository": { "type": "object", "properties": { "full_name": { "type": "string" } } }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Event accepted (ping / no-op for non-push event / branch_mismatch / duplicate)" },
          "202": { "description": "Deploy enqueued — worker will drain shortly" },
          "400": { "description": "invalid_payload — body is not valid JSON" },
          "401": { "description": "signature_invalid — X-Hub-Signature-256 did not verify" },
          "404": { "description": "Webhook not found" },
          "429": { "description": "rate_limited — connection exceeded 10 deploys/hour" },
          "503": { "description": "encryption_unavailable / decrypt_failed / enqueue_failed" }
        }
      }
    },
    "/webhooks/brevo/{secret}": {
      "post": {
        "summary": "Receive a Brevo transactional-email delivery event (PUBLIC, URL-token auth)",
        "description": "Brevo POSTs here for every transactional event (delivered, soft_bounce, hard_bounce, blocked, complaint, deferred, unsubscribed, error). Authentication is by URL token: the {secret} path segment is constant-time-compared against the BREVO_WEBHOOK_SECRET env var (Brevo's transactional webhooks don't carry HMAC signatures by default — the URL-token approach works even when per-callback signing is disabled in their dashboard). Behaviour: matched events update the forwarder_sent ledger row keyed by (provider='brevo', provider_id=message-id), setting classification to the event outcome and (for 'delivered' only) stamping delivered_at = now(). Unknown messageIds return 200 with matched=false (Brevo retries on 5xx — orphan events MUST NOT amplify retry traffic). Unhandled event types (request/click/open/etc.) return 200 with skipped=true. Single-event payloads only — Brevo's optional batched-array endpoint must be disabled in the dashboard. Operator setup: paste https://api.instanode.dev/webhooks/brevo/<SECRET> into Brevo dashboard → Transactional → Settings → Webhook URL, ensure single-event-per-call is selected, and toggle on every event we care about. Closes the '201 ≠ delivered' gap: the worker still stamps classification='success' on Brevo's 201 (API acceptance), but the receiver overwrites that with the real outcome the moment Brevo's relay decides. CLAUDE.md rule 12 verification surface: ledger classification, NOT 201.",
        "parameters": [
          { "name": "secret", "in": "path", "required": true, "schema": { "type": "string", "minLength": 32 }, "description": "Shared secret matching BREVO_WEBHOOK_SECRET. Mismatch returns 401. Never log or echo this value." }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "description": "Brevo transactional webhook event (single-event payload). See https://developers.brevo.com/docs/transactional-webhooks. Only the fields below are consumed; additional fields (tags, link, ts_epoch, ts_event, sending_ip, message_id_v3, ...) are accepted and ignored.",
                "properties": {
                  "event":      { "type": "string", "enum": ["delivered","soft_bounce","hard_bounce","blocked","complaint","spam","deferred","unsubscribed","error"], "description": "Brevo event name. 'spam' is an alias for 'complaint' (older integrations)." },
                  "email":      { "type": "string", "description": "Recipient address. Logged masked-only." },
                  "message-id": { "type": "string", "description": "Brevo's opaque messageId — the lookup key against forwarder_sent.provider_id." },
                  "subject":    { "type": "string", "description": "Subject line at send time. Optional; not persisted." },
                  "reason":     { "type": "string", "description": "Free-text reason for failure events (bounces, blocked, error). Logged but not persisted; raw payload is never stored." },
                  "date":       { "type": "string", "description": "Brevo-side event timestamp. We stamp delivered_at = NOW() server-side instead of trusting upstream clock." }
                },
                "required": ["event"]
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Event accepted. Body: { ok:true, matched:<bool>, event:<string> } when a ledger row was located; { ok:true, skipped:true } when the event type isn't tracked; { ok:true, matched:false, event:<string> } when no row matched the messageId (logged WARN — Brevo dashboard test / cross-cluster traffic / legacy row)." },
          "400": { "description": "invalid_payload (malformed JSON) OR payload_too_large (> 16 KiB)" },
          "401": { "description": "unauthorized — URL :secret did not match BREVO_WEBHOOK_SECRET" },
          "500": { "description": "internal_error — DB unreachable. Brevo retries with exponential backoff, which is the right behaviour." }
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
    "/api/v1/stacks/{slug}": {
      "get": {
        "summary": "Get a single stack by slug",
        "description": "Returns one stack and its current status — used by the dashboard to poll build progress after POST /stacks/new without fetching the full list.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "name": "slug", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Stack", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "stack_id": { "type": "string", "description": "Slug (same as path /stacks/{slug})" }, "name": { "type": "string" }, "status": { "type": "string" }, "tier": { "type": "string" }, "namespace": { "type": "string" }, "env": { "type": "string", "description": "Deployment env (production / staging / dev / ...)." }, "parent_stack_id": { "type": "string", "description": "Root stack id when this is a promoted child. Empty string for the root." }, "created_at": { "type": "string", "format": "date-time" } } } } } },
          "401": { "description": "Unauthorized" },
          "404": { "description": "Stack not found" }
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
    "/api/v1/usage/wall": {
      "get": {
        "summary": "Quota-wall nudge state (dashboard upgrade banner)",
        "description": "Returns the most recent near_quota_wall row written by the worker's QuotaWallNudgeWorker, scoped to the caller's team and bounded to the last 24h. The dashboard polls this on mount and every 5 minutes to decide whether to render the upgrade banner. Team-tier callers always get near_wall=false (team is unlimited). Fails open — a DB error returns 503 rather than a misleading near_wall=false.",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Usage-wall state", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "near_wall": { "type": "boolean", "description": "True when the team has crossed the 80% quota threshold within the freshness window." }, "at": { "type": "string", "format": "date-time", "description": "When the worker recorded the threshold crossing. Present only when near_wall is true." }, "tier": { "type": "string", "description": "Team plan tier at the time the row was written." }, "axis": { "type": "string", "description": "Which quota axis tripped (e.g. 'storage')." }, "service": { "type": "string", "description": "Which service the axis belongs to (postgres / redis / mongodb / …)." }, "current": { "type": "integer", "description": "Measured usage at the time of the crossing." }, "limit": { "type": "integer", "description": "The tier limit the usage is approaching." }, "percent_used": { "type": "number", "description": "current / limit as a percent." } }, "required": ["ok", "near_wall"] } } } },
          "401": { "description": "Unauthorized" },
          "503": { "description": "Failed to read usage-wall state from the platform DB", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/api/v1/experiments/converted": {
      "post": {
        "summary": "A/B-experiment conversion sink",
        "description": "The dashboard fires this from the click handler on an experimental UI element (e.g. the 'Upgrade to Pro' button) before navigating to checkout. Writes an audit_log row (kind = 'experiment.conversion') tagged with the variant the user clicked. The server validates that the experiment + variant are registered AND that the supplied variant matches the variant the server would itself bucket this team into — a mismatch (usually a stale cached /auth/me across a salt rotation) returns 400. The audit write failing still returns 200 (the write is logged, not fatal to the click flow).",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": {
            "experiment": { "type": "string", "description": "Registered experiment name (e.g. 'upgrade_button')." },
            "variant": { "type": "string", "description": "The variant the client rendered. Must be a registered variant of the experiment AND match the server's bucket for this team." },
            "action": { "type": "string", "maxLength": 64, "description": "Short action identifier (e.g. 'checkout_started'). Truncated to 64 chars." }
          }, "required": ["experiment", "variant"] } } }
        },
        "responses": {
          "200": { "description": "Conversion recorded", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" } } } } } },
          "400": { "description": "Invalid body, unknown_experiment, invalid_variant, or variant_mismatch", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/v1/audit": {
      "get": {
        "summary": "Customer-facing audit log export (W7-C compliance)",
        "description": "Returns audit events scoped to the caller's team for compliance review. Includes rows where team_id = caller_team OR metadata.resource_id resolves to a resource the caller owns. Rows whose kind starts with 'admin.' are NEVER returned regardless of tier — those are reserved for the internal operator audit feed (compliance traceability for operator activity is handled through a separate channel). Pagination is cursor-style via ?before=<created_at>. The response body echoes the resolved lookback_days so the caller knows the tier window. Actor emails are partially redacted on the wire ('m***@example.com') to balance traceability against PII exposure; user_id stays in full so the buyer can correlate against their own team-membership records. Emit sites include the existing onboarding.claimed, subscription.*, promote.*, payment.grace_* kinds plus W7-C-added data-access kinds resource.read, resource.list_by_team, connection_url.decrypted. Tier gate: anonymous/free → 402, hobby = 30d lookback, hobby_plus = 60d, pro = 90d, growth/team = unlimited.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 50, "minimum": 1, "maximum": 200 }, "description": "Page size. Default 50, max 200. The endpoint returns at most this many rows per call; use ?before=<next_cursor> to fetch older rows." },
          { "name": "before", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" }, "description": "Cursor — only return rows with created_at strictly older than this RFC3339 timestamp. Pass the previous response's next_cursor field here." },
          { "name": "kind", "in": "query", "required": false, "schema": { "type": "string" }, "description": "Exact kind match (e.g. 'resource.read', 'subscription.upgraded'). Admin.* kinds always return zero rows even when explicitly requested." },
          { "name": "since", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" }, "description": "Inclusive lower bound (RFC3339). The tier lookback floor still wins — if you ask for a wider window than your plan allows you only see your plan's window." },
          { "name": "until", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" }, "description": "Exclusive upper bound (RFC3339)." }
        ],
        "responses": {
          "200": { "description": "Audit event list", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" }, "items": { "type": "array", "items": { "$ref": "#/components/schemas/AuditExportItem" } }, "total_returned": { "type": "integer", "description": "Number of items in this page." }, "next_cursor": { "type": ["string", "null"], "format": "date-time", "description": "Pass to ?before= on the next call. Null when this is the last page (the page wasn't full)." }, "lookback_days": { "type": "integer", "description": "Plan-derived hard floor. -1 means unlimited (growth/team)." }, "tier": { "type": "string", "description": "The caller's resolved plan tier at request time." } } } } } },
          "401": { "description": "Unauthorized" },
          "402": { "description": "Plan does not include audit export. Anonymous/free → upgrade required.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } },
          "400": { "description": "Invalid query parameter (e.g. malformed ?before / ?since / ?until — must be RFC3339)." }
        }
      }
    },
    "/api/v1/audit.csv": {
      "get": {
        "summary": "Customer-facing audit log export — CSV stream (W7-C compliance)",
        "description": "Same filter/scope/redaction rules as GET /api/v1/audit, but the response is streamed text/csv suitable for piping into a customer's own SIEM. Columns: id, kind, created_at, actor, actor_user_id, actor_email_masked, resource_id, resource_type, summary, metadata. Streaming guarantees: rows are encoded + flushed one at a time so a Team-tier customer with months of history does not OOM the api pod. The same admin.* exclusion and tier lookback floor apply.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 200, "minimum": 1, "maximum": 200 }, "description": "Per-call cap. CSV defaults to the max (200) because there is no client-friendly cursor in CSV — pass ?before/?since/?until for additional chunks." },
          { "name": "before", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" } },
          { "name": "kind", "in": "query", "required": false, "schema": { "type": "string" } },
          { "name": "since", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" } },
          { "name": "until", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" } }
        ],
        "responses": {
          "200": { "description": "Audit event CSV. Header row is always emitted. Content-Disposition: attachment; filename=\"audit.csv\".", "content": { "text/csv": { "schema": { "type": "string" } } } },
          "401": { "description": "Unauthorized" },
          "402": { "description": "Plan does not include audit export. Anonymous/free → upgrade required.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/api/v1/capabilities": {
      "get": {
        "summary": "Tier capabilities matrix (public)",
        "description": "Returns the full tier matrix as JSON so AI agents can discover 'what can I do at which tier' without provisioning-and-failing or scraping llms.txt. Iterates the live plans registry — a tier added in plans.yaml automatically appears here without a code change. Tiers are sorted by the upgrade ladder (anonymous → free → hobby → hobby_plus → pro → growth → team — pricing order: hobby $9 < hobby_plus $19 < pro $49 < growth $99 < team $199). *_yearly variants are excluded; their annual discount surfaces on the canonical monthly row via annual_discount_percent. Public, unauthenticated.",
        "responses": {
          "200": { "description": "Capability matrix", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CapabilitiesResponse" } } } },
          "503": { "description": "plans.yaml registry failed to load", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/api/v1/incidents": {
      "get": {
        "summary": "Current and recent incidents (public)",
        "description": "Returns the open incident feed. Today the items array is always empty — the field is reserved for the future incident-feed worker, so dashboards and status pages can wire the response now and have it light up as soon as the worker writes its first row. Public, unauthenticated.",
        "responses": {
          "200": { "description": "Incident list", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/IncidentsResponse" } } } }
        }
      }
    },
    "/api/v1/status": {
      "get": {
        "summary": "Live component-level health (public, cached 60s)",
        "description": "Server-side aggregate driven by the worker's uptime_prober job (about one probe per minute per component). Replaces the dashboard's prior client-side probe loop. Response includes per-component current_status (operational | degraded | down), 7d and 30d uptime percentages, 96 booleans of 15-minute-bucketed last_24h_samples for the bar chart, and a current_incidents array (empty until the incident-feed worker ships). Cached 60s in Redis under one shared key — the payload is identical for every caller. Public, unauthenticated.",
        "responses": {
          "200": {
            "description": "Status payload",
            "headers": {
              "Cache-Control": {
                "schema": { "type": "string", "example": "public, max-age=60, stale-while-revalidate=60" },
                "description": "60s public cache (the response is identical for every caller). stale-while-revalidate=60 lets browsers serve the stale value during the next refresh — useful during incidents when the API itself may be slow."
              }
            },
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StatusResponse" } } }
          },
          "500": { "description": "Failed to compute status (transient DB error). Retry with backoff.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/llms.txt": {
      "get": {
        "summary": "Agent discovery doc (302 to marketing)",
        "description": "Agents that land on api.instanode.dev/llms.txt are redirected (302 Found) to instanode.dev/llms.txt — the source-of-truth surface for the LLM-targeted product docs. Companion of /llms-full.txt. Public, no auth.",
        "responses": {
          "302": { "description": "Redirect to https://instanode.dev/llms.txt", "headers": { "Location": { "schema": { "type": "string", "format": "uri" } } } }
        }
      }
    },
    "/llms-full.txt": {
      "get": {
        "summary": "Full LLM-targeted product docs (302 to marketing)",
        "description": "Agents that land on api.instanode.dev/llms-full.txt are redirected (302 Found) to instanode.dev/llms-full.txt — the long-form companion to /llms.txt. Public, no auth.",
        "responses": {
          "302": { "description": "Redirect to https://instanode.dev/llms-full.txt", "headers": { "Location": { "schema": { "type": "string", "format": "uri" } } } }
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
      "ReadinessResponse": {
        "type": "object",
        "description": "Multi-component readiness envelope returned by GET /readyz. Each check runs in parallel behind a 10-15s cache; overall summarises the worst-status across checks, applying the per-service criticality matrix (platform_db + provisioner_grpc are critical → failed → 503; everything else degrades to 200 + overall=degraded).",
        "properties": {
          "overall": { "type": "string", "enum": ["ok", "degraded", "failed"], "description": "Aggregated status across all checks. 'ok' = every check ok; 'degraded' = at least one non-critical check failed/degraded; 'failed' = at least one critical check failed (response code is 503 only in this case)." },
          "service": { "type": "string", "description": "Identifier for the service answering the probe (e.g. 'instant-api', 'instant-worker', 'instant-provisioner')." },
          "commit_id": { "type": "string", "description": "Short git SHA of the running binary (same value as /healthz.commit_id)." },
          "checks": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "name": { "type": "string", "description": "Stable component identifier (e.g. 'platform_db', 'provisioner_grpc', 'brevo', 'razorpay', 'redis', 'do_spaces', 'river')." },
                "status": { "type": "string", "enum": ["ok", "degraded", "failed"], "description": "Per-component status. Critical components only impact overall=failed; non-critical only impact overall=degraded." },
                "latency_ms": { "type": "integer", "description": "Wall-clock duration of the last probe in milliseconds." },
                "last_error": { "type": "string", "description": "Last observed error message (only present when status != 'ok'). Scrubbed of credentials." },
                "last_check_at": { "type": "string", "format": "date-time", "description": "RFC3339 UTC timestamp of the last probe (may be older than the request if the cache served this response)." }
              }
            }
          }
        }
      },
      "ProvisionRequest": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name": { "type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[A-Za-z0-9][A-Za-z0-9 _-]*$", "description": "REQUIRED. Short human-readable label for this resource (1-64 chars after trimming; must start with a letter or digit, then letters/digits/spaces/underscores/hyphens). Missing/empty → 400 name_required. Bad format/length → 400 invalid_name." },
          "env": { "type": "string", "description": "Optional environment scope (production / staging / dev / ...). Defaults to 'development' (migration 026) so accidental no-env provisions land in the lowest-stakes bucket. Anonymous tier is always 'development'. Every provisioning response echoes the resolved env so callers know which bucket they landed in.", "default": "development" },
          "parent_resource_id": { "type": "string", "format": "uuid", "description": "Optional. Link the new resource into an existing env-twin family — the new row becomes a sibling of the parent (same family root, different env). Validated against same-team + same-type + no-duplicate-twin before provisioning. Authenticated callers only. Errors: 400 type_mismatch (parent is a different resource_type), 403 forbidden_parent_resource (parent belongs to another team), 404 parent_not_found, 409 twin_exists (family already has a row in this env). See GET /api/v1/resources/{id}/family + /api/v1/resources/families." }
        }
      },
      "DBProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid", "description": "Resource row id." },
          "token": { "type": "string", "format": "uuid" },
          "name": { "type": "string", "description": "Human-readable label supplied on the request (or the generated default)." },
          "connection_url": { "type": "string", "description": "postgres:// connection string with pgvector pre-installed. Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal postgres:// URL routed via instant-pg-proxy. Use this when calling from a workload deployed inside the instanode cluster (e.g. an app started by /deploy/new) — the public hostname does not hairpin reliably." },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket the resource landed in (defaults to 'development' when env was omitted — see migration 026)." },
          "env_override_reason": { "type": "string", "description": "Present only when the request omitted env and the API defaulted it (value 'default_no_env_specified'). Absent when env was sent explicitly." },
          "expires_at": { "type": "string", "format": "date-time", "description": "Anonymous-tier only. RFC3339 timestamp at which the resource auto-expires (24h TTL). Absent on authenticated provisions (no auto-expiry). Added by T19 P0-2 (BugHunt 2026-05-20) so the TTL contract matches storage/webhook." },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "connections": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "dedicated": { "type": "boolean", "description": "True when the resource was provisioned on dedicated (single-tenant) infrastructure rather than the shared pool. Authenticated provisions only." },
          "warning": { "type": "string", "description": "Present only when the resource is already over its storage limit at provision time — accompanied by the X-Instant-Notice: storage_limit_reached response header." },
          "note": { "type": "string" },
          "upgrade_jwt": { "type": "string", "description": "Anonymous-tier only. Signed JWT the agent can POST to /claim with an email to convert the anonymous resource into a claimed (authenticated) one — no need to string-parse the upgrade URL. Absent on authenticated provisions." },
          "upgrade": { "type": "string", "format": "uri", "description": "Anonymous-tier only. Pre-baked GET /start?t=<upgrade_jwt> URL the agent can hand to the user to drive the dashboard claim flow." }
        }
      },
      "VectorProvisionRequest": {
        "type": "object",
        "description": "Request body for POST /vector/new. Like ProvisionRequest plus the optional dimensions hint. NOTE: unlike /db/new, the name field on /vector/new is optional — it is sanitized (invalid UTF-8 → 400 invalid_name) but a missing/empty name is accepted and a default label is generated. Send a name explicitly for parity with the other provisioning endpoints.",
        "properties": {
          "name": { "type": "string", "maxLength": 64, "description": "Optional human-readable label. Sanitized server-side; invalid UTF-8 → 400 invalid_name. A missing/empty name is accepted (a default is generated) — this is the one provisioning endpoint where name is not required." },
          "env": { "type": "string", "description": "Optional environment scope. Defaults to 'development'.", "default": "development" },
          "parent_resource_id": { "type": "string", "format": "uuid", "description": "Optional family-link parent (authenticated callers only). See ProvisionRequest." },
          "dimensions": { "type": "integer", "minimum": 1, "maximum": 16000, "default": 1536, "description": "Default embedding dimension for documentation. pgvector lets you pick per-column dimensions at table-create time, so this is purely informational. Defaults to 1536 (OpenAI text-embedding-ada-002 / text-embedding-3-small). Use 3072 for text-embedding-3-large." }
        }
      },
      "VectorProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid", "description": "Resource row id." },
          "token": { "type": "string", "format": "uuid" },
          "name": { "type": "string", "description": "Human-readable label supplied on the request (or the generated default)." },
          "connection_url": { "type": "string", "description": "postgres:// connection string with the pgvector extension already installed (CREATE EXTENSION vector ran during provisioning). Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal postgres:// URL routed via instant-pg-proxy. Use this when calling from a workload deployed inside the instanode cluster." },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket (defaults to 'development' when omitted)." },
          "env_override_reason": { "type": "string", "description": "Present only when env was omitted and defaulted ('default_no_env_specified')." },
          "expires_at": { "type": "string", "format": "date-time", "description": "Anonymous-tier only. RFC3339 24h-TTL expiry. T19 P0-2 (BugHunt 2026-05-20)." },
          "extension": { "type": "string", "enum": ["pgvector"], "description": "Always 'pgvector' for /vector/new. Declared so clients can confirm the extension is present without querying pg_extension." },
          "dimensions": { "type": "integer", "description": "Echo of the requested dimensions hint (defaults to 1536). Informational only — pgvector enforces dimensions per column, not per database." },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "connections": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "dedicated": { "type": "boolean", "description": "True when the resource was provisioned on dedicated (single-tenant) infrastructure rather than the shared pool. Authenticated provisions only." },
          "warning": { "type": "string", "description": "Present only when the resource is already over its storage limit at provision time — accompanied by the X-Instant-Notice: storage_limit_reached response header." },
          "note": { "type": "string" },
          "upgrade_jwt": { "type": "string", "description": "Anonymous-tier only. Signed JWT the agent can POST to /claim with an email. Absent on authenticated provisions." },
          "upgrade": { "type": "string", "format": "uri", "description": "Anonymous-tier only. Pre-baked GET /start?t=<upgrade_jwt> URL for the dashboard claim flow." }
        }
      },
      "CacheProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid", "description": "Resource row id." },
          "token": { "type": "string", "format": "uuid" },
          "name": { "type": "string", "description": "Human-readable label supplied on the request (or the generated default)." },
          "connection_url": { "type": "string", "description": "redis:// connection string with ACL namespace isolation. Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal redis:// URL routed via instant-redis-proxy. Use this when calling from a workload deployed inside the instanode cluster." },
          "key_prefix": { "type": "string", "description": "All keys must use this prefix for namespace isolation" },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket (defaults to 'development' when omitted)." },
          "env_override_reason": { "type": "string", "description": "Present only when env was omitted and defaulted ('default_no_env_specified')." },
          "expires_at": { "type": "string", "format": "date-time", "description": "Anonymous-tier only. RFC3339 24h-TTL expiry. T19 P0-2 (BugHunt 2026-05-20)." },
          "limits": { "type": "object", "properties": { "memory_mb": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "dedicated": { "type": "boolean", "description": "True when the resource was provisioned on dedicated (single-tenant) infrastructure rather than the shared pool. Authenticated provisions only." },
          "warning": { "type": "string", "description": "Present only when the resource is already over its storage limit at provision time — accompanied by the X-Instant-Notice: storage_limit_reached response header." },
          "note": { "type": "string" },
          "upgrade_jwt": { "type": "string", "description": "Anonymous-tier only. Signed JWT the agent can POST to /claim with an email. Absent on authenticated provisions." },
          "upgrade": { "type": "string", "format": "uri", "description": "Anonymous-tier only. Pre-baked GET /start?t=<upgrade_jwt> URL for the dashboard claim flow." }
        }
      },
      "NoSQLProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid", "description": "Resource row id." },
          "token": { "type": "string", "format": "uuid" },
          "name": { "type": "string", "description": "Human-readable label supplied on the request (or the generated default)." },
          "connection_url": { "type": "string", "description": "mongodb:// connection string scoped to a per-token database. Use this from external callers." },
          "internal_url": { "type": "string", "description": "Cluster-internal mongodb:// URL routed via instant-mongo-proxy. Use this when calling from a workload deployed inside the instanode cluster." },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket (defaults to 'development' when omitted)." },
          "env_override_reason": { "type": "string", "description": "Present only when env was omitted and defaulted ('default_no_env_specified')." },
          "expires_at": { "type": "string", "format": "date-time", "description": "Anonymous-tier only. RFC3339 24h-TTL expiry. T19 P0-2 (BugHunt 2026-05-20)." },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "connections": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "dedicated": { "type": "boolean", "description": "True when the resource was provisioned on dedicated (single-tenant) infrastructure rather than the shared pool. Authenticated provisions only." },
          "warning": { "type": "string", "description": "Present only when the resource is already over its storage limit at provision time — accompanied by the X-Instant-Notice: storage_limit_reached response header." },
          "note": { "type": "string" },
          "upgrade_jwt": { "type": "string", "description": "Anonymous-tier only. Signed JWT the agent can POST to /claim with an email. Absent on authenticated provisions." },
          "upgrade": { "type": "string", "format": "uri", "description": "Anonymous-tier only. Pre-baked GET /start?t=<upgrade_jwt> URL for the dashboard claim flow." }
        }
      },
      "QueueProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid", "description": "Resource row id." },
          "token": { "type": "string", "format": "uuid" },
          "name": { "type": "string", "description": "Human-readable label supplied on the request (or the generated default)." },
          "connection_url": { "type": "string", "description": "nats:// connection string. After the operator-mode cutover (MR-P0-5, 2026-05-20) this URL is unauthenticated by itself — pair it with the embedded JWT + NKey in the credentials field below." },
          "internal_url": { "type": "string", "description": "Cluster-internal nats:// URL routed via instant-nats-proxy. Use this when calling from a workload deployed inside the instanode cluster." },
          "auth_mode": { "type": "string", "enum": ["isolated", "legacy_open"], "description": "Credential isolation mode. 'isolated' = per-tenant NATS account JWT in credentials below; 'legacy_open' = grandfathered pre-cutover queue with no auth (will be recycled). MR-P0-5 (NATS per-tenant isolation, 2026-05-20)." },
          "subject_prefix": { "type": "string", "description": "The subject namespace this resource is scoped to (e.g. 'tenant_<token>.'). Publish/subscribe under {subject_prefix}* only." },
          "credentials": {
            "type": "object",
            "description": "Per-tenant NATS credentials. Present only when auth_mode='isolated'. Use either (nats_jwt + nats_nkey) via nats.UserJWTAndSeed() or write creds_file to disk and pass to nats.UserCredentials(path).",
            "properties": {
              "auth_mode": { "type": "string" },
              "nats_jwt": { "type": "string", "description": "Signed user JWT scoped to this resource's subject prefix." },
              "nats_nkey": { "type": "string", "description": "User NKey seed (SU... format). SECRET — treat like a password." },
              "creds_file": { "type": "string", "description": "Pre-rendered .creds blob (combines JWT + NKey). Write to disk and pass path to nats.UserCredentials()." },
              "key_id": { "type": "string", "description": "Account public key (A... format). Used by the platform for credential revocation." },
              "expires_at": { "type": "string", "format": "date-time", "description": "Credential expiry. Omitted = long-lived." }
            }
          },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket (defaults to 'development' when omitted)." },
          "env_override_reason": { "type": "string", "description": "Present only when env was omitted and defaulted ('default_no_env_specified')." },
          "expires_at": { "type": "string", "format": "date-time", "description": "Anonymous-tier only. RFC3339 24h-TTL expiry. T19 P0-2 (BugHunt 2026-05-20)." },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "expires_in": { "type": "string", "description": "Anonymous-only" } }, "description": "Queue storage cap. storage_mb is read from plans.yaml for the resolved tier." },
          "dedicated": { "type": "boolean", "description": "True when the resource was provisioned on dedicated (single-tenant) infrastructure rather than the shared pool." },
          "note": { "type": "string" },
          "upgrade_jwt": { "type": "string", "description": "Anonymous-tier only. Signed JWT the agent can POST to /claim with an email. Absent on authenticated provisions." },
          "upgrade": { "type": "string", "format": "uri", "description": "Anonymous-tier only. Pre-baked GET /start?t=<upgrade_jwt> URL for the dashboard claim flow." }
        }
      },
      "WebhookProvisionResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "id": { "type": "string", "format": "uuid", "description": "Resource row id." },
          "token": { "type": "string", "format": "uuid" },
          "name": { "type": "string", "description": "Human-readable label supplied on the request (T19 P1-6 / T14, BugHunt 2026-05-20). Mandatory on input; now echoed in the response so the field is round-trippable." },
          "receive_url": { "type": "string", "description": "Public URL that accepts any HTTP method and stores the payload" },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket (defaults to 'development' when omitted)." },
          "env_override_reason": { "type": "string", "description": "Present only when env was omitted and defaulted ('default_no_env_specified')." },
          "limits": { "type": "object", "properties": { "requests_stored": { "type": "integer" }, "expires_in": { "type": "string" } } },
          "expires_at": { "type": "string", "format": "date-time" },
          "note": { "type": "string" },
          "upgrade_jwt": { "type": "string", "description": "Anonymous-tier only. Signed JWT the agent can POST to /claim with an email. Absent on authenticated provisions." },
          "upgrade": { "type": "string", "format": "uri", "description": "Anonymous-tier only. Pre-baked GET /start?t=<upgrade_jwt> URL for the dashboard claim flow." }
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
          "endpoint": { "type": "string", "description": "S3-compatible endpoint host (e.g. minio.instant-data.svc.cluster.local:9000 / r2.instanode.dev)" },
          "access_key_id": { "type": "string", "description": "Present in credential modes only (shared-master-key / prefix-scoped / prefix-scoped-temporary). Omitted in broker mode." },
          "secret_access_key": { "type": "string", "description": "Shown ONCE — store now; rotation requires re-provisioning. Omitted in broker mode." },
          "session_token": { "type": "string", "description": "Present only when mode=prefix-scoped-temporary (R2 temp-creds / S3 STS). Pass this to your S3 SDK as the session token to complete the credential triple." },
          "mode": { "type": "string", "enum": ["shared-master-key", "prefix-scoped", "prefix-scoped-temporary", "broker", "dedicated-bucket"], "description": "Isolation mode the tenant is on. 'shared-master-key' = DO Spaces legacy (every tenant holds the master key, prefix-by-convention). 'prefix-scoped' = backend IAM enforces s3:prefix against <prefix>/* (R2, S3, MinIO). 'prefix-scoped-temporary' = same but credentials expire (STS). 'broker' = NO long-lived credential issued; use POST /storage/{token}/presign for short-lived signed URLs. 'dedicated-bucket' = reserved for the paid-tier-on-DO-Spaces flow (not yet auto-issued)." },
          "presign_url": { "type": "string", "description": "Path to the broker-mode access endpoint. Present only when mode=broker. POST to this URL with { operation, key, expires_in } to mint a short-lived signed URL." },
          "broker_reason": { "type": "string", "description": "Human-readable note explaining why broker mode was selected (e.g. 'backend-has-no-prefix-scoping'). Present only when mode=broker." },
          "note_isolation": { "type": "string", "description": "Human-readable explanation of the isolation tradeoff. Present only when mode=broker." },
          "agent_action": { "type": "string", "description": "Machine-readable hint for an automated caller. Present only when mode=broker; value is 'use_presign_endpoint'." },
          "prefix": { "type": "string", "description": "Object-key prefix all writes must use for isolation" },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket (defaults to 'development' when omitted)." },
          "env_override_reason": { "type": "string", "description": "Present only when env was omitted and defaulted ('default_no_env_specified')." },
          "limits": { "type": "object", "properties": { "storage_mb": { "type": "integer" }, "expires_in": { "type": "string", "description": "Anonymous-only" } } },
          "warning": { "type": "string", "description": "Present only when the bucket is already over its storage limit at provision time — accompanied by the X-Instant-Notice: storage_limit_reached response header." },
          "expires_at": { "type": "string", "format": "date-time", "description": "Anonymous-tier only. RFC3339 timestamp at which the resource auto-expires (24h TTL)." },
          "note": { "type": "string", "description": "Anonymous-tier upgrade hint emitted on the 201 happy path (T19 P1-5, BugHunt 2026-05-20). Was previously undocumented; the schema only listed credentials_note which only appears on the dedup path." },
          "credentials_note": { "type": "string", "description": "Present only on the rate-limited anonymous dedup response, where access_key_id/secret_access_key are NOT re-emitted (the secret is minted once at provision time and never stored)." },
          "upgrade_jwt": { "type": "string", "description": "Anonymous-tier only. Signed JWT the agent can POST to /claim with an email. Absent on authenticated provisions." },
          "upgrade": { "type": "string", "format": "uri", "description": "Anonymous-tier only. Pre-baked GET /start?t=<upgrade_jwt> URL for the dashboard claim flow." }
        }
      },
      "DeployItem": {
        "type": "object",
        "description": "Deployment row as returned by GET /deploy/{id} and the list endpoint. Shape matches handlers.deploymentToMap. The env field is redaction-filtered: credential-bearing values are masked '***' and the internal _name key is stripped.",
        "properties": {
          "id": { "type": "string", "format": "uuid" },
          "token": { "type": "string", "description": "Public-facing alias for app_id (same 8-char value)." },
          "app_id": { "type": "string", "description": "8-char public identifier used in the URL" },
          "provider_id": { "type": "string", "description": "Opaque compute-backend handle (k8s namespace/deployment ref)." },
          "name": { "type": "string", "description": "Human-readable label supplied at creation time (stored in env_vars._name; emitted as a top-level field for convenience). Empty string when created before mandatory-naming was enforced." },
          "url": { "type": "string" },
          "status": { "type": "string", "enum": ["building", "deploying", "healthy", "failed", "stopped", "expired"] },
          "tier": { "type": "string" },
          "environment": { "type": "string", "description": "Environment scope (production / staging / dev / ...)." },
          "env": { "type": "object", "additionalProperties": { "type": "string" }, "description": "Application env vars. Credential values are masked '***'; the internal _name key is never present." },
          "port": { "type": "integer" },
          "private": { "type": "boolean", "description": "True when the deployment is IP-allowlist gated (Pro+ feature)." },
          "allowed_ips": { "type": "array", "items": { "type": "string" }, "description": "IP/CIDR allowlist for a private deployment. Always present (empty [] for public deploys)." },
          "team_id": { "type": "string", "format": "uuid" },
          "created_at": { "type": "string", "format": "date-time" },
          "updated_at": { "type": "string", "format": "date-time" },
          "error": { "type": "string", "description": "Present only when the deployment carries a non-empty error_message." },
          "resource_id": { "type": "string", "format": "uuid", "description": "Present only when the deployment is linked to a provisioned resource." },
          "notify_webhook": { "type": "string", "description": "Caller-supplied status webhook URL (echoed back; the plaintext secret is never returned)." },
          "notify_state": { "type": "string", "description": "Lifecycle state of the notify webhook." },
          "notify_attempts": { "type": "integer", "description": "Notify-webhook delivery attempt count. Present only when notify_webhook is configured." },
          "notify_secret_set": { "type": "boolean", "description": "Whether a notify-webhook signing secret is configured. Present only when notify_webhook is configured." },
          "ttl_policy": { "type": "string", "description": "Either 'permanent' or an auto-expiry policy. Always present so callers can branch on permanence." },
          "expires_at": { "type": "string", "format": "date-time", "description": "Auto-expiry timestamp. Omitted entirely when ttl_policy is permanent." },
          "reminders_sent": { "type": "integer", "description": "Count of TTL-expiry reminder emails sent. Present only when expires_at is set." },
          "make_permanent_url": { "type": "string", "description": "Absolute URL to convert an auto-expiring deploy to permanent. Present only when expires_at is set." },
          "extend_ttl_url": { "type": "string", "description": "Absolute URL to extend the auto-expiry window. Present only when expires_at is set." },
          "failure": {
            "type": "object",
            "description": "Structured failure autopsy. Present only when status is 'failed' and an autopsy row exists.",
            "properties": {
              "reason": { "type": "string", "description": "Failure classification (e.g. build_failed, deadline_exceeded)." },
              "event": { "type": "string", "description": "Raw error string from the failed stage." },
              "last_lines": { "type": "array", "items": { "type": "string" }, "description": "Tail of the kaniko build log captured at failure time." },
              "hint": { "type": "string", "description": "Human-readable remediation hint." },
              "occurred_at": { "type": "string", "format": "date-time" }
            }
          }
        }
      },
      "ClaimRequest": {
        "type": "object",
        "required": ["token", "email"],
        "description": "Body for POST /claim. The token field is the canonical field name (2026-05-20). The legacy jwt field is still accepted as a deprecated alias for backward compatibility with the dashboard, sdk-go, and existing curl recipes — when both are present, token wins.",
        "properties": {
          "token": { "type": "string", "description": "Onboarding token. Read this directly from the upgrade_jwt field of any anonymous provisioning response — no need to string-parse the upgrade URL." },
          "jwt": { "type": "string", "deprecated": true, "description": "Deprecated alias for token (kept for backward compatibility). New callers should send token instead." },
          "team_name": { "type": "string", "description": "Optional human-readable team name. Defaults to the email when omitted." },
          "email": { "type": "string", "format": "email", "description": "RFC 5322 email address. Validated server-side via net/mail.ParseAddress — invalid syntax returns 400 with error=invalid_email_format." }
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
            "items": { "$ref": "#/components/schemas/ResourceItem" }
          }
        }
      },
      "AuthMeResponse": {
        "type": "object",
        "description": "Current user + team info. Shape matches handlers.GetCurrentUser. Several fields are emitted only conditionally — their absence is itself signal (e.g. is_platform_admin is never sent empty).",
        "properties": {
          "ok": { "type": "boolean" },
          "user_id": { "type": "string", "format": "uuid" },
          "team_id": { "type": "string", "format": "uuid" },
          "email": { "type": "string" },
          "tier": { "type": "string", "enum": ["anonymous", "free", "hobby", "hobby_plus", "pro", "team", "growth"], "description": "The team's current plan tier." },
          "plan_display_name": { "type": "string", "description": "Human-readable plan name for the current tier (from plans.Registry)." },
          "experiments": { "type": "object", "additionalProperties": { "type": "string" }, "description": "A/B experiment variant assignments keyed by experiment name, bucketed by team_id." },
          "is_platform_admin": { "type": "boolean", "description": "Present (always true) only when the caller's email is on the ADMIN_EMAILS allowlist. Absent for every non-admin caller." },
          "admin_path_prefix": { "type": "string", "description": "Unguessable URL segment for the admin customer-management endpoints. Present only for admins when ADMIN_PATH_PREFIX is configured." },
          "read_only": { "type": "boolean", "description": "Present (always true) only when the session JWT carries read_only=true — i.e. an admin impersonation session. Absent for normal sessions." },
          "impersonated_by": { "type": "string", "description": "Email of the admin who started an impersonation session. Present only on impersonated sessions." }
        }
      },
      "StackRequest": {
        "type": "object",
        "description": "Multipart form. The 'manifest' field is the YAML instant.yaml text; each service declared under services: must have a matching multipart field named after the service whose content is a gzipped tar archive of that service's build context.",
        "properties": {
          "manifest": { "type": "string", "description": "instant.yaml contents. Example: services:\\n  api:\\n    build: ./api\\n    port: 8080\\n  web:\\n    build: ./web\\n    port: 8080\\n    expose: true\\n    env: { API_URL: service://api }" },
          "name": { "type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[A-Za-z0-9][A-Za-z0-9 _-]*$", "description": "REQUIRED. Short human-readable label for this stack (1-64 chars after trimming; must start with a letter or digit, then letters/digits/spaces/underscores/hyphens). Missing/empty → 400 name_required. Bad format/length → 400 invalid_name." },
          "<service-name>": { "type": "string", "format": "binary", "description": "One field per service declared in the manifest, named after the service. Value is a gzipped tar archive containing that service's Dockerfile + source. Total request body cap is 200 MB." }
        },
        "required": ["manifest", "name"]
      },
      "StackResponse": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "stack_id": { "type": "string", "description": "Format: stk-<8-char-hex>. Use this for GET /stacks/{slug}." },
          "status": { "type": "string", "enum": ["building", "deploying", "healthy", "failed", "stopped"], "description": "Overall stack status. 'healthy' only when every service is healthy." },
          "tier": { "type": "string" },
          "env": { "type": "string", "description": "Resolved environment bucket the stack landed in (defaults to 'development' when env was omitted — see migration 026 and CLAUDE.md convention #11). T19 P0-3 (BugHunt 2026-05-20): handler echoes env (stack.go:811) so callers know which bucket they landed in." },
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
          "email": { "type": "string", "format": "email", "description": "Authenticated user's email. Best-effort enrichment from the users table; absent on DB lookup failure." },
          "tier": { "type": "string", "enum": ["anonymous", "free", "hobby", "hobby_plus", "pro", "team", "growth"], "description": "Canonical alias of plan_tier — the dashboard's preferred field name. Best-effort enrichment from the teams table; absent on DB lookup failure." },
          "plan_tier": { "type": "string", "enum": ["anonymous", "free", "hobby", "hobby_plus", "pro", "team", "growth"], "description": "Legacy alias of tier kept for agents that already key off it. Best-effort enrichment from the teams table; absent on DB lookup failure" }
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
        "description": "Provisioned resource row. Shape matches handlers.resourceToMap. connection_url is NEVER included. Several fields are emitted only when their backing column is non-NULL.",
        "properties": {
          "id": { "type": "string", "format": "uuid" },
          "token": { "type": "string", "format": "uuid" },
          "resource_type": { "type": "string", "enum": ["postgres", "redis", "mongodb", "queue", "storage", "webhook", "vector"] },
          "name": { "type": "string", "description": "Caller-supplied resource name. Present only when set." },
          "env": { "type": "string", "description": "Environment scope (production / staging / dev / ...)" },
          "tier": { "type": "string" },
          "status": { "type": "string" },
          "cloud_vendor": { "type": "string", "description": "Backing cloud vendor. Present only when known." },
          "country_code": { "type": "string", "description": "ISO country code of the resource region. Present only when known." },
          "storage_bytes": { "type": "integer", "description": "Current storage usage in bytes (scanner-updated)." },
          "storage_limit_bytes": { "type": "integer", "description": "Tier storage ceiling in bytes (MiB-based). -1 means unlimited. From plans.Registry." },
          "connections_limit": { "type": "integer", "description": "Tier connection ceiling. -1 means unlimited. From plans.Registry." },
          "storage_exceeded": { "type": "boolean", "description": "True when storage_bytes has reached storage_limit_bytes." },
          "expires_at": { "type": "string", "format": "date-time", "nullable": true, "description": "Auto-expiry timestamp. Present only for anonymous/TTL'd resources." },
          "paused_at": { "type": "string", "format": "date-time", "description": "When the resource was paused. Present only when paused." },
          "team_id": { "type": "string", "format": "uuid", "description": "Owning team. Present only for claimed (non-anonymous) resources." },
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
          "name": { "type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[A-Za-z0-9][A-Za-z0-9 _-]*$", "description": "REQUIRED. Short human-readable label for this deployment (1-64 chars after trimming; must start with a letter or digit, then letters/digits/spaces/underscores/hyphens). Missing/empty → 400 name_required. Bad format/length → 400 invalid_name." },
          "port": { "type": "integer", "description": "Container port (default 8080)" },
          "env": { "type": "string", "description": "Environment scope (production / staging / dev / ...). Defaults to 'development' when omitted (migration 026 — the resolved env is echoed back as 'environment' on the response so callers know which bucket they landed in)." },
          "env_vars": { "type": "string", "description": "Optional JSON object of env vars to inject into the deployed pod on the FIRST build — e.g. '{\"DATABASE_URL\":\"postgres://...\",\"REDIS_URL\":\"redis://...\"}'. Avoids the (POST /deploy/new) → (PATCH /env) → (POST /redeploy) round-trip pattern. Values may use 'vault://KEY' refs which resolve at deploy time. Keys starting with underscore are reserved and ignored." },
          "resource_bindings": { "type": "string", "description": "Optional JSON object mapping env-var-name to a resource reference. Values can be either 'family:<family_root_id>' (resolved at submit time to the family member matching the deploy's env — one manifest works across all envs) or a raw resource-token UUID (legacy path; resolves to that specific resource regardless of env). Resolved values are merged into env_vars, with explicit env_vars taking precedence on key collision. Example: '{\"DATABASE_URL\":\"family:7a3f2c91-...\",\"REDIS_URL\":\"family:9bd5f3e0-...\"}'." },
          "private": { "type": "string", "description": "Optional flag (\"true\" / \"1\" / \"yes\") that turns this into a private deploy. When set, the resulting Ingress carries an nginx whitelist-source-range annotation built from allowed_ips. Pro / Team / Growth only — hobby/anonymous/free return 402 with agent_action: \"Tell the user private deploys require Pro tier. Upgrade at https://instanode.dev/pricing — takes 30 seconds.\"" },
          "allowed_ips": { "type": "string", "description": "Comma-separated list of CIDRs or IP literals (e.g. \"1.2.3.4,10.0.0.0/8,2001:db8::/32\"). Required when private=true; max 32 entries. Each entry is validated via Go's net.ParseCIDR / net.ParseIP — invalid entries surface in the 400 message so an agent can fix the literal that broke. Larger allowlists belong in CF Access or a real VPN, not an nginx annotation." },
          "notify_webhook": { "type": "string", "description": "Optional https:// URL fired by POST when the deploy reaches a terminal state (status='healthy' or 'failed'). Lets callers subscribe instead of polling GET /deploy/:id. Rejected with 400 + agent_action if the URL is not https, the hostname is unresolvable, or resolves to a private/loopback/link-local/CGNAT IP (SSRF protection). Payload shape: { event: 'deploy.healthy' | 'deploy.failed', deploy_id, app_id, url, commit_id, build_time, duration_s, error_message? }. 2xx → notify_state='sent'; 4xx → 'failed' (no retry — user URL is broken); 5xx/network → up to 3 retries, then 'failed'." },
          "notify_webhook_secret": { "type": "string", "description": "Optional HMAC-SHA256 signing key. When set, every dispatch includes an X-InstaNode-Signature: sha256=<hex(hmac(secret, body))> header. Stored AES-256-GCM encrypted; plaintext never leaves the request. Omit to dispatch without a signature header." },
          "ttl_policy": { "type": "string", "enum": ["auto_24h", "permanent"], "description": "Wave FIX-J. Sets the deploy's lifecycle. 'auto_24h' (default for new deploys) means the deploy auto-expires 24h from creation; the response's agent_action sentence tells the LLM the three explicit routes to keep it permanent. 'permanent' opts the deploy out of TTL up front — useful for production deploys where the agent already knows the user wants it kept. Anonymous tier is FORCED to auto_24h regardless of caller intent. Team-wide default can be flipped via PATCH /api/v1/team/settings." }
        },
        "required": ["tarball", "name"]
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
              "name": { "type": "string", "description": "Human-readable label supplied at creation time (stored in env_vars._name; emitted as a top-level field for convenience). Empty string when created before mandatory-naming was enforced." },
              "url": { "type": "string", "description": "Live HTTPS URL (set once status=healthy)" },
              "status": { "type": "string", "enum": ["building", "deploying", "healthy", "failed", "stopped", "expired"] },
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
              "team_id": { "type": "string", "format": "uuid" },
              "ttl_policy": { "type": "string", "enum": ["auto_24h", "permanent", "custom"], "description": "Wave FIX-J. Lifecycle policy. 'auto_24h' = expires 24h after creation (default). 'permanent' = no TTL. 'custom' = caller-set TTL via POST /api/v1/deployments/:id/ttl." },
              "expires_at": { "type": "string", "format": "date-time", "description": "Wave FIX-J. When the deploy auto-expires. Omitted when ttl_policy='permanent'." },
              "reminders_sent": { "type": "integer", "description": "Wave FIX-J. Count of reminder emails dispatched (0..6). Present when ttl_policy != 'permanent'." },
              "make_permanent_url": { "type": "string", "description": "Wave FIX-J. Absolute https URL the LLM agent can POST to in order to opt the deploy out of TTL. Present when ttl_policy != 'permanent'." },
              "extend_ttl_url": { "type": "string", "description": "Wave FIX-J. Absolute https URL the LLM agent can POST to with {hours} to set a custom TTL. Present when ttl_policy != 'permanent'." }
            }
          },
          "note": { "type": "string" },
          "agent_action": { "type": "string", "description": "Wave FIX-J. Verbatim sentence the LLM agent relays to the user. Present on 202 responses when ttl_policy='auto_24h'; tells the user the three routes to keep the deploy permanent." }
        }
      },
      "GitHubConnection": {
        "type": "object",
        "description": "One link between a deployment and a GitHub repository. Surfaced by POST/GET /api/v1/deployments/{id}/github. The plaintext webhook_secret is NEVER part of this shape — it is returned exactly once on POST as a sibling field of the connection object.",
        "properties": {
          "id":              { "type": "string", "format": "uuid", "description": "Connection id. Doubles as the webhook_id segment of the public receive URL." },
          "app_id":          { "type": "string", "description": "Deployment short slug (e.g. '6fffcc21')." },
          "github_repo":     { "type": "string", "description": "GitHub repository in 'owner/repo' form." },
          "branch":          { "type": "string", "description": "Tracked branch. Pushes to other branches are ignored at receive time." },
          "created_at":      { "type": "string", "format": "date-time" },
          "last_deploy_at":  { "type": "string", "format": "date-time", "description": "Most recent push that triggered a deploy. Absent when no push has arrived yet." },
          "last_commit_sha": { "type": "string", "description": "Most recent commit SHA we enqueued. Powers idempotency — a duplicate push.event with the same SHA is a no-op." },
          "installation_id": { "type": "integer", "format": "int64", "description": "Optional GitHub App installation id. Absent when plain-webhook flow was used." }
        },
        "required": ["id", "app_id", "github_repo", "branch", "created_at"]
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
          "tier": { "type": "string", "enum": ["anonymous", "free", "hobby", "hobby_plus", "pro", "team", "growth"], "description": "Current plan tier from the team record" },
          "subscription_status": { "type": "string", "enum": ["none", "active", "cancelled"], "description": "'none' when no Razorpay subscription exists; 'cancelled' when Razorpay reports cancelled / completed / expired or cancel_at_cycle_end=true; 'active' otherwise. The platform has no trial period (see policy memory project_no_trial_pay_day_one.md); hobby/pro/team are paid from day one" },
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
          "tier":              { "type": "string", "description": "Current plan tier from the team record. Mirrored here so the sidebar doesn't need a second /billing fetch just to render the upgrade card. Values mirror teams.plan_tier — includes monthly canonical names and their *_yearly variants.", "enum": ["anonymous", "free", "hobby", "hobby_plus", "growth", "pro", "team", "hobby_yearly", "hobby_plus_yearly", "growth_yearly", "pro_yearly", "team_yearly"] },
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
        "description": "Canonical JSON shape returned by every 4xx/5xx response. Every error envelope carries request_id (echo of X-Request-ID, for support tickets), retry_after_seconds (null on 4xx → fix the request; int on 5xx → safe to retry after N seconds), and — for 5xx — an agent_action sentence the calling agent can show the user. For 429/502/503/504 the same retry value is also written to the Retry-After HTTP header so polite HTTP clients honor the wait without parsing the body. Backward-compatible: omitempty fields (agent_action, upgrade_url, request_id) are absent on the wire when empty.",
        "properties": {
          "ok": { "type": "boolean", "enum": [false], "description": "Always false on error responses" },
          "error": { "type": "string", "description": "Stable machine-readable error code (e.g. 'quota_exceeded', 'invalid_token', 'forbidden', 'storage_limit_reached'). Programmatic clients should branch on this." },
          "message": { "type": "string", "description": "Human-readable explanation of the error. May contain tier names, resource IDs, or other context. Not stable — use the 'error' code for programmatic decisions." },
          "request_id": { "type": "string", "description": "Echo of the X-Request-ID header for this request. Stable correlator agents can quote when emailing support@instanode.dev — saves the user from copy/pasting headers." },
          "retry_after_seconds": { "type": ["integer", "null"], "description": "Seconds the agent should wait before retrying. null on 4xx (no retry — fix the request). int on transient 5xx: 30 for 503, 60 for 429, 10 for 502/504. For 429/502/503/504 the same value is also set in the Retry-After HTTP header." },
          "agent_action": { "type": "string", "description": "Optional. A sentence the calling agent should surface verbatim to the human user — e.g. 'Tell the user they've hit the hobby tier storage limit (500MB). Have them upgrade at https://instanode.dev/pricing to provision more storage.' Present on quota walls, invalid-token errors, permission-denied errors, expired-resource errors, tier-gate errors, AND on plumbing 5xx (where it falls back to a generic 'email support with this request_id' sentence)." },
          "upgrade_url": { "type": "string", "format": "uri", "description": "Optional. Where the user can resolve the error — typically the pricing/upgrade page for quota walls and the login page for token errors. Present whenever following the URL would clear the error." },
          "claim_url": { "type": "string", "format": "uri", "description": "Optional. Present specifically on error='free_tier_recycle_requires_claim' (402 from /db/new, /cache/new, /nosql/new, /queue/new, /storage/new, /webhook/new): the URL the anonymous caller should visit to claim their existing resources with email before they can provision again. Distinct from upgrade_url — claim_url is about identity (anonymous → claimed), upgrade_url is about tier (claimed → paid). Both may be present on the same envelope." }
        },
        "required": ["ok", "error", "message", "retry_after_seconds"]
      },
      "AuditExportItem": {
        "type": "object",
        "description": "One row of the customer-facing audit export. The same shape underlies the JSON list endpoint and (one column per field) the CSV stream endpoint. actor_email_masked redacts to first-char + domain ('m***@example.com'); actor_user_id stays in full so the buyer can correlate against their own team-membership records. Internal-only rows (kind starts with 'admin.') are never returned.",
        "properties": {
          "id":                 { "type": "string", "format": "uuid" },
          "kind":               { "type": "string", "description": "Stable event kind. See internal/models/audit_kinds.go for the canonical list. W7-C added: resource.read, resource.list_by_team, connection_url.decrypted." },
          "created_at":         { "type": "string", "format": "date-time" },
          "metadata":           { "type": ["object", "null"], "additionalProperties": true, "description": "Arbitrary k/v stamped at emit time. Per-kind shape — see individual emit sites." },
          "actor_user_id":      { "type": ["string", "null"], "format": "uuid", "description": "Null when the row came from a system actor (worker, billing webhook, dunning job)." },
          "actor_email_masked": { "type": ["string", "null"], "description": "Partial-redacted email of the acting user. Format: first character of local-part + '***' + '@' + full domain (e.g. 'm***@example.com'). Null when actor_user_id is null or the user row has been deleted." }
        },
        "required": ["id", "kind", "created_at"]
      },
      "TeamSelf": {
        "type": "object",
        "description": "Public-safe team record returned by GET /api/v1/team and PATCH /api/v1/team. Distinct from the cached aggregate at /api/v1/team/summary (counts panel) and the member roster at /api/v1/team/members.",
        "properties": {
          "id":                       { "type": "string", "format": "uuid" },
          "name":                     { "type": "string", "description": "Display name. Empty string when never set." },
          "plan_tier":                { "type": "string", "description": "Current plan tier. Source of truth: teams.plan_tier (Razorpay webhook authoritative). Values include anonymous, free, hobby, hobby_plus, growth, pro, team and their *_yearly variants." },
          "has_active_subscription":  { "type": "boolean", "description": "Mirror of teams.razorpay_subscription_id IS NOT NULL — true once the team has been wired to a Razorpay subscription." },
          "created_at":               { "type": "string", "format": "date-time", "description": "When the team row was created. UTC, second precision." }
        },
        "required": ["id", "name", "plan_tier", "has_active_subscription", "created_at"]
      },
      "TierCapabilities": {
        "type": "object",
        "description": "Capability row for one tier in the /api/v1/capabilities matrix. Adding a new tier in plans.yaml automatically produces a new row.",
        "properties": {
          "tier":                    { "type": "string", "description": "Canonical tier name (e.g. 'hobby', 'pro'). *_yearly variants are not surfaced; the canonical monthly tier represents the capability bundle." },
          "display_name":            { "type": "string", "description": "Human-readable name for the tier, e.g. 'Hobby' or 'Pro'." },
          "price_usd_monthly":       { "type": "integer", "description": "Monthly price in whole USD (cents/100). 0 for free/anonymous tiers." },
          "paid_from_day_one":       { "type": "boolean", "description": "True iff price_usd_monthly > 0. Mirrors project policy: no trial — paid tiers are paid from signup." },
          "storage_limit_mb":        { "type": "object", "additionalProperties": { "type": "integer" }, "description": "Per-service storage cap in MB. Keys: postgres, redis, mongodb, queue, storage, webhook, vector. -1 sentinel means 'unlimited'." },
          "connections_limit":       { "type": "object", "additionalProperties": { "type": "integer" }, "description": "Per-service concurrent-connection cap. Keys mirror storage_limit_mb. -1 = unlimited." },
          "deployments_apps":        { "type": "integer", "description": "Max number of /deploy/new apps allowed. -1 = unlimited." },
          "backup_retention_days":   { "type": "integer" },
          "backup_restore_enabled":  { "type": "boolean" },
          "manual_backups_per_day":  { "type": "integer" },
          "rpo_minutes":             { "type": "integer", "description": "Recovery Point Objective in minutes — the maximum window of data loss a restore can incur. 0 means no backup/RPO guarantee for the tier." },
          "rto_minutes":             { "type": "integer", "description": "Recovery Time Objective in minutes — the target time to restore service after an incident. 0 means no RTO guarantee for the tier." },
          "annual_discount_percent": { "type": "integer", "description": "Discount percent of the {tier}_yearly variant vs 12x the monthly. 0 when no yearly variant exists." },
          "upgrade_url":             { "type": "string", "format": "uri" }
        },
        "required": ["tier", "display_name", "price_usd_monthly", "paid_from_day_one", "storage_limit_mb", "connections_limit", "deployments_apps", "upgrade_url"]
      },
      "CapabilitiesResponse": {
        "type": "object",
        "properties": {
          "ok":      { "type": "boolean" },
          "tiers":   { "type": "array", "items": { "$ref": "#/components/schemas/TierCapabilities" }, "description": "Tier rows in upgrade-ladder order (anonymous first → team last)." },
          "docs":    { "type": "string", "format": "uri", "description": "Pointer to the LLM-targeted product docs surface." },
          "contact": { "type": "string", "description": "Mailto link for enterprise inquiries." }
        },
        "required": ["ok", "tiers"]
      },
      "Incident": {
        "type": "object",
        "description": "One incident row. The future incident-feed worker will populate these; today the items array is always empty.",
        "properties": {
          "id":          { "type": "string" },
          "title":       { "type": "string" },
          "severity":    { "type": "string", "enum": ["info", "minor", "major", "critical"] },
          "status":      { "type": "string", "enum": ["investigating", "identified", "monitoring", "resolved"] },
          "started_at":  { "type": "string", "format": "date-time" },
          "resolved_at": { "type": "string", "format": "date-time", "description": "Omitted while status != 'resolved'." },
          "summary":     { "type": "string" },
          "url":         { "type": "string", "format": "uri", "description": "Optional link to the public incident write-up." }
        },
        "required": ["id", "title", "severity", "status", "started_at", "summary"]
      },
      "IncidentsResponse": {
        "type": "object",
        "properties": {
          "ok":          { "type": "boolean" },
          "items":       { "type": "array", "items": { "$ref": "#/components/schemas/Incident" } },
          "total":       { "type": "integer", "description": "Equal to items.length today; the field is reserved for future pagination." },
          "status_page": { "type": "string", "format": "uri", "description": "Companion human-readable status page." }
        },
        "required": ["ok", "items", "total"]
      },
      "ComponentStatus": {
        "type": "object",
        "description": "One row of the /api/v1/status components array. last_24h_samples is exactly 96 booleans (96 x 15min = 24h), oldest first.",
        "properties": {
          "slug":             { "type": "string", "description": "Stable component identifier (e.g. 'api', 'provisioner', 'worker', 'marketing')." },
          "name":             { "type": "string", "description": "Display name for the dashboard's status page." },
          "category":         { "type": "string", "enum": ["core", "compute", "edge"], "description": "Ordering bucket. Render order: core then compute then edge." },
          "description":      { "type": "string", "description": "Optional one-liner describing the component. Omitted when blank." },
          "current_status":   { "type": "string", "enum": ["operational", "degraded", "down"], "description": "Derived from the most recent 15-minute slot with data. 'operational' = 100% healthy probes; 'degraded' = at least 50% healthy; 'down' = less than 50%. No data falls open to 'operational'." },
          "uptime_7d_pct":    { "type": "number", "description": "Percent healthy across the last 7 days. -1 sentinel = no samples in the window." },
          "uptime_30d_pct":   { "type": "number", "description": "Percent healthy across the last 30 days. -1 sentinel = no samples in the window." },
          "last_24h_samples": { "type": "array", "items": { "type": "boolean" }, "minItems": 96, "maxItems": 96, "description": "96 x 15-minute slots, oldest first. true = slot healthy; false = slot had at least one unhealthy probe. Empty slots inherit the previous slot's value to keep the bar continuous." }
        },
        "required": ["slug", "name", "category", "current_status", "uptime_7d_pct", "uptime_30d_pct", "last_24h_samples"]
      },
      "StatusResponse": {
        "type": "object",
        "properties": {
          "ok":                { "type": "boolean" },
          "freshness_seconds": { "type": "integer", "description": "Cache window the server enforces. Matches Cache-Control max-age." },
          "as_of":             { "type": "string", "format": "date-time", "description": "Wall-clock at which the underlying aggregation ran. Stable across multiple replays of the same cache entry." },
          "components":        { "type": "array", "items": { "$ref": "#/components/schemas/ComponentStatus" }, "description": "Rendered in display order — core services first, then compute, then edge." },
          "current_incidents": { "type": "array", "items": { "$ref": "#/components/schemas/Incident" }, "description": "Open incidents at the time of the snapshot. Today this is always empty — the field is reserved for the future incident-feed worker." }
        },
        "required": ["ok", "freshness_seconds", "as_of", "components", "current_incidents"]
      }
    },
    "responses": {
      "TooManyRequests": {
        "description": "T19 P1-1 (BugHunt 2026-05-20): shared 429 response. A global 100 req/min/IP rate-limit applies to EVERY route — this component documents the canonical envelope so callers don't have to re-discover it on each path. Per-route 429 entries (deploy daily cap, GitHub-webhook hourly cap, manual_backups_per_day, etc.) override with route-specific guidance but the wire shape stays the same. Retry-After header carries the wait in seconds; retry_after_seconds in the body mirrors it.",
        "headers": {
          "Retry-After": {
            "description": "Seconds the caller should wait before retrying.",
            "schema": { "type": "integer" }
          }
        },
        "content": {
          "application/json": {
            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
          }
        }
      },
      "PayloadTooLarge": {
        "description": "T19 P1-2 (BugHunt 2026-05-20): shared 413 response. Fiber's global BodyLimit is 50 MiB — exceeding it returns this JSON envelope (NOT the upstream nginx HTML 502 the older shape returned). Per-route handlers may cap further (e.g. /webhook/receive caps at 1 MiB); the envelope is identical regardless of which layer rejected the body.",
        "content": {
          "application/json": {
            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
          }
        }
      }
    }
  }
}`
