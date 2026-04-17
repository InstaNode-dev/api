# instanode.dev API Reference

**Base URL:** `https://instanode.dev`

---

## Authentication

### Anonymous endpoints (no auth required)

The following endpoints accept requests without any credentials:

- `POST /db/new`, `POST /cache/new`, `POST /nosql/new`, `POST /queue/new`, `POST /storage/new`, `POST /webhook/new` (each subject to `INSTANT_ENABLED_SERVICES`)
- `GET /start`
- `POST /claim`
- `POST /auth/github`
- `POST /auth/google`
- `GET /healthz`
- `GET /metrics`

### Bearer token auth

The following endpoints require a session JWT in the `Authorization` header:

- `POST /billing/checkout`
- `GET /api/v1/resources`
- `GET /api/v1/resources/:id`
- `POST /api/v1/resources/:id/rotate-credentials`
- `DELETE /api/v1/resources/:id`

```
Authorization: Bearer <session_jwt>
```

### JWT format

Session JWTs are HS256-signed tokens issued by `/auth/github` or `/auth/google`. They expire after **24 hours**. The payload contains:

```json
{
  "uid": "<user_uuid>",
  "tid": "<team_uuid>",
  "email": "user@example.com",
  "jti": "<unique_token_id>",
  "iat": 1712345678,
  "exp": 1712432078
}
```

After a successful OAuth call, the `token` field in the response is your session JWT. Store it securely and pass it as a Bearer token on subsequent authenticated requests.

---

## Response Envelope

All responses use a consistent envelope:

**Success:**
```json
{
  "ok": true,
  "<field>": "<value>"
}
```

**Error:**
```json
{
  "ok": false,
  "error": "error_code",
  "message": "Human-readable description"
}
```

---

## Endpoints

### 1. GET /start?t={jwt}

Onboarding landing endpoint. Validates the onboarding JWT issued when anonymous resources are provisioned (for example `POST /db/new`) and returns the session context. Used by the upgrade funnel to identify which anonymous resources to claim.

**Query parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `t` | string | Yes | Onboarding JWT from the `upgrade` URL |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | JWT is valid and unused |
| `400 Bad Request` | `t` parameter missing |
| `401 Unauthorized` | JWT is invalid, expired, or not recognized |
| `409 Conflict` | JWT has already been used to claim an account |
| `503 Service Unavailable` | Database error |

**200 body:**
```json
{
  "ok": true,
  "fingerprint": "abc123...",
  "country": "US",
  "cloud_vendor": "aws",
  "tokens": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
  "resource_types": ["postgres", "redis"],
  "suggested_plan": "hobby",
  "jti": "unique-jwt-id"
}
```

**Example:**

```bash
curl "https://instanode.dev/start?t=eyJ..."
```

---

### 2. POST /claim

Convert an anonymous session into a registered account. Transfers anonymous resources to the new team, removes the 24-hour expiry, and starts a 14-day trial. The onboarding JWT is single-use — replaying it returns `409`.

**Request body:**

```json
{
  "jwt": "eyJ...",
  "email": "you@example.com",
  "team_name": "acme"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jwt` | string | Yes | Onboarding JWT from the `upgrade` URL |
| `email` | string | Yes | Email address for the new account |
| `team_name` | string | No | Team display name; defaults to email if omitted |

**Response**

| Status | Description |
|--------|-------------|
| `201 Created` | Account created and tokens transferred |
| `400 Bad Request` | Missing or malformed fields |
| `401 Unauthorized` | JWT is invalid, expired, or not recognized |
| `409 Conflict` | JWT has already been claimed |
| `503 Service Unavailable` | Database error |

**201 body:**
```json
{
  "ok": true,
  "team_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "message": "Account created. Your resources have been transferred."
}
```

**Example:**

```bash
curl -X POST https://instanode.dev/claim \
  -H "Content-Type: application/json" \
  -d '{"jwt": "eyJ...", "email": "you@example.com", "team_name": "acme"}'
```

---

### 3. POST /auth/github

Exchange a GitHub OAuth authorization code for a session JWT.

**Request body:**

```json
{
  "code": "github_oauth_code"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | Authorization code from GitHub OAuth callback |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Authentication successful |
| `400 Bad Request` | Missing `code` field or malformed JSON |
| `401 Unauthorized` | GitHub rejected the OAuth code |
| `503 Service Unavailable` | OAuth not configured, or database/token error |

**200 body:**
```json
{
  "ok": true,
  "token": "eyJ...",
  "user_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "team_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "email": "you@example.com"
}
```

The `token` field is a 24-hour session JWT. Use it as a Bearer token on authenticated endpoints.

**Example:**

```bash
curl -X POST https://instanode.dev/auth/github \
  -H "Content-Type: application/json" \
  -d '{"code": "abc123def456"}'
```

---

### 4. POST /auth/google

Verify a Google ID token and issue a session JWT.

**Request body:**

```json
{
  "id_token": "google_id_token"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id_token` | string | Yes | ID token from Google Sign-In |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Authentication successful |
| `400 Bad Request` | Missing `id_token` field or malformed JSON |
| `401 Unauthorized` | Google rejected the ID token |
| `503 Service Unavailable` | OAuth not configured, or database/token error |

**200 body:**
```json
{
  "ok": true,
  "token": "eyJ...",
  "user_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "team_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "email": "you@example.com"
}
```

**Example:**

```bash
curl -X POST https://instanode.dev/auth/google \
  -H "Content-Type: application/json" \
  -d '{"id_token": "eyJ..."}'
```

---

### 5. POST /billing/checkout

Create a Razorpay subscription checkout for a plan upgrade. Requires authentication.

**Request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <session_jwt>` |
| `Content-Type` | Yes | `application/json` |

**Request body:**

```json
{
  "plan": "pro"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `plan` | string | Yes | `"pro"` or `"team"` |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Checkout created |
| `400 Bad Request` | Invalid or missing `plan` |
| `401 Unauthorized` | Missing or invalid session token |
| `404 Not Found` | Team not found |
| `503 Service Unavailable` | Razorpay API error |

**200 body:**
```json
{
  "ok": true,
  "short_url": "https://rzp.io/i/..."
}
```

Open `short_url` in the browser so the customer can complete payment on Razorpay.

**Example:**

```bash
curl -X POST https://instanode.dev/billing/checkout \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"plan": "pro"}'
```

---

### 6. POST /razorpay/webhook

Razorpay webhook endpoint. Verifies the payload using `RAZORPAY_WEBHOOK_SECRET` (HMAC-SHA256 over the raw body, hex digest). Configure this URL in the Razorpay dashboard.

**Request body:** Raw JSON payload from Razorpay (verify before parsing in application code).

**Typical effects** (exact event names depend on Razorpay subscription configuration):

| Scenario | Effect |
|----------|--------|
| Successful paid subscription / activation | Upgrades team to `pro` or `team`; promotes resource tiers as implemented in billing handler |
| Subscription cancelled / ended | May downgrade team to `hobby` per handler rules |
| Payment issues | May send notification email; downgrade behavior follows `billing.go` |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Event processed (or acknowledged) |
| `400 Bad Request` | Signature verification failed |

**200 body:**
```json
{ "ok": true }
```

---

### 7. GET /api/v1/resources

List all resources belonging to the authenticated team.

**Request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <session_jwt>` |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Resource list returned |
| `401 Unauthorized` | Missing or invalid session token |
| `503 Service Unavailable` | Database error |

**200 body:**
```json
{
  "ok": true,
  "total": 2,
  "items": [
    {
      "id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
      "token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "resource_type": "postgres",
      "tier": "hobby",
      "status": "active",
      "created_at": "2026-04-01T12:00:00Z",
      "name": "nightly-backup",
      "cloud_vendor": "aws",
      "country_code": "US",
      "team_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    }
  ]
}
```

Optional fields (`name`, `cloud_vendor`, `country_code`, `expires_at`, `team_id`) are omitted when not set. `expires_at` is only present for anonymous-tier resources.

**Example:**

```bash
curl https://instanode.dev/api/v1/resources \
  -H "Authorization: Bearer eyJ..."
```

---

### 8. GET /api/v1/resources/:id

Get a single resource by its token UUID.

**Request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <session_jwt>` |

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | The resource token (same as the `token` field) |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Resource returned |
| `400 Bad Request` | `id` is not a valid UUID |
| `401 Unauthorized` | Missing or invalid session token |
| `403 Forbidden` | Resource belongs to a different team |
| `404 Not Found` | Resource not found |
| `503 Service Unavailable` | Database error |

**200 body:**
```json
{
  "ok": true,
  "item": {
    "id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
    "token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "resource_type": "postgres",
    "tier": "hobby",
    "status": "active",
    "created_at": "2026-04-01T12:00:00Z"
  }
}
```

**Example:**

```bash
curl https://instanode.dev/api/v1/resources/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer eyJ..."
```

---

### 9. POST /api/v1/resources/:id/rotate-credentials

Rotate database credentials for an owned resource. **RotateCredentials** is implemented for **Postgres** (`ALTER ROLE ... PASSWORD`), **Redis** (`ACL SETUSER`), and **MongoDB** (`updateUser`). Returns a new `connection_url` in the response body.

**Request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <session_jwt>` |

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | The resource id (stable row id, same as in list/get responses) |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | New credentials issued |
| `400 Bad Request` | Invalid `id` or unsupported `resource_type` |
| `401 Unauthorized` | Missing or invalid session |
| `403 Forbidden` | Resource not owned by this team |
| `404 Not Found` | Resource not found |
| `501 Not Implemented` | Resource type does not support rotation (for example queue, storage, webhook) |

**200 body (shape):**
```json
{
  "ok": true,
  "connection_url": "postgres://usr_new:pass_new@..."
}
```

---

### 10. DELETE /api/v1/resources/:id

Soft-delete a resource. Credentials stop working immediately (status changes to `deleted`).

**Request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <session_jwt>` |

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | The resource id (same stable UUID as in list/get responses) |

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Resource deleted |
| `400 Bad Request` | `id` is not a valid UUID |
| `401 Unauthorized` | Missing or invalid session token |
| `403 Forbidden` | Resource belongs to a different team |
| `404 Not Found` | Resource not found |
| `503 Service Unavailable` | Database error |

**200 body:**
```json
{
  "ok": true,
  "message": "Resource deleted"
}
```

**Example:**

```bash
curl -X DELETE https://instanode.dev/api/v1/resources/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer eyJ..."
```

---

### 11. GET /healthz

Service health check.

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Service is up |

**200 body:**
```json
{
  "ok": true,
  "service": "instanode.dev"
}
```

**Example:**

```bash
curl https://instanode.dev/healthz
```

---

## Provisioning Endpoints

Provisioning endpoints are available with or without authentication. Anonymous requests provision resources that expire after 24 hours. Authenticated requests (Bearer session JWT) provision permanent resources tied to your team.

All provisioning endpoints accept an optional JSON body with a `name` field. The name is stored and echoed in the response — use it to distinguish multiple resources of the same type.

**Anonymous request body (optional):**
```json
{ "name": "my-database" }
```

**Response headers on all provisioning endpoints:**

| Header | When set |
|--------|----------|
| `X-Instant-Upgrade` | Always on successful provision; contains the upgrade URL |

---

### 12. POST /db/new

Provision an anonymous Postgres database (Phase 2). No account required.

**Feature flag:** Requires `postgres` in `INSTANT_ENABLED_SERVICES`. Returns `503` if not enabled.

**Request body (optional):**
```json
{ "name": "my-app-db" }
```

**Response**

| Status | Description |
|--------|-------------|
| `201 Created` | Database provisioned successfully |
| `200 OK` | Daily provisioning limit reached; returns existing resource |
| `503 Service Unavailable` | Service disabled or database error |

**201 body:**
```json
{
  "ok": true,
  "id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "my-app-db",
  "connection_url": "postgres://usr_a1b2c3d4:pass_a1b2c3d4@shared.instanode.dev/db_a1b2c3d4",
  "tier": "anonymous",
  "limits": {
    "storage_mb": 10,
    "connections": 2,
    "expires_in": "24h"
  },
  "note": "Works now. Free forever with a free account: https://instanode.dev/start?t=<jwt>"
}
```

The `id` field is the stable UUID for this resource. Use it to reference the resource in the management API (`/api/v1/resources/:id`). The `token` is the public-facing credential embedded in `connection_url`.

**Example:**

```bash
# Anonymous provision
curl -X POST https://instanode.dev/db/new

# With a name
curl -X POST https://instanode.dev/db/new \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app-db"}'

# Authenticated provision (permanent, no expiry)
curl -X POST https://instanode.dev/db/new \
  -H "Authorization: Bearer eyJ..."
```

---

### 13. POST /cache/new

Provision an anonymous Redis cache (Phase 3). No account required.

**Feature flag:** Requires `redis` in `INSTANT_ENABLED_SERVICES`. Returns `503` if not enabled.

**Request body (optional):**
```json
{ "name": "session-cache" }
```

**Response**

| Status | Description |
|--------|-------------|
| `201 Created` | Cache provisioned successfully |
| `200 OK` | Daily provisioning limit reached; returns existing resource |
| `503 Service Unavailable` | Service disabled or database error |

**201 body:**
```json
{
  "ok": true,
  "id": "e5f6a7b8-c9d0-1234-efab-567890abcdef",
  "token": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "name": "session-cache",
  "connection_url": "redis://:pass_b2c3d4e5@shared.instanode.dev:6379/0",
  "tier": "anonymous",
  "limits": {
    "memory_mb": 5,
    "expires_in": "24h"
  },
  "note": "Works now. Free forever with a free account: https://instanode.dev/start?t=<jwt>"
}
```

**Example:**

```bash
# Anonymous provision
curl -X POST https://instanode.dev/cache/new

# With a name
curl -X POST https://instanode.dev/cache/new \
  -H "Content-Type: application/json" \
  -d '{"name": "session-cache"}'

# Authenticated provision (permanent)
curl -X POST https://instanode.dev/cache/new \
  -H "Authorization: Bearer eyJ..."
```

---

### 14. POST /nosql/new

Provision an anonymous MongoDB database (Phase 4). No account required.

**Feature flag:** Requires `mongodb` in `INSTANT_ENABLED_SERVICES`. Returns `503` if not enabled.

**Request body (optional):**
```json
{ "name": "events-db" }
```

**Response**

| Status | Description |
|--------|-------------|
| `201 Created` | MongoDB database provisioned successfully |
| `200 OK` | Daily provisioning limit reached; returns existing resource |
| `503 Service Unavailable` | Service disabled or database error |

**201 body:**
```json
{
  "ok": true,
  "id": "f6a7b8c9-d0e1-2345-fab0-678901abcdef",
  "token": "c3d4e5f6-a7b8-9012-cdef-012345678902",
  "name": "events-db",
  "connection_url": "mongodb://usr_c3d4e5f6:pass_c3d4e5f6@shared.instanode.dev:27017/db_c3d4e5f6",
  "tier": "anonymous",
  "limits": {
    "storage_mb": 5,
    "connections": 2,
    "expires_in": "24h"
  },
  "note": "Works now. Free forever with a free account: https://instanode.dev/start?t=<jwt>"
}
```

**Example:**

```bash
# Anonymous provision
curl -X POST https://instanode.dev/nosql/new

# With a name
curl -X POST https://instanode.dev/nosql/new \
  -H "Content-Type: application/json" \
  -d '{"name": "events-db"}'

# Authenticated provision (permanent)
curl -X POST https://instanode.dev/nosql/new \
  -H "Authorization: Bearer eyJ..."
```

---

### 15. GET /metrics

Prometheus metrics endpoint. Returns metrics in the standard Prometheus text exposition format.

**Response**

| Status | Description |
|--------|-------------|
| `200 OK` | Metrics payload |

**Content-Type:** `text/plain; version=0.0.4`

**Example:**

```bash
curl https://instanode.dev/metrics
```

---

## Rate Limits

### Provisioning limit

- **5 anonymous provisions** per browser fingerprint per calendar day (UTC), across provision endpoints.
- When the limit is reached, the API returns `200` with an existing resource token rather than `429`. This is intentional fail-open behavior — callers always get a usable credential.
- Counter resets at midnight UTC. The Redis key has a 25-hour TTL to avoid thundering-herd issues at midnight.

### Response headers

| Header | Description |
|--------|-------------|
| `X-Instant-Notice` | Informational message when approaching throughput or storage limits (service-dependent). |
| `X-Instant-Upgrade` | Absolute URL to the upgrade/onboarding page |

Both headers are exposed via CORS (`ExposeHeaders`) and safe to read from browser clients.

### General request rate limit

A global rate limit of **100 requests per key per window** is enforced at the router level across all endpoints.

---

## Quota and SKU Limits

Two independent control planes govern resource usage:

### 1. Throughput quota (Redis, enforced inline)

Throughput-sensitive operations (for example Redis commands on a cache resource) are counted against a daily per-token Redis counter where implemented. The counter key format is:

```
throughput:{service}:{token}:{YYYY-MM-DD}   (25-hour TTL)
```

- Enforced **in the request handler**, not in a background job.
- **Fails open** on Redis error — a Redis outage never blocks a customer request.
- `-1` limit = unlimited (team tier).

### 2. Storage quota (Postgres, enforced by background job)

`resources.storage_bytes` tracks current storage per resource. It is updated every 6 hours by `UpdateStorageBytesWorker` (real provider queries wired in Phase 2+) and checked by `EnforceStorageQuotaWorker`, which suspends over-quota resources.

- Suspended resources return `ok: true` with a `warning` and `upgrade` CTA on their next request.
- **Fails open** on DB error during check — a transient DB issue does not block writes.

### Per-tier limits

| Tier | Postgres storage | Postgres conns | Redis memory | Redis cmds/day | MongoDB storage | MongoDB conns |
|------|-----------------|---------------|-------------|---------------|----------------|--------------|
| **Anonymous** | 10 MB | 2 | 5 MB | 1,000 | 5 MB | 2 |
| **Hobby** ($0) | 500 MB | 5 | 25 MB | 10,000 | 100 MB | 5 |
| **Pro** ($12/mo) | 5 GB | 20 | 256 MB | 500,000 | 2 GB | 20 |
| **Team** ($49/mo) | unlimited | unlimited | unlimited | unlimited | unlimited | unlimited |

All limits are defined in [`plans.yaml`](../plans.yaml) and loaded at startup — no code deploy needed to change a limit.

### Running quota E2E tests

High-volume quota tests are skipped by default to avoid cloud cost. To run them:

```bash
E2E_ALLOW_QUOTA_BURN=true E2E_BASE_URL=http://localhost:30080 \
  go test ./e2e/... -v -tags e2e -run TestE2E_Quota -timeout 120s
```

Do **not** set `E2E_ALLOW_QUOTA_BURN=true` in CI. Once real providers are wired, each run costs real cloud quota.

### Running authenticated management API E2E tests

Some E2E tests cover endpoints that require a valid signed session JWT (e.g. `GET /auth/me`, `POST /api/v1/resources/:id/rotate-credentials`). **RotateCredentials** is implemented for Postgres (`ALTER ROLE`), Redis (`ACL SETUSER`), and MongoDB (`updateUser`) and returns a new `connection_url`. These tests are skipped automatically when `E2E_JWT_SECRET` is not set.

To run the full suite including these tests, use `make test-e2e-full`, which reads `JWT_SECRET` directly from the k8s cluster:

```bash
make test-e2e-full
```

This is equivalent to:

```bash
E2E_JWT_SECRET=$(kubectl get secret instant-secrets -n instant \
  -o jsonpath='{.data.JWT_SECRET}' | base64 -d) \
  go test ./e2e/... -v -tags e2e -timeout 60s
```

**`E2E_JWT_SECRET`** must match the `JWT_SECRET` value the live server uses to sign and verify session JWTs. Setting it to any other value will cause all JWT-signed requests to be rejected with 401.

---

## Error Codes

All error responses include an `error` field with one of the following string codes:

| Code | HTTP status | Description |
|------|-------------|-------------|
| `service_disabled` | 503 | The requested service (e.g. `postgres`) is disabled server-side |
| `provision_failed` | 503 | Could not create the requested resource |
| `invalid_token` | 400 / 401 | Token is not a valid UUID, or the JWT is invalid/expired/unrecognized |
| `not_found` | 404 | Resource or token does not exist |
| `lookup_failed` | 503 | Database read failed |
| `record_failed` | 503 | Could not persist an event or write |
| `expired` | 410 | Resource has expired (anonymous tier TTL) |
| `missing_token` | 400 | Required `t` query parameter or `jwt` body field is absent |
| `already_claimed` | 409 | Onboarding JWT has already been used to create an account |
| `missing_email` | 400 | `email` field is required but missing |
| `invalid_body` | 400 | Request body is not valid JSON |
| `missing_code` | 400 | `code` field missing from GitHub auth request |
| `missing_id_token` | 400 | `id_token` field missing from Google auth request |
| `oauth_not_configured` | 503 | GitHub or Google OAuth credentials are not set on the server |
| `oauth_failed` | 401 | OAuth provider rejected the code or ID token |
| `user_upsert_failed` | 503 | Could not create or find the user record |
| `token_issue_failed` | 503 | Could not sign the session JWT |
| `team_creation_failed` | 503 | Could not create the team record |
| `user_creation_failed` | 503 | Could not create the user record |
| `invalid_plan` | 400 | `plan` must be `"pro"` or `"team"` |
| `team_not_found` | 404 | Authenticated team does not exist |
| `team_fetch_failed` | 503 | Database read failed when fetching team |
| `razorpay_error` | 503 | Razorpay API call failed |
| `invalid_signature` | 400 | Razorpay webhook signature verification failed |
| `unauthorized` | 401 | Missing or invalid session JWT on an authenticated endpoint |
| `forbidden` | 403 | Authenticated team does not own the requested resource |
| `invalid_id` | 400 | Resource `:id` path parameter is not a valid UUID |
| `fetch_failed` | 503 | Database read failed when fetching a resource |
| `delete_failed` | 503 | Database write failed when deleting a resource |
| `list_failed` | 503 | Database read failed when listing resources |
| `internal_error` | 500 | Unhandled panic or unexpected server error |
