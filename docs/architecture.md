# Architecture

instanode.dev is a Go + Fiber API server with Postgres, Redis, and background workers. This document covers the internal design decisions and data flows.

---

## Request pipeline

Every HTTP request passes through this middleware chain (order is load-bearing):

```
HTTP Request
    │
    ├─ 1. RequestID         Generate UUID v4 if X-Request-ID absent; propagate on response.
    │                       All log lines include request_id — never use a request without one.
    │
    ├─ 2. Recover           Catch panics → 500. Stack trace logged in development only.
    │
    ├─ 3. CORS              Allow all origins in dev. Tighten to specific origins in prod.
    │
    ├─ 4. GeoEnrich         MaxMind GeoLite2 local binary lookup (<1ms, no network call).
    │                       Attaches country code + ASN + org name to fiber.Locals.
    │                       No-op if .mmdb file is absent (graceful degradation).
    │
    ├─ 5. Fingerprint       SHA256(ip/24 + ASN) for IPv4, SHA256(ip/48 + ASN) for IPv6.
    │                       Stored as hex; never the raw IP. GDPR-safe by design.
    │                       Used for: provisioning rate limits, abuse detection, funnel analytics.
    │
    └─ 6. RateLimit         Redis INCR + EXPIRE on key "rl:{fingerprint}:{date}".
                            Fail-open: Redis errors allow the request through.
                            Limit exceeded → context flag set, handler decides response shape.
                            Never returns 429 — the provisioning handler degrades gracefully.
                            │
                            ▼
                       Handler
```

---

## Database architecture

Two separate Postgres instances. Isolation is a security boundary — a compromised customer database cannot read platform metadata.

```
┌─────────────────────────────┐    ┌─────────────────────────────────┐
│     Platform DB             │    │     Customer DB                  │
│  (DATABASE_URL)             │    │  (CUSTOMER_DATABASE_URL)         │
│                             │    │                                  │
│  teams                      │    │  db_{token}  ← Phase 2+          │
│  users                      │    │  db_{token2}                     │
│  resources                  │    │  ...                             │
│  pings (partitioned)        │    │                                  │
│  onboarding_events          │    │  Each database is isolated:      │
│  river_* (job queue)        │    │  separate user, separate schema  │
└─────────────────────────────┘    └─────────────────────────────────┘
```

### Platform schema

```sql
teams            -- billing unit: plan_tier, stripe_customer_id, trial_ends_at
users            -- email, github_id, google_id (one or more per team)
resources        -- universal: all service types (monitor, postgres, redis, ...)
pings            -- heartbeat log, partitioned monthly by created_at
onboarding_events-- JWT single-use enforcement: jti, converted_at, team_id
```

**resources** is the universal table — every provisioned object (monitor token, Postgres DB, Redis namespace, etc.) is a row with `resource_type`, `connection_url` (AES-256-GCM encrypted), `tier`, `fingerprint`, `expires_at`.

**pings** uses Postgres range partitioning by month. New partition must be created before the month starts (see `docs/TODOS.md` item B-05). Partitioning keeps query latency stable as the table grows.

---

## Redis key design

```
rl:{fingerprint}:{YYYY-MM-DD}       General request rate limit (100/day)
prov:{fingerprint}:{YYYY-MM-DD}     Provisioning rate limit (5/day)
throughput:{service}:{token}:...   Per-token daily throughput counters (where enforced)
res:{token}                         Resource cache (5-minute TTL)
```

All keys use 25-hour TTL to avoid midnight thundering herd (clock skew + timezone edge cases).

Rate limiting is always fail-open: if Redis is unavailable, the request proceeds. This matches the product philosophy — we never block a developer because our cache is down.

---

## Onboarding funnel

The agentic conversion funnel is the core business mechanic. It works without any human interaction until the signup step.

```
POST /{service}/new   (e.g. /db/new, /cache/new — see provision handlers)
    │
    ├─ Create resource row (expires_at = now + 24h for anonymous)
    ├─ Issue HMAC-SHA256 onboarding JWT (7-day expiry)
    │    Claims: fingerprint, country, cloud_vendor, tokens[], resource_types[], suggested_plan
    ├─ Insert onboarding_events row (jti, fingerprint, jwt_expires_at, resource_tokens[])
    └─ Return response with upgrade URL in note field + X-Instant-Upgrade header
                │
                │  Developer sees URL in logs, clicks it
                ▼
GET /start?t={jwt}
    │
    ├─ Verify JWT signature + expiry
    ├─ Lookup onboarding_events by jti (GetOnboardingByJTI)
    ├─ Reject if converted_at IS NOT NULL → 401 (already claimed)
    └─ Return resource context (fingerprint, tokens, suggested_plan) → pre-fill signup form
                │
                │  Developer signs up with GitHub/Google OAuth
                ▼
POST /claim
    │
    ├─ Verify JWT
    ├─ Pre-check: GetOnboardingByJTI → 401 if not found, 409 if already converted
    ├─ CreateTeam + CreateUser
    ├─ MarkOnboardingConverted (atomic UPDATE WHERE converted_at IS NULL RETURNING id)
    │    → 0 rows → 409 Conflict (concurrent claim race handled here)
    ├─ Transfer anonymous resources to new team
    ├─ StartTrial (plan_tier = 'hobby', trial_ends_at = now + 14 days)
    └─ SendTrialStarted email
```

**Single-use enforcement is atomic.** The `MarkOnboardingConverted` UPDATE with `RETURNING id` is the authoritative gate. The pre-check in `Claim` reduces wasted work for the common case (replayed link) but does not replace the atomic gate for concurrent access.

---

## Background jobs

River (MPL-2.0, Postgres-native job queue) runs all scheduled work inside the same process. No separate worker deployment.

```
workers.StartWorkers()
    │
    ├─ ExpireAnonymousWorker     Every 5 min: soft-delete resources past expires_at
    ├─ EnforceQuotaWorker        Every 10 min: enforce storage quotas (Phase 2+)
    ├─ TrialExpiryWorker         Hourly: send Day 12 warning, suspend on Day 14
    ├─ WeeklyDigestWorker        Monday 08:00 UTC: usage digest email (where enabled)
    └─ RefreshGeoDBWorker        Weekly: download fresh GeoLite2 MMDB from MaxMind
```

River uses advisory locks for leader election. The scheduler connects directly to Postgres (bypassing PgBouncer if used), because `pg_try_advisory_lock` is session-scoped and PgBouncer transaction mode would release locks between queries.

---

## Security model

### Fingerprinting (GDPR)

Raw IPs are never stored in Postgres. The fingerprint is `SHA256(subnet + asn)` where subnet is `/24` for IPv4 and `/48` for IPv6. The hash is one-way — you cannot derive the IP from the fingerprint. This satisfies GDPR's data minimization principle while still enabling abuse detection and funnel analytics.

### Connection URL encryption

Every `resources.connection_url` is encrypted with AES-256-GCM before storage. The key comes from `AES_KEY` env var. A compromised database backup does not expose customer credentials.

### JWT single-use

Onboarding JWTs are single-use: the `jti` is stored in `onboarding_events` and the `converted_at` column is set atomically on first claim. Replaying a JWT after it's been claimed returns 409 immediately (pre-check) without creating orphaned records.

### Auth

Authenticated endpoints (`/api/v1/*`, `/billing/checkout`) require `Authorization: Bearer <jwt>` where the JWT was issued at OAuth completion. The JWT contains `uid` and `tid` (user ID and team ID) and is verified with the same HMAC-SHA256 key as onboarding tokens.

---

## Observability

Prometheus metrics are exposed at `/metrics` (unauthenticated — restrict in prod via network policy or reverse proxy).

```
provisions_total{service, tier}          Counter  — new resources provisioned
fingerprint_abuse_blocked_total          Counter  — provisioning limit hits
conversion_funnel{step}                  Counter  — funnel steps (provision → claimed → paid)
redis_errors_total{operation}            Counter  — Redis failure rate (should be near zero)
geoip_db_age_hours                       Gauge    — alert if > 720h (monthly refresh needed)
```

All log output is structured JSON via `log/slog`. Every log line includes `request_id`. Fingerprints are logged truncated to 8 hex chars (never the full 32-char hash).

---

## Feature flags

Services are gated by the `INSTANT_ENABLED_SERVICES` env var (comma-separated):

```
INSTANT_ENABLED_SERVICES=postgres,redis,mongodb
```

Handlers call `cfg.IsServiceEnabled("postgres")` and return 503 if the service is not enabled. This controls the rollout of Phase 2+ services without code deploys.

---

## Local infrastructure topology

```
┌─ Rancher Desktop ──────────────────────────────────────────────────┐
│                                                                      │
│  instant-api:local (Docker image)                                    │
│      │                                                               │
│      ├─ postgres-platform:5432   (instant_platform DB)              │
│      ├─ postgres-customers:5433  (instant_customers DB, Phase 2+)   │
│      └─ redis:6379                                                   │
│                                                                      │
│  Docker Compose:  make docker-up + make migrate-platform             │
│  Kubernetes:      make k8s-deploy  (NodePort on localhost)           │
└──────────────────────────────────────────────────────────────────────┘
```

The k8s deployment uses an init container to run migrations before the API starts, so the schema is always current on pod start.
