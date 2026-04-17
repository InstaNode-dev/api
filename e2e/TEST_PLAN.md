# instanode.dev E2E Test Plan
## Coverage for Agent 3-way changes: queue/new, storage quota, E2E cleanup

---

## Personas

| ID | Persona | Auth | Fingerprint | Notes |
|----|---------|------|-------------|-------|
| P1 | Anonymous agent | None | random/unique IP per test | Primary agentic user — no account |
| P2 | Authenticated hobby user | JWT (hobby tier) | fixed IP | Has account, lower limits |
| P3 | Pro user | JWT (pro tier) | fixed IP | After Stripe upgrade |
| P4 | Multi-agent (same IP) | None | shared fingerprint | Two+ agents from same machine |
| P5 | Abuser | None | cycling IPs | Tries to exceed limits per-fingerprint |

---

## Section 1: POST /queue/new — Core Scenarios

### Q1 — Anonymous provision returns valid shape
- Persona: P1
- Steps: POST /queue/new with unique X-Forwarded-For
- Assert:
  - Status 201
  - `ok: true`
  - `token` is UUID
  - `connection_url` starts with `nats://`
  - `tier == "anonymous"`
  - `limits.storage_mb == 1024`
  - `limits.expires_in == "24h"`

### Q2 — Anonymous dedup: 6th provision from same fingerprint returns existing token
- Persona: P4 (same fingerprint × 6)
- Steps: POST /queue/new × 6 from same IP
- Assert:
  - Calls 1–5: distinct tokens (or dedup'd within those 5, which is fine)
  - Call 6 (or whichever triggers the limit): returns existing token
  - Response includes `note` with upgrade URL

### Q3 — Service disabled returns 503
- Steps: Hit /queue/new when `INSTANT_ENABLED_SERVICES` excludes `queue`
- Assert: Status 503, `error: service_disabled`
- Note: Test via a separate env check or mark as skip-if-enabled

### Q4 — Authenticated hobby provision
- Persona: P2
- Steps: POST /queue/new with Authorization: Bearer {hobby_jwt}
- Assert:
  - Status 201
  - `tier == "hobby"`
  - `limits.storage_mb == 5120`
  - No `expires_in` (permanent resource)

### Q5 — Authenticated pro provision
- Persona: P3
- Steps: POST /queue/new with pro JWT
- Assert:
  - `tier == "pro"`
  - `limits.storage_mb == 10240`

### Q6 — Claim anonymous queue elevates tier
- Persona: P1 → P2
- Steps:
  1. POST /queue/new (anonymous) → token A
  2. POST /claim with JWT containing token A
  3. GET /api/v1/resources (authenticated)
- Assert:
  - Resource for token A appears in list
  - `tier` elevated to hobby (or team.plan_tier)
  - `expires_at` is null (permanent after claim)

### Q7 — connection_url persists across GET /api/v1/resources/:id
- Persona: P1 → claim → P2
- Steps:
  1. POST /queue/new → token, connection_url
  2. POST /claim
  3. GET /api/v1/resources/:id
- Assert:
  - `connection_url` returned matches what was provisioned (decrypted correctly)
  - URL is still a valid `nats://` string

---

## Section 2: Storage Quota

### SQ1 — Fresh provision has storage_exceeded: false
- Steps:
  1. POST /db/new (or /cache/new or /nosql/new) → resource_id
  2. POST /claim to get auth
  3. GET /api/v1/resources/:id
- Assert: `storage_exceeded: false` (fresh resource has 0 bytes)

### SQ2 — provision response has no warning when fresh
- Steps: POST /db/new → inspect response
- Assert:
  - No `warning` field in response (or `warning` is absent/empty)
  - No `X-Instant-Notice` header

### SQ3 — storage_exceeded field always present in GET /api/v1/resources/:id
- Steps: GET /api/v1/resources/:id for any resource
- Assert:
  - Response JSON contains `storage_exceeded` key (bool)
  - Value is false for a new resource

### SQ4 — Provision warning appears when resource.storage_bytes >= limit
- Note: Requires directly setting `storage_bytes` in DB to simulate quota breach
- Steps:
  1. Provision a DB
  2. UPDATE resources SET storage_bytes = storage_limit to simulate full usage
  3. GET /api/v1/resources/:id
- Assert:
  - `storage_exceeded: true`
  - (For provision path: would need a new provision with pre-seeded resource)

---

## Section 3: Race Conditions

### R1 — Concurrent anonymous queue provisions (same fingerprint)
- Scenario: 5 goroutines hit POST /queue/new simultaneously with the same IP
- Assert:
  - Total distinct tokens created <= 5 (dedup may collapse some)
  - No 500 errors (DB constraint safe)
  - No duplicate token UUIDs across responses

### R2 — Concurrent provisions (different fingerprints, same service)
- Scenario: 10 goroutines, each unique IP, hit /queue/new concurrently
- Assert:
  - All 10 get distinct tokens
  - All return status 201
  - No deadlocks or 500s

### R3 — Concurrent claim + new provision (same fingerprint)
- Scenario:
  - Goroutine A: POST /claim with JWT containing token T
  - Goroutine B: simultaneously POST /queue/new from same fingerprint
- Assert:
  - Claim succeeds atomically (no double-claim)
  - New provision either gets team tier (if claim finishes first) or anonymous (if provision finishes first)
  - No 500 errors

### R4 — Double-claim race (same JWT used twice concurrently)
- Scenario: 2 goroutines simultaneously POST /claim with same JWT
- Assert:
  - Exactly one succeeds (200), exactly one gets 409 Conflict
  - Resources are only transferred once (atomic UPDATE ... WHERE converted_at IS NULL)

### R5 — Concurrent rate limit (Redis INCR race)
- Scenario: Send 6 concurrent /queue/new requests from same fingerprint
- Assert:
  - Total resources created <= 5 (limit) — not 6
  - At least one response has dedup/limit note
  - No 500 errors from Redis

### R6 — Upgrade webhook during active provision
- Scenario:
  1. Start POST /queue/new (slow path — simulated with test delay not possible in black-box)
  2. Simultaneously POST /stripe/webhook with subscription.updated → pro
- Assert (eventual): GET /api/v1/resources shows all resources at pro tier
- Note: This is a timing race; test verifies eventual consistency, not strict ordering

### R7 — Concurrent resource deletion + GET
- Scenario:
  1. Goroutine A: DELETE /api/v1/resources/:id
  2. Goroutine B: GET /api/v1/resources/:id (same ID, simultaneously)
- Assert:
  - DELETE returns 200
  - GET returns either the resource (if before delete) or 404 (after) — never 500

### R8 — Concurrent same-IP provisions across multiple services
- Scenario: 3 goroutines from same fingerprint, each hits a different service (/queue/new, /db/new, /cache/new)
- Assert:
  - Each service tracks its OWN fingerprint limit independently
  - All 3 can provision successfully (limit is per-service, not global)
  - Each returns distinct token

---

## Section 4: Upgrade/Downgrade Tier Mechanics (queue-specific)

### T1 — Queue resource elevated on upgrade
- Steps:
  1. POST /queue/new (anonymous) → tier=anonymous
  2. POST /claim → team_id
  3. POST /stripe/webhook with subscription.updated (hobby→pro)
  4. GET /api/v1/resources/:id
- Assert: `tier == "pro"`

### T2 — Queue resource tier snapshot after downgrade
- Steps:
  1. Provision as pro
  2. POST /stripe/webhook (pro→hobby)
  3. GET /api/v1/resources/:id (existing resource)
- Assert: existing resource keeps `tier == "pro"` (downgrade only affects new provisions)

---

## Section 5: Shape Validation

### SH1 — /queue/new response fields complete
- Every response must include: `ok, token, connection_url, tier, limits`
- Dedup response must include: `note, upgrade` (non-empty)

### SH2 — connection_url format
- Must match: `nats://usr_[a-f0-9]{8}:[a-f0-9]{32}@[^:]+:4222`

### SH3 — Provision metrics emitted
- After /queue/new: Prometheus `instant_provisions_total{service="queue",tier="anonymous"}` increments
- Assert via GET /metrics

---

## Skip Conditions

| Condition | Tests to skip |
|-----------|--------------|
| Queue service not enabled | Q1–Q7, R1–R8 (all queue tests) |
| E2E_ALLOW_QUOTA_BURN not set | R1, R2, R5 (high-volume) |
| Port-forwards not configured | SQ4 (needs DB write) |
| No Stripe webhook secret | T1, T2 |
