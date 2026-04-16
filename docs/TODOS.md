# instant.dev — Task List

**Goal:** Ship anonymous provisioning of real infrastructure with upgrade → claim → Razorpay billing.

> Legend: Priority = P1/P2/P3 | Effort = XS/S/M/L | Status = TODO/IN_PROGRESS/DONE  
> Legacy `/ping/*` heartbeat tasks were removed from this document; provisioning uses `POST /{service}/new` handlers.

---

## Infrastructure Setup

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| I-01 | **[MUST SHIP FIRST]** Platform PostgreSQL with `teams`, `users`, `resources`, `onboarding_events`, migrations | P1 | M | TODO | Customer workloads live in `CUSTOMER_DATABASE_URL` |
| I-02 | **[MUST SHIP FIRST]** Redis (rate limits, sessions, throughput counters) | P1 | S | TODO | Fail-open on Redis errors for limits |
| I-03 | **[MUST SHIP FIRST]** Go + Fiber layout: handlers, middleware, models, router | P1 | M | TODO | |
| I-04 | **[MUST SHIP FIRST]** Environment config: DB URLs, Redis, JWT, Razorpay keys, AES, GeoIP path | P1 | S | TODO | |
| I-05 | Schema migrations idempotent in CI | P1 | S | TODO | |
| I-06 | GeoLite2 MMDB refresh strategy | P2 | M | TODO | |
| I-07 | ASN → cloud vendor mapping config | P2 | S | TODO | |
| I-08 | River (or worker) job runner + migrations | P2 | M | TODO | |
| I-09 | Docker Compose / k8s dev parity | P2 | M | TODO | |
| I-10 | CI: lint, test, build | P2 | M | TODO | |

---

## Core API

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| A-01 | `POST /db/new` — Postgres provision + onboarding JWT | P1 | L | TODO | Feature-flagged |
| A-02 | `POST /cache/new`, `POST /nosql/new`, queue/storage/webhook as enabled | P1 | L | TODO | Same provision helper patterns |
| A-03 | `GET /start`, `POST /claim` — atomic single-use JWT | P1 | L | TODO | |
| A-04 | `GET /healthz`, `GET /metrics` | P1 | S | TODO | |
| A-05 | Management APIs under `/api/v1/resources*` + rotate-credentials for pg/redis/mongo | P1 | M | TODO | **RotateCredentials:** Postgres `ALTER ROLE`, Redis `ACL SETUSER`, MongoDB `updateUser`; returns new `connection_url` |

---

## Middleware

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| M-01 | Fingerprint + geo enrichment | P1 | M | TODO | |
| M-02 | Provisioning dedup: `prov:{fingerprint}:{date}` fail-open | P1 | M | TODO | 6th provision returns existing resource |
| M-03 | Throughput quota where applicable | P1 | S | TODO | Service-specific keys |
| M-04 | Onboarding JWT in `note` + `X-Instant-Upgrade` | P1 | M | TODO | |

---

## Background Jobs

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| J-01 | Expire anonymous resources | P1 | S | TODO | |
| J-02 | Storage / quota enforcement workers | P2 | M | TODO | |
| J-03 | Trial / billing reconciliation emails | P2 | S | TODO | |
| J-04 | Geo DB refresh | P3 | M | TODO | |

---

## Auth & Billing

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| B-01 | GitHub OAuth + session JWT | P1 | M | TODO | |
| B-02 | `POST /billing/checkout` — Razorpay subscription | P1 | M | TODO | |
| B-03 | `POST /razorpay/webhook` — verify `RAZORPAY_WEBHOOK_SECRET` | P1 | L | TODO | |
| B-04 | CLI device flow `/auth/cli` | P2 | M | TODO | |

---

## Observability

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| O-01 | `/metrics` + `provisions_total` | P1 | S | TODO | |
| O-02 | Structured logs with `request_id` | P1 | S | TODO | |
| O-03 | Conversion funnel counters | P1 | M | TODO | |

---

## Testing

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| T-01 | Crypto + fingerprint unit tests | P1 | XS | TODO | |
| T-02 | JWT + onboarding claim concurrency | P1 | M | TODO | |
| T-03 | Provisioning integration tests per service | P1 | M | TODO | httptest + real Postgres/Redis |
| T-04 | E2E black-box against running cluster | P1 | M | TODO | `-tags e2e` |

---

## Summary

| Group | P1 | P2 | P3 | Total |
|-------|----|----|-----|-------|
| Infrastructure | 5 | 5 | 0 | 10 |
| Core API | 5 | 0 | 0 | 5 |
| Middleware | 4 | 0 | 0 | 4 |
| Background Jobs | 1 | 2 | 1 | 4 |
| Auth & Billing | 3 | 1 | 0 | 4 |
| Observability | 3 | 0 | 0 | 3 |
| Testing | 4 | 0 | 0 | 4 |
| **Total** | **25** | **8** | **1** | **34** |

**Critical path (indicative):** I-01 → I-02 → I-03 → I-04 → M-01 → M-02 → A-01 → A-03 → B-02 → B-03

---

## Phase 6 — Multi-Service Stack Feature (Post-Review TODOs)

> Items below were deferred during the /plan-eng-review of the Stack architecture (2026-04-10).
> Stack MVP covers: instant.yaml manifest, parallel builds, per-stack k8s namespace,
> credential injection via k8s Secret, selective Ingress for expose: true services.

| # | Task | Priority | Effort | Status | Notes |
|---|------|----------|--------|--------|-------|
| S-01 | Ingress TLS (HTTPS for exposed services) | P1 | M | TODO | MVP creates HTTP-only Ingress. Production startup APIs need HTTPS. Requires cert-manager + Let's Encrypt ACME solver installed in cluster. In K8sStackProvider.createIngress(): add spec.tls[].hosts + spec.tls[].secretName + annotation cert-manager.io/cluster-issuer: letsencrypt-prod. **Depends on:** Stack MVP shipped, cert-manager installed. |
| S-02 | Stack compute billing / usage tracking | P2 | L | TODO | Pro/Team stacks consume CPU/memory indefinitely. Without metering, a 10-service Pro stack is underpriced. Approach: Worker job runs hourly, queries metrics-server per stack namespace (kubectl top pod -n instant-stack-{id} or Prometheus node_namespace_pod_container metric), writes to stacks_usage table. Bill at month-end or enforce hard stop at monthly quota. **Depends on:** Stack MVP, Prometheus metrics-server in cluster, Razorpay or usage-based billing as designed. |
| S-03 | Unit tests for deploy_stack MCP tool | P1 | S | TODO | mcp/src/client.ts deploy_stack tool reads instant.yaml and creates per-service tarballs from build contexts. Incorrect relative paths or missing Dockerfiles fail silently (server returns 400 with no clear cause). Use node:test + tmp directories. Cover: valid 2-service project, missing Dockerfile in one service, symlinks in build context, service:// refs in instant.yaml. **Depends on:** deploy_stack MCP tool implementation. |
