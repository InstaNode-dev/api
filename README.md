# instanode.dev — Agent API

Zero-friction developer infrastructure. One HTTP call provisions a real database, cache, queue,
webhook receiver, or object storage bucket — no account, no Docker, no setup.

```bash
# Provision a Postgres database — no auth required
curl -s -X POST https://api.instanode.dev/db/new | jq .
```
```json
{
  "ok": true,
  "token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "connection_url": "postgres://usr_a1b2:pass_a1b2@shared.instanode.dev/db_a1b2",
  "tier": "anonymous",
  "limits": { "storage_mb": 10, "connections": 2, "expires_in": "24h" },
  "note": "Works now. Free forever with a free account: https://instanode.dev/start?t=eyJ..."
}
```

Use the `connection_url` directly with any standard driver. The upgrade URL in the `note` field
pre-fills a signup page with everything you've provisioned. Sign up → resources claimed → continue on the free anonymous tier (24h TTL) or upgrade to a paid tier — no trial; pay from day one.

---

## What's live

| Endpoint | What you get |
|---|---|
| `POST /db/new` | Postgres connection string |
| `POST /cache/new` | Redis connection string |
| `POST /nosql/new` | MongoDB connection string |
| `POST /queue/new` | NATS JetStream URL |
| `POST /webhook/new` | Webhook receiver URL |
| `POST /storage/new` | S3-compatible bucket credentials |
| `POST /stacks/new` | Deploy a full multi-service Docker app |

All endpoints work anonymously (24h, shared infra) or with a Bearer JWT (permanent, plan limits).

---

## Quick start (local Kubernetes)

**Prerequisites:** Go 1.24+, Rancher Desktop (includes k3s), kubectl, Docker, buf

```bash
# From the repo root (cron/)
cd infra/k8s

# 1. Namespaces first
kubectl apply -f namespace.yaml

# 2. Secrets (edit with real values — see secrets.yaml comments)
kubectl apply -f secrets.yaml
kubectl apply -f infra-secrets.yaml

# 3. Data services
kubectl apply -f data/postgres-customers.yaml
kubectl apply -f data/redis-provision.yaml
kubectl apply -f data/mongodb.yaml
kubectl apply -f data/nats.yaml
kubectl apply -f data/minio.yaml

# 4. Platform services
kubectl apply -f postgres-platform.yaml
kubectl apply -f redis.yaml
kubectl apply -f configmap.yaml
kubectl apply -f migrations-configmap.yaml

# 5. Build + deploy
docker build -f api/Dockerfile -t instant-api:local .   # from cron/ root
kubectl apply -f app.yaml

# 6. Verify (Service is ClusterIP — port-forward for local access):
kubectl rollout status deployment/instant-api -n instant
kubectl port-forward -n instant svc/instant-api 8080:8080 &
curl http://localhost:8080/healthz
# → {"ok":true}
```

See [CLAUDE.md](../CLAUDE.md) for the complete setup including provisioner and worker.

---

## Quick start (docker-compose)

```bash
cd infra
docker compose up -d

cd api
cp .env.example .env   # edit INSTANT_ENABLED_SERVICES and secrets
make run
# → Server listening on :8080
```

---

## Development

```bash
cd api

make run          # start server (reads .env)
make test         # unit + integration tests (needs TEST_DATABASE_URL)
make test-e2e     # E2E against k8s (port-forward svc/instant-api 8080:8080 first; NodePort retired)
make docker-build # docker build from repo root
```

### E2E tests

```bash
# Port-forward the API (Service is ClusterIP; NodePort retired 2026-05-11):
kubectl port-forward -n instant svc/instant-api 8080:8080 &

# Basic — no auth/Razorpay needed
E2E_BASE_URL=http://localhost:8080 go test ./e2e/... -tags e2e -timeout 60s

# Full — with tier mechanics, Razorpay, real DB writes
JWT_SECRET=$(kubectl get secret instant-secrets -n instant -o jsonpath='{.data.JWT_SECRET}' | base64 -d)
RAZORPAY_SECRET=$(kubectl get secret instant-secrets -n instant -o jsonpath='{.data.RAZORPAY_WEBHOOK_SECRET}' | base64 -d)

E2E_BASE_URL=http://localhost:8080 \
E2E_JWT_SECRET="$JWT_SECRET" \
E2E_RAZORPAY_WEBHOOK_SECRET="$RAZORPAY_SECRET" \
go test ./e2e/... -v -tags e2e -timeout 90s
```

---

## Project structure

```
api/
├── main.go                      Entry point — wires config, DB, router
├── plans.yaml                   SINGLE SOURCE OF TRUTH for all tier limits
├── Dockerfile                   Build context is repo root (COPY api/ .)
├── internal/
│   ├── config/                  Environment config (panics on missing required vars)
│   ├── crypto/                  AES-256-GCM encryption + JWT signing
│   ├── db/migrations/           SQL schema (001_initial.sql)
│   ├── handlers/                HTTP handlers — one file per service
│   │   ├── db.go                POST /db/new
│   │   ├── cache.go             POST /cache/new
│   │   ├── nosql.go             POST /nosql/new
│   │   ├── queue.go             POST /queue/new
│   │   ├── webhook.go           POST /webhook/new + /receive + /requests
│   │   ├── storage.go           POST /storage/new
│   │   ├── deploy.go            POST /deploy/new (single-service app deploy)
│   │   ├── stack.go             POST /stacks/new (multi-service stack deploy)
│   │   ├── logs.go              GET /resources/:token/logs (SSE streaming)
│   │   ├── billing.go           POST /razorpay/webhook, billing checkout
│   │   └── onboarding.go        POST /claim, GET /start
│   ├── middleware/              Auth, fingerprint, geo, rate-limit
│   ├── models/                  DB query functions (no ORM)
│   ├── plans/                   Loads + exposes plans.yaml limits
│   ├── provisioner/             gRPC client → instant-provisioner service
│   ├── manifest/                instant.yaml parser for stack deploys
│   └── router/                  Fiber app wiring
└── e2e/                         Black-box E2E tests (build tag: e2e)
```

---

## Architecture

```
Claude Code / curl / MCP tools
        │
        ▼
  api/ — port 8080 (ClusterIP Service; port-forward locally)
        │
        ├─ Middleware chain:
        │   RequestID → Recover → CORS → GeoEnrich → Fingerprint → RateLimit
        │
        ├─ Synchronous provisioning handlers
        │   (provision fails → 503, never returns broken credentials)
        │
        └─ gRPC ──────────────────────────────────────────────────────────────►
                                                           provisioner/ port 50051
                                                           (CREATE DATABASE, ACL USER, etc.)
        │
        ├─ Platform DB (postgres-platform)   — teams, resources, tokens, events
        └─ Customer DB (postgres-customers)  — actual customer databases live here
```

Two separate Postgres instances. Using the wrong one causes silent failures — see [docs/gotchas.md](../docs/gotchas.md).

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | Platform Postgres DSN (instant_platform) |
| `CUSTOMER_DATABASE_URL` | ✅ | Customer provisioning Postgres DSN |
| `REDIS_URL` | ✅ | Redis DSN |
| `JWT_SECRET` | ✅ | HMAC-SHA256 key, ≥32 bytes |
| `AES_KEY` | ✅ | AES-256 key, **exactly 64 hex chars** |
| `PROVISIONER_ADDR` | ✅ | gRPC address of instant-provisioner |
| `INSTANT_ENABLED_SERVICES` | — | Comma-separated feature flags (default: all) |
| `ENVIRONMENT` | — | `development` or `production` |
| `RAZORPAY_KEY_ID` | — | Razorpay API key id (billing; disabled if empty) |
| `RAZORPAY_KEY_SECRET` | — | Razorpay API key secret |
| `RAZORPAY_WEBHOOK_SECRET` | — | Razorpay webhook HMAC verification |
| `GITHUB_CLIENT_ID/SECRET` | — | GitHub OAuth |
| `GEOLITE2_DB_PATH` | — | MaxMind GeoLite2 path (geo enrichment) |

All values live in `infra/k8s/secrets.yaml` (k8s) or `.env` (local). See [CLAUDE.md](../CLAUDE.md) for secret generation.

---

## Key conventions

1. **Fail-open on Redis errors** — rate limit and quota checks return `(false, err)`. Redis outage never blocks provisioning.
2. **All limits from `plans.yaml`** — never hardcode limit values. Use `h.plans.StorageLimitMB(tier, service)`.
3. **Synchronous provisioning** — if it fails, return 503. Never return credentials for a non-existent resource.
4. **AES-256-GCM for `connection_url`** — all URLs encrypted at rest, decrypted on read. Key rotation is fail-open (returns ciphertext on decrypt error).
5. **Token = credential** — most endpoints use the token directly, no separate auth.

See [docs/gotchas.md](../docs/gotchas.md) for common mistakes.
