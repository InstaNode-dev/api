# Contributing to instant.dev

## Prerequisites

- Go 1.23+
- Rancher Desktop (or Docker Desktop) — for local Postgres + Redis
- `psql` client — for running migrations manually
- `kubectl` — for k8s deployment (optional)

## Development setup

```bash
# Clone and enter the repo
git clone https://github.com/instant-dev/instant
cd instant

# Generate cryptographic secrets for local dev
make gen-secrets
# Copy the output into .env

cp .env.example .env
# Fill in JWT_SECRET and AES_KEY from gen-secrets output.
# All other vars are optional in development.

# Start the database containers
make docker-up

# Run platform schema migrations
make migrate-platform

# Start the server (hot reload not included — just re-run on changes)
make run
```

The server starts on `:8080`. Verify with `curl http://localhost:8080/healthz`.

## Running tests

Tests split into two tiers:

### Unit + integration tests

Run against real Postgres and Redis. Set `TEST_DATABASE_URL` and `TEST_REDIS_URL`, or rely on defaults:

```bash
# Defaults: postgres://postgres:postgres@localhost:5432/instant_dev_test, redis://localhost:6379/15
make test

# With explicit DSNs
TEST_DATABASE_URL=postgres://instant:instant@localhost:5432/instant_platform?sslmode=disable \
TEST_REDIS_URL=redis://localhost:6379/15 \
make test
```

### E2E tests

Run against a live server — uses real HTTP, no in-process Fiber:

```bash
# Against local k8s (Rancher Desktop)
make test-e2e                     # default: http://localhost:32108

# Against docker-compose
make docker-up && make migrate-platform
make run &
make test-e2e-docker              # http://localhost:8080
```

E2E tests use the `//go:build e2e` build tag and live in `e2e/`. They are isolated from the regular test suite and will not run with `go test ./...`.

## Project layout

```
internal/config/     — Environment loading. Add new env vars here only.
internal/crypto/     — AES encryption, JWT signing, IP fingerprinting. No external state.
internal/db/         — DB + Redis connection helpers. One function per resource.
internal/email/      — Resend client. Wrap all sends in the Client.send() dispatcher.
internal/handlers/   — HTTP handlers. Each handler file owns one domain (ping, auth, etc.).
internal/jobs/       — River background workers. One worker per file.
internal/metrics/    — Prometheus gauges/counters/histograms. Register once at package init.
internal/middleware/  — Fiber middleware. Each file is one middleware function.
internal/models/     — DB query functions. No ORM — raw sql.DB + typed errors only.
internal/router/     — Fiber app assembly. Middleware chain order is load-bearing.
internal/testhelpers/ — Shared test utilities. No production code here.
e2e/                 — Black-box HTTP tests. Must compile with -tags e2e.
```

## Coding conventions

**No ORM.** All DB queries use `database/sql` directly. Write typed error sentinel types (`ErrXNotFound`, `ErrXAlreadyUsed`) rather than checking `sql.ErrNoRows` in handlers.

**Fail-open on Redis errors.** Rate limit and cache misses must never block a request. Log the error and continue.

**Two separate databases.** Platform metadata (teams, users, resources, pings) goes in `DATABASE_URL`. Customer-provisioned databases (Phase 2+) go in `CUSTOMER_DATABASE_URL`. Never mix them.

**Atomic single-use enforcement.** The onboarding JWT claim uses an atomic `UPDATE ... WHERE jti = $2 AND converted_at IS NULL RETURNING id`. All single-use semantics must use this pattern — never a SELECT-then-UPDATE.

**Typed errors over sentinel strings.** Define `type ErrFoo struct { ... }` and use `errors.As` in callers. Do not check `err.Error() == "some string"`.

**Middleware context values.** Use the typed getters in `internal/middleware` (`GetFingerprint`, `GetGeoCountry`, etc.) to read context values. Do not access `fiber.Locals` with string keys directly in handlers.

**Prometheus metrics.** Every new significant codepath needs at least one counter. Register metrics in `internal/metrics/metrics.go`. Label cardinality must stay low — no per-token labels.

**Background jobs.** All scheduled work runs as River workers. Do not add `time.Sleep` loops or `cron.Cron` schedulers. See `internal/jobs/workers.go` for registration.

**Feature flags.** Gate new services behind `cfg.IsServiceEnabled("service-name")`. Add the service name to `INSTANT_ENABLED_SERVICES` in `.env.example` when ready to enable by default.

## Adding a new endpoint

1. Add the handler method to the appropriate file in `internal/handlers/`.
2. Register the route in `internal/router/router.go`.
3. Add model functions in `internal/models/` if new DB queries are needed.
4. Add integration tests in `internal/handlers/*_test.go`.
5. Add E2E coverage in `e2e/e2e_test.go`.

## Adding a new background job

1. Create `internal/jobs/{name}.go` with a River worker struct.
2. Register it in `internal/jobs/workers.go` (`workers.AddWorker`).
3. Schedule it in `StartWorkers` with `river.NewClient` periodic jobs.

## Schema changes

Add a new migration file:

```bash
# Name it sequentially
touch internal/db/migrations/002_add_something.sql

# Apply locally
make migrate-platform

# Embed in the k8s ConfigMap
make k8s-regen-migrations
```

All migration SQL must be idempotent (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`).

If adding a new monthly pings partition, update the helpers in `testhelpers.go` too.

## Pull request checklist

- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] New code has unit or integration tests
- [ ] E2E tests updated if new endpoints added
- [ ] `.env.example` updated if new env vars added
- [ ] No secrets or credentials committed
- [ ] Migrations are idempotent
