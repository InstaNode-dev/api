.PHONY: run build build-cli test test-unit gate test-db-up test-db-down test-db-reset \
        docker-up docker-down docker-logs \
        migrate migrate-platform migrate-customers \
        docker-build smoke-buildinfo \
        openapi-snapshot openapi-snapshot-check \
        k8s-deploy k8s-delete k8s-status k8s-regen-migrations \
        gen-secrets install-cli \
        storage-verify-isolation \
        loadtest chaostest

# Build-time metadata injected into instant.dev/common/buildinfo via -ldflags.
# Override on the make line if needed. GIT_SHA falls back to "dev" when not
# in a git checkout (e.g. CI tarball builds).
GIT_SHA    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION    ?= dev

# Local test database — Postgres 16 in Docker on localhost:5432. Matches
# testhelpers.defaultTestDBURL so tests run without setting any env vars
# beyond TEST_DATABASE_URL (which `make test-unit` sets for you).
TEST_DB_URL := postgres://postgres:postgres@localhost:5432/instant_dev_test?sslmode=disable

# Spin up the test-pg container + create + migrate the test DB. Idempotent.
test-db-up:
	@docker inspect test-pg >/dev/null 2>&1 || \
	  docker run -d --name test-pg -p 5432:5432 \
	    -e POSTGRES_PASSWORD=postgres postgres:16-alpine
	@docker start test-pg >/dev/null 2>&1 || true
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
	  docker exec test-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; \
	done
	@docker exec test-pg psql -U postgres -tc \
	  "SELECT 1 FROM pg_database WHERE datname='instant_dev_test'" | grep -q 1 || \
	  docker exec test-pg psql -U postgres -c "CREATE DATABASE instant_dev_test"
	@for f in internal/db/migrations/*.sql; do \
	  docker exec -i test-pg psql -U postgres -d instant_dev_test < "$$f" >/dev/null 2>&1; \
	done
	@echo "test-pg ready · TEST_DATABASE_URL=$(TEST_DB_URL)"

test-db-down:
	@docker rm -f test-pg 2>/dev/null || true

test-db-reset: test-db-down test-db-up

# PR gate: run unit tests per-package against the test DB. Per-package
# avoids cross-package test-pollution issues in the existing suite.
test-unit: test-db-up
	@TEST_DATABASE_URL="$(TEST_DB_URL)" go build ./...
	@TEST_DATABASE_URL="$(TEST_DB_URL)" go vet ./...
	@for pkg in $$(go list ./... | grep -v /e2e); do \
	  echo "→ $$pkg"; \
	  TEST_DATABASE_URL="$(TEST_DB_URL)" go test "$$pkg" -short -count=1 -timeout 90s || exit 1; \
	done
	@echo "test-unit: all packages green"

# PR/deploy gate: runs EXACTLY what .github/workflows/deploy.yml runs as its
# test gate, so a green `make gate` locally == a green CI test step. The
# deploy.yml gate is `go build ./... && go vet ./... && go test ./... -short
# -count=1 -p 1` against a real Postgres + Redis (see the deploy.yml
# "Run unit tests" step). `-p 1` is load-bearing — every package shares the
# single instant_dev_test DB + redis/15 and the suite corrupts itself under
# default parallelism. test-db-up provides the DB; the customer-DB admin
# target (TEST_POSTGRES_CUSTOMERS_URL) defaults to an unreachable localhost
# instance locally, so a handful of postgres-provisioning tests may 503 on a
# bare laptop — that is the known local-only gap, CI provides that DB.
gate: test-db-up
	@TEST_DATABASE_URL="$(TEST_DB_URL)" go build ./...
	@TEST_DATABASE_URL="$(TEST_DB_URL)" go vet ./...
	@TEST_DATABASE_URL="$(TEST_DB_URL)" go test ./... -short -count=1 -p 1
	@echo "gate: green — matches deploy.yml test step"

# ── Local development ─────────────────────────────────────────────────────────

run:
	go run main.go

build:
	go build -o bin/instant-api main.go

# Build the `instant` CLI tool (for external users — install to instrument their cron jobs)
build-cli:
	go build -o bin/instant ./cmd/instant/

# Install the `instant` CLI to /usr/local/bin (requires write permission)
install-cli: build-cli
	install -m 0755 bin/instant /usr/local/bin/instant
	@echo "instant CLI installed to /usr/local/bin/instant"
	@echo "Try: instant monitor new"
	@echo "     instant discover"

test:
	go test ./... -v -race

# E2E tests — run against live server (k8s or docker-compose)
# E2E_BASE_URL defaults to http://localhost:32108 (Rancher Desktop NodePort)
test-e2e:
	go test ./e2e/... -v -tags e2e -timeout 60s

# E2E tests with secrets fetched from the k8s cluster.
# This enables management-API tests (GET /auth/me, credential rotation, etc.)
# that require a valid signed session JWT, the Razorpay billing/webhook suite,
# and the genuine free/hobby -> pro upgrade assertions.
#
# When to use: run `make test-e2e-full` instead of `make test-e2e` any time
# you change an authenticated endpoint, the billing path, or want the complete
# E2E suite.
#
# Secrets pulled read-only from the `instant-secrets` secret:
#   JWT_SECRET               — sign session JWTs (auth-gated tests)
#   RAZORPAY_WEBHOOK_SECRET  — sign synthetic Razorpay webhook payloads
#   RAZORPAY_PLAN_ID_PRO     — the real Pro plan_id; without it the pro-tier
#                              upgrade assertions SKIP (post-F3 an empty
#                              plan_id maps to `hobby`, not `pro`).
#   E2E_TEST_TOKEN           — restores per-test fingerprint isolation behind
#                              an ingress that overwrites X-Forwarded-For;
#                              without it every test can hit the recycle gate.
#
# Requires: kubectl access to the `instant` namespace.
test-e2e-full:
	E2E_JWT_SECRET=$(shell kubectl get secret instant-secrets -n instant -o jsonpath='{.data.JWT_SECRET}' 2>/dev/null | base64 -d) \
	E2E_RAZORPAY_WEBHOOK_SECRET=$(shell kubectl get secret instant-secrets -n instant -o jsonpath='{.data.RAZORPAY_WEBHOOK_SECRET}' 2>/dev/null | base64 -d) \
	E2E_RAZORPAY_PLAN_ID_PRO=$(shell kubectl get secret instant-secrets -n instant -o jsonpath='{.data.RAZORPAY_PLAN_ID_PRO}' 2>/dev/null | base64 -d) \
	E2E_TEST_TOKEN=$(shell kubectl get secret instant-secrets -n instant -o jsonpath='{.data.E2E_TEST_TOKEN}' 2>/dev/null | base64 -d) \
	  go test ./e2e/... -v -tags e2e -timeout 90s

test-e2e-docker:
	E2E_BASE_URL=http://localhost:8080 go test ./e2e/... -v -tags e2e -timeout 60s

# ── Docker (Rancher Desktop) ──────────────────────────────────────────────────

docker-up:
	docker compose up -d
	@echo "Waiting for databases to be healthy..."
	@docker compose exec postgres_platform pg_isready -U instant -d instant_platform --timeout=30 2>/dev/null || true
	@docker compose exec postgres_customers pg_isready -U instant_cust -d instant_customers --timeout=30 2>/dev/null || true

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

# ── Migrations ────────────────────────────────────────────────────────────────

# Migrate both databases
migrate: migrate-platform migrate-customers

# Platform DB: teams, users, resources, pings, onboarding_events
migrate-platform:
	psql "$(DATABASE_URL)" -f internal/db/migrations/001_initial.sql
	@echo "Platform DB migration complete."

# Customer DB: no schema needed yet (Phase 1); creates the DB and enables pgvector for Phase 2
migrate-customers:
	@echo "Customer DB: no schema migration needed in Phase 1 (monitoring only)."
	@echo "Phase 2+: provisioning handlers will CREATE DATABASE db_{token} dynamically."

# ── Local Kubernetes (Rancher Desktop / k3s) ─────────────────────────────────

# NOTE: per CLAUDE.md the canonical build is from the repo root:
#   docker build -f api/Dockerfile -t instant-api:local \
#     --build-arg GIT_SHA=$(git rev-parse --short HEAD) \
#     --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
#     --build-arg VERSION=$VERSION ..
# This target mirrors that — `cd ..` first so the build context is the repo root.
docker-build:
	cd .. && docker build -f api/Dockerfile -t instant-api:local \
	  --build-arg GIT_SHA=$(GIT_SHA) \
	  --build-arg BUILD_TIME=$(BUILD_TIME) \
	  --build-arg VERSION=$(VERSION) \
	  .

# Verifies the -ldflags injection actually wires through to the buildinfo
# package. Builds a tiny throwaway binary, then runs it; expects to see the
# override value (`smoke-sha`) in stdout. CI can run this on every PR to
# catch a regression where someone breaks the ldflag path.
smoke-buildinfo:
	@tmpdir=$$(mktemp -d) && \
	  go build -ldflags "-X instant.dev/common/buildinfo.GitSHA=smoke-sha -X instant.dev/common/buildinfo.BuildTime=smoke-time -X instant.dev/common/buildinfo.Version=smoke-ver" \
	    -o $$tmpdir/smoke ./cmd/smoke-buildinfo && \
	  out=$$($$tmpdir/smoke) && \
	  echo "$$out" | grep -q "GitSHA=smoke-sha" || (echo "FAIL: $$out" && exit 1) && \
	  echo "$$out" | grep -q "BuildTime=smoke-time" || (echo "FAIL: $$out" && exit 1) && \
	  echo "$$out" | grep -q "Version=smoke-ver" || (echo "FAIL: $$out" && exit 1) && \
	  echo "smoke-buildinfo: OK ($$out)" && \
	  rm -rf $$tmpdir

# ── Cross-stack OpenAPI contract snapshot ─────────────────────────────────────
#
# api/openapi.snapshot.json is the source-of-truth artifact that the
# dashboard and instanode-web repos consume to generate their typed API
# clients (via openapi-typescript). It is the canonicalised JSON output of
# handlers.OpenAPISpecProduction() — the same spec served at GET /openapi.json
# in production.
#
# Workflow:
#   - Edit internal/handlers/openapi.go (add a path, change a schema).
#   - Run `make openapi-snapshot` — regenerates openapi.snapshot.json.
#   - Commit both files in the same PR (rule 22: contract surface checklist).
#   - CI runs `make openapi-snapshot-check` and fails the PR if the
#     committed snapshot differs from a freshly regenerated one.
#
# The snapshot tool canonicalises (sorted keys, 2-space indent) so that
# whitespace-only edits to the const do not flip the snapshot — only real
# contract changes do.
openapi-snapshot:
	@go run ./cmd/openapi-snapshot/

openapi-snapshot-check:
	@go run ./cmd/openapi-snapshot/ -out /tmp/openapi.snapshot.regenerated.json
	@if ! diff -q openapi.snapshot.json /tmp/openapi.snapshot.regenerated.json >/dev/null; then \
	  echo ""; \
	  echo "::error::openapi.snapshot.json is out of date."; \
	  echo "::error::Run \`make openapi-snapshot\` and commit the updated file."; \
	  echo ""; \
	  echo "Drift (committed → regenerated):"; \
	  diff -u openapi.snapshot.json /tmp/openapi.snapshot.regenerated.json | head -80 || true; \
	  exit 1; \
	fi
	@echo "openapi-snapshot-check: snapshot matches handlers.OpenAPISpecProduction()"

# Regen the SQL ConfigMap from the actual migration file (run after schema changes)
k8s-regen-migrations:
	kubectl create configmap instant-migrations \
	  --from-file=001_initial.sql=internal/db/migrations/001_initial.sql \
	  -n instant --dry-run=client -o yaml > k8s/migrations-configmap.yaml
	@echo "k8s/migrations-configmap.yaml updated. Run: kubectl apply -f k8s/migrations-configmap.yaml"

k8s-deploy:
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/secrets.yaml
	kubectl apply -f k8s/configmap.yaml
	kubectl apply -f k8s/
	@echo "Waiting for pods to be ready..."
	kubectl wait --for=condition=ready pod -l app=postgres-platform -n instant --timeout=60s
	kubectl wait --for=condition=ready pod -l app=postgres-customers -n instant --timeout=60s
	kubectl wait --for=condition=ready pod -l app=redis -n instant --timeout=60s
	kubectl wait --for=condition=ready pod -l app=instant-api -n instant --timeout=120s

k8s-delete:
	kubectl delete -f k8s/ --ignore-not-found

k8s-status:
	kubectl get pods,svc,configmap,secret -n instant

# ── Utilities ─────────────────────────────────────────────────────────────────

# Generate secure values for JWT_SECRET and AES_KEY
gen-secrets:
	@echo "JWT_SECRET=$(shell openssl rand -hex 32)"
	@echo "AES_KEY=$(shell openssl rand -hex 32)"

# ── Storage isolation verification ────────────────────────────────────────────
#
# Provision two storage tokens, then prove customer A's IAM user can't read
# customer B's prefix. With admin mode enabled, the cross-prefix GET MUST
# return HTTP 403. With shared-key mode (the loophole this PR closes) it
# would return HTTP 200 — that's the regression this target detects.
#
# Run against a live API + S3 endpoint:
#   API_BASE_URL=http://localhost:8080 \
#   S3_ENDPOINT=http://localhost:9000 \
#   make storage-verify-isolation
#
# Requires: curl, aws-cli (or mc) in PATH. See e2e/storage_isolation_e2e_test.go
# for an automated version that runs in CI.
storage-verify-isolation:
	@echo ""
	@echo "Storage isolation verification"
	@echo "──────────────────────────────"
	@: $${API_BASE_URL:?API_BASE_URL is required, e.g. http://localhost:8080}
	@: $${S3_ENDPOINT:?S3_ENDPOINT is required, e.g. http://localhost:9000}
	@echo "1/4 provisioning customer A..."
	@A=$$(curl -fsS -X POST $$API_BASE_URL/storage/new -H 'Content-Type: application/json' -d '{}'); \
	  AK_A=$$(echo $$A | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["access_key_id"])'); \
	  SK_A=$$(echo $$A | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["secret_access_key"])'); \
	  PRE_A=$$(echo $$A | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["prefix"])'); \
	  echo "2/4 provisioning customer B..."; \
	  B=$$(curl -fsS -X POST $$API_BASE_URL/storage/new -H 'Content-Type: application/json' -d '{}'); \
	  AK_B=$$(echo $$B | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["access_key_id"])'); \
	  PRE_B=$$(echo $$B | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["prefix"])'); \
	  echo "  A: ak=$$AK_A prefix=$$PRE_A"; \
	  echo "  B: ak=$$AK_B prefix=$$PRE_B"; \
	  echo "3/4 writing a test object as A under A's prefix..."; \
	  echo "hello-from-A" > /tmp/.storage-iso-test.txt; \
	  AWS_ACCESS_KEY_ID=$$AK_A AWS_SECRET_ACCESS_KEY=$$SK_A \
	    aws --endpoint-url $$S3_ENDPOINT s3 cp /tmp/.storage-iso-test.txt s3://instant-shared/$${PRE_A}probe.txt; \
	  echo "4/4 attempting cross-prefix read (B's key trying to read A's object)..."; \
	  AWS_ACCESS_KEY_ID=$$AK_B AWS_SECRET_ACCESS_KEY=$$SK_A \
	    aws --endpoint-url $$S3_ENDPOINT s3 cp s3://instant-shared/$${PRE_A}probe.txt /tmp/.steal.txt 2>&1 | grep -q 'AccessDenied\|403' \
	    && echo "PASS isolation enforced — cross-prefix read returned 403" \
	    || (echo "FAIL cross-prefix read succeeded — shared-key loophole is OPEN"; exit 1)

# ── Load & chaos harness ──────────────────────────────────────────────────────
#
# The load/chaos harness lives in e2e/loadtest_*.go behind the build
# constraint `//go:build loadtest && e2e`. The normal PR/deploy gate uses NO
# tag and the standard E2E gate uses `-tags e2e` only — so neither ever
# compiles or runs this harness. Only `make loadtest` / `make chaostest`
# pass both tags.
#
# Both targets run against a LIVE deployment (prod or local). They are
# free-tier-only and cost-safe: no Razorpay, no deploy/kaniko builds, and
# every provisioned resource is tracked in a ledger and torn down (per-
# resource defer + mid-run batch sweeps + final sweep + zero-leak assertion).
#
# ── loadtest ──
# Concurrency / dedup / rate-limit load. Two lanes:
#   Lane A (authenticated): claims ONE free-tier team, mints a session JWT,
#           and drives concurrent provisioning through the authenticated
#           path (which bypasses the free-tier recycle gate). Requires
#           E2E_JWT_SECRET. If unavailable, Lane A self-skips.
#   Lane B (anonymous): load-tests the 402 recycle gate + dedup + rate
#           limiting directly, asserting clean 402/429s and no 5xx.
#
# Required: E2E_BASE_URL.   Recommended: E2E_JWT_SECRET (enables Lane A).
# Optional: LOAD_CONCURRENCY (default 20).
#
#   E2E_BASE_URL=https://api.instanode.dev \
#   E2E_JWT_SECRET=$$(kubectl get secret instant-secrets -n instant \
#     -o jsonpath='{.data.JWT_SECRET}' | base64 -d) \
#   make loadtest
loadtest:
	@: $${E2E_BASE_URL:?set E2E_BASE_URL to the live API root, e.g. https://api.instanode.dev}
	go test ./e2e/... -tags 'e2e loadtest' -v -count=1 -timeout 600s \
	  -run 'TestLoad_'

# ── chaostest ──
# Safe, non-destructive chaos: kills ONE replica at a time of instant-api,
# instant-worker, instant-provisioner (`kubectl delete pod`), waits for full
# self-heal, and asserts /healthz stays serving with no 5xx / no silent
# drops. Stateless deployments only — instant-data stateful pods are never
# touched, nothing is scaled to zero, no DB failover.
#
# Required: E2E_BASE_URL + working kubectl context (do-nyc3-instant-prod).
# Optional: CHAOS_NAMESPACE_APP (default instant),
#           CHAOS_NAMESPACE_INFRA (default instant-infra),
#           CHAOS_RECOVER_TIMEOUT (default 120s).
#
#   E2E_BASE_URL=https://api.instanode.dev make chaostest
chaostest:
	@: $${E2E_BASE_URL:?set E2E_BASE_URL to the live API root, e.g. https://api.instanode.dev}
	go test ./e2e/... -tags 'e2e loadtest' -v -count=1 -timeout 600s \
	  -run 'TestChaos_'

# ── chaostest-propagation (CHAOS-DRILL-2026-05-20 Test 1) ──
# Exercises the propagation_runner retry + dead-letter path end-to-end against
# the LIVE worker. Seeds a synthetic team + bogus postgres resource + a
# pending_propagations row pre-attempted to (maxAttempts-1) so the next worker
# tick dead-letters. Asserts:
#   - Worker picks up the row within the tick budget.
#   - Backoff schedule advances per propagationBackoffSchedule[0]=1m.
#   - Row transitions to failed_at, propagation.dead_lettered audit row emitted.
#
# Required: E2E_PLATFORM_DB_URL (= kubectl get secret instant-secrets -n instant \
#                                     -o jsonpath='{.data.DATABASE_URL}' | base64 -d)
# Optional: CHAOS_TICK_BUDGET (default 90s),
#           CHAOS_BACKOFF_PHASE=skip to skip Phase B.
chaostest-propagation:
	@: $${E2E_PLATFORM_DB_URL:?set E2E_PLATFORM_DB_URL — see CHAOS-DRILL-2026-05-20.md}
	go test ./e2e/... -tags chaos -v -count=1 -timeout 600s \
	  -run 'TestChaos_PropagationRunner_DeadLetterPath'

# ── chaostest-lease-recovery (CHAOS-DRILL-2026-05-20 Test 2) ──
# Worker pod-kill / lease-takeover drill. Enqueues a stub chaos_lease_recovery
# job, waits for the start marker, then PAUSES for the operator to run
#   kubectl delete pod -n instant-infra <pod-id> --grace-period=0 --force
# and polls for the end marker emitted by a sibling worker after River's
# rescuer re-leases the orphaned job. Reports the observed lease-recovery
# RTO. River default = JobTimeout (20m) + RescueAfter (1h) ≈ 1h20m worst case.
#
# Required: E2E_PLATFORM_DB_URL (same as chaostest-propagation).
# Optional: CHAOS_LEASE_SLEEP_SECONDS (default 180),
#           CHAOS_LEASE_RTO_BUDGET (default 90m),
#           CHAOS_LEASE_MODE=observe to skip the operator prompt.
chaostest-lease-recovery:
	@: $${E2E_PLATFORM_DB_URL:?set E2E_PLATFORM_DB_URL — see CHAOS-DRILL-2026-05-20.md}
	go test ./e2e/... -tags chaos -v -count=1 -timeout 7200s \
	  -run 'TestChaos_WorkerLeaseRecovery'
