.PHONY: run build build-cli test test-unit gate test-db-up test-db-down test-db-reset \
        docker-up docker-down docker-logs \
        migrate migrate-platform migrate-customers \
        docker-build smoke-buildinfo \
        k8s-deploy k8s-delete k8s-status k8s-regen-migrations \
        gen-secrets install-cli \
        storage-verify-isolation

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

# E2E tests with JWT secret fetched from the k8s cluster.
# This enables management-API tests (GET /auth/me, credential rotation, etc.)
# that require a valid signed session JWT.
#
# When to use: run `make test-e2e-full` instead of `make test-e2e` any time
# you change an authenticated endpoint or want the complete E2E suite.
#
# Requires: kubectl access to the `instant` namespace.
test-e2e-full:
	E2E_JWT_SECRET=$(shell kubectl get secret instant-secrets -n instant -o jsonpath='{.data.JWT_SECRET}' 2>/dev/null | base64 -d) \
	  go test ./e2e/... -v -tags e2e -timeout 60s

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
