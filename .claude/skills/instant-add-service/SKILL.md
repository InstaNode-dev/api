---
name: instant-add-service
version: 1.0.0
description: |
  Scaffold a new provisioning service for instant.dev (e.g., postgres, redis, mongodb).
  Creates handler, model, route, migration, feature flag, metrics, tests, E2E, and docs.
  Run as: /instant-add-service postgres
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - AskUserQuestion
---

# /instant-add-service — Add a New Provisioning Service

You are scaffolding a new instant.dev provisioning service. The service name is the argument passed to this skill (e.g., `/instant-add-service postgres` → service = "postgres").

**If no service name is provided**, ask: "Which service are you adding? (e.g., postgres, redis, mongodb, nats, storage, webhook)"

Read the existing `internal/handlers/db.go`, `internal/handlers/cache.go`, and `internal/router/router.go` before writing anything. Your implementation must follow the same provisioning patterns as those handlers.

---

## Step 0: Gather context

Ask the user (one question, all at once):
1. Service name (if not provided as argument)
2. What does provisioning return? (connection string, bucket URL, webhook URL, etc.)
3. What are the anonymous tier limits? (storage, connections, TTL)
4. Is there an external provider to call? (Neon, Upstash, Atlas, R2, etc.) Or is it local-only for now?

If the user says "use defaults" or "figure it out", use these defaults:
- Tier: anonymous, 24h TTL
- Return: `{ token, connection_url, tier, limits, note }`
- Provider: stub (return a placeholder URL, real provisioning in Phase N+1)

---

## Step 1: Confirm the plan

Output a concise plan before writing any code:

```
Adding service: {name}

Files to create:
  internal/handlers/{name}.go
  internal/handlers/{name}_test.go
  e2e/{name}_e2e_test.go

Files to edit:
  internal/router/router.go          (register routes)
  internal/metrics/metrics.go        (add provisions counter label)
  .env.example                       (add service to INSTANT_ENABLED_SERVICES comment)
  docs/api.md                        (add endpoint documentation)
  docs/openapi.yaml                  (add path and schema)
  docs/quickstart.md                 (add language examples if appropriate)
  README.md                          (update Phase table if new phase)

Migration: only if new DB columns needed (most services reuse resources table)
```

AskUserQuestion: "Does this plan look right? Any changes before I start?" Do not proceed until confirmed.

---

## Step 2: Handler (`internal/handlers/{name}.go`)

Create the handler file following the `db.go` / `cache.go` provisioning structure:

```go
package handlers

// {Name}Handler handles POST /{name}/new provisioning.
type {Name}Handler struct {
    db  *sql.DB
    rdb *redis.Client
    cfg *config.Config
}

// New{Name}Handler constructs a {Name}Handler.
func New{Name}Handler(db *sql.DB, rdb *redis.Client, cfg *config.Config) *{Name}Handler { ... }

// New{Name} handles POST /{name}/new — provision an anonymous {name} resource.
func (h *{Name}Handler) New{Name}(c *fiber.Ctx) error {
    // 1. Check cfg.IsServiceEnabled("{name}") → 503 if disabled
    // 2. Extract fingerprint, country, vendor, requestID from middleware
    // 3. checkProvisionLimit (same Redis pattern as db.go / provision_helper)
    // 4. If limit exceeded → return existing resource or CTA
    // 5. Provision the resource (stub or real provider call)
    // 6. models.CreateResource(...)
    // 7. Issue onboarding JWT + create onboarding_event
    // 8. Set X-Instant-Upgrade header
    // 9. Increment metrics.ProvisionsTotal.WithLabelValues("{name}", "anonymous")
    // 10. Return 201 with token, connection_url, tier, limits, note
}
```

**Critical rules:**
- `checkProvisionLimit` must use the `prov:{fingerprint}:{date}` Redis key with 25h TTL — copy from `db.go` / shared provision helpers exactly.
- Create the `onboarding_event` row in BOTH the new-resource path AND the limit-exceeded path.
- Never return the raw `connection_url` from the DB — it is AES-encrypted at rest. Decrypt before returning (or return the plain value that was encrypted on write).
- Fail open on Redis errors.
- The `note` field must contain the full upgrade URL: `https://instant.dev/start?t={jwt}`.

---

## Step 3: Route registration (`internal/router/router.go`)

Add after the existing provisioning routes (see `router.go`):

```go
// {Name} provisioning
{name}H := handlers.New{Name}Handler(db, rdb, cfg)
app.Post("/{name}/new", {name}H.New{Name})
```

Also wire the handler into `router.New`'s function signature if it needs additional dependencies (e.g., a customer DB connection for Phase 2+).

---

## Step 4: Metrics (`internal/metrics/metrics.go`)

The `provisions_total` counter already accepts a `service` label. No new metric registration is needed. Verify the handler uses:

```go
metrics.ProvisionsTotal.WithLabelValues("{name}", "anonymous").Inc()
```

---

## Step 5: Feature flag (`.env.example`)

Add the service name to the comment on `INSTANT_ENABLED_SERVICES`:

```
# Services: postgres,redis,mongodb,nats,storage,webhook,queue
INSTANT_ENABLED_SERVICES=postgres,redis
```

Do NOT enable it by default. The operator adds it to `.env` when ready.

---

## Step 6: Handler tests (`internal/handlers/{name}_test.go`)

Write integration tests covering:
- `Test{Name}New_Returns201WithRequiredFields` — happy path, check token/url/tier/limits/note
- `Test{Name}New_XInstantUpgradeHeaderPresent` — X-Instant-Upgrade on every provision
- `Test{Name}New_StoresResourceInDB` — resource row created in Postgres
- `Test{Name}New_ServiceDisabled_Returns503` — when feature flag is off
- `Test{Name}New_6thCallReturnsPreviousToken` — provisioning rate limit fail-open

Use `testhelpers.SetupTestDB`, `testhelpers.SetupTestRedis`, `testhelpers.NewTestApp` as base.

---

## Step 7: E2E tests (`e2e/{name}_e2e_test.go`)

```go
//go:build e2e

package e2e

func TestE2E_{Name}Provision_Returns201(t *testing.T) { ... }
func TestE2E_{Name}Provision_XInstantUpgradeHeader(t *testing.T) { ... }
func TestE2E_{Name}Provision_TokenIsValidUUID(t *testing.T) { ... }
```

---

## Step 8: Documentation

### docs/api.md
Add a new endpoint section under "Provisioning" following the existing `POST /db/new` format:

```markdown
### POST /{name}/new

Provisions an anonymous {name} resource. No account required.

**Response (201)**
...
```

### docs/openapi.yaml
Add the path under `paths:` following the `/db/new` schema as a template. Reuse or extend `ProvisionResponse` in `components/schemas`.

### docs/quickstart.md
Add a language example if the service is commonly used by developers directly (skip for internal services like webhooks).

### README.md
Update the Phase table if this service is part of a new phase.

---

## Step 9: Verify

```bash
go build ./... && go vet ./...
```

**If it fails:** Fix the errors before reporting done.

Run the unit tests for the new package:
```bash
go test ./internal/handlers/... -run Test{Name} -v 2>&1
```

---

## Step 10: Summary

Output:
```
Service '{name}' scaffolded.

Created:
  internal/handlers/{name}.go        (handler + provisioning)
  internal/handlers/{name}_test.go   (N unit tests)
  e2e/{name}_e2e_test.go             (N E2E tests)

Edited:
  internal/router/router.go
  .env.example
  docs/api.md
  docs/openapi.yaml

Next steps:
  1. Implement real provider call in handlers/{name}.go (currently stubbed)
  2. Add service to INSTANT_ENABLED_SERVICES in .env to enable it
  3. Run: /instant-ship to deploy
  4. Run: make test-e2e to verify E2E
```

---

## Rules

- Never skip the onboarding_event creation — it's the only way /start and /claim work.
- Never return encrypted connection_url directly from the DB.
- Fail open on Redis. This is non-negotiable.
- Always gate behind IsServiceEnabled. No service goes live without a feature flag.
- Write E2E tests before marking done. Untested endpoints are not shipped.
