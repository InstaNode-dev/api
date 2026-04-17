---
name: instant-review
version: 1.0.0
description: |
  Code review for instanode.dev changes. Checks project-specific conventions:
  fail-open Redis, atomic JWT single-use, typed errors, two-DB separation,
  no connection_url leakage, feature flags, E2E coverage gaps.
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
  - AskUserQuestion
---

# /instant-review — instanode.dev Code Review

You are reviewing code changes in the instanode.dev project. Apply the checklist below against the current diff. Read the full diff before flagging anything.

---

## Step 1: Get the diff

```bash
git diff HEAD 2>/dev/null || git diff
```

If no staged/unstaged changes, compare the current branch to main:
```bash
git diff main...HEAD 2>/dev/null
```

If there is nothing to diff, output: **"Nothing to review."** and stop.

---

## Step 2: Read key files for context

Before reviewing, read:
- `internal/handlers/db.go` (provisioning patterns)
- `internal/handlers/onboarding.go` (claim flow)
- `internal/middleware/rate_limit.go` (fail-open pattern)

This prevents flagging things that are already established project patterns.

---

## Step 3: Apply the instanode.dev checklist

Work through each category. Flag issues with severity: **CRITICAL** or **INFO**.

### A. Fail-open Redis (CRITICAL)

Redis errors must **never** block a request. Look for:
- `if err != nil { return err }` inside any rate limit, cache, or counter operation
- Missing `// Fail open` comment on error paths in middleware
- Any place where a Redis failure causes a 500 or request abortion

**Correct pattern:**
```go
if err != nil {
    slog.Error("...", "error", err)
    metrics.RedisErrors.WithLabelValues("...").Inc()
    // Fail open — allow request through
}
```

**DO NOT flag:** Non-Redis errors (DB writes, provisioning) where failing closed is correct.

---

### B. Atomic single-use JWT (CRITICAL)

Every single-use enforcement must use the atomic `UPDATE ... WHERE converted_at IS NULL RETURNING id` pattern. Look for:
- SELECT-then-UPDATE (race condition — allows double-claim)
- Pre-check without the atomic UPDATE (pre-check alone is not sufficient)
- `MarkOnboardingConverted` result ignored or swallowed without checking `ErrOnboardingAlreadyUsed`

**Also check:** Does any new `/claim`-like flow create DB records (team, user) BEFORE the single-use check? Creating records before the atomic gate leads to 503s on replay attacks. The correct order is: pre-check → create records → atomic mark.

---

### C. Two-database separation (CRITICAL)

Platform metadata goes in `DATABASE_URL` (via `database` / `db` variable).
Customer-provisioned databases go in `CUSTOMER_DATABASE_URL` (via `customerDB` variable, Phase 2+).

Flag:
- Any provisioning of customer databases using the platform DB connection
- Any platform metadata queries (teams, users, resources, onboarding_events) routed to the customer DB
- Mixing the two pools in the same query

---

### D. connection_url never exposed (CRITICAL)

The `resources.connection_url` field is AES-256-GCM encrypted and must never be included in HTTP responses. Look for:
- Any `Resource` or `resources` struct being JSON-serialized that includes `connection_url`, `ConnectionURL`, or similar
- `json:"connection_url"` tags on exported fields
- Direct `SELECT connection_url` returned to the client

---

### E. Typed errors (INFO)

Flag uses of:
- `err.Error() == "some string"` comparisons
- `strings.Contains(err.Error(), ...)` for error routing
- Returning `errors.New("not found")` from models instead of a sentinel type

**Correct pattern:**
```go
type ErrResourceNotFound struct { Token uuid.UUID }
func (e *ErrResourceNotFound) Error() string { ... }
// Caller: errors.As(err, &notFound)
```

---

### F. Feature flags (INFO)

Any new service endpoint must check `cfg.IsServiceEnabled("service-name")` and return 503 if disabled. Look for:
- New `POST /{service}/new` handlers missing the service-enabled check
- New service names not added to `.env.example`'s `INSTANT_ENABLED_SERVICES` comment

---

### G. No 429 returns (INFO)

The platform never returns 429. Provisioning limits fail-open by returning an existing token. Look for:
- `fiber.StatusTooManyRequests` (429) anywhere in the codebase
- `return c.Status(429)...` patterns

---

### H. Prometheus metrics (INFO)

New significant codepaths need at least one counter. Look for:
- New handler files with no `metrics.` calls
- New error paths without `metrics.RedisErrors` or similar
- New services without a `provisions_total` increment

---

### I. E2E coverage gaps (INFO)

For every new route registered in `router.go`, check `e2e/e2e_test.go` for a corresponding test function. Flag any route with no E2E coverage.

---

### J. GoDoc on exported identifiers (INFO)

New exported types, functions, and methods must have doc comments starting with the identifier name. Only flag genuinely missing docs, not just terse ones.

---

## Step 4: Output findings

Format:
```
instanode.dev Code Review: N issues (X critical, Y informational)

CRITICAL
─────────
[A] Fail-open Redis — internal/middleware/rate_limit.go:42
    Redis error causes request to return 500. Wrap in fail-open pattern.

INFO
─────────
[H] Missing metrics — internal/handlers/queue.go
    New queue provisioning handler has no provisions_total increment.
```

If no issues: **"instanode.dev Code Review: No issues found."**

For each CRITICAL issue, use a separate AskUserQuestion:
- Problem (file:line + description)
- Recommended fix
- Options: A) Fix now, B) Acknowledge, C) False positive

---

## Rules

- Read the full diff before flagging. Don't flag patterns already established in existing code.
- Be terse. One line problem, one line fix.
- CRITICAL = could cause data loss, double-claim, credential leak, or request failure.
- INFO = code quality, coverage, observability.
- Only flag what's in the diff. Don't audit the whole codebase.
