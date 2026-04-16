# QA Strategy — instant.dev

> Owner: QA Engineering  
> Last updated: 2026-04-16  
> Covers: crypto, middleware, provisioning handlers, onboarding, jobs

---

## 1. Test Pyramid

```
            /\
           /  \
          / E2E \         ~5%  — full stack, real cluster or compose
         /--------\
        /Integration\     ~60% — real Postgres + Redis, Fiber httptest
       /--------------\
      /   Unit Tests   \  ~35% — pure functions, no I/O (crypto, config, models)
     /------------------\
```

### Rationale

Core behaviour is IO-heavy: DB writes, Redis counters, JWT verification. Integration tests against real infrastructure catch SQL constraints, Redis TTL races, and middleware ordering. We avoid mock DB/Redis for provisioning paths.

---

## 2. What Needs a Real DB vs. Pure Unit

### Pure unit (no I/O, no network)

| Package | What to unit-test |
|---|---|
| `crypto/aes.go` | Encrypt/Decrypt round-trip, key size validation |
| `crypto/fingerprint.go` | /24 + /48 masking, hex output, ASN mixing |
| `crypto/jwt.go` | Sign/Verify, expiry, JTI |
| `config/config.go` | `IsServiceEnabled`, secret masking helpers |
| `models/*` | Validation helpers where logic is local |

### Requires real Postgres

| Area | Why |
|---|---|
| `handlers/onboarding_test.go` | Atomic claim requires real `UPDATE ... RETURNING` semantics |
| `handlers/*_test.go` for provisions | Resource rows + onboarding_events |
| `jobs/expire_test.go` | Batch UPDATE semantics |
| `testhelpers` | Migration runner |

### Requires real Redis

| Area | Why |
|---|---|
| `middleware/rate_limit_test.go` | INCR + TTL, fail-open with a bad connection |

---

## 3. "Ship at 2am" — P1 Gate Tests

These tests MUST be green before production deploy:

```
crypto/aes_test.go         TestAES_EncryptDecryptRoundtrip
crypto/jwt_test.go         TestJWT_ValidTokenVerifies
crypto/fingerprint_test.go TestFingerprintIP_OutputIsHexString

middleware/rate_limit_test.go TestRateLimit_RedisDown_FailOpen
middleware/rate_limit_test.go TestRateLimit_6thProvisionReturnsExistingTokenFlag

handlers/onboarding_test.go TestOnboarding_PostClaim_Atomic_ConcurrentClaims_OnlyOneSucceeds
handlers/onboarding_test.go TestOnboarding_PostClaim_AlreadyClaimed_Returns409Conflict

jobs/expire_test.go    TestExpireAnonymousJob_ClaimedResourceNeverExpired
jobs/expire_test.go    TestExpireAnonymousJob_IsIdempotent
```

(Exact test names may vary — keep the *categories* as the gate.)

---

## 4. Performance — Provisioning Handlers

Provisioning (`POST /db/new`, etc.) is synchronous: keep median latency predictable and avoid extra round-trips inside the request path.

| Metric | Target |
|---|---|
| p50 latency | Low ms for DB + Redis checks only |
| p99 latency | Dominated by external provisioner / provider — document SLO separately |
| DB queries | Minimize N+1 in the provision + persist path |

Load-test against a **staging** cluster; do not burn shared dev quotas in CI.

---

## 5. Chaos Scenarios

### 5.1 Postgres Down Mid-Provision

**Expected:** Handler returns `503` / `provision_failed` — no partial credentials returned to the client.

### 5.2 Redis Down During Rate Limit Check

**Setup:** Take Redis offline. Call `POST /db/new`.

**Expected:** Request may still succeed (fail-open). Warning logs for Redis errors. No panic.

**Test:** `TestRateLimit_RedisDown_FailOpen` in `middleware/rate_limit_test.go`.

### 5.3 Concurrent Claim Race

**Setup:** Many goroutines POST `/claim` with the same JWT.

**Expected:** Exactly one `201`, others `409`; `converted_at` set once.

**Test:** `TestOnboarding_PostClaim_Atomic_ConcurrentClaims_OnlyOneSucceeds`.

### 5.4 Expire Job Overlap

**Expected:** Idempotent soft-delete of expired anonymous resources; no deadlocks.

---

## 6. Environment Variables for Test Runs

| Variable | Purpose |
|---|---|
| `TEST_DATABASE_URL` | Postgres DSN for integration tests |
| `TEST_REDIS_URL` | Redis for integration tests |

---

## 7. Test Naming Conventions

```
Test{Package}_{Scenario}_{ExpectedOutcome}
```

Helpers use `t.Helper()`.

---

## 8. Coverage Targets

| Package | Target line coverage |
|---|---|
| `crypto/*` | 90% |
| `middleware/*` | 80% |
| `handlers/*` | 75% |
| `jobs/*` | 85% |

```bash
go test -coverprofile=cover.out ./...
go tool cover -html=cover.out
```
