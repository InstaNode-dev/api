# W9 Security Loophole Audit

Date: 2026-05-13
Branch: `feat/w9-security-loophole-audit-fresh`
Scope: 5 concrete loopholes flagged in the W9 brief. No commits made — diff left uncommitted for review.

---

## Findings

### Loophole 1 — DPoP binding actually enforced? — **FIXED-IN-THIS-PR**

`internal/middleware/dpop.go` implements RFC 9449 correctly (signature check, jkt match, htm/htu, iat freshness, Redis-backed jti replay dedup). The middleware was **fully implemented and unit-tested** in `internal/middleware/dpop_test.go` (7 passing tests covering valid / bad-sig / replay / opt-in / stale / wrong-method / missing-header). The loophole was at the **wiring layer**: `RequireDPoP(rdb)` was never installed in the router, so every mutating endpoint accepted bearer-only auth even from key-bound tokens. A stolen JWT with `cnf.jkt` could be replayed unconditionally.

**Fix:** wired `middleware.RequireDPoP(rdb)` into both the `/api/v1` group and the `/deploy` group in `internal/router/router.go`. Back-compat safe because the middleware is opt-in: bearers without `cnf.jkt` pass through unchanged (preserves all dashboard/CLI/PAT clients), and only key-bound tokens get the full enforcement chain.

### Loophole 2 — Magic-link single-use enforcement — **NOT VULNERABLE**

`internal/handlers/magic_link.go` consumes the link via `models.ConsumeMagicLink` which executes `UPDATE magic_links SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL` and inspects `RowsAffected`. Consume runs **before** session JWT minting. Race: two simultaneous callbacks collapse to exactly one winner; loser sees the "already used" branch. TTL is 15 minutes (`magicLinkTTL`). No fix needed.

### Loophole 3 — Promote-approval token single-use — **NOT VULNERABLE (one follow-up flag)**

`internal/models/promote_approvals.go::ApprovePromoteApproval` uses `UPDATE ... WHERE id=$1 AND status='pending' AND expires_at > now()`, returning false on race. `RejectPromoteApproval` mirrors the pattern. Reject-on-already-rejected returns a clean 409 `not_pending` (no crash). The expiry path (`MarkPromoteApprovalExpired`) is idempotent and best-effort.

**Follow-up flag (not fixed in this PR):** `PromoteApprovalTokenTTL = 24 * time.Hour` exceeds the brief's "≤ 1 hour" target. Comment in the model file frames the 24h window as deliberate for human-in-the-loop review. Tracked-as-follow-up — recommend a tier-aware split (1h for prod, 24h for staging) rather than a blanket change that would break long-running ops.

### Loophole 4 — Resource ownership cross-tenant probe — **NOT VULNERABLE**

Audited every handler entry-point in scope. All seven check `resource.TeamID.UUID == teamID` **before** any operation:

| Handler | File | Line |
|---|---|---|
| `Get` | `internal/handlers/resource.go` | 120 |
| `Delete` | `internal/handlers/resource.go` | 165 |
| `GetCredentials` | `internal/handlers/resource.go` | 259 (404-not-403 variant) |
| `RotateCredentials` | `internal/handlers/resource.go` | 321 |
| `Pause` | `internal/handlers/resource.go` | 478 |
| `Resume` | `internal/handlers/resource.go` | 609 |
| `ProvisionTwin` | `internal/handlers/twin.go` | 136 |
| `Family` (read) | `internal/handlers/resource_family.go` | 99 |

No fix needed. The credentials endpoint correctly uses the "404-not-403" pattern to avoid confirming foreign-team resource existence.

### Loophole 5 — Audit-log XSS via metadata render — **FIXED-IN-THIS-PR**

Two paths examined:

**Server side:** `models.InsertAuditEvent` callers across `handlers/*.go` never embed user-controlled fields (resource `Name`, vault keys, custom domains) into `Summary` or `Metadata` JSON. Existing summaries use the controlled `resource_type` enum and the first 8 chars of an internal UUID. No XSS surface in the audit emit path.

**Dashboard side (out-of-tree, observed for completeness):** `dashboard/src/api/index.ts::fetchActivity` has a fallback path that runs when `/api/v1/audit` 4xx/5xxs. The fallback synthesises feed rows as:
```js
text: `<strong>${res.cloud_vendor}</strong> provisioned <strong>${res.resource_type}</strong> <code>${(res.name ?? res.token).slice(0, 16)}</code>`
```
…and `dashboard/src/pages/OverviewPage.tsx:215` renders `text` via `dangerouslySetInnerHTML`. A user with resource name `<img src=x onerror=alert(1)>` would XSS themselves and any team member who views the activity feed when the audit endpoint hiccups.

**Fix (server-side, defence-in-depth):** tightened `sanitizeName()` in `internal/handlers/provision_helper.go` to strip `<`, `>`, `"`, `'` from every resource name at provisioning time. The strip is applied by every `/{service}/new` handler that already calls `sanitizeName` (db, cache, nosql, queue, storage, webhook, deploy, stack, twin) — so the four HTML-injection chars cannot enter stored state regardless of the downstream renderer. `&` is deliberately preserved (legitimate in names like "Smith & Co Postgres"); React's text-mode rendering escapes it.

This closes the XSS vector at the boundary rather than trying to audit every present and future renderer. The dashboard's `dangerouslySetInnerHTML` change is a separate (out-of-tree) follow-up.

---

## Files modified

| File | Change |
|---|---|
| `internal/router/router.go` | Wired `middleware.RequireDPoP(rdb)` into `/api/v1` group and `/deploy` group |
| `internal/handlers/provision_helper.go` | Tightened `sanitizeName` to strip `<>"'` |
| `internal/handlers/provision_helper_test.go` | Added `TestSanitizeName_StripsXSSVectors` (9 sub-cases) |
| `internal/router/dpop_wiring_test.go` | New: pins DPoP middleware presence in both auth-gated groups |

---

## Test gate

`make test-unit` result: 3 pre-existing flakes (`TestAdminList_*`, `TestAdminRateLimit_*`, `TestRateLimit_6thProvisionReturnsExistingTokenFlag`) — all flagged in the brief as non-blocking. All new tests pass. All `middleware` and `router` packages pass clean.

---

## Out-of-scope follow-ups

1. **Dashboard `dangerouslySetInnerHTML` removal** — replace with React text node + a small bold/code formatter; let server send structured fields not HTML strings.
2. **Promote-approval TTL** — consider tier-aware split (1h for prod env, 24h for staging/dev).
3. **DPoP rollout** — add an OpenAPI `cnf.jkt` example so agent clients know how to mint key-bound tokens.
