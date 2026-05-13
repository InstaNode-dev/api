> ⚠️  INTERNAL ONLY — DO NOT PUBLISH
> This document describes operational secrets and recovery procedures.
> If you're reading this on a public mirror, the repo has been leaked.
> Treat the entire contents as compromised + rotate everything below.

# instanode.dev — internal ops runbook

Last edited: 2026-05-13. Owner: founder.

This is the runbook for everything we deliberately keep out of `README.md`,
`docs/`, the OpenAPI spec, and the marketing site. The defining property of
content in this file is "an attacker would benefit from reading this." It is
checked into the **private** api repo so the operator on call has it inline,
not buried in a third-party doc tool.

Two automated guardrails keep this file off public surfaces:

1. The OpenAPI spec (handlers/openapi.go) deliberately omits any endpoint
   documented here. A regression test (`auth_me_admin_prefix_test.go ::
   TestAuthMe_AdminPrefix_NotInOpenAPI`) fails CI if an admin route reappears
   in the spec.
2. The repo's `.gitattributes` marks this file `export-ignore`, so
   `git archive` (which is how release tarballs are built) excludes it.
   Confirm with: `git archive HEAD | tar -t | grep INTERNAL-OPS && echo LEAK`.

---

## 1. Admin API access

The founder-only customer-management endpoints are protected by **two
independent gates**:

### Gate 1 — unguessable URL path prefix

Admin endpoints register under `/api/v1/<ADMIN_PATH_PREFIX>/customers/...`
instead of the guessable `/api/v1/admin/customers/...`. When
`ADMIN_PATH_PREFIX` is empty/unset, the routes are not registered at all and
the surface returns 404 to every caller (closed-by-default).

- **Where it's configured:** `instant-secrets/ADMIN_PATH_PREFIX` in the
  `instant` namespace.
- **How it surfaces to admin clients:** the dashboard reads the prefix off
  `GET /auth/me` (the response carries `admin_path_prefix` for callers on
  the ADMIN_EMAILS allowlist only — silent omission for everyone else) and
  builds URLs from it client-side.
- **Validation:** `internal/config/config.go::validateAdminPathPrefix` —
  empty is allowed (closed-by-default); < 32 chars or non-alphanumeric is a
  fatal startup error.
- **Generate a new value:** `openssl rand -hex 32` → 64-char lowercase hex.

### Gate 2 — ADMIN_EMAILS allowlist

The standard founder-email gate. Closed by default: empty/unset rejects
every caller.

- **Where:** `instant-secrets/ADMIN_EMAILS`, comma-separated, case-insensitive
- **Add an admin email:**

  ```bash
  current=$(kubectl get secret instant-secrets -n instant -o jsonpath='{.data.ADMIN_EMAILS}' | base64 -d)
  next="${current},new@instanode.dev"
  kubectl patch secret instant-secrets -n instant --type merge \
    -p "{\"data\":{\"ADMIN_EMAILS\":\"$(printf '%s' "$next" | base64)\"}}"
  kubectl rollout restart deploy/instant-api -n instant
  ```

- **Note:** the allowlist is read fresh from env on each request
  (`middleware.IsAdminEmail`), so a Pod restart is what you need after a
  patch — no app-internal cache to flush.

### Routine: rotate ADMIN_PATH_PREFIX

Do this if you suspect the prefix has leaked, on a periodic schedule (say
quarterly), or whenever an admin user's session token leaks. The old value
becomes invalid within ~10s of pod restart; live admin dashboard tabs need
to log out and back in to refresh `/auth/me`.

```bash
new=$(openssl rand -hex 32)
encoded=$(printf '%s' "$new" | base64)
kubectl patch secret instant-secrets -n instant --type merge \
  -p "{\"data\":{\"ADMIN_PATH_PREFIX\":\"$encoded\"}}"
kubectl rollout restart deploy/instant-api -n instant
kubectl rollout status deploy/instant-api -n instant --timeout=120s
```

After the rollout, admin users need to refresh their dashboard tab (or hit
`/login` to mint a fresh `/auth/me` payload) before the new prefix is in
their client state.

### Incident response: prefix leak

If you have reason to believe the prefix has leaked (e.g. shoulder-surfed,
posted to a public channel, found in a browser dev-tools recording, found
in a third-party tool's request logs):

1. Rotate immediately (the routine above).
2. Audit `audit_log` for any `admin.*` rows in the window between leak
   and rotation:

   ```bash
   kubectl exec -n instant deploy/postgres-platform -- \
     psql -U instant -d instant_platform -c \
     "SELECT actor, kind, at, metadata FROM audit_log
        WHERE kind LIKE 'admin.%'
          AND at > NOW() - INTERVAL '7 days'
        ORDER BY at DESC LIMIT 200;"
   ```

3. If a non-allowlisted email shows up as `actor`, treat as a compromised
   JWT and rotate `JWT_SECRET` too (same patch flow as above, key
   `JWT_SECRET`).

### Routine: temporarily disable the admin surface

If you want to take the admin endpoints offline entirely (e.g. during an
incident, or while doing a wholesale rewrite), clear the prefix:

```bash
kubectl patch secret instant-secrets -n instant --type merge \
  -p '{"data":{"ADMIN_PATH_PREFIX":""}}'
kubectl rollout restart deploy/instant-api -n instant
```

The startup log will emit `admin.endpoints.disabled` and every admin route
returns 404 platform-wide. Restore by patching a real value back in.

---

## 2. Audit-log artifacts

Every successful admin action writes an `audit_log` row with one of these
`kind` values:

| Kind | Endpoint | Metadata fields |
|---|---|---|
| `admin.tier_changed` | `POST /api/v1/<prefix>/customers/:team_id/tier` | `from`, `to`, `by_admin_email`, `reason` |
| `admin.promo_issued` | `POST /api/v1/<prefix>/customers/:team_id/promo` | `code`, `kind`, `value`, `expires_at`, `by_admin_email` |

These rows are NOT redacted from `audit_log` exports and the dashboard's
Recent Activity panel — admins can see their own actions in the timeline.
That's intentional: actions taken under the admin gate must be traceable
back to the human who took them, and the dashboard is the canonical surface
for that traceability.

---

## 3. Other operational secrets

This file is the canonical home for runbooks that touch credentials. As
new surfaces grow up (anomaly detection, content moderation, manual
billing override), add them here so the on-call has a single place to
look.

(no other entries yet)
