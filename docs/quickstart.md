# Quickstart

Provision real **Postgres**, **Redis**, **MongoDB**, **NATS JetStream**, **S3-compatible storage**, or a **webhook receiver** with one HTTP call — no account required for anonymous resources (24h TTL, shared infrastructure).

---

## 1. Provision a Postgres database

```bash
curl -s -X POST https://instant.dev/db/new | jq .
```

Example response:

```json
{
  "ok": true,
  "id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "connection_url": "postgres://usr_a1b2c3d4:pass_a1b2c3d4@shared.instant.dev/db_a1b2c3d4",
  "tier": "anonymous",
  "limits": {
    "storage_mb": 10,
    "connections": 2,
    "expires_in": "24h"
  },
  "note": "Works now. Free forever with a free account: https://instant.dev/start?t=eyJ..."
}
```

Use `connection_url` with any Postgres client (`psql`, `libpq`, Drizzle, Prisma, etc.). The `id` is the stable resource identifier for management APIs; the `token` is embedded in credentials.

Optional label:

```bash
curl -s -X POST https://instant.dev/db/new \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app-db"}' | jq .
```

**Feature flag:** `POST /db/new` requires `postgres` in `INSTANT_ENABLED_SERVICES` on the server, or you will receive `503`.

---

## 2. Other one-shot provisions

Same pattern: `POST` with optional `{"name": "..."}` body.

| Endpoint | You get |
|----------|---------|
| `POST /cache/new` | `redis://...` connection string |
| `POST /nosql/new` | `mongodb://...` connection string |
| `POST /queue/new` | NATS JetStream URL |
| `POST /storage/new` | S3-compatible endpoint + credentials |
| `POST /webhook/new` | Receiver URL for inbound HTTP |

```bash
curl -s -X POST https://instant.dev/cache/new | jq .
curl -s -X POST https://instant.dev/nosql/new | jq .
```

Authenticated calls (same endpoints, add header) create **permanent** resources tied to your team:

```bash
curl -s -X POST https://instant.dev/db/new \
  -H "Authorization: Bearer <session_jwt>" | jq .
```

---

## 3. Keep resources after 24 hours (claim)

Anonymous resources expire after **24 hours**. The `note` field includes an onboarding link (`https://instant.dev/start?t=...`).

1. Open that URL in a browser (or send users through your product).
2. Sign in (e.g. GitHub OAuth where enabled).
3. Or call `POST /claim` with the JWT from the upgrade URL plus email and optional team name — see [api.md](./api.md).

---

## 4. Limits (anonymous tier)

Exact numbers come from [`plans.yaml`](../plans.yaml). Typical anonymous Postgres limits include small storage, low connection count, and `expires_in: "24h"`. Provision deduplication: after **5 provisions per fingerprint per day**, the API may return `200` with an **existing** resource instead of creating another (fail-open, no `429`).

---

## 5. Health check

```bash
curl -s https://instant.dev/healthz
```

```json
{ "ok": true, "service": "instant.dev" }
```

---

## Common issues

**`503 service_disabled`** — the operator has not enabled that service in `INSTANT_ENABLED_SERVICES`.

**`503` / `provision_failed`** — provisioning failed upstream; retry with backoff. You should not receive a `connection_url` for a failed provision.

**`410` / `expired`** — anonymous TTL elapsed; claim to a team or provision again.
