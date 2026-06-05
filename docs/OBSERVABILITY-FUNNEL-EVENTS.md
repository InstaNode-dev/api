# Observability — WS4 Behavioral-Intelligence Funnel Events

This note documents the New Relic custom event the api emits at the conversion
funnel points, and the Prometheus counter that backs the bridge's failure mode.
It satisfies CLAUDE.md rule 25 (every observability signal ships with its
documentation). The NR **alert + dashboard tile** for these signals live in the
separate `infra` repo (`infra/newrelic/alerts/`, `infra/newrelic/dashboards/`,
`infra/observability/METRICS-CATALOG.md`) — that repo has no auto-apply, so the
operator wires the tiles/alerts there; this note is the source-of-truth for the
event/attribute contract the dashboards FACET on.

## Why this exists

`instant_conversion_funnel_total{step}` (Prometheus) is an **aggregate count** —
it answers "how many provisions today" but cannot be keyed on a stable entity
(team / anonymous fingerprint bucket / cohort), so it cannot compute the per-
entity / cohorted funnel KPIs the WS4 plan needs:

- anonymous → claimed  (target **> 2%**)
- claimed → paid       (target **> 20%**)

The `InstantFunnel` New Relic custom event is the **per-entity** companion. Both
are emitted at every funnel point — the Prometheus counter is **not** removed.

## `InstantFunnel` custom event

Emitted via `common/analyticsevent` (factory-wrapped: fail-open + PII-sanitized).
The api wires the emitter once at boot (`router.wireAnalyticsEmitter`) from
`ANALYTICS_BACKEND` (default `noop` — **inert** until New Relic is configured;
the noop default is the flag protection, no separate feature flag needed). The
`newrelic` backend reuses the api's existing `*newrelic.Application`.

| Attribute      | Always? | Values / notes |
|----------------|---------|----------------|
| `funnelStep`   | yes     | `landing` \| `provision` \| `claim` \| `paid` |
| `serviceName`  | yes     | `api` (FACET to attribute a step to the emitting service) |
| `tier`         | most    | `anonymous`/`free`/`hobby`/`pro`/… (omitted at `landing`) |
| `env`          | provision | `development`/`production`/… (resolved env of the provision) |
| `fingerprint`  | anon    | **already-hashed** SHA256(/24+ASN) bucket — never a raw IP |
| `teamId`       | claim/paid | team UUID (opaque id, not PII) |

PII policy: the attribute map passes through `analyticsevent.Sanitize` (explicit
allowlist + email-hashing) before any backend sees it, so no raw email / token /
connection string can leak even if a future emit site passes one.

### Emit sites (api)

| Step        | File:func | Trigger |
|-------------|-----------|---------|
| `landing`   | `onboarding.go` `StartLanding` | GET `/start` (top of funnel) |
| `provision` | `db.go`/`cache.go`/`nosql.go`/`vector.go`/`queue.go`/`storage.go`/`webhook.go` `New*` (anonymous path) | anonymous resource provisioned |
| `claim`     | `onboarding.go` `Claim` | anonymous → claimed (account created) |
| `paid`      | `billing.go` `handleSubscriptionCharged` | claimed → paid (subscription active) |

### NRQL starters

```sql
-- anon->claimed (exclude synthetic prober traffic)
SELECT uniqueCount(fingerprint) FROM InstantFunnel
WHERE funnelStep = 'landing' AND cohort != 'synthetic' SINCE 1 day ago

SELECT uniqueCount(teamId) FROM InstantFunnel
WHERE funnelStep = 'paid' AND cohort != 'synthetic' FACET tier SINCE 7 days ago
```

> **Exclude `cohort = 'synthetic'` from all funnel analysis.** Synthetic
> flow-test traffic (`InstantFlowTest`, emitted by the worker's prober) carries
> `cohort='synthetic'`; the real-traffic funnel `InstantFunnel` events carry no
> cohort attribute, so `WHERE cohort != 'synthetic'` keeps the two separated.

## `instant_analytics_emit_failed_total{reason}` (Prometheus)

Counts behavioral-intelligence custom events **dropped** before reaching the
analytics sink, by `reason`.

- `reason="nil_app"` — the New Relic sink had no `*newrelic.Application` (NR not
  configured). This is the **expected steady state** until
  `ANALYTICS_BACKEND=newrelic` + a license key are wired, so a flat non-zero
  value in that configuration is benign.
- A **sudden climb after** NR is configured means the bridge is dropping real
  funnel events — that is the alertable condition (suggested: P2 observability,
  warn on `rate(...[10m]) > 0` once `ANALYTICS_BACKEND=newrelic`).

Lazy `*Vec`: not visible at `/metrics` until the first dropped emit observes a
label.
