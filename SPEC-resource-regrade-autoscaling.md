# SPEC — Resource Right-Sizing, Regrade & Scale-to-Zero

Status: proposal · Owner: platform · Spans: api + worker + provisioner + *-proxy

## 1. Motivation

Two gaps surfaced during 2026-05-15 payment testing:

1. **Upgrade drift.** A plan upgrade flips `resources.tier` (`ElevateResourceTiersByTeam`)
   but never re-applies the *hard* infrastructure limits — the per-role Postgres
   `CONNECTION LIMIT`, pod CPU/RAM, Mongo `maxConns`. A customer pays for Pro and
   keeps hobby capacity until the resource is destroyed and re-created.
2. **Cost leakage.** Every resource runs at its full tier-sized pod allocation
   regardless of actual use. Idle resources burn compute that nobody is using.

Root cause is one missing idea: the platform conflates **entitlement** (what the
plan tier allows) with **allocation** (what is actually running). This spec
separates them.

## 2. Core model

- **Entitlement** — derived from `team.plan_tier`. It is a *ceiling*: the maximum
  any of the team's resources may be sized to. Free to apply; the customer paid
  for it.
- **Applied size** — what the resource is actually running with right now
  (CPU, memory, connection cap, storage, pod replica count).
- A reconciliation controller continuously moves *applied size* toward a
  *desired size* computed from recent usage, bounded by `[floor, ceiling]`.

```
floor  ≤  applied size  ≤  ceiling(plan_tier)
                ▲
        desired = f(recent usage)
```

### 2.1 Customer-facing surface — show entitlement, never applied

The dashboard and every customer-facing API (`/api/v1/billing`, `/api/v1/resources`,
the usage tiles) **must present limits as the plan entitlement** —
`plans.Registry.<Limit>(team.plan_tier, …)`, i.e. *what the customer purchased* —
and **never** the *applied* size (`applied_conn_limit`, future `applied_sizing`).

Rationale: the applied size is deliberately ≤ the entitlement and grows on demand.
Surfacing it would (a) alarm the customer — "I pay for Pro's 20 connections, why
does it say 5?" — and (b) leak the cost-optimisation. The applied size is an
internal control-loop detail.

The customer's mental model is unchanged by this whole feature:

```
        what they see  =  current usage  ÷  plan entitlement
                           ("12 MB used of my 10 GB")
```

- **Numerator** = live consumption — keep it fresh (the existing ~30 s usage-tile
  cache is fine; declare the freshness window).
- **Denominator** = the tier entitlement, always. Never the physical/applied cap.
- The autoscaler moving the physical allocation between `floor` and `ceiling` is
  invisible to the customer — that is the whole point.

`applied_*` columns are internal to the reconciler/controller. They must not
appear in any customer-facing response, ever. (Phase 1 adds `applied_conn_limit`
— it is read only by the `entitlement_reconciler`; no API/dashboard surface reads
it, and none should.)

## 3. Design decisions

### 3.1 Memory — pre-allocate to the tier ceiling. Do NOT autoscale.
Memory is cheap relative to the failure mode. Reactive memory scaling cannot win:
the kernel OOM-kills the DB process *before* a 30 s control loop can react, and
shrinking a DB's memory evicts its cache. So memory is pinned at the tier's max
from provision time and only changes on a tier change. Simple and safe.

### 3.2 CPU — autoscale within `[floor, ceiling]`. This is the cost lever.
CPU starvation is graceful (slow queries, not a crash) and k8s **v1.35 in-place
pod resize is GA**, so CPU changes apply with no pod restart and no dropped
connections. Most active resources are light most of the time; trimming idle CPU
is where the savings are.

> Prior art (§9): Neon *does* autoscale Postgres memory too — but only with hard
> overcommit prevention via k8s-scheduler coordination, having found cgroup
> `memory.high` events too unreliable and switched to 100 ms polling of cgroup
> usage. A fixed memory ceiling is the deliberate, lower-risk simplification of
> that; revisit only if memory cost becomes material.

### 3.3 Connection cap / entitlement limits — lazy re-grade.
Apply the tier's entitled cap (`ALTER ROLE … CONNECTION LIMIT`, etc.) when a
resource crosses 75 % of its *currently applied* cap, or on plan upgrade. The
operation is a catalog write — instant, affects only new connections, no restart.
This is the fix for gap #1 (upgrade drift): re-grade each resource when it
actually needs the headroom rather than eagerly at upgrade time.

### 3.4 Storage — online PVC expansion.
Expand the PVC when usage crosses threshold; DO block storage supports online
expansion + filesystem grow with no restart.

### 3.5 Idle resources — pause to zero, wake on connect (§5).
Right-sizing saves a fraction; pausing a truly idle resource saves ~100 % of its
compute. The two compose: autoscale the active ones, pause the dead ones.

## 4. The controller — `resource_regrade`

A worker job (lives with the other reconcilers in `worker/internal/jobs/`).

- **Cadence:** every 30 s.
- **Per `active` resource:**
  1. Read recent usage (CPU util, open connections, storage bytes) from
     `resource_heartbeat` / metrics.
  2. Compute `desired` size, clamped to `[floor, ceiling(plan_tier)]`.
  3. **Asymmetric hysteresis** — fast up, slow down:
     - scale **up** when usage > 75 % sustained ≥ 30 s
     - scale **down** only when usage < 30 % sustained ≥ 10 min
  4. If `desired ≠ applied`: patch the **pod resize subresource**
     (`kubectl patch pod … --subresource resize`) — in-place, no restart.
     *Never* patch the Deployment template — that triggers a rolling replace and
     a real outage.
  5. Re-grade connection cap / storage if drifted below tier entitlement.
- **Per `active` resource with zero usage ≥ `idleWindow`:** transition to
  `paused` (§5).

### Idempotency
The controller is a **reconciliation loop, not an event stream** — idempotent by
construction. Running it once, every 30 s, or concurrently all converge to the
same state. Reinforced by:
- resize ops keyed on `(resource_id, target_spec_hash)` → no-op if already there;
- a per-resource cooldown `last_regraded_at` (≥ 30 s) to damp oscillation;
- a usage *event* may *hint* the loop to run early, but the loop — not the event —
  is the source of truth. Frequent use therefore costs at most one resize per
  cooldown window, never a storm.

## 5. Idle → recovery (scale-to-zero & wake-on-connect)

### Pause
A resource idle ≥ `idleWindow` → controller sets `status = paused`, scales the
Deployment to `replicas: 0`. The **PVC is retained** — data is preserved; only
compute is reclaimed. (Block storage is cheap; compute is the cost.)

> **Idle ≠ "no open connections."** A connection pooler (or a long-lived agent
> session) holds idle connections open indefinitely — Railway and Neon both warn
> this defeats naive idle detection. The idle signal must be *real activity*
> (queries/commands executed, bytes moved) over `idleWindow`, not socket count.

### Cold-boot vs. snapshot
A plain `replicas: 0 → 1` is a **cold boot** (~5–30 s: schedule + PVC attach + DB
process start + recovery + readiness). Fly.io's data shows a **memory-snapshot
suspend/resume** returns in *hundreds of ms* — no OS/process restart. Two ways to
close that gap, in preference order:
1. **Warm pool.** The provisioner already runs a hot-pool manager for
   pre-created resources (`provisioner/internal/pool/`). Extend it to keep a
   small pool of pre-scheduled, ready pods so a resume is a pod *assignment*, not
   a cold boot — this is how Neon hits 300–500 ms (pre-created VM pool) and how
   Modal hides allocation latency.
2. **Checkpoint/restore.** k8s container checkpointing (CRIU) is still alpha;
   note as future, not Phase 3.

### Wake
The platform already runs connection proxies in-cluster — `instant-pg-proxy`,
`instant-redis-proxy`, `instant-mongo-proxy`, `instant-nats-proxy`. The proxy is
the client's entry point and therefore the natural wake trigger:

```
client connects → proxy
  proxy sees resource.status = paused
    → SETNX wake lock (resource_id)         # N concurrent clients ⇒ ONE resume
    → status = resuming
    → provisioner scales Deployment replicas 0 → 1
    → pod schedules, attaches PVC, DB starts, readiness probe passes
    → status = active, last_seen_at = now()
  proxy holds the client connection until ready (bounded by wakeTimeout)
    → on ready  : forward the connection normally
    → on timeout: return a clean retryable error ("resuming, retry in Ns")
```

**Cold-start cost** is explicit and accepted: the *first* connection after idle
waits for the wake — typically ~5–30 s for a DB pod (node has the image cached;
cost is PVC attach + process start + recovery + readiness). Subsequent
connections are normal.

State machine:
```
active ──idle ≥ idleWindow──▶ paused ──connect──▶ resuming ──ready──▶ active
```

### Cold-start mitigations
- Keep resource pod images pre-pulled on nodes (DaemonSet warm or `imagePullPolicy`).
- **Tier-gate the aggression:** free / anonymous → short `idleWindow`, accept cold
  starts; paid tiers → long `idleWindow` or always-warm — a paying customer should
  not eat a cold start.
- Optional predictive pre-warm if a resource shows a daily-active pattern.
- Bounded `wakeTimeout` so a slow wake fails fast with a retryable error instead
  of hanging the client.

## 6. Edge cases

- **Plan downgrade.** Ceiling drops; the controller scales applied size down
  toward the new ceiling. Memory shrink may need a restart → schedule it into a
  low-traffic window, do not do it reactively.
- **Concurrent wake.** The SETNX wake lock ensures N simultaneous connections to a
  paused resource fire exactly one resume.
- **Mongo connection cap.** `maxIncomingConnections` is historically a startup
  parameter — raising it may require a mongod restart. Verify on the prod
  (`remote`) Mongo backend; if restart-only, treat it like memory (apply on a
  scheduled window, not reactively).
- **Webhook / queue resources.** No long-lived "connection" — drive wake off the
  next inbound request to the proxy / receiver rather than a socket open.
- **Anonymous tier.** Already has a 24 h TTL; pause + TTL compose (pause first,
  expire later).

## 7. Schema changes (`resources`)

- `applied_sizing jsonb` — current CPU / memory / conn-cap actually applied.
- `last_regraded_at timestamptz` — resize cooldown.
- `last_active_at timestamptz` — drives the idle decision (distinct from
  `last_seen_at` heartbeat).
- `status` enum — add `resuming`.

## 8. Observability (per the "every change ships with monitoring" rule)

- Metrics: `regrade_total`, `resize_latency_seconds`, `wake_duration_seconds`,
  `paused_resources`, `oom_kills_total`, estimated `$ saved`.
- NR dashboard tile per metric; alerts on `wake_duration_seconds` p95 > target and
  any `oom_kills_total > 0`.

## 9. Prior art & validation

Survey of comparable platforms' engineering blogs (2026-05-15).

| Platform | Idle handling | Wake | Cold start |
|---|---|---|---|
| **Neon** | compute scale-to-zero after 5 min idle; storage persists | proxy holds the client connection while compute resumes | **300–500 ms** (pre-created VM pool) |
| **Fly.io** | proxy auto-stops Machines; `suspend` = memory snapshot | Fly Proxy holds the request, resumes the Machine | suspend ~hundreds of ms; cold boot full |
| **Modal** | `scaledown_window` (default 60 s); `min/buffer_containers` floors | n/a (request-routed) | ~1 s; mem/GPU snapshots cut 4–10× |
| **Supabase** | free projects pause after 7 days | **manual** restore (no auto-wake); paid never pauses | n/a |
| **Render / Railway** | free spins down after 15 / ~10 min | wake on first request | Render ~50 s+ |
| **Cloudflare DO** | hibernate after ~10 s idle | WebSocket Hibernation keeps clients connected | constructor re-runs |
| **Emergent** | k8s pods on GCP; **no public engineering writing** on this | — | — |

**Validated by prior art:** scale-to-zero keeping storage (Neon/Fly/Supabase);
wake-on-connect with a proxy-held connection (**exactly** Neon's and Fly's model —
strongest validation of §5); in-place CPU resize with no restart (Neon: "autoscaling
requires the ability to scale without restarting"); cold-start tier-gating
free-vs-paid (Supabase/Render/Railway); periodic idempotent reconciliation
(Fly's proxy reconciles every few minutes).

**Corrections folded in:** memory note in §3.1; the "idle ≠ no open connections"
pooler pitfall and the cold-boot-vs-snapshot/warm-pool gap in §5.

**Watch-outs they published:** Neon — large shared-memory allocs (pgvector index
builds) still OOM despite polling; a kernel `acpi_hotplug` bug stalled TPS during
resize. Fly — at thousands of Machines the rate-limited reconcile loop leaves idle
ones running (flapping/backlog is real — reinforces §4's hysteresis + cooldown);
a brief post-start window where proxy routing can fail (reinforces §5's bounded
`wakeTimeout` + retryable error). Modal — idle *warm* containers are still billed
(a warm pool has a carrying cost — size it small).

## 10. Rollout

1. **Phase 1 — lazy entitlement re-grade** (connection caps). Fixes upgrade
   drift. Transparent, low risk. Ship first.
2. **Phase 2 — CPU autoscaling** for active resources (in-place resize).
3. **Phase 3 — pause-to-zero + wake-on-connect**, free / anonymous tier first;
   prove the cost savings and wake latency before extending to paid tiers.

## 11. Open questions

- Exact `idleWindow` / hysteresis thresholds per tier — tune from real usage.
- Whether to hand-roll the CPU controller or adapt k8s VPA (VPA historically
  restarts pods; a custom controller using the 1.35 resize subresource gives DB-
  aware control — lean custom).
- Wake latency budget that is acceptable for paid tiers (may imply paid = always-warm).

---

## 12. Phase 1 — implementation plan (lazy entitlement re-grade)

**Objective.** Close the upgrade-drift gap for **Postgres connection caps**: after
any tier change — or any drift from any cause — a resource's actual Postgres role
`CONNECTION LIMIT` is reconciled to what `team.plan_tier` entitles. Zero downtime
(`ALTER ROLE` is a catalog write affecting only new connections).

**In scope:** Postgres connection cap, `POSTGRES_PROVISION_BACKEND=k8s` (prod).
**Out of scope (later phases):** Mongo (`maxIncomingConnections` is restart-prone —
defer), Redis (`maxclients` is server-wide, not per-tenant), CPU/memory autoscaling
(Phase 2), pause / scale-to-zero (Phase 3), storage, and the separate
billing↔Razorpay reconciler. Phase 1 reconciles `resources` against
`teams.plan_tier`; it does **not** reconcile `teams.plan_tier` against Razorpay.

### Work items

**WI-1 — proto + provisioner: `RegradeConnectionLimit` RPC**
- `proto/provisioner/v1/`: add `rpc RegradeConnectionLimit(RegradeRequest) returns
  (RegradeResponse)`; request = `{resource_token, tier}`; `buf generate` (never
  hand-edit rawDesc).
- `provisioner/internal/backend/postgres/k8s.go`: resolve token → namespace/pod →
  admin connection → `ALTER ROLE <appUser> CONNECTION LIMIT <n>`. `n` from the
  **same `tierSizing` table** used at `CREATE USER` time (consistency with
  provision-time; `-1` ⇒ unlimited). Idempotent — re-applying the same `n` is a
  harmless no-op. Skip cleanly when: backend ≠ k8s, pod not running, resource
  expired/anonymous.

**WI-2 — upgrade trigger**
- `api/internal/handlers/billing.go` `handleSubscriptionCharged`: after
  `ElevateResourceTiersByTeam`, **enqueue** a River job (do not block the webhook).
- New worker job `RegradeTeamResources(team_id, tier)`: load the team's active
  Postgres resources, call `RegradeConnectionLimit` per resource. Best-effort —
  one failure must not block the rest.

**WI-3 — periodic `entitlement_reconciler` job**
- `worker/internal/jobs/entitlement_reconciler.go`, cadence ~5 min. For each active
  Postgres resource: entitled `n` = f(`team.plan_tier`); if `≠ applied_conn_limit`
  → regrade + update the column. Catches drift from missed webhooks, manual
  `/internal/set-tier`, downgrades, etc.

**WI-4 — schema**
- Migration `api/internal/db/migrations/NNN_resources_applied_conn_limit.sql`:
  add `resources.applied_conn_limit int` (nullable; NULL = never re-graded). Lets
  the reconciler skip no-op work and gives observability. (The broader
  `applied_sizing jsonb` from §7 lands in Phase 2.)

**WI-5 — observability**
- Metrics: `entitlement_regrade_total{result}`, `entitlement_drift_detected_total`,
  regrade latency. One log line per regrade (`resource_id`, old→new). NR tile +
  alert if drift persists (regrade failing).

**WI-6 — tests**
- Unit: tier→connLimit mapping; reconciler drift detection — **iterate the live
  registry, not a hand-typed slice** (reliability rule 18).
- E2E: provision a hobby Postgres → upgrade team to pro → assert
  `pg_roles.rolconnlimit` on the customer DB actually changed.
- Coverage test that fails if a new resource type gains a tier without a regrade path.

### Sequencing
1. WI-4 migration + WI-1 proto/provisioner RPC (foundation).
2. WI-2 upgrade trigger (the fix).
3. WI-3 periodic reconciler (the safety net).
4. WI-5 / WI-6 alongside.

### Risks & guards
- DB unreachable (paused/down pod) → skip, retry next sweep; never hard-fail.
- `tierSizing.connLimit = -1` → `CONNECTION LIMIT -1` (Postgres = unlimited). OK.
- Backend ≠ k8s (dev `local`/shared) → no per-role cap exists → RPC no-ops.
- Never regrade `anonymous`/expired resources.
- Idempotent throughout (River job + `applied_conn_limit` check) — safe to re-run.
- Webhook stays fast: enqueue only, never block on the provisioner call.

### Deploy (reliability rules 15 & 23)
proto change ⇒ `buf generate` ⇒ rebuild **provisioner + worker + api** ⇒ deploy
each ⇒ verify-live. Provisioner/worker rebuilds are manual unless their auto-deploy
workflows are confirmed green.

### Assumptions to verify before coding
- The provisioner can map a resource token → its k8s namespace/pod (it provisioned
  it — `provider_resource_id`/`key_prefix` should suffice).
- Worker queue is River (`worker/` uses River per repo docs).
- Provisioner `tierSizing.connLimit` vs `plans.Registry.ConnectionsLimit` may
  disagree — Phase 1 uses `tierSizing` (provision-time parity); a follow-up should
  unify them onto `plans.Registry` (reliability rule 22, single source of truth).
