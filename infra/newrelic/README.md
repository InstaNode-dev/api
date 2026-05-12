# New Relic dashboards + alerts (as code)

Version-controlled NerdGraph JSON for the instanode.dev observability stack.
Track 7 of 8 in the 2026-05-12 observability rollout
(`/Users/manassrivastava/Documents/InstaNode/OBSERVABILITY-PLAN-2026-05-12.md`).

## Layout

```
infra/newrelic/
  dashboards/
    api-overview.json    # rpm, error rate, p95/p99, top endpoints, apdex
    provisioning.json    # Custom/Provision/{Success,Fail}, anon-tier recycles
    deploy.json          # /deploy/* build duration, success/fail, active deploys
    worker.json          # River throughput, retries, expire-job lag
  alerts/
    error-rate-high.json # error rate > 1% over 5m
    p95-latency-high.json# p95 > 500ms over 5m
    worker-stalled.json  # no jobs processed in 10m
    nats-down.json       # >=3 NATS error logs in 5m
```

Each JSON file is a stand-alone dashboard or alert condition payload in the shape
NR's NerdGraph schema expects. The `accountIds: [0]` placeholders in dashboard
queries are rewritten by the apply tooling (see below) to the real account ID
before the API call.

## Required env

| Var | What | Where it lives |
|---|---|---|
| `NEW_RELIC_API_KEY` | User key (`NRAK-…`) with dashboards + alerts write scope | 1Password vault `instanode-prod`, item `New Relic — User API key (terraform)`. Mirror as a GitHub Actions secret `NEW_RELIC_API_KEY` on the `InstaNode-dev/api` repo. |
| `NEW_RELIC_ACCOUNT_ID` | Numeric account ID | Same 1Password item. The number under "Account ID" in the NR UI top-right. |
| `NEW_RELIC_REGION` | `US` or `EU` | We're on `US`. |

The license key used by the Go agents at runtime is a separate secret
(`NEW_RELIC_LICENSE_KEY`) and lives in the k8s `instant-secrets` Secret
(see `infra/k8s/secrets.yaml`, owned by track 6) — it is **not** used to apply
dashboards/alerts.

## Apply — option A: terraform-provider-newrelic (recommended)

The provider's `newrelic_one_dashboard_json` and `newrelic_nrql_alert_condition`
resources accept these payloads almost verbatim. Minimal example:

```hcl
terraform {
  required_providers {
    newrelic = { source = "newrelic/newrelic", version = "~> 3.40" }
  }
}

provider "newrelic" {
  account_id = var.account_id
  api_key    = var.api_key
  region     = "US"
}

resource "newrelic_one_dashboard_json" "api_overview" {
  json = replace(
    file("${path.module}/dashboards/api-overview.json"),
    "\"accountIds\": [0]",
    "\"accountIds\": [${var.account_id}]",
  )
}

resource "newrelic_alert_policy" "instanode" {
  name = "instanode"
}

resource "newrelic_nrql_alert_condition" "error_rate_high" {
  policy_id = newrelic_alert_policy.instanode.id
  name      = "instant-api — error rate > 1% (5m)"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT percentage(count(*), WHERE error IS true) FROM Transaction WHERE appName LIKE 'instant-api%'"
  }

  critical {
    operator              = "above"
    threshold             = 1.0
    threshold_duration    = 300
    threshold_occurrences = "all"
  }

  aggregation_window  = 60
  aggregation_method  = "event_flow"
  aggregation_delay   = 120
}
```

Repeat the dashboard resource for each `dashboards/*.json` and map each
`alerts/*.json` to a `newrelic_nrql_alert_condition` block. Field names in
Terraform are snake_case; the JSON uses NerdGraph camelCase — translation is
mechanical (`thresholdDuration` → `threshold_duration`, etc.).

`terraform plan && terraform apply` from CI on push to `main` of the
`InstaNode-dev/infra` repo (proposed home for this Terraform; not yet created).

## Apply — option B: direct NerdGraph via curl

For one-off bootstrap or when Terraform is unavailable.

**Dashboard:**

```bash
ACCOUNT_ID=1234567
API_KEY=$NEW_RELIC_API_KEY

# substitute the real account ID into the JSON
DASHBOARD=$(jq --arg id "$ACCOUNT_ID" \
  '(.. | objects | select(.accountIds?) | .accountIds) |= [$id|tonumber]' \
  infra/newrelic/dashboards/api-overview.json)

curl -sS https://api.newrelic.com/graphql \
  -H "Content-Type: application/json" \
  -H "API-Key: $API_KEY" \
  -d "$(jq -n --argjson dash "$DASHBOARD" --argjson acct "$ACCOUNT_ID" '{
    query: "mutation($acct: Int!, $dash: DashboardInput!) { dashboardCreate(accountId: $acct, dashboard: $dash) { entityResult { guid } errors { description } } }",
    variables: { acct: $acct, dash: $dash }
  }')"
```

**Alert condition:** create a policy once via `alertsPolicyCreate`, then
`alertsNrqlConditionStaticCreate` per alert JSON. Both mutations take fields
that mirror the JSON 1:1 (rename `type: "NRQL"` to the GraphQL enum, fold
`signal.*` into the top-level input).

NR's official "Dashboards API" page covers the `dashboardCreate` /
`dashboardUpdate` mutations. "NRQL alert conditions" covers the alert
mutations. Both at `https://docs.newrelic.com/`.

## Rotating `NEW_RELIC_API_KEY`

1. **NR UI** → API keys → create a new User key with the same role
   (`Admin` or `All product admin`).
2. **1Password** → update `instanode-prod` vault → `New Relic — User API key
   (terraform)`. Add the old key value to the "notes" field with a revocation
   date so the rotation is reversible for 24h.
3. **GitHub Actions** → `InstaNode-dev/api` repo → Settings → Secrets and
   variables → update `NEW_RELIC_API_KEY`. (Will be repeated on the
   `InstaNode-dev/infra` repo once it exists.)
4. **Run Terraform** with the new key (`terraform apply`) to confirm it works.
5. **NR UI** → revoke the old key.

The agent license key (`NEW_RELIC_LICENSE_KEY`) is rotated separately via the
k8s `instant-secrets` Secret and a rolling restart of the three deployments;
see `infra/k8s/README.md` (owned by track 6) for that procedure.

## NR account

- Org: instanode
- Region: US
- Account name: `instanode-prod`
- App naming convention: `{service}-{env}` — e.g. `instant-api-prod`,
  `instant-api-staging`, `instant-api-dev`. The dashboard NRQL uses
  `appName LIKE 'instant-api%'` so a single dashboard covers all envs;
  per-env dashboards can be cloned with `appName = 'instant-api-prod'` once
  staging volume is large enough to be worth separating.

## Validation

```bash
# Every JSON file must parse
find infra/newrelic -name '*.json' -exec jq empty {} \;

# NRQL queries are not lintable offline — copy a query into the NR UI's
# "Query your data" tool to sanity-check syntax after any edit.
```

## Dependencies

These payloads assume the metrics/log fields wired up by:

- track 3 (api Fiber NR middleware → `Transaction` events with `error`,
  `duration`, `name`, `httpResponseCode`; `Custom/Provision/Success` +
  `Custom/Provision/Fail` timeslices)
- track 4 (worker River middleware → `job.completed` / `job.failed` /
  `job.retried` log records with `job_kind`, `duration_ms`)
- track 5 (provisioner gRPC interceptor → gRPC `Transaction` events)
- track 2 (`common/logctx` enrichment handler → `service`, `commit_id`,
  `trace_id`, `team_id` on every log line)

If any of those tracks lands with different field names, update the queries
here in the same PR.
