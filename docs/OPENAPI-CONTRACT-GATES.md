# OpenAPI contract gates

The UI↔API contract is the single most expensive thing to get wrong here: it
lives as three hand-maintained copies (api handlers → `instanode-web`'s
`src/api/types.ts` → Playwright mock fixtures). A backend field/enum/status
rename passes the api's own unit tests AND the web's `tsc`+`vitest` (the web
mirrors the *old* shape by hand) and then breaks prod at runtime. That is the
class that broke login for ~24h (AUTH-004).

Two CI gates make that drift a compile/PR-time failure instead of a prod break.

## 1. `openapi-snapshot.yml` — producer freshness gate

`openapi.snapshot.json` is the committed OpenAPI 3.1 spec, generated from
`internal/handlers/openapi.go` by `cmd/openapi-snapshot`. This gate regenerates
it on every PR that touches the handlers/snapshot and **fails if the committed
file is stale**. So the snapshot is always faithful to the live handlers.

Regenerate locally:

```sh
make openapi-snapshot   # writes openapi.snapshot.json
```

## 2. `openapi-breaking.yml` — breaking-change gate (Wave 1)

Diffs the PR's `openapi.snapshot.json` against the **base branch's** committed
snapshot using [`oasdiff`](https://github.com/oasdiff/oasdiff) (pinned version)
and **fails the PR on any breaking change**:

| Change | oasdiff severity | Gate |
|---|---|---|
| Remove / rename a response field | WARN | **fails** |
| Narrow / change a property type | WARN/ERR | **fails** |
| Add a new **required** request field | ERR | **fails** |
| Remove an endpoint or response code | ERR | **fails** |
| Add an optional response/request field | INFO | passes |
| Add a new endpoint | INFO | passes |
| Add a new enum value to a response | INFO | passes |
| Remove an enum value from a **response** | INFO | passes (not breaking for a consumer) |

The gate runs `oasdiff breaking <base> <pr> --fail-on WARN`.

### Why `--fail-on WARN`, not `--fail-on ERR`

The api emits most response fields as **optional** (no `required` array on
response schemas). oasdiff classifies removing an optional *response* property
as **WARN**, not ERR — but that removal is exactly the login-break class (the UI
reads `me.tier`, the api drops it, the UI silently gets `undefined`).
`--fail-on ERR` would let it through. `--fail-on WARN` catches it while still
passing pure additions. Verified locally:

```sh
# breaking: remove AuthMeResponse.tier  → exit 1
oasdiff breaking base.json removed-tier.json --fail-on WARN; echo $?   # 1
# additive: add an optional field        → exit 0
oasdiff breaking base.json added-field.json --fail-on WARN; echo $?    # 0
```

## Shipping an intentional breaking change

The gate failing is the **signal**, not a wall. Per rule 22 (contract-surface
checklist) a breaking contract change touches all surfaces in one change:

1. Land the api change (regenerate the snapshot with `make openapi-snapshot`).
2. In `instanode-web`, regenerate `src/api/generated.ts` from the new snapshot
   (`npm run gen:api-types`). Its `tsc` will red at every UI site using the
   removed/renamed field — fix them in the same PR.
3. Merge via repo-admin with the two PRs cross-referenced. There is
   deliberately no in-workflow allowlist, so every breaking override is a
   recorded human decision on the PR.

The consumer-side gate (`instanode-web`'s `gen:api-types` + `tsc`) and this
producer-side gate together move contract drift from runtime to compile time.
