# obs/obs-2-worker — Track 4 of 8 in observability rollout

This PR adds observability scaffolding for the **worker** service. It is one
of three service-track PRs (api, worker, provisioner) that depend on the
shared common packages from tracks 1 (`common/buildinfo`) and 2
(`common/logctx`).

> **Layout note.** This PR lives in the `api` repo on branch
> `obs/obs-2-worker-fresh` because the orchestrator created the worktree
> against `InstaNode-dev/api` rather than `InstaNode-dev/worker`. The
> intended merge target is `InstaNode-dev/worker`. The merger should copy
> the files under `worker/` in this PR to the worker repo at the same
> relative paths (one level up — `worker/internal/...` here maps to
> `internal/...` in the worker repo's root). See "Merge story" below.

## What ships

| File | Purpose |
|---|---|
| `worker/internal/jobs/middleware.go` | `WithObservability[T]` — generic River-Worker wrapper that stamps `tid`/`trace_id` on ctx and opens an NR transaction per job. |
| `worker/internal/jobs/middleware_test.go` | 6 tests: tid-on-ctx, trace_id-set-when-missing, trace_id-preserved-when-present, error-propagation, nil-NR-safe (success+failure), delegation of NextRetry/Timeout, plus int64 formatter. |
| `worker/internal/obs/nr.go` | `InitNewRelic()` — fail-open NR application factory. Returns `(nil, nil)` on missing `NEW_RELIC_LICENSE_KEY`. |
| `worker/internal/obs/nr_test.go` | 2 tests: fail-open contract, nil-safe `WaitForConnection`. |
| `worker/internal/_obs_stubs/buildinfo/buildinfo.go` | TEMPORARY stub for track 1. Deleted post-merge. |
| `worker/internal/_obs_stubs/logctx/logctx.go` | TEMPORARY stub for track 2. Deleted post-merge. |
| `worker/go.mod`, `worker/go.sum` | Self-contained module so this PR is buildable in isolation. |

## What does NOT ship

The wrapper is **opt-in at the call site**. The actual job implementations
(`expire.go`, `quota.go`, `storage.go`, `geodb.go`, `trial.go`,
`expire_stacks.go`, `expiry_reminder.go`, `custom_domain_reconcile.go`,
`deploy_status_reconcile.go`) are **not modified by this PR**. The merger
applies the integration patch (below) to `internal/jobs/workers.go` to wire
every `river.AddWorker(...)` call through `jobs.WithObservability(...)`.

## Integration patch (apply to worker repo)

### 1. `worker/main.go` — slog default + NR init + `/healthz` commit_id

Diff against `worker/main.go`:

```go
 import (
     ...
+    "instant.dev/common/buildinfo"
+    "instant.dev/common/logctx"
+    "instant.dev/worker/internal/obs"
 )

 func main() {
-    // Structured JSON logging.
-    slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
-        Level: slog.LevelInfo,
-    })))
+    // Structured JSON logging — wrapped in logctx so every line carries
+    // service + commit_id + (when present) tid / trace_id / team_id.
+    slog.SetDefault(slog.New(logctx.NewHandler(
+        "worker",
+        buildinfo.GitSHA,
+        slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
+            Level:     slog.LevelInfo,
+            AddSource: true,
+        }),
+    )))
+
+    nrApp, _ := obs.InitNewRelic() // fail-open: nil is fine, errors logged
+    defer func() {
+        if nrApp != nil {
+            nrApp.Shutdown(5 * time.Second)
+        }
+    }()
+
     shutdownTracer := telemetry.InitTracer("instant-worker", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
     ...

-    workers := jobs.StartWorkers(ctx, database, rdb, cfg, provClient, planRegistry, deployStatusK8s)
+    workers := jobs.StartWorkers(ctx, database, rdb, cfg, provClient, planRegistry, deployStatusK8s, nrApp)
     ...

     mux := http.NewServeMux()
     mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
-        fmt.Fprintf(w, `{"ok":true,"service":"instant-worker"}`)
+        fmt.Fprintf(w, `{"ok":true,"service":"instant-worker","commit_id":%q,"build_time":%q,"version":%q}`,
+            buildinfo.GitSHA, buildinfo.BuildTime, buildinfo.Version)
     })
```

### 2. `worker/internal/jobs/workers.go` — wrap every AddWorker call

The `StartWorkers` signature gains a `nrApp *newrelic.Application` parameter.
Every `river.AddWorker(workers, X)` becomes
`river.AddWorker(workers, jobs.WithObservability(X, nrApp))`. The exact
call-sites in the current file (worker/internal/jobs/workers.go, lines
~130–155):

```go
-river.AddWorker(workers, NewExpireAnonymousWorker(db, provClient, minioClient))
-river.AddWorker(workers, NewExpireStacksWorker(db, cfg.KubeNamespaceApps+"-"))
-river.AddWorker(workers, NewRefreshGeoDBWorker())
-river.AddWorker(workers, &TrialExpiryWorker{db: db, email: emailClient})
-river.AddWorker(workers, &WeeklyDigestWorker{db: db, email: emailClient})
-river.AddWorker(workers, NewExpiryReminderWorker(db, emailClient))
-river.AddWorker(workers, NewEnforceStorageQuotaWorker(db, planRegistry))
-river.AddWorker(workers, NewUpdateStorageBytesWorker(db, provClient, minioScanner))
-river.AddWorker(workers, NewCustomDomainReconciler(db, nil, nil))
-river.AddWorker(workers, NewDeployStatusReconciler(db, deployStatusK8s))
+river.AddWorker(workers, WithObservability(NewExpireAnonymousWorker(db, provClient, minioClient), nrApp))
+river.AddWorker(workers, WithObservability(NewExpireStacksWorker(db, cfg.KubeNamespaceApps+"-"), nrApp))
+river.AddWorker(workers, WithObservability(NewRefreshGeoDBWorker(), nrApp))
+river.AddWorker(workers, WithObservability[TrialExpiryArgs](&TrialExpiryWorker{db: db, email: emailClient}, nrApp))
+river.AddWorker(workers, WithObservability[WeeklyDigestArgs](&WeeklyDigestWorker{db: db, email: emailClient}, nrApp))
+river.AddWorker(workers, WithObservability(NewExpiryReminderWorker(db, emailClient), nrApp))
+river.AddWorker(workers, WithObservability(NewEnforceStorageQuotaWorker(db, planRegistry), nrApp))
+river.AddWorker(workers, WithObservability(NewUpdateStorageBytesWorker(db, provClient, minioScanner), nrApp))
+river.AddWorker(workers, WithObservability(NewCustomDomainReconciler(db, nil, nil), nrApp))
+river.AddWorker(workers, WithObservability(NewDeployStatusReconciler(db, deployStatusK8s), nrApp))
```

The explicit type parameters on the `TrialExpiryWorker` / `WeeklyDigestWorker`
lines are only needed because those two are registered via composite literal
(`&Foo{...}`) rather than a `NewFoo(...)` constructor — type inference can't
walk back from the struct pointer to the JobArgs type.

## Merge story (stubs → common)

1. Land tracks 1 + 2 (which add `instant.dev/common/buildinfo` and
   `instant.dev/common/logctx`).
2. In the worker repo, delete `worker/internal/_obs_stubs/`.
3. Rewrite two imports in `worker/internal/jobs/middleware.go` and
   `worker/internal/obs/nr.go`:
   ```
   instant.dev/worker/internal/_obs_stubs/buildinfo → instant.dev/common/buildinfo
   instant.dev/worker/internal/_obs_stubs/logctx    → instant.dev/common/logctx
   ```
4. Add `instant.dev/common` to `worker/go.mod` (already present in the real
   worker repo via the existing `replace ../common` directive).
5. Apply the diffs above to `main.go` and `internal/jobs/workers.go`.
6. Bump the `newrelic/go-agent/v3` dep in the real worker `go.mod`.

## Test results

```
$ cd worker && go test ./...
ok   instant.dev/worker/internal/jobs           [middleware: 6 tests, 1 sub-test]
ok   instant.dev/worker/internal/obs            [2 tests]
ok   instant.dev/worker/internal/_obs_stubs/... [no tests, compile-only]
```

8 tests total, all passing. See PR description for raw output.

## Pushback (orchestrator)

The worktree `/tmp/wt-obs-2-worker` is on the `api` repo, not the `worker`
repo. The PR is opened against `api` but the substantive code targets
`worker`. The merger needs to extract the `worker/` subdir and apply it
against the actual `worker` repo. Future tracks splitting work across
multiple repos should consider creating per-service worktrees against the
correct upstream remote.
