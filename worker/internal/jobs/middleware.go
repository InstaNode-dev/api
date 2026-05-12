// File adds the observability middleware used by every River worker
// registered in StartWorkers (see workers.go). Wrapping is opt-in at the
// AddWorker call-site: the actual job implementations in expire.go, quota.go,
// storage.go, geodb.go, trial.go, etc. are NOT modified by this track —
// the wrapper does its job around them.
//
// Track 4 of the observability rollout (OBSERVABILITY-PLAN-2026-05-12.md).
//
// What it does, per executed job:
//
//   1. Stamps `tid = <job.ID>` on the ctx via logctx.WithTID so every slog
//      line emitted inside the job carries the same task id — agents can
//      grep one job's full trace from a stream of interleaved workers.
//   2. Stamps `trace_id = <uuid.New()>` on the ctx via logctx.WithTraceID
//      if one is not already present. Real ingest of OTel-derived trace ids
//      will follow track 7 — this guarantees the field is always non-empty
//      so log queries can be written today.
//   3. Opens a New Relic transaction named `job.<JobKind>` and defers its
//      end. Errors returned by the inner Work bubble through nrtxn.NoticeError
//      before being returned, so they surface in the NR error inbox.
//   4. Logs duration on completion at INFO (success) or ERROR (failure)
//      using a consistent shape so the dashboard panels under track 7 can
//      bind to a stable schema.
//
// The wrapper is a thin generic function: it preserves the concrete
// `river.Worker[T]` type so `river.AddWorker` keeps accepting it without
// reflection. NextRetry, Timeout, and every other Worker method delegate
// to the inner worker so existing retry / timeout policy is untouched.
package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/riverqueue/river"

	"instant.dev/worker/internal/_obs_stubs/logctx"
)

// observabilityWorker wraps an inner river.Worker[T] with the per-job
// observability concerns described in the package doc. It is constructed
// via WithObservability and never used directly.
//
// The inner worker is held by value of an interface type so the wrapper does
// not have to know any of its fields. Every Worker[T] method delegates.
type observabilityWorker[T river.JobArgs] struct {
	inner river.Worker[T]
	nrApp *newrelic.Application // may be nil — fail-open
}

// WithObservability wraps next so that each job execution is instrumented
// with logctx ids and an optional New Relic transaction.
//
// nrApp may be nil — in that case the wrapper still stamps ctx ids and logs
// duration, it just does not open an NR transaction. This matches the
// fail-open contract of obs.InitNewRelic.
//
// Call site (workers.go):
//
//	river.AddWorker(workers, jobs.WithObservability(jobs.NewExpireAnonymousWorker(...), nrApp))
//
// Note the generic parameter is inferred from the wrapped worker, so the
// caller writes WithObservability(...) not WithObservability[ExpireAnonymousArgs](...).
func WithObservability[T river.JobArgs](next river.Worker[T], nrApp *newrelic.Application) river.Worker[T] {
	return &observabilityWorker[T]{inner: next, nrApp: nrApp}
}

// Work is the only method that does real work — the rest delegate. It runs
// in this order: stamp ids, open NR txn, call inner.Work, record outcome,
// end NR txn (via defer), log duration.
func (w *observabilityWorker[T]) Work(ctx context.Context, job *river.Job[T]) error {
	// Step 1: stamp ids on ctx so every slog call inside the job sees them.
	// We always overwrite tid (the job is the authoritative source for the
	// task id) but we PRESERVE an existing trace_id if one is present — that
	// path is taken when a periodic-job dispatcher already opened a trace.
	tid := jobIDString(job.ID)
	ctx = logctx.WithTID(ctx, tid)
	if logctx.TraceIDFromContext(ctx) == "" {
		ctx = logctx.WithTraceID(ctx, uuid.New().String())
	}

	// Step 2: open the New Relic transaction. txn is nil-safe — every method
	// on (*newrelic.Transaction)(nil) is a no-op in the v3 SDK — but we still
	// gate the StartTransaction call to avoid the nil-deref on nrApp itself.
	kind := jobKind(job)
	var txn *newrelic.Transaction
	if w.nrApp != nil {
		txn = w.nrApp.StartTransaction("job." + kind)
		// nrtxn carries the ctx for the duration of Work. Cross-process
		// linkage (OTel headers) is set up by track 7 — today we only need
		// the in-process span.
		ctx = newrelic.NewContext(ctx, txn)
		defer txn.End()
	}

	start := time.Now()
	err := w.inner.Work(ctx, job)
	elapsed := time.Since(start)

	if err != nil {
		if txn != nil {
			txn.NoticeError(err)
		}
		slog.ErrorContext(ctx, "jobs.middleware.work_failed",
			"kind", kind,
			"job_id", job.ID,
			"attempt", job.Attempt,
			"duration_ms", elapsed.Milliseconds(),
			"error", err.Error(),
		)
		return err
	}

	slog.InfoContext(ctx, "jobs.middleware.work_ok",
		"kind", kind,
		"job_id", job.ID,
		"attempt", job.Attempt,
		"duration_ms", elapsed.Milliseconds(),
	)
	return nil
}

// NextRetry, Timeout — pure delegation. The wrapper MUST NOT impose its own
// retry or timeout policy; that belongs to the wrapped worker (typically via
// river.WorkerDefaults embedded by the concrete worker struct).
func (w *observabilityWorker[T]) NextRetry(job *river.Job[T]) time.Time {
	return w.inner.NextRetry(job)
}

func (w *observabilityWorker[T]) Timeout(job *river.Job[T]) time.Duration {
	return w.inner.Timeout(job)
}

// jobKind extracts the job kind without forcing the caller to depend on the
// concrete args type. It calls (T).Kind() through the JobArgs interface;
// every River job args type already implements Kind() so this is free.
//
// We pull Kind() from job.Args rather than a fresh zero value because the
// JobArgs interface contract is that Kind() is constant per type.
func jobKind[T river.JobArgs](job *river.Job[T]) string {
	return job.Args.Kind()
}

// jobIDString formats an int64 job id without pulling in strconv at the
// call site. Kept tiny because it sits on the hot path of every job.
func jobIDString(id int64) string {
	if id == 0 {
		return ""
	}
	const digits = "0123456789"
	var buf [20]byte
	pos := len(buf)
	neg := id < 0
	u := uint64(id)
	if neg {
		u = uint64(-id)
	}
	for u >= 10 {
		pos--
		buf[pos] = digits[u%10]
		u /= 10
	}
	pos--
	buf[pos] = digits[u]
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
