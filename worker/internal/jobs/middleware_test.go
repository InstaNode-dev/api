// Tests for the observability middleware. The interesting properties:
//
//   1. `tid` ends up on the ctx via logctx.WithTID — readable with
//      logctx.TIDFromContext — and matches the job.ID.
//   2. `trace_id` is non-empty after the wrapper runs, even when the caller
//      passed no trace id in, and is preserved when the caller did.
//   3. An error from the inner worker bubbles through unchanged.
//   4. Duration is recorded (we can't easily assert it from outside, but we
//      can assert the wrapper doesn't crash on a slow job).
//   5. The wrapper is safe with a nil New Relic application (fail-open).
//
// We don't unit-test the New-Relic-present path because it would require a
// live agent connection. The nil-app path covers the only branch under our
// control; integration tests for the present-path live in the deployment
// rollout (track 7).
package jobs

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"instant.dev/worker/internal/_obs_stubs/logctx"
)

// fakeArgs is a minimal river.JobArgs that the test uses to type the wrapper.
type fakeArgs struct{}

func (fakeArgs) Kind() string { return "fake_test_job" }

// fakeWorker is a river.Worker[fakeArgs] whose Work captures the ctx it was
// called with and optionally returns a configured error. NextRetry/Timeout
// return zero values to satisfy the interface.
type fakeWorker struct {
	river.WorkerDefaults[fakeArgs]
	gotCtx  context.Context
	gotJob  *river.Job[fakeArgs]
	returns error
	delay   time.Duration
}

func (f *fakeWorker) Work(ctx context.Context, job *river.Job[fakeArgs]) error {
	f.gotCtx = ctx
	f.gotJob = job
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(f.delay):
		}
	}
	return f.returns
}

// newJob returns a river.Job[fakeArgs] with the given id. river.Job embeds
// *rivertype.JobRow, so we construct the row separately and point the job
// at it. The middleware only reads ID + Attempt off the row plus Args.Kind()
// so the rest of the JobRow fields can stay zero.
func newJob(id int64) *river.Job[fakeArgs] {
	return &river.Job[fakeArgs]{
		JobRow: &rivertype.JobRow{ID: id, Kind: "fake_test_job"},
		Args:   fakeArgs{},
	}
}

// TestWithObservability_StampsTIDOnContext is the contract test the task
// brief calls out: the wrapper must put job.ID on the ctx under the logctx
// "tid" key so downstream slog calls pick it up automatically.
func TestWithObservability_StampsTIDOnContext(t *testing.T) {
	fake := &fakeWorker{}
	wrapped := WithObservability[fakeArgs](fake, nil)

	want := int64(42)
	if err := wrapped.Work(context.Background(), newJob(want)); err != nil {
		t.Fatalf("wrapped.Work returned error: %v", err)
	}
	if fake.gotCtx == nil {
		t.Fatalf("inner worker was never called")
	}
	got := logctx.TIDFromContext(fake.gotCtx)
	if got != strconv.FormatInt(want, 10) {
		t.Fatalf("tid on ctx: got %q, want %q", got, strconv.FormatInt(want, 10))
	}
}

// TestWithObservability_SetsTraceIDWhenMissing asserts the wrapper generates
// a trace id when the incoming ctx has none. The exact value doesn't matter,
// only that it's non-empty so log queries always find a populated field.
func TestWithObservability_SetsTraceIDWhenMissing(t *testing.T) {
	fake := &fakeWorker{}
	wrapped := WithObservability[fakeArgs](fake, nil)

	if err := wrapped.Work(context.Background(), newJob(7)); err != nil {
		t.Fatalf("wrapped.Work returned error: %v", err)
	}
	if got := logctx.TraceIDFromContext(fake.gotCtx); got == "" {
		t.Fatalf("trace_id was not set on ctx")
	}
}

// TestWithObservability_PreservesExistingTraceID asserts the wrapper does NOT
// overwrite a trace id that the caller already attached. This matters when a
// periodic-job dispatcher (out of scope for this track) opens the trace and
// the worker needs to inherit it.
func TestWithObservability_PreservesExistingTraceID(t *testing.T) {
	fake := &fakeWorker{}
	wrapped := WithObservability[fakeArgs](fake, nil)

	const want = "trace-from-dispatcher"
	ctx := logctx.WithTraceID(context.Background(), want)
	if err := wrapped.Work(ctx, newJob(9)); err != nil {
		t.Fatalf("wrapped.Work returned error: %v", err)
	}
	if got := logctx.TraceIDFromContext(fake.gotCtx); got != want {
		t.Fatalf("trace_id: got %q, want %q (wrapper must not overwrite)", got, want)
	}
}

// TestWithObservability_PropagatesError covers the failure path: an error
// from the inner worker must reach the caller unchanged so River's retry
// machinery still sees it. We assert errors.Is to be defensive against the
// wrapper deciding to wrap the error in the future.
func TestWithObservability_PropagatesError(t *testing.T) {
	want := errors.New("simulated job failure")
	fake := &fakeWorker{returns: want}
	wrapped := WithObservability[fakeArgs](fake, nil)

	err := wrapped.Work(context.Background(), newJob(11))
	if !errors.Is(err, want) {
		t.Fatalf("error not propagated: got %v, want %v", err, want)
	}
}

// TestWithObservability_NilNRAppIsSafe is the fail-open contract test. With
// no NR app, the wrapper still runs the inner worker, still stamps ids on
// ctx, still returns the inner's error. We cover both error-free and
// error-returning paths so the deferred txn.End() path is exercised.
func TestWithObservability_NilNRAppIsSafe(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fake := &fakeWorker{}
		wrapped := WithObservability[fakeArgs](fake, nil)
		if err := wrapped.Work(context.Background(), newJob(1)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("failure", func(t *testing.T) {
		boom := errors.New("boom")
		fake := &fakeWorker{returns: boom}
		wrapped := WithObservability[fakeArgs](fake, nil)
		if err := wrapped.Work(context.Background(), newJob(2)); !errors.Is(err, boom) {
			t.Fatalf("unexpected error: got %v, want %v", err, boom)
		}
	})
}

// TestWithObservability_DelegatesNextRetryAndTimeout asserts the wrapper
// doesn't impose its own policy. The fakeWorker embeds river.WorkerDefaults
// which returns zero values; we just confirm calling those methods through
// the wrapper does not panic and returns the inner values.
func TestWithObservability_DelegatesNextRetryAndTimeout(t *testing.T) {
	fake := &fakeWorker{}
	wrapped := WithObservability[fakeArgs](fake, nil)

	if got := wrapped.NextRetry(newJob(1)); !got.IsZero() {
		t.Fatalf("NextRetry should delegate to WorkerDefaults (zero time), got %v", got)
	}
	if got := wrapped.Timeout(newJob(1)); got != 0 {
		t.Fatalf("Timeout should delegate to WorkerDefaults (0), got %v", got)
	}
}

// TestJobIDString covers the tiny int64->string formatter used to keep the
// hot path allocation-light. Belt-and-braces: 0, positive, negative.
func TestJobIDString(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, ""},
		{1, "1"},
		{42, "42"},
		{9876543210, "9876543210"},
		{-7, "-7"},
	}
	for _, c := range cases {
		if got := jobIDString(c.in); got != c.want {
			t.Errorf("jobIDString(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
