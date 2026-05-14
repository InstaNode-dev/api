package handlers

// magic_link_circuit_test.go — unit tests for the consecutive-failures
// circuit breaker that sits in front of the magic-link email client.
//
// Each test uses newCircuitBreakingMailerWithConfig with a tight threshold
// and short cooldown so the state machine is deterministic without sleeps
// running into seconds.
//
// Lives in package handlers (not handlers_test) so it can call the
// package-private constructor + reach the errCircuitOpen sentinel.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// flakyMailer is a programmable test double. Each call returns nextErr.
// Tests flip nextErr between failure and nil to drive the breaker through
// open / half-open / closed transitions.
type flakyMailer struct {
	nextErr atomic.Value // error or nil
	calls   atomic.Int32
}

// setErr writes the value that the next Send call should return. Pass nil
// to make the next call succeed.
func (f *flakyMailer) setErr(err error) {
	if err == nil {
		// atomic.Value can't store an untyped nil — wrap in a typed
		// (error)(nil) so the type doesn't change between writes.
		f.nextErr.Store((*flakyMailerErr)(nil))
		return
	}
	f.nextErr.Store(&flakyMailerErr{err: err})
}

// flakyMailerErr is the boxing wrapper for atomic.Value — the docs warn
// against storing nil and against storing different concrete types into
// the same Value, so we box everything in one type.
type flakyMailerErr struct {
	err error
}

func (f *flakyMailer) SendMagicLink(ctx context.Context, toEmail, link string) error {
	f.calls.Add(1)
	raw := f.nextErr.Load()
	if raw == nil {
		return nil
	}
	box, ok := raw.(*flakyMailerErr)
	if !ok || box == nil {
		return nil
	}
	return box.err
}

// errFake is a sentinel returned by flakyMailer in the failing tests.
var errFake = errors.New("fake provider error")

// TestCircuit_OpensAfterNConsecutiveFailures asserts the primary state
// transition: 4 failures keep the breaker closed (inner is called every
// time), 5th failure opens it (inner stops being called).
func TestCircuit_OpensAfterNConsecutiveFailures(t *testing.T) {
	inner := &flakyMailer{}
	inner.setErr(errFake)
	cb := newCircuitBreakingMailerWithConfig(inner, 5, 1*time.Second)

	// 5 calls — all should hit the inner (threshold=5 means the 5th
	// failure is what flips state, but the inner is still called for it).
	for i := 0; i < 5; i++ {
		err := cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")
		if !errors.Is(err, errFake) {
			t.Fatalf("call %d: want errFake, got %v", i+1, err)
		}
	}
	if got := inner.calls.Load(); got != 5 {
		t.Errorf("inner.calls after 5 failing sends: want 5, got %d", got)
	}

	// 6th call — breaker is now open, inner must NOT be called.
	err := cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")
	if !errors.Is(err, errCircuitOpen) {
		t.Errorf("6th call: want errCircuitOpen, got %v", err)
	}
	if got := inner.calls.Load(); got != 5 {
		t.Errorf("inner.calls after 6th (open) send: want 5 (unchanged), got %d", got)
	}
}

// TestCircuit_RejectsImmediatelyWhenOpen exercises a separate code path
// from the test above: once open, a flood of subsequent requests is
// rejected without invoking the inner mailer. This is the "fast fail"
// property that protects a degraded provider from being hammered.
func TestCircuit_RejectsImmediatelyWhenOpen(t *testing.T) {
	inner := &flakyMailer{}
	inner.setErr(errFake)
	cb := newCircuitBreakingMailerWithConfig(inner, 3, 5*time.Second)

	// Trip the breaker with 3 failures.
	for i := 0; i < 3; i++ {
		_ = cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")
	}
	tripCalls := inner.calls.Load()
	if tripCalls != 3 {
		t.Fatalf("inner.calls after trip: want 3, got %d", tripCalls)
	}

	// 50 follow-up requests must all see errCircuitOpen and NOT touch inner.
	for i := 0; i < 50; i++ {
		if err := cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y"); !errors.Is(err, errCircuitOpen) {
			t.Fatalf("rejection-flood call %d: want errCircuitOpen, got %v", i+1, err)
		}
	}
	if got := inner.calls.Load(); got != tripCalls {
		t.Errorf("inner.calls after rejection flood: want %d (unchanged), got %d", tripCalls, got)
	}
}

// TestCircuit_HalfOpenAfterCooldown asserts that once the cooldown
// elapses, exactly one trial request is admitted to the inner mailer.
// Uses a very short cooldown (50ms) so the test doesn't slow the suite.
func TestCircuit_HalfOpenAfterCooldown(t *testing.T) {
	inner := &flakyMailer{}
	inner.setErr(errFake)
	cb := newCircuitBreakingMailerWithConfig(inner, 2, 50*time.Millisecond)

	// Trip the breaker.
	for i := 0; i < 2; i++ {
		_ = cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")
	}
	if !errors.Is(cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y"), errCircuitOpen) {
		t.Fatalf("breaker should be open immediately after threshold")
	}
	tripCalls := inner.calls.Load()

	// Wait past the cooldown.
	time.Sleep(75 * time.Millisecond)

	// Next call: the inner mailer should be invoked. The inner is still
	// returning errFake, so the breaker will re-open — but the trial
	// itself must reach the inner.
	_ = cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")
	if got := inner.calls.Load(); got != tripCalls+1 {
		t.Errorf("inner.calls after half-open trial: want %d, got %d", tripCalls+1, got)
	}
}

// TestCircuit_HalfOpenSuccessClosesCircuit asserts the recovery path: a
// successful trial after cooldown resets consecutive=0 and clears the
// open state, so subsequent failures (even single ones) are again
// admitted instead of fast-failed.
func TestCircuit_HalfOpenSuccessClosesCircuit(t *testing.T) {
	inner := &flakyMailer{}
	inner.setErr(errFake)
	cb := newCircuitBreakingMailerWithConfig(inner, 2, 25*time.Millisecond)

	// Trip the breaker.
	for i := 0; i < 2; i++ {
		_ = cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")
	}

	// Wait past the cooldown.
	time.Sleep(50 * time.Millisecond)

	// Flip inner to success for the trial.
	inner.setErr(nil)
	if err := cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y"); err != nil {
		t.Fatalf("trial after cooldown: want nil err, got %v", err)
	}

	// Now flip inner back to failing. With consecutive reset, the breaker
	// should allow the next 1 failure through (NOT immediately fast-fail).
	inner.setErr(errFake)
	if err := cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y"); !errors.Is(err, errFake) {
		t.Errorf("post-recovery call must hit inner (return errFake), got %v", err)
	}
}

// TestCircuit_HalfOpenFailureReopens asserts the converse: a failing
// trial after the first cooldown re-opens the breaker for another
// cooldown period. The subsequent immediate call must fast-fail again.
func TestCircuit_HalfOpenFailureReopens(t *testing.T) {
	inner := &flakyMailer{}
	inner.setErr(errFake)
	cb := newCircuitBreakingMailerWithConfig(inner, 2, 25*time.Millisecond)

	// Trip the breaker.
	for i := 0; i < 2; i++ {
		_ = cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")
	}

	// Wait past the cooldown.
	time.Sleep(50 * time.Millisecond)

	// Trial — still failing, breaker re-opens.
	_ = cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y")

	// Next call must be fast-failed again.
	if err := cb.SendMagicLink(context.Background(), "u@example.com", "https://x/y"); !errors.Is(err, errCircuitOpen) {
		t.Errorf("post-trial-failure call must fast-fail with errCircuitOpen, got %v", err)
	}
}
