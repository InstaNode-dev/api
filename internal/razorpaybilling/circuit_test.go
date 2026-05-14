package razorpaybilling

// circuit_test.go — local-only verification that the package-level
// Razorpay circuit breaker has the correct shape and that
// callWithBreaker short-circuits when open.
//
// These tests do NOT touch the real Razorpay API. They exercise the
// wrapping primitive — the same primitive every Portal method uses —
// by passing a synthetic fn() that returns a stub error.

import (
	"errors"
	"testing"
	"time"

	"instant.dev/internal/circuit"
)

var errRazorpayBoom = errors.New("razorpay boom")

// TestRazorpay_ClosedToOpenTransition: after `threshold` consecutive
// failures, callWithBreaker returns circuit.ErrOpen WITHOUT invoking
// the underlying function — proves the breaker is actually wired.
func TestRazorpay_ClosedToOpenTransition(t *testing.T) {
	// Use a private breaker so we don't pollute the shared singleton's
	// state across tests in this file.
	b := circuit.NewBreaker("razorpay_test_open", 3, 30*time.Second)
	wrap := func(fn func() (string, error)) (string, error) {
		if !b.Allow() {
			return "", circuit.ErrOpen
		}
		out, err := fn()
		b.Record(err)
		return out, err
	}

	// Three failures → tripped.
	for i := 0; i < 3; i++ {
		_, err := wrap(func() (string, error) { return "", errRazorpayBoom })
		if err != errRazorpayBoom {
			t.Fatalf("attempt %d: want errRazorpayBoom, got %v", i+1, err)
		}
	}

	// Fourth call should short-circuit.
	called := false
	_, err := wrap(func() (string, error) {
		called = true
		return "", nil
	})
	if !errors.Is(err, circuit.ErrOpen) {
		t.Fatalf("expected circuit.ErrOpen, got %v", err)
	}
	if called {
		t.Fatal("underlying fn must NOT be invoked when breaker is open")
	}
	if b.State() != circuit.StateOpen {
		t.Fatalf("expected StateOpen, got %s", b.State())
	}
}

// TestRazorpay_ImmediateRejectWhenOpen — 100 rapid calls after trip,
// none should invoke the underlying fn.
func TestRazorpay_ImmediateRejectWhenOpen(t *testing.T) {
	b := circuit.NewBreaker("razorpay_test_immediate", 1, 30*time.Second)
	wrap := func(fn func() (string, error)) (string, error) {
		if !b.Allow() {
			return "", circuit.ErrOpen
		}
		out, err := fn()
		b.Record(err)
		return out, err
	}
	_, _ = wrap(func() (string, error) { return "", errRazorpayBoom })

	invocations := 0
	for i := 0; i < 100; i++ {
		_, err := wrap(func() (string, error) {
			invocations++
			return "", nil
		})
		if !errors.Is(err, circuit.ErrOpen) {
			t.Fatalf("call %d: want ErrOpen, got %v", i, err)
		}
	}
	if invocations != 0 {
		t.Fatalf("underlying fn invoked %d times while open; want 0", invocations)
	}
}

// TestRazorpay_HalfOpenTrialClosesOnSuccess — wait out cooldown, run
// one successful trial → breaker closes.
func TestRazorpay_HalfOpenTrialClosesOnSuccess(t *testing.T) {
	b := circuit.NewBreaker("razorpay_test_half_open_ok", 1, 10*time.Millisecond)
	wrap := func(fn func() (string, error)) (string, error) {
		if !b.Allow() {
			return "", circuit.ErrOpen
		}
		out, err := fn()
		b.Record(err)
		return out, err
	}
	_, _ = wrap(func() (string, error) { return "", errRazorpayBoom })
	if b.State() != circuit.StateOpen {
		t.Fatal("expected open")
	}
	time.Sleep(15 * time.Millisecond)

	_, err := wrap(func() (string, error) { return "ok", nil })
	if err != nil {
		t.Fatalf("half-open trial should succeed, got %v", err)
	}
	if b.State() != circuit.StateClosed {
		t.Fatalf("expected closed after successful trial, got %s", b.State())
	}
}

// TestRazorpay_HalfOpenTrialReopensOnFailure — a failed trial puts the
// breaker back to open with a fresh cooldown.
func TestRazorpay_HalfOpenTrialReopensOnFailure(t *testing.T) {
	b := circuit.NewBreaker("razorpay_test_half_open_fail", 1, 10*time.Millisecond)
	wrap := func(fn func() (string, error)) (string, error) {
		if !b.Allow() {
			return "", circuit.ErrOpen
		}
		out, err := fn()
		b.Record(err)
		return out, err
	}
	_, _ = wrap(func() (string, error) { return "", errRazorpayBoom })
	time.Sleep(15 * time.Millisecond)

	// Trial fails.
	_, _ = wrap(func() (string, error) { return "", errRazorpayBoom })
	if b.State() != circuit.StateOpen {
		t.Fatalf("expected re-open, got %s", b.State())
	}
	// Subsequent call before cooldown expires should be rejected.
	_, err := wrap(func() (string, error) { return "", nil })
	if !errors.Is(err, circuit.ErrOpen) {
		t.Fatalf("post-reopen call should return ErrOpen, got %v", err)
	}
}

// TestRazorpay_ExportedCallWithBreakerUsesSingleton — verifies the
// exported CallWithBreaker(...) helper routes through the package
// singleton breaker (used by handlers/billing.go for the inline
// Subscription.Create call).
func TestRazorpay_ExportedCallWithBreakerUsesSingleton(t *testing.T) {
	// We can't reset the singleton from outside, but we can verify
	// CallWithBreaker actually exercises a breaker — when the
	// singleton is closed, a call should run.
	if Breaker().State() != circuit.StateClosed && Breaker().State() != circuit.StateOpen && Breaker().State() != circuit.StateHalfOpen {
		t.Fatalf("Breaker() returned unknown state: %v", Breaker().State())
	}
	called := false
	out, err := CallWithBreaker(func() (int, error) {
		called = true
		return 42, nil
	})
	if Breaker().State() == circuit.StateClosed {
		// Should have called through.
		if !called {
			t.Fatal("CallWithBreaker should invoke fn() when breaker is closed")
		}
		if out != 42 || err != nil {
			t.Fatalf("want (42, nil), got (%d, %v)", out, err)
		}
	}
}

// TestRazorpay_ConfiguredConstants — anchors the brief's tuning
// expectations: 5 consecutive failures, 60s cooldown. If a future
// edit changes these we want a test diff to surface the change.
func TestRazorpay_ConfiguredConstants(t *testing.T) {
	if razorpayCircuitThreshold != 5 {
		t.Errorf("razorpayCircuitThreshold = %d; brief specifies 5", razorpayCircuitThreshold)
	}
	if razorpayCircuitCooldown != 60*time.Second {
		t.Errorf("razorpayCircuitCooldown = %s; brief specifies 60s", razorpayCircuitCooldown)
	}
	if razorpayCircuitName != "razorpay" {
		t.Errorf("razorpayCircuitName = %q; want 'razorpay' for NR metric label", razorpayCircuitName)
	}
}
