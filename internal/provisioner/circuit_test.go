package provisioner

// circuit_test.go — verifies the provisioner gRPC boundary's circuit
// breaker correctly intercepts RPCs. We don't dial a real provisioner;
// instead we exercise the package-private callWithBreaker helper with
// a fake fn() that simulates gRPC successes and failures.
//
// The 2026-05-13 outage post-mortem named this exact test as a hedge:
// "every /db/new call burned 30s before 503-ing — wire a breaker that
// short-circuits in <1ms after the threshold". These tests are the
// regression guard for that pathology.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"instant.dev/internal/circuit"
)

var errGRPCBoom = errors.New("rpc error: provisioner unavailable")

// TestProvisioner_ClosedToOpenTransition — 5 failures in a row trips
// the circuit. Mirrors the brief's "5 consecutive 5xx-class failures".
func TestProvisioner_ClosedToOpenTransition(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_trip", 5, 30*time.Second)
	for i := 0; i < 5; i++ {
		_, err := callWithBreaker(b, func() (int, error) {
			return 0, errGRPCBoom
		})
		if !errors.Is(err, errGRPCBoom) {
			t.Fatalf("attempt %d: want errGRPCBoom, got %v", i+1, err)
		}
	}
	if b.State() != circuit.StateOpen {
		t.Fatalf("expected open after 5 failures, got %s", b.State())
	}
}

// TestProvisioner_ImmediateRejectWhenOpen — the whole point of the
// circuit. After the trip every subsequent call must return ErrOpen
// in <1ms without invoking the underlying gRPC stub.
func TestProvisioner_ImmediateRejectWhenOpen(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_short_circuit", 1, 30*time.Second)
	_, _ = callWithBreaker(b, func() (int, error) {
		return 0, errGRPCBoom
	})

	calls := 0
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_, err := callWithBreaker(b, func() (int, error) {
			calls++
			return 0, nil
		})
		if !errors.Is(err, circuit.ErrOpen) {
			t.Fatalf("call %d: want ErrOpen, got %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if calls != 0 {
		t.Errorf("underlying fn invoked %d times; want 0", calls)
	}
	// 1000 short-circuit checks should be MUCH faster than one gRPC call.
	// Sanity check: < 100ms for 1000 atomic loads.
	if elapsed > 100*time.Millisecond {
		t.Errorf("1000 short-circuit checks took %s; want < 100ms", elapsed)
	}
}

// TestProvisioner_HalfOpenSingleTrialWins — under concurrent load
// during the half-open phase, only ONE goroutine should win the trial
// slot. Real-world: a /db/new flood after the cooldown expires shouldn't
// stampede the provisioner.
func TestProvisioner_HalfOpenSingleTrialWins(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_half_open_concurrent", 1, 10*time.Millisecond)
	_, _ = callWithBreaker(b, func() (int, error) {
		return 0, errGRPCBoom
	})
	time.Sleep(15 * time.Millisecond)

	const concurrent = 50
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		admitted int
	)
	// Make the trial fn slow so all goroutines pile up on Allow() before
	// the first one's Record() fires. This is the racy path we need to
	// guard against — the breaker MUST admit exactly one even under load.
	wg.Add(concurrent)
	for i := 0; i < concurrent; i++ {
		go func() {
			defer wg.Done()
			_, err := callWithBreaker(b, func() (int, error) {
				mu.Lock()
				admitted++
				mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				return 0, nil
			})
			_ = err
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("exactly one goroutine should win the half-open trial, got %d", admitted)
	}
}

// TestProvisioner_HalfOpenTrialCloses — successful trial after cooldown
// fully closes the circuit and subsequent calls proceed normally.
func TestProvisioner_HalfOpenTrialCloses(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_recovery", 1, 10*time.Millisecond)
	_, _ = callWithBreaker(b, func() (int, error) {
		return 0, errGRPCBoom
	})
	time.Sleep(15 * time.Millisecond)
	out, err := callWithBreaker(b, func() (int, error) {
		return 42, nil
	})
	if err != nil || out != 42 {
		t.Fatalf("recovery call should succeed, got (%d, %v)", out, err)
	}
	if b.State() != circuit.StateClosed {
		t.Fatalf("breaker should close after successful trial, got %s", b.State())
	}
}

// TestProvisioner_BreakerErrIsCircuitErrOpen — handlers branch on
// errors.Is(err, circuit.ErrOpen) to translate to the
// `provisioner_unavailable` envelope. Verify the chain works.
func TestProvisioner_BreakerErrIsCircuitErrOpen(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_errors_is", 1, 30*time.Second)
	_, _ = callWithBreaker(b, func() (int, error) { return 0, errGRPCBoom })
	_, err := callWithBreaker(b, func() (int, error) { return 0, nil })
	if !errors.Is(err, circuit.ErrOpen) {
		t.Fatalf("errors.Is(err, circuit.ErrOpen) should be true, got err=%v", err)
	}
}

// TestProvisioner_ConfiguredConstants — anchors the brief's "5
// consecutive failures, 30s cooldown" so a future tuning change is
// surfaced as a test diff.
func TestProvisioner_ConfiguredConstants(t *testing.T) {
	if provisionerCircuitThreshold != 5 {
		t.Errorf("provisionerCircuitThreshold = %d; brief specifies 5", provisionerCircuitThreshold)
	}
	if provisionerCircuitCooldown != 30*time.Second {
		t.Errorf("provisionerCircuitCooldown = %s; brief specifies 30s", provisionerCircuitCooldown)
	}
	if provisionerCircuitName != "provisioner" {
		t.Errorf("provisionerCircuitName = %q; want 'provisioner' for NR metric label", provisionerCircuitName)
	}
}
