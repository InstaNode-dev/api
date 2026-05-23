package circuit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// errBoom is a sentinel for the failure path that doesn't carry any
// information besides "the call failed". Mirrors how the real wrappers
// will pass through gRPC / HTTP errors.
var errBoom = errors.New("boom")

// TestBreaker_ClosedToOpenTransition asserts that after `threshold`
// consecutive Record(err) calls the breaker flips to open and Allow()
// returns false. Covers the primary state transition.
func TestBreaker_ClosedToOpenTransition(t *testing.T) {
	b := NewBreaker("test_closed_to_open", 3, 30*time.Second)
	if b.State() != StateClosed {
		t.Fatalf("fresh breaker should be closed, got %s", b.State())
	}
	// First two failures should leave the breaker closed.
	for i := 0; i < 2; i++ {
		if !b.Allow() {
			t.Fatalf("attempt %d: Allow() should return true (still closed)", i+1)
		}
		b.Record(errBoom)
		if b.State() != StateClosed {
			t.Fatalf("attempt %d: state should still be closed, got %s", i+1, b.State())
		}
	}
	// Third failure crosses the threshold → open.
	if !b.Allow() {
		t.Fatal("third attempt should still be allowed before recording")
	}
	b.Record(errBoom)
	if b.State() != StateOpen {
		t.Fatalf("after threshold breach state should be open, got %s", b.State())
	}
}

// TestBreaker_ImmediateRejectWhenOpen asserts that an open breaker
// returns Allow()==false WITHOUT consulting the underlying dependency.
// This is the whole point of the circuit — fail fast on a known-bad
// dependency.
func TestBreaker_ImmediateRejectWhenOpen(t *testing.T) {
	b := NewBreaker("test_immediate_reject", 1, 30*time.Second)
	// Trip the breaker.
	if !b.Allow() {
		t.Fatal("initial Allow() should succeed")
	}
	b.Record(errBoom)
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %s", b.State())
	}
	// 100 follow-up calls should all be short-circuited.
	for i := 0; i < 100; i++ {
		if b.Allow() {
			t.Fatalf("call %d: Allow() should return false while open", i+1)
		}
	}
}

// TestBreaker_HalfOpenTrialSucceedsClosesBreaker asserts the recovery
// happy path: after cooldown elapses, exactly one trial call is
// permitted, and on success the breaker fully closes.
func TestBreaker_HalfOpenTrialSucceedsClosesBreaker(t *testing.T) {
	// Use a 10ms cooldown so the test doesn't waste wall-clock time.
	b := NewBreaker("test_half_open_success", 1, 10*time.Millisecond)
	_ = b.Allow()
	b.Record(errBoom)
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %s", b.State())
	}
	// Wait for cooldown.
	time.Sleep(15 * time.Millisecond)
	// First Allow() after cooldown should win the half-open trial.
	if !b.Allow() {
		t.Fatal("first Allow() after cooldown should succeed (half-open trial)")
	}
	// Any subsequent Allow() before Record() finishes should be rejected —
	// only one trial allowed.
	if b.Allow() {
		t.Fatal("second concurrent Allow() should be rejected while trial in flight")
	}
	// Successful trial closes the breaker.
	b.Record(nil)
	if b.State() != StateClosed {
		t.Fatalf("after successful trial state should be closed, got %s", b.State())
	}
	// New calls should sail through.
	if !b.Allow() {
		t.Fatal("post-recovery Allow() should succeed")
	}
}

// TestBreaker_HalfOpenTrialFailsReopens asserts the recovery sad path:
// if the trial fails the breaker re-opens and the cooldown restarts.
func TestBreaker_HalfOpenTrialFailsReopens(t *testing.T) {
	b := NewBreaker("test_half_open_fail", 1, 10*time.Millisecond)
	_ = b.Allow()
	b.Record(errBoom)
	time.Sleep(15 * time.Millisecond)
	// Grab the trial.
	if !b.Allow() {
		t.Fatal("trial should be allowed after cooldown")
	}
	// Trial fails.
	b.Record(errBoom)
	if b.State() != StateOpen {
		t.Fatalf("failed trial should re-open the breaker, got %s", b.State())
	}
	// And subsequent Allow() should be rejected (cooldown reset).
	if b.Allow() {
		t.Fatal("Allow() should be rejected right after re-open")
	}
}

// TestBreaker_SuccessResetsConsecutiveCounter asserts that a successful
// call clears the failure tally — a flapping dependency that fails
// twice, succeeds, then fails twice should NOT trip a threshold=3
// breaker.
func TestBreaker_SuccessResetsConsecutiveCounter(t *testing.T) {
	b := NewBreaker("test_success_resets", 3, 30*time.Second)
	// Two failures.
	for i := 0; i < 2; i++ {
		_ = b.Allow()
		b.Record(errBoom)
	}
	// One success.
	_ = b.Allow()
	b.Record(nil)
	// Two more failures — should NOT trip (counter was reset).
	for i := 0; i < 2; i++ {
		_ = b.Allow()
		b.Record(errBoom)
	}
	if b.State() != StateClosed {
		t.Fatalf("state should still be closed after reset, got %s", b.State())
	}
}

// TestBreaker_OnOpenCallback asserts the optional callback fires on
// every closed→open and half_open→open transition.
func TestBreaker_OnOpenCallback(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	b := NewBreaker("test_on_open_cb", 1, 10*time.Millisecond).WithOnOpen(func() {
		mu.Lock()
		defer mu.Unlock()
		calls++
	})
	// First trip → calls should = 1.
	_ = b.Allow()
	b.Record(errBoom)
	mu.Lock()
	if calls != 1 {
		mu.Unlock()
		t.Fatalf("expected onOpen called once after first trip, got %d", calls)
	}
	mu.Unlock()
	// Wait, grab the trial, fail it → callback fires again.
	time.Sleep(15 * time.Millisecond)
	_ = b.Allow()
	b.Record(errBoom)
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected onOpen called twice after re-open, got %d", calls)
	}
}

// TestBreaker_ConcurrentCallersOnlyOneTrial asserts the half-open
// CAS truly admits exactly one caller across N concurrent goroutines.
// Regression guard for the "one Redis outage = N customers' provisions
// all try the trial at once" pathology.
func TestBreaker_ConcurrentCallersOnlyOneTrial(t *testing.T) {
	b := NewBreaker("test_concurrent_trial", 1, 10*time.Millisecond)
	_ = b.Allow()
	b.Record(errBoom)
	time.Sleep(15 * time.Millisecond)

	const n = 50
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		admitted int
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if b.Allow() {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("exactly one goroutine should win the half-open trial, got %d", admitted)
	}
}

// TestBreaker_NilErrInHalfOpenWithNoTrialIsNoOp ensures Record(nil)
// when the breaker is closed and never tripped does nothing surprising —
// no state change, no metric inflation.
func TestBreaker_NilErrInHalfOpenWithNoTrialIsNoOp(t *testing.T) {
	b := NewBreaker("test_nil_noop", 3, 30*time.Second)
	for i := 0; i < 5; i++ {
		_ = b.Allow()
		b.Record(nil)
	}
	if b.State() != StateClosed {
		t.Fatalf("repeated success should leave breaker closed, got %s", b.State())
	}
}

// TestBreaker_StateStringValues — quick sanity check the string labels
// match what the metrics scrape will emit. NR runbook references these
// strings literally.
func TestBreaker_StateStringValues(t *testing.T) {
	cases := []struct {
		s    State
		want string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half_open"},
	}
	for _, c := range cases {
		if c.s.String() != c.want {
			t.Errorf("State(%d).String() = %q, want %q", c.s, c.s.String(), c.want)
		}
	}
}

// TestBreaker_ErrOpenIsStableSentinel — wrappers branch on
// errors.Is(err, circuit.ErrOpen). Make sure that path works.
func TestBreaker_ErrOpenIsStableSentinel(t *testing.T) {
	wrapped := errors.Join(errors.New("wrapper"), ErrOpen)
	if !errors.Is(wrapped, ErrOpen) {
		t.Fatal("errors.Is should detect ErrOpen through errors.Join")
	}
}

// ---------------------------------------------------------------------------
// NewBreaker input-clamping + accessors
// ---------------------------------------------------------------------------

// TestNewBreaker_ClampsInvalidThreshold verifies a threshold < 1 is clamped
// to 1, so a single failure trips the breaker rather than never tripping.
func TestNewBreaker_ClampsInvalidThreshold(t *testing.T) {
	b := NewBreaker("clamp_threshold", 0, time.Second)
	if got := b.threshold; got != 1 {
		t.Fatalf("threshold 0 must clamp to 1, got %d", got)
	}
	b2 := NewBreaker("clamp_threshold_neg", -5, time.Second)
	if got := b2.threshold; got != 1 {
		t.Fatalf("threshold -5 must clamp to 1, got %d", got)
	}
}

// TestNewBreaker_ClampsInvalidCooldown verifies a non-positive cooldown is
// replaced by the 30s default so the breaker never reopens instantly.
func TestNewBreaker_ClampsInvalidCooldown(t *testing.T) {
	b := NewBreaker("clamp_cooldown", 3, 0)
	if got := b.cooldown; got != 30*time.Second {
		t.Fatalf("cooldown 0 must default to 30s, got %v", got)
	}
	b2 := NewBreaker("clamp_cooldown_neg", 3, -time.Minute)
	if got := b2.cooldown; got != 30*time.Second {
		t.Fatalf("negative cooldown must default to 30s, got %v", got)
	}
}

// TestBreaker_NameReturnsLabel verifies Name() echoes the metric-label name.
func TestBreaker_NameReturnsLabel(t *testing.T) {
	b := NewBreaker("name_accessor", 3, time.Second)
	if got := b.Name(); got != "name_accessor" {
		t.Fatalf("Name() = %q, want name_accessor", got)
	}
}

// ---------------------------------------------------------------------------
// State() — all three branches
// ---------------------------------------------------------------------------

// TestState_ClosedWhenFresh covers the openUntil==0 closed branch.
func TestState_ClosedWhenFresh(t *testing.T) {
	b := NewBreaker("state_fresh", 3, time.Second)
	if got := b.State(); got != StateClosed {
		t.Fatalf("fresh breaker State() = %v, want StateClosed", got)
	}
}

// TestState_HalfOpenAfterCooldown covers the halfOpen==true branch: trip the
// breaker, wait past cooldown, then Allow() grabs the trial slot moving it to
// half-open, which State() must report.
func TestState_HalfOpenAfterCooldown(t *testing.T) {
	b := NewBreaker("state_halfopen", 1, 20*time.Millisecond)
	b.Record(errors.New("boom")) // trip → open
	if got := b.State(); got != StateOpen {
		t.Fatalf("after trip State() = %v, want StateOpen", got)
	}
	time.Sleep(40 * time.Millisecond) // wait out cooldown
	if !b.Allow() {
		t.Fatal("Allow() should grant the half-open trial slot after cooldown")
	}
	if got := b.State(); got != StateHalfOpen {
		t.Fatalf("after trial slot State() = %v, want StateHalfOpen", got)
	}
}

// TestState_OpenWhileCoolingDown covers the openUntil>now open branch.
func TestState_OpenWhileCoolingDown(t *testing.T) {
	b := NewBreaker("state_open", 1, time.Hour)
	b.Record(errors.New("boom"))
	if got := b.State(); got != StateOpen {
		t.Fatalf("during cooldown State() = %v, want StateOpen", got)
	}
}

// TestState_OpenAfterCooldownButNoProbeYet covers the final State() branch:
// cooldown has elapsed but no Allow() has grabbed the trial slot, so the
// dashboard still treats the breaker as open until something probes it.
func TestState_OpenAfterCooldownButNoProbeYet(t *testing.T) {
	b := NewBreaker("state_open_unprobed", 1, 15*time.Millisecond)
	b.Record(errors.New("boom")) // open, openUntil ≈ now+15ms
	time.Sleep(35 * time.Millisecond)
	// Deliberately do NOT call Allow() — halfOpen stays false, openUntil
	// is non-zero but now > openUntil, hitting the trailing return StateOpen.
	if got := b.State(); got != StateOpen {
		t.Fatalf("State() after elapsed cooldown w/o probe = %v, want StateOpen", got)
	}
}
