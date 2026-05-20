package circuit

// counter_test.go — P3 hygiene regression
// (CIRCUIT-RETRY-AUDIT-2026-05-20). Pins the metric contract:
//
//   instant_circuit_breaker_attempts_total{name=X}  — incremented ONLY
//                                                     when Allow()=true
//                                                     (admitted)
//   instant_circuit_breaker_rejected_total{name=X}  — incremented when
//                                                     Allow()=false
//   instant_circuit_breaker_failures_total{name=X}  — incremented in
//                                                     Record(err!=nil)
//
// Invariant: attempts - failures == successes. The pre-P3 semantics
// double-counted rejected calls into attempts, breaking this invariant.

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// readCounter returns the current value of the labelled counter or 0.
func readCounter(t *testing.T, vec *prometheus.CounterVec, label string) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 8)
	vec.WithLabelValues(label).Collect(ch)
	close(ch)
	var sum float64
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("counter.Write: %v", err)
		}
		sum += pb.GetCounter().GetValue()
	}
	return sum
}

// TestAttemptsAndRejected_DoNotDoubleCount — the load-bearing P3 invariant.
// On a closed-then-open transition, attempts MUST equal admitted calls
// and rejected MUST equal short-circuited calls. Their sum is the total
// number of Allow() invocations.
func TestAttemptsAndRejected_DoNotDoubleCount(t *testing.T) {
	const name = "p3_no_double_count"
	beforeAtt := readCounter(t, breakerAttempts, name)
	beforeRej := readCounter(t, breakerRejected, name)

	b := NewBreaker(name, 2, 30*time.Second)

	// Two attempts that the breaker admits.
	if !b.Allow() {
		t.Fatal("first Allow should admit (closed)")
	}
	b.Record(errors.New("e1"))
	if !b.Allow() {
		t.Fatal("second Allow should admit (closed, threshold-1 failures)")
	}
	b.Record(errors.New("e2")) // trips the breaker

	// Three subsequent calls are rejected (still open).
	for i := 0; i < 3; i++ {
		if b.Allow() {
			t.Fatalf("call %d after trip should be rejected", i+1)
		}
	}

	afterAtt := readCounter(t, breakerAttempts, name)
	afterRej := readCounter(t, breakerRejected, name)

	// attempts must have grown by EXACTLY 2 (the two admitted calls).
	if got, want := afterAtt-beforeAtt, float64(2); got != want {
		t.Errorf("attempts delta = %v; want %v (admitted-only semantics)", got, want)
	}
	// rejected must have grown by EXACTLY 3 (the three rejected calls).
	if got, want := afterRej-beforeRej, float64(3); got != want {
		t.Errorf("rejected delta = %v; want %v", got, want)
	}
}

// TestAttemptsMinusFailuresEqualsSuccesses — the operator invariant
// the P3 fix exists to restore. attempts - failures == successes.
func TestAttemptsMinusFailuresEqualsSuccesses(t *testing.T) {
	const name = "p3_invariant"
	beforeAtt := readCounter(t, breakerAttempts, name)
	beforeFail := readCounter(t, breakerFailures, name)

	b := NewBreaker(name, 10, 30*time.Second)

	// Sequence: success, success, fail, success, fail.
	successes := 0
	failures := 0
	calls := []error{nil, nil, errors.New("e"), nil, errors.New("e")}
	for _, e := range calls {
		if !b.Allow() {
			t.Fatal("breaker should stay closed across this sequence")
		}
		b.Record(e)
		if e == nil {
			successes++
		} else {
			failures++
		}
	}

	afterAtt := readCounter(t, breakerAttempts, name)
	afterFail := readCounter(t, breakerFailures, name)

	gotAtt := afterAtt - beforeAtt
	gotFail := afterFail - beforeFail
	if gotAtt != float64(len(calls)) {
		t.Errorf("attempts delta = %v; want %d (one per admitted call)", gotAtt, len(calls))
	}
	if gotFail != float64(failures) {
		t.Errorf("failures delta = %v; want %d", gotFail, failures)
	}
	if (gotAtt - gotFail) != float64(successes) {
		t.Errorf("attempts - failures = %v; want %d (operator success invariant broken)",
			gotAtt-gotFail, successes)
	}
}
