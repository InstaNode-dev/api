package models

// deployment_failure_test.go — unit tests for the failure-autopsy model layer.
//
// Tests:
//   TestFailureHintMap_AllReasonsHaveHints      — every FailureReason constant has an entry
//   TestHintForReason_KnownReasons              — correct hint returned per reason
//   TestHintForReason_UnknownFallback           — unrecognised reason → Unknown hint
//   TestHintForReason_NeverEmpty                — hint is never an empty string

import (
	"testing"
)

// knownReasons is the closed set of FailureReason constants.
// Tests iterate this slice to verify exhaustive coverage.
var knownReasons = []string{
	FailureReasonOOMKilled,
	FailureReasonEvicted,
	FailureReasonImagePullBackOff,
	FailureReasonCrashLoopBackOff,
	FailureReasonBuildFailed,
	FailureReasonDeadlineExceeded,
	FailureReasonError,
	FailureReasonUnknown,
}

// TestFailureHintMap_AllReasonsHaveHints verifies that every FailureReason
// constant is present in FailureHint. A new constant without a hint is a
// regression — the dashboard would render an empty hint string.
func TestFailureHintMap_AllReasonsHaveHints(t *testing.T) {
	for _, reason := range knownReasons {
		hint, ok := FailureHint[reason]
		if !ok {
			t.Errorf("FailureHint missing entry for reason %q", reason)
			continue
		}
		if hint == "" {
			t.Errorf("FailureHint[%q] is empty", reason)
		}
	}
}

// TestHintForReason_KnownReasons verifies that HintForReason returns the
// correct hint for each known reason (not the Unknown fallback).
func TestHintForReason_KnownReasons(t *testing.T) {
	for _, reason := range knownReasons {
		got := HintForReason(reason)
		want, _ := FailureHint[reason]
		if got != want {
			t.Errorf("HintForReason(%q) = %q, want %q", reason, got, want)
		}
	}
}

// TestHintForReason_UnknownFallback verifies that an unrecognised reason
// returns the Unknown hint (not an empty string or panic).
func TestHintForReason_UnknownFallback(t *testing.T) {
	got := HintForReason("FutureBrandNewReason")
	want := FailureHint[FailureReasonUnknown]
	if got != want {
		t.Errorf("HintForReason(unrecognised) = %q, want Unknown hint %q", got, want)
	}
}

// TestHintForReason_NeverEmpty verifies that HintForReason never returns an
// empty string for any input. The dashboard unconditionally renders the hint
// field, so an empty hint would show blank to the user.
func TestHintForReason_NeverEmpty(t *testing.T) {
	inputs := append(knownReasons, "", "garbage", "oomkilled" /* wrong case */)
	for _, reason := range inputs {
		if h := HintForReason(reason); h == "" {
			t.Errorf("HintForReason(%q) returned empty string", reason)
		}
	}
}
