package provisioner

// circuit_filter_test.go — P1-1 regression test
// (CIRCUIT-RETRY-AUDIT-2026-05-20).
//
// Confirms callWithBreaker DOES NOT advance the consecutive-failure counter
// for caller-side cancellations (context.Canceled / DeadlineExceeded) or
// for gRPC codes that represent "bad input from the caller" rather than
// "the provisioner is sick" (InvalidArgument, FailedPrecondition,
// PermissionDenied, Unauthenticated, NotFound, AlreadyExists, OutOfRange).
//
// Without this, five misbehaving / abandoned callers in a row could trip
// the provisioner breaker and 503 every other tenant — a self-inflicted
// DDoS. The 2026-05-13 outage post-mortem explicitly named this as the
// pathology the breaker design must NOT have.

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"instant.dev/internal/circuit"
)

// TestCircuitBreaker_RecordsContextCanceledAsSuccess is the load-bearing
// regression test the brief calls out by name. context.Canceled is the
// canonical "the user closed the browser tab while we were waiting on
// the RPC" surface — the provisioner is fine, the request just went away.
// A flood of these MUST NOT trip the breaker.
func TestCircuitBreaker_RecordsContextCanceledAsSuccess(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_context_canceled", 5, 30*time.Second)

	// 50 calls returning context.Canceled — must NOT trip a threshold-of-5
	// breaker, because none of these represent a server fault.
	for i := 0; i < 50; i++ {
		_, err := callWithBreaker(b, func() (int, error) {
			return 0, context.Canceled
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("attempt %d: want context.Canceled, got %v", i+1, err)
		}
	}
	if state := b.State(); state != circuit.StateClosed {
		t.Errorf("breaker should remain CLOSED after 50 context.Canceled returns; got %s", state)
	}
}

// TestCircuitBreaker_DoesNotTripOnContextDeadlineExceeded — same property
// for context.DeadlineExceeded. A slow caller hitting their own request
// deadline must not punish the provisioner.
func TestCircuitBreaker_DoesNotTripOnContextDeadlineExceeded(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_deadline_exceeded", 3, 30*time.Second)

	for i := 0; i < 10; i++ {
		_, err := callWithBreaker(b, func() (int, error) {
			return 0, context.DeadlineExceeded
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("attempt %d: want context.DeadlineExceeded, got %v", i+1, err)
		}
	}
	if state := b.State(); state != circuit.StateClosed {
		t.Errorf("breaker should remain CLOSED after 10 deadline-exceeded; got %s", state)
	}
}

// TestCircuitBreaker_DoesNotTripOnInvalidArgument — gRPC InvalidArgument is
// what a malformed /db/new payload turns into on the server. A misbehaving
// agent flooding 1000 bad-tier requests must NOT lock every other tenant
// out of provisioning.
func TestCircuitBreaker_DoesNotTripOnInvalidArgument(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_invalid_argument", 3, 30*time.Second)
	badInputErr := status.Error(codes.InvalidArgument, "tier must be one of [anonymous, hobby, pro]")

	for i := 0; i < 100; i++ {
		_, err := callWithBreaker(b, func() (int, error) {
			return 0, badInputErr
		})
		// Caller still sees the error — we just don't count it.
		if err == nil {
			t.Fatalf("attempt %d: want non-nil err, got nil", i+1)
		}
	}
	if state := b.State(); state != circuit.StateClosed {
		t.Errorf("breaker should remain CLOSED after 100 InvalidArgument errors; got %s", state)
	}
}

// TestCircuitBreaker_DoesNotTripOnFailedPreconditionPermissionUnauthNotFound
// — the rest of the "bad input" gRPC family. Each is a code that signals
// the caller's request is malformed/forbidden, not that the server is sick.
func TestCircuitBreaker_DoesNotTripOnFailedPreconditionPermissionUnauthNotFound(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
	}{
		{"FailedPrecondition", codes.FailedPrecondition},
		{"PermissionDenied", codes.PermissionDenied},
		{"Unauthenticated", codes.Unauthenticated},
		{"NotFound", codes.NotFound},
		{"AlreadyExists", codes.AlreadyExists},
		{"OutOfRange", codes.OutOfRange},
		{"Canceled", codes.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := circuit.NewBreaker("provisioner_test_filter_"+tc.name, 3, 30*time.Second)
			rpcErr := status.Error(tc.code, tc.name+" — simulated server response")
			for i := 0; i < 20; i++ {
				_, _ = callWithBreaker(b, func() (int, error) {
					return 0, rpcErr
				})
			}
			if state := b.State(); state != circuit.StateClosed {
				t.Errorf("%s: breaker should remain CLOSED; got %s", tc.name, state)
			}
		})
	}
}

// TestCircuitBreaker_StillTripsOnUnavailable — counter-test that the filter
// did NOT defang the breaker. codes.Unavailable is the canonical "the
// provisioner is genuinely sick" code; the breaker MUST still trip on a
// burst of these. Without this counter-test the P1-1 fix could over-scrub
// and silently disable circuit protection entirely.
func TestCircuitBreaker_StillTripsOnUnavailable(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_unavailable_still_trips", 5, 30*time.Second)
	upstreamErr := status.Error(codes.Unavailable, "provisioner: connection refused")

	for i := 0; i < 5; i++ {
		_, _ = callWithBreaker(b, func() (int, error) {
			return 0, upstreamErr
		})
	}
	if state := b.State(); state != circuit.StateOpen {
		t.Fatalf("breaker MUST trip OPEN on 5 codes.Unavailable; got %s", state)
	}
}

// TestCircuitBreaker_StillTripsOnGenericError — non-gRPC errors (e.g.
// connection refused before gRPC ever wrapped them) still indicate server
// trouble and MUST still count.
func TestCircuitBreaker_StillTripsOnGenericError(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_generic_still_trips", 5, 30*time.Second)
	for i := 0; i < 5; i++ {
		_, _ = callWithBreaker(b, func() (int, error) {
			return 0, errors.New("dial tcp 10.0.0.1:50051: connect: connection refused")
		})
	}
	if state := b.State(); state != circuit.StateOpen {
		t.Fatalf("breaker MUST trip OPEN on 5 generic non-gRPC errors; got %s", state)
	}
}

// TestCircuitBreaker_MixedTrafficDoesNotTrip — realistic mixed traffic:
// a flood of bad-input requests interleaved with successful ones, no
// genuine server failures. The breaker MUST stay closed.
func TestCircuitBreaker_MixedTrafficDoesNotTrip(t *testing.T) {
	b := circuit.NewBreaker("provisioner_test_mixed_traffic", 3, 30*time.Second)
	badInputErr := status.Error(codes.InvalidArgument, "bad tier")

	// Pattern: 5 bad-input, 1 success, repeat. Without the filter the 3rd
	// bad-input would have tripped the breaker.
	for cycle := 0; cycle < 4; cycle++ {
		for i := 0; i < 5; i++ {
			_, _ = callWithBreaker(b, func() (int, error) {
				return 0, badInputErr
			})
		}
		_, _ = callWithBreaker(b, func() (int, error) { return 1, nil })
	}
	if state := b.State(); state != circuit.StateClosed {
		t.Errorf("mixed bad-input + success traffic must keep breaker CLOSED; got %s", state)
	}
}

// TestShouldRecordBreakerErr_TableDriven pins the policy directly so a
// future refactor that accidentally drops a code from the scrub list (or
// adds a server-fault code to it) is caught at compile-of-test-time.
func TestShouldRecordBreakerErr_TableDriven(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantRecord bool
	}{
		{"nil_is_recorded_as_success", nil, true},
		{"context.Canceled_scrubbed", context.Canceled, false},
		{"context.DeadlineExceeded_scrubbed", context.DeadlineExceeded, false},
		{"InvalidArgument_scrubbed", status.Error(codes.InvalidArgument, "x"), false},
		{"FailedPrecondition_scrubbed", status.Error(codes.FailedPrecondition, "x"), false},
		{"PermissionDenied_scrubbed", status.Error(codes.PermissionDenied, "x"), false},
		{"Unauthenticated_scrubbed", status.Error(codes.Unauthenticated, "x"), false},
		{"NotFound_scrubbed", status.Error(codes.NotFound, "x"), false},
		{"AlreadyExists_scrubbed", status.Error(codes.AlreadyExists, "x"), false},
		{"OutOfRange_scrubbed", status.Error(codes.OutOfRange, "x"), false},
		{"gRPC_Canceled_scrubbed", status.Error(codes.Canceled, "x"), false},
		{"Unavailable_RECORDED", status.Error(codes.Unavailable, "x"), true},
		{"Internal_RECORDED", status.Error(codes.Internal, "x"), true},
		{"Unknown_RECORDED", status.Error(codes.Unknown, "x"), true},
		{"ResourceExhausted_RECORDED", status.Error(codes.ResourceExhausted, "x"), true},
		{"gRPC_DeadlineExceeded_RECORDED", status.Error(codes.DeadlineExceeded, "x"), true},
		{"plain_error_RECORDED", errors.New("network unreachable"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRecordBreakerErr(tc.err)
			if got != tc.wantRecord {
				t.Errorf("shouldRecordBreakerErr(%v) = %v; want %v", tc.err, got, tc.wantRecord)
			}
		})
	}
}
