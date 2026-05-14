// Package circuit provides a small, allocation-free circuit breaker primitive
// shared across every external boundary the api crosses (provisioner gRPC,
// Razorpay HTTP, DPoP replay Redis, worker→api internal HTTP).
//
// Why a hand-rolled breaker (vs sony/gobreaker or hashicorp/go-conntrack):
//
//   - We want a SINGLE behavior model across api + worker so on-call only
//     learns the state machine once. Vendoring gobreaker would still leave
//     the worker's HTTP wrapper as a custom thing.
//   - The hot path needs to be lock-free: every gRPC call hits Allow() and
//     Record() and a sync.Mutex around state would serialize every customer
//     provision behind a single semaphore on the api process.
//   - We need NR-shaped metrics (counter on opens / attempts / failures,
//     gauge on state) emitted via prometheus/promauto, and that's easier
//     to wire when the breaker owns its own observation calls.
//
// State machine:
//
//	closed → (consecutive failures ≥ threshold) → open
//	open   → (cooldown elapsed)                 → half-open (one trial allowed)
//	half-open → (trial succeeds)                → closed
//	half-open → (trial fails)                   → open (cooldown restarts)
//
// All transitions are observable via the `instant_circuit_breaker_state`
// gauge (0=closed, 1=open, 2=half_open) labelled by `name`, plus counters
// for opens, attempts, and failures.
//
// Concurrency: all state is held in atomic primitives so Allow / Record
// can be called from any number of goroutines without taking a lock.
package circuit

import (
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// State enumerates the breaker's three possible states. Exported so
// tests and metrics consumers can compare with sentinel values.
type State int32

const (
	// StateClosed — every call is permitted; failures accumulate.
	StateClosed State = 0
	// StateOpen — calls are short-circuited until openUntil elapses.
	StateOpen State = 1
	// StateHalfOpen — exactly one trial call is permitted; success
	// closes the breaker, failure re-opens it.
	StateHalfOpen State = 2
)

// String returns the lowercased label used in NR / Prometheus metrics
// ("closed" | "open" | "half_open"). Matches the spec in the brief.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}

// ErrOpen is the sentinel error returned by a caller wrapper when the
// breaker is open. Callers can branch on errors.Is(err, circuit.ErrOpen)
// to translate the open-circuit case into the canonical 503 envelope.
var ErrOpen = errors.New("circuit_breaker_open")

var (
	// breakerOpens counts open transitions (closed→open or half_open→open).
	// Drives the NR alert "circuit X opened ≥ 3 times in 10 min".
	breakerOpens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_circuit_breaker_opens_total",
		Help: "Circuit breaker open transitions (closed→open or half_open→open)",
	}, []string{"name"})

	// breakerAttempts counts every Allow() call regardless of outcome.
	// (Allow() = true + Allow() = false combined.) Useful as the
	// denominator for "what fraction of attempts were short-circuited?".
	breakerAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_circuit_breaker_attempts_total",
		Help: "Calls that hit the circuit breaker (Allow() invocations)",
	}, []string{"name"})

	// breakerFailures counts Record(err) calls where err != nil.
	// Distinct from breakerOpens — the breaker may absorb N failures
	// before flipping open.
	breakerFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_circuit_breaker_failures_total",
		Help: "Failures recorded against the circuit breaker",
	}, []string{"name"})

	// breakerState is sampled on every state transition so an NR widget
	// can show "is the provisioner circuit currently open?".
	// 0=closed, 1=open, 2=half_open.
	breakerState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "instant_circuit_breaker_state",
		Help: "Circuit breaker state (0=closed, 1=open, 2=half_open)",
	}, []string{"name"})
)

// Breaker is a single-instance circuit breaker. It is NOT safe to copy
// after first use — all atomic fields rely on a stable memory address.
type Breaker struct {
	name      string
	threshold int32         // consecutive failures required to open
	cooldown  time.Duration // how long to stay open before allowing one trial

	// consecutive — current consecutive-failure count. Reset on success.
	consecutive atomic.Int32
	// openUntil — UnixNano timestamp at which the open state should end
	// and a half-open trial becomes allowed. Zero when closed.
	openUntil atomic.Int64
	// halfOpen — true when a half-open trial is currently in flight, so
	// concurrent callers don't both fire the trial call. CAS'd to false
	// on Record() to free the slot for the next attempt.
	halfOpen atomic.Bool

	// onOpen is an optional callback fired on every closed/half_open →
	// open transition. The breaker calls this AFTER updating internal
	// state so callbacks can read State() and see the new value.
	// Errors from onOpen are swallowed; alerting must not block calls.
	onOpen func()
}

// NewBreaker constructs a Breaker that opens after `threshold` consecutive
// failures and stays open for `cooldown` before allowing a single trial.
//
// threshold MUST be ≥ 1. cooldown MUST be > 0. Both are validated here
// rather than at Allow() time so a misconfigured breaker fails loudly at
// process startup instead of silently never opening (or never closing).
//
// The `name` is used as the only metric label and SHOULD be a short
// snake_case identifier (`provisioner`, `razorpay`, `dpop_redis`, etc.).
// Avoid colons / slashes — they're legal Prometheus but hurt readability
// in NR widget titles.
func NewBreaker(name string, threshold int, cooldown time.Duration) *Breaker {
	if threshold < 1 {
		threshold = 1
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	b := &Breaker{
		name:      name,
		threshold: int32(threshold),
		cooldown:  cooldown,
	}
	// Seed the state gauge so a freshly-constructed breaker is
	// observable in NR before its first call.
	breakerState.WithLabelValues(name).Set(0)
	return b
}

// WithOnOpen returns the breaker for chaining and installs an optional
// callback fired on every transition into the open state. Used by the
// provisioner wrapper to emit a structured slog event ("circuit opened —
// see https://instanode.dev/status") so on-call sees the open before NR
// fires its 10-min alert window.
//
// The callback runs synchronously inside Record(); keep it cheap (slog,
// metric increment). Long work (HTTP POSTs to PagerDuty, etc.) MUST be
// fired in a goroutine inside the callback itself.
func (b *Breaker) WithOnOpen(fn func()) *Breaker {
	b.onOpen = fn
	return b
}

// Allow reports whether a call should be attempted right now.
//
// Returns true in two cases:
//
//  1. The breaker is closed (the common path; no extra cost).
//  2. The breaker is open BUT the cooldown elapsed and no other
//     goroutine has already grabbed the half-open trial slot.
//
// Returns false when:
//
//   - The breaker is open and the cooldown hasn't elapsed.
//   - The breaker is in half-open and another goroutine already holds
//     the single trial slot.
//
// Callers that get `false` MUST NOT call Record() — they didn't make
// the request, so they can't fail it. Returning ErrOpen from the
// caller wrapper is the canonical pattern.
func (b *Breaker) Allow() bool {
	breakerAttempts.WithLabelValues(b.name).Inc()
	openUntilNs := b.openUntil.Load()
	if openUntilNs == 0 {
		// Closed — fast path.
		return true
	}
	now := time.Now().UnixNano()
	if now < openUntilNs {
		// Still open; reject.
		return false
	}
	// Cooldown elapsed → try to grab the half-open trial slot.
	// CAS ensures exactly one concurrent caller wins; the rest see
	// halfOpen==true and bounce.
	if b.halfOpen.CompareAndSwap(false, true) {
		// Win — transition the gauge so dashboards reflect the trial.
		breakerState.WithLabelValues(b.name).Set(float64(StateHalfOpen))
		return true
	}
	// Lost the CAS — another goroutine owns the trial. Reject.
	return false
}

// Record is called AFTER an attempt completes to feed the outcome back
// into the breaker.
//
//   - err == nil: success. Resets the consecutive-failure counter. If
//     the breaker was in half-open, transitions to closed.
//   - err != nil: failure. Increments consecutive; if threshold is
//     crossed, transitions to open and arms the cooldown timer. If
//     the breaker was in half-open, the trial counts as the failure
//     that re-opens it (cooldown restarts from now).
//
// Record MUST NOT be called when Allow() returned false — the caller
// didn't actually make the request so there's nothing to record.
// Calling it anyway will inflate the failure metrics incorrectly.
func (b *Breaker) Record(err error) {
	if err == nil {
		// Success — reset consecutive counter. If we were in half-open,
		// close the breaker fully.
		b.consecutive.Store(0)
		if b.halfOpen.CompareAndSwap(true, false) {
			b.openUntil.Store(0)
			breakerState.WithLabelValues(b.name).Set(float64(StateClosed))
			slog.Info("circuit.closed",
				"name", b.name,
				"reason", "half_open_trial_succeeded",
			)
		}
		return
	}
	breakerFailures.WithLabelValues(b.name).Inc()

	// If we're in half-open, the trial counts as the failure that
	// re-opens us — restart cooldown and bail.
	if b.halfOpen.Load() {
		b.halfOpen.Store(false)
		b.consecutive.Store(0) // reset; threshold doesn't apply in half-open
		b.openUntil.Store(time.Now().Add(b.cooldown).UnixNano())
		breakerOpens.WithLabelValues(b.name).Inc()
		breakerState.WithLabelValues(b.name).Set(float64(StateOpen))
		slog.Warn("circuit.reopened",
			"name", b.name,
			"reason", "half_open_trial_failed",
			"cooldown_seconds", int(b.cooldown.Seconds()),
		)
		if b.onOpen != nil {
			b.onOpen()
		}
		return
	}

	n := b.consecutive.Add(1)
	if n < b.threshold {
		return
	}
	// Threshold crossed — open the breaker. We CAS on openUntil so
	// only the first crosser actually emits the metric / log event,
	// even when N goroutines all increment past the threshold at once.
	now := time.Now()
	until := now.Add(b.cooldown).UnixNano()
	if b.openUntil.CompareAndSwap(0, until) {
		breakerOpens.WithLabelValues(b.name).Inc()
		breakerState.WithLabelValues(b.name).Set(float64(StateOpen))
		slog.Warn("circuit.opened",
			"name", b.name,
			"reason", "consecutive_failure_threshold_crossed",
			"threshold", b.threshold,
			"cooldown_seconds", int(b.cooldown.Seconds()),
		)
		if b.onOpen != nil {
			b.onOpen()
		}
	}
}

// State returns the breaker's current state (closed / open / half_open).
// Computed live from the atomic fields — no lock needed.
//
// Used by tests and by the worker→api wrapper's "should I log a circuit
// open?" branch. Hot-path callers should use Allow() instead; State()
// does the same work without recording an attempt.
func (b *Breaker) State() State {
	if b.halfOpen.Load() {
		return StateHalfOpen
	}
	openUntilNs := b.openUntil.Load()
	if openUntilNs == 0 {
		return StateClosed
	}
	if time.Now().UnixNano() < openUntilNs {
		return StateOpen
	}
	// Cooldown elapsed but no Allow() has grabbed the trial slot yet —
	// from the dashboard's POV we're still open until something probes us.
	return StateOpen
}

// Name returns the breaker's metric-label name. Used by tests.
func (b *Breaker) Name() string { return b.name }
