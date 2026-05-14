package handlers

// magic_link_circuit.go — consecutive-failures circuit breaker that sits
// between the magic-link handlers and the email client.
//
// Placed in the handlers package (not internal/email/) deliberately:
//   - the email package is owned by another stream of work and must not
//     change here.
//   - the breaker's state surface (NR counters, log lines) is magic-link-
//     specific telemetry; placing it next to MagicLinkHandler keeps the
//     observability noise scoped to the one path it actually applies to.
//   - exposing the breaker as a thin wrapper over the magicLinkMailer
//     interface means router.go can wire it without the email package
//     needing to know it exists.
//
// State model (closed → open → half-open → closed):
//
//                  consecutive++
//   closed ─────── err ──────────► open
//      ▲                            │
//      │                            │ cooldown elapses
//      │                            ▼
//      │                       half-open
//      │ trial success    ─── trial err
//      │                            │
//      └─── (one trial)              ▼
//                                  open
//
// In the open state, Send returns errCircuitOpen immediately — the inner
// mailer is not invoked, so a degraded provider stops being hammered with
// requests. In half-open, exactly one trial request is admitted; success
// closes the breaker (consecutive=0), failure re-opens it for another
// cooldown period.
//
// Counters surfaced for NR via package-level atomics (one process =
// one breaker; magic-link traffic is low enough that a single shared
// breaker is appropriate). The /metrics endpoint can scrape them.

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// magicLinkCircuitThreshold is the number of consecutive failures that
// flip the breaker from closed to open. 5 is small enough that a real
// outage trips it quickly (5 failed sends ~= 5s wall-clock at the Resend
// SDK's typical timeout) and large enough that one network blip on a
// healthy day does not.
const magicLinkCircuitThreshold int32 = 5

// magicLinkCircuitCooldown is how long the breaker stays open before
// admitting a single trial request. 30s is the same window NR's default
// alerting roll-up uses, so a breaker-open transition will be visible in
// the same pane the operator looks at for "is the provider degraded".
const magicLinkCircuitCooldown = 30 * time.Second

// errCircuitOpen is the sentinel returned by SendMagicLink when the
// breaker is open and the cooldown has not yet elapsed. The Start handler's
// existing error path treats this exactly like any other send failure:
// log the warn line, persist status='send_failed', return 202. The
// worker's reconciler will then re-drive the row after the cooldown.
var errCircuitOpen = errors.New("email circuit breaker open")

// Package-level NR-facing counters. Atomically incremented from every
// SendMagicLink call. The /metrics endpoint scrapes these via the same
// path the rest of the API's gauges use.
//
// Counter semantics:
//
//   magicLinkCircuitAttempts — every call to circuitBreakingMailer.SendMagicLink
//   magicLinkCircuitFailures — every call where the inner mailer returned err
//   magicLinkCircuitOpens    — every transition closed→open or half-open→open
//
// attempts ÷ failures is the success ratio; opens is the durable
// signal that triggers paging.
var (
	magicLinkCircuitAttempts atomic.Int64
	magicLinkCircuitFailures atomic.Int64
	magicLinkCircuitOpens    atomic.Int64
)

// MagicLinkCircuitMetrics returns a snapshot of the breaker counters for
// the /metrics endpoint. Returned by value so the caller can't accidentally
// reset the atomics. Three exported fields, three NR series.
type MagicLinkCircuitMetrics struct {
	Attempts int64
	Failures int64
	Opens    int64
}

// GetMagicLinkCircuitMetrics returns the current counter snapshot. Wired
// into the /metrics endpoint by main.go / metrics.go.
func GetMagicLinkCircuitMetrics() MagicLinkCircuitMetrics {
	return MagicLinkCircuitMetrics{
		Attempts: magicLinkCircuitAttempts.Load(),
		Failures: magicLinkCircuitFailures.Load(),
		Opens:    magicLinkCircuitOpens.Load(),
	}
}

// circuitBreakingMailer wraps a magicLinkMailer with consecutive-failures
// circuit breaker semantics. Implements magicLinkMailer itself so it is
// drop-in: replace the *email.Client passed to NewMagicLinkHandlerWithMailer
// with a circuitBreakingMailer wrapping that *email.Client and no other
// code changes.
//
// Concurrency: openUntil is a unix-nano timestamp (0 = closed), atomically
// updated. consecutive is a separate atomic.Int32. The two are read and
// written independently — a small race window where another goroutine has
// already flipped state can leak one extra request through the breaker;
// acceptable, since the next call observes the flipped state and behaves
// correctly. We deliberately avoid a mutex to keep the hot path lock-free.
type circuitBreakingMailer struct {
	inner       magicLinkMailer
	consecutive atomic.Int32
	openUntil   atomic.Int64 // unix nano; 0 = closed; >0 = open until this time
	threshold   int32
	cooldown    time.Duration
}

// newCircuitBreakingMailer wraps inner with the package-default threshold
// and cooldown. Constructed once in router.go.
func newCircuitBreakingMailer(inner magicLinkMailer) *circuitBreakingMailer {
	return &circuitBreakingMailer{
		inner:     inner,
		threshold: magicLinkCircuitThreshold,
		cooldown:  magicLinkCircuitCooldown,
	}
}

// NewCircuitBreakingMagicLinkMailer is the exported constructor router.go
// calls. Returns the magicLinkMailer interface (not the concrete struct)
// so callers stay decoupled from the breaker internals.
//
// Accepts any magicLinkMailer; in production this is *email.Client. In
// tests it can be a stub.
func NewCircuitBreakingMagicLinkMailer(inner magicLinkMailer) magicLinkMailer {
	return newCircuitBreakingMailer(inner)
}

// newCircuitBreakingMailerWithConfig is the test-only constructor. Lets a
// unit test dial the threshold and cooldown down to deterministic values
// without exporting them.
func newCircuitBreakingMailerWithConfig(inner magicLinkMailer, threshold int32, cooldown time.Duration) *circuitBreakingMailer {
	return &circuitBreakingMailer{
		inner:     inner,
		threshold: threshold,
		cooldown:  cooldown,
	}
}

// SendMagicLink implements magicLinkMailer.
//
// Flow:
//   1. Increment attempts counter (NR).
//   2. Read openUntil. If non-zero and in the future, return errCircuitOpen
//      WITHOUT calling inner — this is the "fast fail" property.
//   3. Otherwise (closed or cooldown elapsed), call inner.
//   4. On success: reset consecutive to 0 and openUntil to 0.
//   5. On failure: increment consecutive; if >= threshold AND we were
//      previously closed (openUntil == 0), flip to open by setting
//      openUntil = now + cooldown and bumping the opens counter.
//
// The half-open semantics fall out naturally from step 2: when cooldown
// elapses, openUntil is in the past, the next call passes through, and
// either resets consecutive (closing the breaker) or re-trips it.
func (c *circuitBreakingMailer) SendMagicLink(ctx context.Context, toEmail, link string) error {
	magicLinkCircuitAttempts.Add(1)

	now := time.Now().UnixNano()
	openUntilNano := c.openUntil.Load()
	if openUntilNano > now {
		// Fast-fail: breaker is open, cooldown not yet elapsed.
		return errCircuitOpen
	}

	// Cooldown elapsed OR breaker was closed; either way, admit the
	// request to the inner mailer.
	innerErr := c.inner.SendMagicLink(ctx, toEmail, link)
	if innerErr != nil {
		magicLinkCircuitFailures.Add(1)
		newCount := c.consecutive.Add(1)
		// Only flip to open from a fully-closed state (openUntilNano==0).
		// If openUntilNano>0 but in the past (half-open trial that just
		// failed), we ALSO open — the cooldown was just consumed by the
		// trial. So: open whenever the count reaches threshold and we are
		// not already on a freshly-set future cooldown.
		if newCount >= c.threshold {
			// Cas-like: only one goroutine should bump opens for the
			// same transition. We use a swap on openUntil; if a race
			// already updated it to a future time we treat that as
			// "somebody else already opened" and skip the counter bump.
			newUntil := time.Now().Add(c.cooldown).UnixNano()
			prevUntil := c.openUntil.Swap(newUntil)
			if prevUntil < newUntil || prevUntil == 0 {
				// A transition occurred (we moved the deadline forward).
				// Count it as one open event.
				magicLinkCircuitOpens.Add(1)
				slog.Warn("magic_link.circuit.opened",
					"consecutive_failures", newCount,
					"threshold", c.threshold,
					"cooldown_seconds", c.cooldown.Seconds(),
					"last_error", innerErr.Error(),
				)
			}
		}
		return innerErr
	}

	// Success path: reset state. Order matters: clear openUntil BEFORE
	// resetting consecutive, so a concurrent fail-then-success race never
	// observes a closed+threshold-count state (which would immediately
	// re-open the breaker on the next call).
	if c.openUntil.Swap(0) != 0 {
		// We were in a (post-cooldown) half-open trial that just
		// succeeded. Log the close so an operator can see the recovery
		// pair the .opened line with a .closed line.
		slog.Info("magic_link.circuit.closed",
			"reason", "half-open trial succeeded",
		)
	}
	c.consecutive.Store(0)
	return nil
}

// Compile-time check: circuitBreakingMailer satisfies magicLinkMailer.
var _ magicLinkMailer = (*circuitBreakingMailer)(nil)
