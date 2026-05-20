package email

// breaker.go — generalized circuit breaker for synchronous transactional
// email sends (P0-1 CIRCUIT-RETRY-AUDIT-2026-05-20).
//
// Before this file existed, only SendMagicLink was protected by a
// consecutive-failure breaker (handlers/magic_link_circuit.go). The four
// other sync sends — SendPaymentSucceeded, SendPaymentFailed,
// SendTeamInvite, SendDeletionConfirmation — were one-shot: a Brevo brownout
// would freeze the request handler for the SDK's 10s timeout on EVERY
// upgrade webhook, every team invite, every deletion request, indefinitely.
//
// BreakingClient wraps a *Client and intercepts every Send* method through
// a consecutive-failure breaker. The state machine and tunables are
// deliberately identical to the magic-link breaker so on-call learns
// one mental model.
//
// State:
//
//   closed ── threshold consecutive errors ──► open
//      ▲                                       │
//      │   trial succeeds                      │ cooldown elapsed
//      └──────────────── half-open ◄───────────┘
//                       │ trial fails
//                       ▼
//                      open
//
// In open state every Send* fast-fails with ErrCircuitOpen — callers see
// a structured error within microseconds instead of the SDK timeout
// (Brevo: 10s; Resend: SDK default). Handlers existing error paths log
// + degrade to "we tried, surface the failure to the caller / audit row",
// which is the same behaviour they already have for a real provider
// failure — no per-handler change is required to benefit from the
// breaker.
//
// Concurrency: every state field is an atomic. The Send* methods are
// safe to call from any number of goroutines.

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// transactionalCircuitThreshold — consecutive failures that flip the
// breaker from closed to open. 5 matches the magic-link breaker (P0-1
// design: identical state machine for operational simplicity).
const transactionalCircuitThreshold int32 = 5

// transactionalCircuitCooldown — how long the breaker stays open before
// admitting a half-open trial.
const transactionalCircuitCooldown = 30 * time.Second

// ErrCircuitOpen is the sentinel returned by every Send* on BreakingClient
// when the breaker is open. Callers can branch on errors.Is(err,
// email.ErrCircuitOpen) to distinguish "we never tried" from "we tried and
// upstream said no".
var ErrCircuitOpen = errors.New("email transactional circuit breaker open")

// NR-facing counters. One global set per process — every Send* against any
// BreakingClient increments these. Three counters, three NR series.
var (
	transactionalCircuitAttempts atomic.Int64
	transactionalCircuitFailures atomic.Int64
	transactionalCircuitOpens    atomic.Int64
)

// TransactionalCircuitMetrics is the read-only snapshot the /metrics
// endpoint exports. Keeps the atomics from being directly resettable by
// scrape code.
type TransactionalCircuitMetrics struct {
	Attempts int64
	Failures int64
	Opens    int64
}

// GetTransactionalCircuitMetrics returns the current counter snapshot.
// Wired into the api's /metrics endpoint.
func GetTransactionalCircuitMetrics() TransactionalCircuitMetrics {
	return TransactionalCircuitMetrics{
		Attempts: transactionalCircuitAttempts.Load(),
		Failures: transactionalCircuitFailures.Load(),
		Opens:    transactionalCircuitOpens.Load(),
	}
}

// BreakingClient wraps a *Client with a consecutive-failure circuit
// breaker. Implements every Send* method exposed by *Client. Construct via
// NewBreakingClient (production) or newBreakingClientWithConfig (tests).
//
// Concurrency: openUntil is a unix-nano timestamp (0 = closed), atomically
// updated. consecutive is a separate atomic.Int32. The two are read +
// written independently — a small race window where another goroutine has
// already flipped state can leak one extra request through; acceptable,
// since the next call observes the flipped state and behaves correctly.
// We deliberately avoid a mutex to keep the hot path lock-free.
type BreakingClient struct {
	inner       *Client
	consecutive atomic.Int32
	openUntil   atomic.Int64 // unix nano; 0 = closed; >0 = open until this time
	threshold   int32
	cooldown    time.Duration
	name        string // metric label; "email_transactional" by default
}

// NewBreakingClient wraps inner with the package-default threshold and
// cooldown. Construct once at process start and share the *BreakingClient
// across all handlers.
//
// Returns a *BreakingClient (concrete type, not interface) so callers can
// continue to use the *WithKey method variants — Go interfaces can't
// cover both the keyless and keyed shapes without an explosion of
// interface methods, so we keep it concrete.
func NewBreakingClient(inner *Client) *BreakingClient {
	return &BreakingClient{
		inner:     inner,
		threshold: transactionalCircuitThreshold,
		cooldown:  transactionalCircuitCooldown,
		name:      "email_transactional",
	}
}

// newBreakingClientWithConfig is the test-only constructor. Lets unit tests
// dial threshold + cooldown down to deterministic values without exporting
// the knobs.
func newBreakingClientWithConfig(inner *Client, threshold int32, cooldown time.Duration) *BreakingClient {
	return &BreakingClient{
		inner:     inner,
		threshold: threshold,
		cooldown:  cooldown,
		name:      "email_transactional_test",
	}
}

// allow reports whether the breaker should admit this send. Increments the
// attempts counter. Returns false when the breaker is open and the
// cooldown has not elapsed.
//
// Note (P3 hygiene from the audit): the magic-link breaker incremented
// attempts on every call REGARDLESS of admission. We do the same here for
// consistency, BUT we also expose Opens separately so an operator can
// compute "actual attempts that hit the inner" = attempts - (rejected
// while open). Tests pin the semantics.
func (b *BreakingClient) allow() bool {
	transactionalCircuitAttempts.Add(1)
	now := time.Now().UnixNano()
	openUntilNs := b.openUntil.Load()
	return openUntilNs == 0 || openUntilNs <= now
}

// record feeds the outcome back. nil resets consecutive; non-nil
// increments and may flip the breaker open. Symmetric to the magic-link
// implementation.
func (b *BreakingClient) record(innerErr error) {
	if innerErr == nil {
		// Success — close fully if we were in a half-open trial.
		if b.openUntil.Swap(0) != 0 {
			slog.Info("email.transactional.circuit.closed",
				"name", b.name,
				"reason", "half_open_trial_succeeded",
			)
		}
		b.consecutive.Store(0)
		return
	}
	transactionalCircuitFailures.Add(1)
	newCount := b.consecutive.Add(1)
	if newCount < b.threshold {
		return
	}
	newUntil := time.Now().Add(b.cooldown).UnixNano()
	prevUntil := b.openUntil.Swap(newUntil)
	if prevUntil < newUntil || prevUntil == 0 {
		transactionalCircuitOpens.Add(1)
		slog.Warn("email.transactional.circuit.opened",
			"name", b.name,
			"consecutive_failures", newCount,
			"threshold", b.threshold,
			"cooldown_seconds", b.cooldown.Seconds(),
			"last_error", innerErr.Error(),
			"impact", "payment receipts / payment-failed / team-invite / deletion-confirm will fast-fail until provider recovers",
		)
	}
}

// ProviderName forwards to the wrapped client. Exposed so callers that
// previously inspected *Client.ProviderName() can swap in a BreakingClient
// without changes.
func (b *BreakingClient) ProviderName() ProviderName {
	if b == nil || b.inner == nil {
		return ProviderNoop
	}
	return b.inner.ProviderName()
}

// SendPaymentFailed wraps *Client.SendPaymentFailed with the breaker.
func (b *BreakingClient) SendPaymentFailed(ctx context.Context, to string, attemptCount int, nextAttemptDate *time.Time) error {
	return b.SendPaymentFailedWithKey(ctx, to, "", attemptCount, nextAttemptDate)
}

// SendPaymentFailedWithKey wraps the keyed variant.
func (b *BreakingClient) SendPaymentFailedWithKey(ctx context.Context, to, idempotencyKey string, attemptCount int, nextAttemptDate *time.Time) error {
	if !b.allow() {
		return ErrCircuitOpen
	}
	err := b.inner.SendPaymentFailedWithKey(ctx, to, idempotencyKey, attemptCount, nextAttemptDate)
	b.record(err)
	return err
}

// SendPaymentSucceeded wraps *Client.SendPaymentSucceeded with the breaker.
func (b *BreakingClient) SendPaymentSucceeded(ctx context.Context, to string, receipt PaymentReceipt) error {
	return b.SendPaymentSucceededWithKey(ctx, to, "", receipt)
}

// SendPaymentSucceededWithKey wraps the keyed variant.
func (b *BreakingClient) SendPaymentSucceededWithKey(ctx context.Context, to, idempotencyKey string, receipt PaymentReceipt) error {
	if !b.allow() {
		return ErrCircuitOpen
	}
	err := b.inner.SendPaymentSucceededWithKey(ctx, to, idempotencyKey, receipt)
	b.record(err)
	return err
}

// SendTeamInvite wraps *Client.SendTeamInvite with the breaker.
func (b *BreakingClient) SendTeamInvite(ctx context.Context, toEmail, teamName, acceptURL string) error {
	return b.SendTeamInviteWithKey(ctx, toEmail, "", teamName, acceptURL)
}

// SendTeamInviteWithKey wraps the keyed variant.
func (b *BreakingClient) SendTeamInviteWithKey(ctx context.Context, toEmail, idempotencyKey, teamName, acceptURL string) error {
	if !b.allow() {
		return ErrCircuitOpen
	}
	err := b.inner.SendTeamInviteWithKey(ctx, toEmail, idempotencyKey, teamName, acceptURL)
	b.record(err)
	return err
}

// SendDeletionConfirmation wraps *Client.SendDeletionConfirmation with the
// breaker.
func (b *BreakingClient) SendDeletionConfirmation(ctx context.Context, toEmail, resourceLabel, link string, ttlMinutes int) error {
	return b.SendDeletionConfirmationWithKey(ctx, toEmail, "", resourceLabel, link, ttlMinutes)
}

// SendDeletionConfirmationWithKey wraps the keyed variant. The audit
// flagged deletion-confirm as the highest-stakes target (no redelivery
// safety net); the breaker here is what stops a Brevo outage from
// burning the customer's only chance to actually delete a resource.
func (b *BreakingClient) SendDeletionConfirmationWithKey(ctx context.Context, toEmail, idempotencyKey, resourceLabel, link string, ttlMinutes int) error {
	if !b.allow() {
		return ErrCircuitOpen
	}
	err := b.inner.SendDeletionConfirmationWithKey(ctx, toEmail, idempotencyKey, resourceLabel, link, ttlMinutes)
	b.record(err)
	return err
}

// SendMagicLink wraps *Client.SendMagicLink with the breaker. The
// magic-link path has its OWN separate breaker (the third-copy primitive
// in handlers/magic_link_circuit.go) — this method exists so a future
// consolidation (P3-3 follow-up from the audit) can drop the third copy
// without changing call sites. Today, callers should keep wiring
// SendMagicLink through the handlers-package circuitBreakingMailer; the
// BreakingClient version is here for symmetry / future use.
func (b *BreakingClient) SendMagicLink(ctx context.Context, toEmail, link string) error {
	if !b.allow() {
		return ErrCircuitOpen
	}
	err := b.inner.SendMagicLink(ctx, toEmail, link)
	b.record(err)
	return err
}

// Mailer is the structural interface satisfied by both *Client and
// *BreakingClient. Handlers depend on Mailer (NOT *Client) so a router
// constructor in main.go can swap in a *BreakingClient — wrapping the
// original *Client in a process-wide circuit breaker — without
// touching every handler.
//
// The interface lists ONLY the methods that handlers actually call. Adding
// a new Send* to *Client does not automatically widen this interface; the
// extension is intentional (each new send method is a fresh contract
// decision, e.g. "do we want it gated by the breaker?").
type Mailer interface {
	ProviderName() ProviderName
	SendPaymentFailed(ctx context.Context, to string, attemptCount int, nextAttemptDate *time.Time) error
	SendPaymentFailedWithKey(ctx context.Context, to, idempotencyKey string, attemptCount int, nextAttemptDate *time.Time) error
	SendPaymentSucceeded(ctx context.Context, to string, receipt PaymentReceipt) error
	SendPaymentSucceededWithKey(ctx context.Context, to, idempotencyKey string, receipt PaymentReceipt) error
	SendTeamInvite(ctx context.Context, toEmail, teamName, acceptURL string) error
	SendTeamInviteWithKey(ctx context.Context, toEmail, idempotencyKey, teamName, acceptURL string) error
	SendDeletionConfirmation(ctx context.Context, toEmail, resourceLabel, link string, ttlMinutes int) error
	SendDeletionConfirmationWithKey(ctx context.Context, toEmail, idempotencyKey, resourceLabel, link string, ttlMinutes int) error
	SendMagicLink(ctx context.Context, toEmail, link string) error
}

// Compile-time assertion: *Client and *BreakingClient both satisfy
// Mailer. If a future refactor drops a method from either, this check
// fails at `go build` rather than at runtime in a webhook handler.
var (
	_ Mailer = (*Client)(nil)
	_ Mailer = (*BreakingClient)(nil)
)
