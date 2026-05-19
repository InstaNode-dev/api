package models

// email_events.go — read/write surface for the email_events table.
//
// Two callers today: handlers/email_webhooks.go inserts on every provider
// callback, worker/internal/jobs/event_email_forwarder.go calls
// HasSuppressionFor before every send. The query shape is tuned for the
// suppression path — it's the hot one (every send-attempt hits it) and
// it must use idx_email_events_email_type as a covering index scan.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// EmailEventProvider enumerates the providers we accept webhooks from today.
// Strings — not enums — because the DB column is TEXT and downstream
// dashboards filter on the raw string. Keep these in sync with the CHECK
// list operators add via psql when querying ad-hoc.
const (
	EmailEventProviderBrevo     = "brevo"
	EmailEventProviderSES       = "ses"
	EmailEventProviderSendGrid  = "sendgrid"
)

// EmailEventType enumerates the normalized event categories. Provider-specific
// shapes collapse to these four. Soft bounces are kept separate from hard
// bounces because the suppression rule deliberately excludes them — a soft
// bounce (mailbox full, greylisted) shouldn't permanently silence a user.
const (
	EmailEventTypeBounce         = "bounce"          // hard bounce — permanent failure
	EmailEventTypeUnsubscribe    = "unsubscribe"     // user clicked unsubscribe
	EmailEventTypeSpamComplaint  = "spam_complaint"  // user marked as spam
	EmailEventTypeSoftBounce     = "soft_bounce"     // transient failure, retryable
)

// SuppressionEventTypes is the set of event_type values that cause the
// worker forwarder to skip future sends to that address. Hard bounces,
// unsubscribes, and spam complaints — soft bounces deliberately omitted
// (see EmailEventTypeSoftBounce comment).
//
// Exported so the worker reads the same canonical list the model writes.
var SuppressionEventTypes = []string{
	EmailEventTypeBounce,
	EmailEventTypeUnsubscribe,
	EmailEventTypeSpamComplaint,
}

// SuppressionWindow is how far back we look for a suppression row. Bounces
// and complaints decay after a year (the address may have been fixed, the
// user may have moved). Unsubscribes do NOT decay — see HasSuppressionFor
// for the carve-out.
const SuppressionWindow = 365 * 24 * time.Hour

// EmailEvent is the row shape. raw is held as a json.RawMessage so callers
// don't have to re-marshal when echoing the provider payload back into the
// table on insert.
type EmailEvent struct {
	ID         uuid.UUID
	Provider   string
	EventType  string
	Email      string
	Reason     sql.NullString
	Raw        json.RawMessage
	CreatedAt  time.Time
}

// InsertEmailEvent appends a row to email_events. The (provider, event_type,
// email, raw->>'message_id') partial-UNIQUE index dedupes provider retries
// silently — ON CONFLICT DO NOTHING means a redelivered webhook is a no-op
// instead of an error.
//
// Returns the inserted row id; on conflict (already inserted), returns
// uuid.Nil and a nil error so the caller can return 200 without surfacing
// the duplicate to the provider (which would then retry harder).
func InsertEmailEvent(ctx context.Context, db *sql.DB, provider, eventType, emailAddr, reason string, raw json.RawMessage) (uuid.UUID, error) {
	if provider == "" || eventType == "" || emailAddr == "" {
		return uuid.Nil, errors.New("models.InsertEmailEvent: provider, event_type, email all required")
	}
	if len(raw) == 0 {
		// JSONB column is NOT NULL; an empty payload is a programmer bug,
		// not a runtime fallback case. The webhook handler always has the
		// raw body in hand.
		return uuid.Nil, errors.New("models.InsertEmailEvent: raw payload required")
	}

	var reasonArg interface{}
	if reason != "" {
		reasonArg = reason
	} else {
		reasonArg = nil
	}

	var id uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO email_events (provider, event_type, email, reason, raw)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (provider, event_type, email, (raw->>'message_id'))
		WHERE raw->>'message_id' IS NOT NULL
		DO NOTHING
		RETURNING id
	`, provider, eventType, emailAddr, reasonArg, []byte(raw)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		// Conflict path: row already exists. Surface as (Nil, nil) so the
		// caller can return 200 without retrying.
		return uuid.Nil, nil
	}
	if err != nil {
		// Some Postgres versions choke on the WHERE-clause form of ON CONFLICT.
		// pq surfaces the syntax error via a *pq.Error; the caller has no
		// graceful fallback, so we bubble it up verbatim.
		return uuid.Nil, fmt.Errorf("models.InsertEmailEvent: %w", err)
	}
	return id, nil
}

// HasSuppressionFor reports whether the given email address has a
// suppression event recorded within the lookback window. The lookback is
// the SuppressionWindow constant (365d) for bounces + spam complaints,
// but unsubscribes are checked against a separate "any time" lookup so
// they never decay — once a user has unsubscribed we stay unsubscribed
// until they explicitly re-opt-in.
//
// Two queries fired in series rather than one OR'd query so the planner
// uses idx_email_events_email_type as a clean range scan on each. A
// combined query with both lookback semantics in one WHERE clause forces
// a bitmap-or that loses the index.
//
// Returns (true, nil) on first match, (false, nil) when no suppression
// row exists, and (false, err) on a DB error. Callers in the forwarder
// fail-open: a DB error returns false so a Postgres blip doesn't pin the
// queue or block sends.
func HasSuppressionFor(ctx context.Context, db *sql.DB, emailAddr string) (bool, error) {
	if emailAddr == "" {
		return false, nil
	}

	// Path 1: unsubscribes — no decay window. Index range scan: email +
	// event_type='unsubscribe' is a single point lookup in the composite.
	var found int
	err := db.QueryRowContext(ctx, `
		SELECT 1
		FROM email_events
		WHERE email = $1 AND event_type = $2
		LIMIT 1
	`, emailAddr, EmailEventTypeUnsubscribe).Scan(&found)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("models.HasSuppressionFor unsubscribe: %w", err)
	}

	// Path 2: bounces + spam complaints — 365d decay window. The decay
	// gives a previously-bouncing address a chance to come back; an
	// unsubscribe deliberately doesn't decay.
	decayCutoff := time.Now().UTC().Add(-SuppressionWindow)
	decayTypes := []string{EmailEventTypeBounce, EmailEventTypeSpamComplaint}
	err = db.QueryRowContext(ctx, `
		SELECT 1
		FROM email_events
		WHERE email = $1
		  AND event_type = ANY($2::text[])
		  AND created_at > $3
		LIMIT 1
	`, emailAddr, pq.Array(decayTypes), decayCutoff).Scan(&found)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, fmt.Errorf("models.HasSuppressionFor decay: %w", err)
}

// Email-send dedup-kind labels. Stored in email_send_dedup.email_kind for
// operator-side filtering ("how many receipts vs dunning sends today").
const (
	EmailSendKindReceipt = "receipt" // payment-success receipt (C4)
	EmailSendKindDunning = "dunning" // payment-failed dunning notice (C5)
)

// ClaimEmailSend attempts to claim a one-time email send for dedupKey.
//
// EMAIL-BUGBASH C4/C5: Razorpay fires DISTINCT events for one billing cycle
// (subscription.activated + subscription.charged → receipt; payment.failed
// + subscription.pending → dunning). Each event has its own event_id so the
// razorpay_webhook_events replay guard does not collapse them. ClaimEmailSend
// collapses them at the email layer: the caller builds a dedupKey that is
// stable across both events of a cycle, calls ClaimEmailSend, and only sends
// the email when this returns (true, nil).
//
// Returns:
//   - (true,  nil) — this caller inserted the row; it OWNS the send.
//   - (false, nil) — the row already existed; another event of the same
//     cycle already sent (or is sending) the email — caller MUST skip.
//   - (false, err) — DB error. The caller decides: a fail-OPEN caller may
//     send anyway (better a rare duplicate than a missed receipt); a
//     fail-CLOSED caller skips. sendPaymentReceipt / dunning fail open.
//
// Idempotent: a webhook redelivery re-attempts the same key and gets
// (false, nil) — no duplicate email.
func ClaimEmailSend(ctx context.Context, db *sql.DB, dedupKey, emailKind string) (bool, error) {
	if db == nil {
		// No DB — degrade to "always send" (the historical behaviour
		// before the dedup ledger existed). A nil DB only happens in unit
		// tests that don't exercise dedup.
		return true, nil
	}
	if strings.TrimSpace(dedupKey) == "" {
		// No stable key to dedup on — fall back to always-send rather than
		// claiming an empty key that would collide across unrelated cycles.
		return true, nil
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO email_send_dedup (dedup_key, email_kind)
		VALUES ($1, $2)
		ON CONFLICT (dedup_key) DO NOTHING
	`, dedupKey, emailKind)
	if err != nil {
		return false, fmt.Errorf("models.ClaimEmailSend: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecentAuditEventExists reports whether an audit_log row of the given kind
// exists for teamID created within the lookback window.
//
// EMAIL-BUGBASH F2: an admin demote emits subscription.canceled_by_admin AND
// triggers a Razorpay cancel that fires a subscription.cancelled webhook ->
// emitSubscriptionCanceledAudit -> a second customer-facing cancellation
// email. handleSubscriptionCancelled calls this before emitting its audit
// row: if a fresh subscription.canceled_by_admin row exists for the team,
// the admin-path email already covers the customer and the webhook path
// skips its emit, so the customer gets exactly one cancellation email.
func RecentAuditEventExists(ctx context.Context, db *sql.DB, teamID uuid.UUID, kind string, within time.Duration) (bool, error) {
	if db == nil || teamID == uuid.Nil || kind == "" {
		return false, nil
	}
	cutoff := time.Now().UTC().Add(-within)
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM audit_log
			 WHERE team_id = $1
			   AND kind = $2
			   AND created_at > $3
		)
	`, teamID, kind, cutoff).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("models.RecentAuditEventExists: %w", err)
	}
	return exists, nil
}

// SuppressionChecker is a DB-backed implementation of the structural
// interface the api's email.Client consults before every synchronous send
// (EMAIL-BUGBASH C3). It exists so the api's own sends (magic link, payment
// receipt, dunning, team invite, deletion confirm) respect the email_events
// suppression table — previously HasSuppressionFor had zero callers in api,
// only the worker forwarder used it, so a hard-bounced or unsubscribed
// address still received every api-originated email.
//
// It is deliberately a thin wrapper around HasSuppressionFor: one canonical
// suppression rule, used by both the worker forwarder and the api send path.
type SuppressionChecker struct {
	db *sql.DB
}

// NewSuppressionChecker returns a SuppressionChecker bound to db. A nil db
// yields a checker whose IsSuppressed always returns (false, nil) — i.e. a
// no-op that never suppresses — so test/bootstrap paths without a database
// degrade to "send everything" rather than panicking.
func NewSuppressionChecker(db *sql.DB) *SuppressionChecker {
	return &SuppressionChecker{db: db}
}

// IsSuppressed reports whether emailAddr has a recorded hard bounce,
// unsubscribe, or spam complaint within the suppression window. It satisfies
// the email.SuppressionChecker interface structurally (no import cycle:
// models does not import email).
//
// Fail-open contract: a DB error is returned as (false, err) so the email
// Client's send path can log it and proceed — a Postgres blip must never
// block a transactional email such as a sign-in link.
func (s *SuppressionChecker) IsSuppressed(ctx context.Context, emailAddr string) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	return HasSuppressionFor(ctx, s.db, emailAddr)
}
