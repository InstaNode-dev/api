package email

// fail_open_metrics.go — P2 (CIRCUIT-RETRY-AUDIT-2026-05-20) visibility
// helpers. The email Client's sync send path documents two fail-open
// degrade paths: the suppression check (so a Postgres blip never
// swallows a sign-in link) and the idempotency ledger probe (same
// rationale for receipts/deletion-confirm). Both are correct calls, but
// the audit flagged them as silent — a Postgres brownout disables
// suppression for its duration with no operator-visible signal.
//
// Each helper increments instant_fail_open_events_total with a stable
// subsystem label so the "fail-open rate" alert can fire on a per-
// subsystem rate(). Helpers (not direct metrics imports inside email.go)
// because the email package's send path stays cleanly testable and the
// metrics import-site is single-file.

import (
	"instant.dev/internal/metrics"
)

// recordSuppressionFailOpen bumps the suppression-checker fail-open
// counter. Called once per IsSuppressed DB error.
func recordSuppressionFailOpen() {
	metrics.FailOpenEvents.WithLabelValues("email_suppression", "db_error").Inc()
}

// recordLedgerProbeFailOpen bumps the SendLedger.Sent fail-open counter.
// Called once per probe DB error.
func recordLedgerProbeFailOpen() {
	metrics.FailOpenEvents.WithLabelValues("email_ledger_probe", "db_error").Inc()
}
