package dbsafety

import (
	"context"
	"log/slog"
	"sync"
)

// AuditKindCustomerDBDirectDrop is the audit_log kind emitted before every
// drop that flows through the dev-fallback (PROVISIONER_ADDR-unset) providers.
// It is deliberately distinct from the worker/orphan-sweep teardown kinds:
// reaching this kind at all means the api itself acted as the customer-DB
// superuser, which in prod should NEVER happen. A single row of this kind in
// the prod audit_log is an operator-investigate signal, not routine activity.
// Operator-internal only — NOT wired into the customer email forwarder.
const AuditKindCustomerDBDirectDrop = "customer_db.direct_drop"

// auditEventMsg is the slog message the structured fallback line is logged
// under when no DB-backed sink is configured, so the event still reaches NR Log.
const auditEventMsg = "dbsafety.direct_drop"

// AuditSink persists one audit record for a sanctioned direct drop. The handler
// wires a *sql.DB-backed implementation via SetAuditSink; until then (and in
// unit tests of the providers) the default sink logs a structured slog line so
// the event is never silently lost.
//
// Emit MUST be best-effort and non-blocking-on-failure: an audit write failure
// must NEVER block (or fail) the deprovision. Implementations should bound
// their own context and swallow errors after logging them.
type AuditSink interface {
	Emit(ctx context.Context, rec AuditRecord)
}

// AuditRecord is the provider-agnostic payload an AuditSink persists.
type AuditRecord struct {
	// Kind is always AuditKindCustomerDBDirectDrop.
	Kind string
	// Provider is the resolved fallback path ("db.local" | "nosql.mongo").
	Provider string
	// Token / DatabaseName / UserName name the destroyed resources.
	Token        string
	DatabaseName string
	UserName     string
	// DSNHost is the bare host of the admin DSN (no credentials) — recorded so
	// an operator can see WHICH customer-DB host the api dropped against.
	DSNHost string
}

// sinkMu guards the package sink so SetAuditSink (wired once at startup) and
// emitAudit (called per-drop) don't race under -race.
var (
	sinkMu sync.RWMutex
	sink   AuditSink = slogSink{}
)

// SetAuditSink installs the audit sink the dev-fallback providers use. The
// handler calls this once at construction with a *sql.DB-backed writer. Passing
// nil resets to the structured-slog default (used by provider unit tests).
func SetAuditSink(s AuditSink) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	if s == nil {
		s = slogSink{}
	}
	sink = s
}

// emitAudit fires the configured sink for a vetted drop. Best-effort: it never
// returns an error and never blocks the caller on a sink failure.
func emitAudit(ctx context.Context, p DropParams) {
	sinkMu.RLock()
	s := sink
	sinkMu.RUnlock()
	s.Emit(ctx, AuditRecord{
		Kind:         AuditKindCustomerDBDirectDrop,
		Provider:     p.Provider,
		Token:        p.Token,
		DatabaseName: p.DatabaseName,
		UserName:     p.UserName,
		DSNHost:      HostFromDSN(p.DSNHost),
	})
}

// slogSink is the default AuditSink: it writes a structured slog line so the
// event reaches NR Log even when no DB-backed sink is wired (provider unit
// tests, or a degraded startup). It is intentionally NOT silent.
type slogSink struct{}

// Emit logs the direct-drop as a structured warning. WARN (not INFO): in prod
// this path should never execute, so any occurrence warrants attention.
func (slogSink) Emit(ctx context.Context, rec AuditRecord) {
	slog.WarnContext(ctx, auditEventMsg,
		"audit_kind", rec.Kind,
		"provider", rec.Provider,
		"token", rec.Token,
		"database", rec.DatabaseName,
		"user", rec.UserName,
		"dsn_host", rec.DSNHost,
	)
}
