package models

// dbsafety_audit_sink.go — the *sql.DB-backed audit sink for the dbsafety guard
// used by the dev-fallback (PROVISIONER_ADDR-unset) customer-data providers
// (internal/providers/db/local.go + internal/providers/nosql/mongo.go).
//
// dbsafety lives below the models layer and must not import it (that would pull
// the platform-DB stack into the provider packages and risk a cycle). So the
// audit emission is an injected seam: dbsafety calls its AuditSink interface;
// this file provides the production implementation that writes an audit_log row
// of kind customer_db.direct_drop via InsertAuditEvent.
//
// The sink is registered once at handler construction (the fallback path of
// NewDBHandler / NewNoSQLHandler / NewVectorHandler) via WireDBSafetyAuditSink.
// Writes are best-effort and bounded: an audit failure must NEVER block (or
// fail) a deprovision (audit_log.go's contract).

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"instant.dev/internal/providers/dbsafety"
	"instant.dev/internal/safego"
)

// dbSafetyAuditTimeout bounds the best-effort audit write so a stalled
// platform-DB never wedges (or delays) the deprovision goroutine.
const dbSafetyAuditTimeout = 3 * time.Second

// dbSafetyAuditSink persists one audit_log row of kind customer_db.direct_drop
// per sanctioned direct drop. It never blocks the caller — the row is written
// in a panic-safe, bounded-context goroutine.
type dbSafetyAuditSink struct {
	db *sql.DB
}

// WireDBSafetyAuditSink installs a *sql.DB-backed dbsafety audit sink. Called
// once from the fallback path of the provisioning handler constructors. A nil
// db (test config) leaves the structured-slog default sink in place so the
// event is still logged.
func WireDBSafetyAuditSink(db *sql.DB) {
	if db == nil {
		return
	}
	dbsafety.SetAuditSink(&dbSafetyAuditSink{db: db})
}

// Emit writes the audit_log row best-effort. The metadata captures the
// destroyed identifiers + the admin DSN host (never credentials) so an operator
// can reconstruct exactly what the api dropped, and where — even though layers
// 1+2 of the guard should make a prod drop unreachable.
func (s *dbSafetyAuditSink) Emit(_ context.Context, rec dbsafety.AuditRecord) {
	// json.Marshal of a fixed-shape map[string]string cannot error — the only
	// failure modes are unsupported types / cycles, neither of which a string
	// map has. A nil meta would be a strictly worse audit than the marshalled
	// one, which always succeeds here, so the error is intentionally dropped.
	meta, _ := json.Marshal(map[string]string{
		"provider": rec.Provider,
		"token":    rec.Token,
		"database": rec.DatabaseName,
		"user":     rec.UserName,
		"dsn_host": rec.DSNHost,
	})

	safego.Go("dbsafety.audit.emit", func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), dbSafetyAuditTimeout)
		defer cancel()
		ev := AuditEvent{
			Actor:    "system",
			Kind:     rec.Kind,
			Summary:  "direct customer-DB drop via dev-fallback provider",
			Metadata: meta,
		}
		if err := InsertAuditEvent(bgCtx, s.db, ev); err != nil {
			// Best-effort: a failed audit write must not surface anywhere.
			// Log loudly — a missing trail for THIS kind is itself notable.
			slog.WarnContext(bgCtx, "dbsafety_audit: InsertAuditEvent failed",
				"audit_kind", rec.Kind, "error", err)
		}
	})
}
