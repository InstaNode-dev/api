package handlers_test

// promote_audit_final3_test.go — FINAL serial pass #3. Drives the
// InsertAuditEvent-error arm of emitPromoteAuditEvent (promote_approval.go:517)
// via the exporter + a fault DB. Best-effort audit: the warn arm runs without
// surfacing to the caller.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
)

func TestPromoteAuditFinal3_InsertError(t *testing.T) {
	faultDB := openFaultDB(t, 0) // the audit INSERT is the first (and only) DB call
	row := &models.PromoteApproval{
		ID:               uuid.New(),
		TeamID:           uuid.New(),
		RequestedByEmail: "ops@example.com",
		PromoteKind:      "stack",
		FromEnv:          "staging",
		ToEnv:            "production",
		Status:           "approved",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	// Should not panic / surface — the InsertAuditEvent error is logged + swallowed.
	handlers.EmitPromoteAuditEventForTest(context.Background(), faultDB, row,
		"promote.approved", "promote approved", map[string]any{"extra": "v"})
}
