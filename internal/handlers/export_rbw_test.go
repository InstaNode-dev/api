package handlers

// export_rbw_test.go — re-exports for the resource/billing/webhook/onboarding/
// admin/readyz coverage slice (_rbw suffix). Kept separate from the shared
// export_test.go to avoid collisions with the concurrent provisioning-arm
// coverage work.

import (
	"context"
	"database/sql"

	"instant.dev/common/readiness"
)

// CustomerDBCheckForTest exposes the unexported customerDBCheck CheckFunc so a
// test can drive the empty-DSN defensive arm directly (the public path only
// wires the check when CustomerDatabaseURL != "").
func CustomerDBCheckForTest(h *ReadyzHandler) func(context.Context) readiness.CheckResult {
	fn := h.customerDBCheck()
	return func(ctx context.Context) readiness.CheckResult { return fn(ctx) }
}

// StatusToFloatForTest exposes statusToFloat for direct enum-walk coverage.
func StatusToFloatForTest(s readiness.Status) float64 { return statusToFloat(s) }

// SetReadyzSQLOpenForTest swaps the customer-DB sql.Open seam and returns a
// restore func.
func SetReadyzSQLOpenForTest(fn func(string, string) (*sql.DB, error)) (restore func()) {
	prev := readyzSQLOpen
	readyzSQLOpen = fn
	return func() { readyzSQLOpen = prev }
}
