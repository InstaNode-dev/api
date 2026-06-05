package handlers

// mb_to_bytes_internal_test.go — directly exercises the unexported mbToBytes
// helper. Lives in package handlers (not handlers_test) because the symbol is
// unexported.
//
// History: the unlimited (-1 → -1, "∞") path used to be covered by routing the
// team tier (whose storage limit was -1) through the HTTP usage handler in
// billing_usage_coverage_test.go. The strict-≥80%-margin tier redesign
// (2026-06-05) retired every real -1 storage limit to a finite cap, so that
// path can no longer be reached via any tier. The defensive "-1 → ∞" branch
// still ships (a negative value may arrive from non-storage limits such as
// provisions_per_day, or from a future tier), so it is exercised here with
// synthetic inputs instead.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMbToBytes_UnlimitedAndFinite(t *testing.T) {
	// Unlimited sentinel: any negative input renders -1 ("∞" on the dashboard).
	assert.Equal(t, int64(-1), mbToBytes(-1), "unlimited (-1) limit must serialise as -1")
	assert.Equal(t, int64(-1), mbToBytes(-9999), "any negative limit is treated as unlimited (-1)")

	// Finite conversions: MB → bytes (×1024×1024).
	assert.Equal(t, int64(0), mbToBytes(0))
	assert.Equal(t, int64(1024*1024), mbToBytes(1))
	// Team's new finite postgres cap (51200 MB = 50 GiB) — the value the
	// retired HTTP test wrongly expected as -1 now serialises as real bytes.
	assert.Equal(t, int64(51200)*1024*1024, mbToBytes(51200))
}
