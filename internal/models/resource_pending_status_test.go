package models_test

// resource_pending_status_test.go — MR-P0-2 regression guard (BugBash 2026-05-20).
//
// CreateResource must insert a row with status='pending', NOT the column DEFAULT
// 'active'. MarkResourceActive must flip the row to 'active' atomically. Together
// the two functions make the provisioner_reconciler's crash-recovery sweep
// (`WHERE status='pending'`) actually reachable — before this fix the sweep
// matched zero rows in prod because every CreateResource INSERT landed on the
// column DEFAULT 'active' immediately, hiding any api-crash-mid-provision orphan
// from the reconciler.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestCreateResource_InsertsPendingStatus is the load-bearing assertion: a
// fresh CreateResource row is 'pending', not 'active'. If this fails the
// crash-recovery subsystem (provisioner_reconciler + idx_resources_pending_sweep)
// has nothing to scan and the MR-P0-2 fix has regressed.
func TestCreateResource_InsertsPendingStatus(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	res, err := models.CreateResource(ctx, db, models.CreateResourceParams{
		ResourceType: "postgres",
		Name:         "p0-2-pending-guard",
		Tier:         "anonymous",
		Env:          "development",
		Fingerprint:  "fp-p0-2-pending",
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	// The Go struct already carries the status from the RETURNING clause —
	// belt-and-braces re-read straight from the DB column so a future change
	// to scanResource cannot mask a regression.
	assert.Equal(t, "pending", res.Status,
		"CreateResource must insert status='pending' (MR-P0-2 — crash-recovery key)")

	var dbStatus string
	require.NoError(t, db.QueryRow(
		`SELECT status FROM resources WHERE id = $1`, res.ID,
	).Scan(&dbStatus))
	assert.Equal(t, "pending", dbStatus,
		"DB row must be status='pending' so the provisioner_reconciler sweep can match it")

	// And: the row must NOT yet appear to consumers that filter status='active'
	// (e.g. fingerprint dedup, dashboard listing). The dedup helper returns
	// ErrResourceNotFound for a pending row.
	if _, err := models.GetActiveResourceByFingerprintType(
		ctx, db, "fp-p0-2-pending", "postgres", "development",
	); err == nil {
		t.Fatalf("GetActiveResourceByFingerprintType must NOT return a pending row — that would " +
			"leak a half-provisioned resource to a dedup caller")
	}
}

// TestMarkResourceActive_FlipsPendingToActive verifies the second phase:
// MarkResourceActive flips 'pending' → 'active' atomically and is idempotent
// against a double call.
func TestMarkResourceActive_FlipsPendingToActive(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	res, err := models.CreateResource(ctx, db, models.CreateResourceParams{
		ResourceType: "postgres",
		Name:         "p0-2-flip-guard",
		Tier:         "anonymous",
		Env:          "development",
		Fingerprint:  "fp-p0-2-flip",
	})
	require.NoError(t, err)

	// First flip: should succeed.
	require.NoError(t, models.MarkResourceActive(ctx, db, res.ID))

	var dbStatus string
	require.NoError(t, db.QueryRow(
		`SELECT status FROM resources WHERE id = $1`, res.ID,
	).Scan(&dbStatus))
	assert.Equal(t, "active", dbStatus, "MarkResourceActive must flip pending → active")

	// Second flip on an already-active row: must return ErrResourceNotPending
	// (the WHERE status='pending' guard matches zero rows). A second call is
	// not silently treated as a success — the caller would otherwise have no
	// way to detect a torn write.
	err = models.MarkResourceActive(ctx, db, res.ID)
	assert.ErrorIs(t, err, models.ErrResourceNotPending,
		"a second MarkResourceActive on an already-active row must return ErrResourceNotPending")
}
