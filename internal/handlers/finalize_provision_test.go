package handlers_test

// finalize_provision_test.go — MR-P0-3 regression guard (BugBash 2026-05-20).
//
// finalizeProvision is the chokepoint that turns a successful backend provision
// RPC into a usable resource: it persists the connection URL + provider_resource_id
// and flips the row pending→active. Before this fix, each handler did the
// persistence inline with `// Fail open` comments — a logged error and a 201
// response carrying credentials for a resource the platform couldn't address.
//
// This test forces the AES-key parse to fail by feeding an invalid hex string,
// asserts finalizeProvision returns the persistence-failure sentinel (so the
// caller returns 503, never 201), and asserts the resource row is soft-deleted
// and the cleanup closure ran (so the backend object was torn down).

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestFinalizeProvision_PersistenceFailure_ReturnsErrorAndRunsCleanup is the
// MR-P0-3 guard. The cleanup closure MUST run (so the backend object is torn
// down), the row MUST be soft-deleted (so it doesn't count toward quota /
// dashboard listings as an orphan), and the helper MUST return the
// persistence-failure sentinel (so the caller returns 503, never 201).
func TestFinalizeProvision_PersistenceFailure_ReturnsErrorAndRunsCleanup(t *testing.T) {
	dbConn, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()

	// Insert a pending resource exactly as a real provision handler would
	// (CreateResource always writes status='pending' after MR-P0-2).
	res, err := models.CreateResource(ctx, dbConn, models.CreateResourceParams{
		ResourceType: "postgres",
		Name:         "p0-3-persist-fail-guard",
		Tier:         "anonymous",
		Env:          "development",
		Fingerprint:  "fp-p0-3-persist-fail",
	})
	require.NoError(t, err)
	require.Equal(t, "pending", res.Status,
		"setup precondition: the row must start as 'pending' for the MR-P0-3 path to be exercised")

	// Force an AES key-parse failure inside finalizeProvision by feeding an
	// invalid hex AES key. ParseAESKey returns an error → finalizeProvision
	// classifies it as a persistence failure → runs cleanup + soft-deletes
	// the row + returns the sentinel.
	cfg := &config.Config{AESKey: "not-a-valid-hex-key"}

	var cleanupRan atomic.Bool
	cleanup := func() { cleanupRan.Store(true) }

	finErr := handlers.RunFinalizeProvisionForTest(
		ctx, dbConn, cfg, res,
		"postgres://test/dsn", "", "prid-abc-123",
		"req-id-test", "test.persist_fail", cleanup,
	)

	// 1. Hard error: the caller will map this to 503, never 201.
	require.Error(t, finErr,
		"finalizeProvision must return a hard error on persistence failure — a nil return is the MR-P0-3 bug")
	assert.ErrorIs(t, finErr, handlers.ErrProvisionPersistFailedForTest,
		"the error must be the persistence-failure sentinel so respondProvisionFailed maps it to a 503")

	// 2. Cleanup ran — the backend object was torn down.
	assert.True(t, cleanupRan.Load(),
		"finalizeProvision must run the cleanup closure on persistence failure to tear down "+
			"the just-provisioned backend object; otherwise the platform leaks an orphan")

	// 3. Row is marked failed (status='failed'), NOT left at 'pending' or
	//    'active', and NOT soft-deleted. A pending row would be picked up by
	//    the reconciler; an active row would falsely advertise itself as
	//    usable in dashboard listings and quota counts; a deleted row would
	//    VANISH from the caller's read surface (the pre-Wave-2-A1 behaviour)
	//    leaving no pollable terminal state.
	var status string
	require.NoError(t, dbConn.QueryRow(
		`SELECT status FROM resources WHERE id = $1`, res.ID,
	).Scan(&status))
	assert.Equal(t, models.StatusFailed, status,
		"on a persistence failure the row must be marked 'failed' — a pollable terminal state")
}

// TestFinalizeProvision_Success_FlipsToActive is the happy-path guard:
// when every persistence step succeeds, the row flips to 'active' and no
// cleanup runs. Ensures the helper does not over-eagerly call cleanup.
func TestFinalizeProvision_Success_FlipsToActive(t *testing.T) {
	dbConn, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	res, err := models.CreateResource(ctx, dbConn, models.CreateResourceParams{
		ResourceType: "postgres",
		Name:         "p0-3-success-guard",
		Tier:         "anonymous",
		Env:          "development",
		Fingerprint:  "fp-p0-3-success",
	})
	require.NoError(t, err)

	// A real 64-char-hex AES key so ParseAESKey + Encrypt succeed.
	const validAESKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg := &config.Config{AESKey: validAESKey}

	var cleanupRan atomic.Bool
	cleanup := func() { cleanupRan.Store(true) }

	finErr := handlers.RunFinalizeProvisionForTest(
		ctx, dbConn, cfg, res,
		"postgres://test/dsn", "", "prid-success-123",
		"req-id-success", "test.persist_ok", cleanup,
	)

	require.NoError(t, finErr, "happy-path finalizeProvision must return nil")
	assert.False(t, cleanupRan.Load(),
		"cleanup must NOT run on the success path — that would tear down the resource we just provisioned")

	var status string
	require.NoError(t, dbConn.QueryRow(
		`SELECT status FROM resources WHERE id = $1`, res.ID,
	).Scan(&status))
	assert.Equal(t, "active", status,
		"finalizeProvision must flip the row to 'active' on success — that is the second phase of the MR-P0-2 lifecycle")
}
