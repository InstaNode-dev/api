package handlers

// export_test.go — test-only exports of unexported symbols so external
// (handlers_test) tests can exercise package internals without making the
// surface area public. Go automatically only includes this file in test
// builds (file name suffix `_test.go`).

import (
	"context"
	"database/sql"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
)

// ErrProvisionPersistFailedForTest re-exports the persistence-failure sentinel
// for MR-P0-3 regression tests.
var ErrProvisionPersistFailedForTest = errProvisionPersistFailed

// RunFinalizeProvisionForTest invokes the unexported finalizeProvision helper
// with the supplied dependencies. Used by the MR-P0-3 regression test to
// assert that a persistence failure runs cleanup, soft-deletes the row, and
// returns the sentinel error — without making finalizeProvision part of the
// package's public surface.
func RunFinalizeProvisionForTest(
	ctx context.Context,
	dbConn *sql.DB,
	cfg *config.Config,
	res *models.Resource,
	connectionURL, keyPrefix, providerResourceID, requestID, logPrefix string,
	cleanup func(),
) error {
	helper := provisionHelper{db: dbConn, cfg: cfg}
	return helper.finalizeProvision(ctx, res, connectionURL, keyPrefix, providerResourceID, requestID, logPrefix, cleanup)
}
