package handlers

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"instant.dev/internal/quota"
)

// checkStorageQuota is a package-level indirection over quota.CheckStorageQuota
// so coverage tests can force the StorageExceeded warning arms of the
// provisioning handlers (db.go / cache.go / nosql.go). Those arms are otherwise
// only reachable when a freshly-provisioned resource already exceeds its tier's
// storage_mb cap — a state that cannot be set up before the resource exists.
// The var defaults to quota.CheckStorageQuota; production behaviour is
// byte-for-byte identical.
var checkStorageQuota = quota.CheckStorageQuota

// checkStorageQuotaSig documents the seam's signature for readers; it mirrors
// quota.CheckStorageQuota exactly.
//
//	func(ctx context.Context, db *sql.DB, resourceID uuid.UUID, limitMB int) (bytesUsed int64, exceeded bool, err error)
var _ func(context.Context, *sql.DB, uuid.UUID, int) (int64, bool, error) = checkStorageQuota
