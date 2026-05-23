package handlers

// export_provarms_test.go — test-only re-exports for the provisioning-arms
// coverage slice (db/cache/nosql/queue/queue_provider/storage/storage_presign/
// provision_helper/family_bulk_twin). Kept in a dedicated file (NOT the shared
// export_test.go) so concurrent coverage work on other handler files never
// collides on the same file. Go only compiles this in test builds.

import (
	"context"
	"database/sql"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/common/queueprovider"
	"instant.dev/internal/config"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
)

// BuildQueueProviderForTest re-exports the unexported buildQueueProvider so the
// external handlers_test package can drive its backend-selection branches
// (legacy_open fallback, nats-when-seed, explicit backend, Factory error)
// without standing up a real NATS server.
func BuildQueueProviderForTest(cfg *config.Config) (queueprovider.QueueCredentialProvider, error) {
	return buildQueueProvider(cfg)
}

// IsSafePresignKeyForTest re-exports isSafePresignKey.
func IsSafePresignKeyForTest(in string) bool { return isSafePresignKey(in) }

// SanitisePresignKeyForTest re-exports sanitisePresignKey.
func SanitisePresignKeyForTest(in string) string { return sanitisePresignKey(in) }

// MaskPresignTokenForAuditForTest re-exports maskPresignTokenForAudit.
func MaskPresignTokenForAuditForTest(token string) string { return maskPresignTokenForAudit(token) }

// MaskPresignKeyForAuditForTest re-exports maskPresignKeyForAudit.
func MaskPresignKeyForAuditForTest(key string) string { return maskPresignKeyForAudit(key) }

// ── decryptConnectionURL re-exports (one per handler) ───────────────────────
// Each handler carries its own fail-closed decryptConnectionURL whose
// AES-parse-error and Decrypt-error branches the dedup-path tests can't reach
// (the dedup path needs a successfully-provisioned + decryptable row first).
// These re-exports drive those two error branches directly with a bad AES key
// (parse error) and a garbage-but-parseable ciphertext (decrypt error).

func (h *DBHandler) DecryptConnectionURLForTest(enc, rid string) (string, bool) {
	return h.decryptConnectionURL(enc, rid)
}
func (h *CacheHandler) DecryptConnectionURLForTest(enc, rid string) (string, bool) {
	return h.decryptConnectionURL(enc, rid)
}
func (h *NoSQLHandler) DecryptConnectionURLForTest(enc, rid string) (string, bool) {
	return h.decryptConnectionURL(enc, rid)
}
func (h *QueueHandler) DecryptConnectionURLForTest(enc, rid string) (string, bool) {
	return h.decryptConnectionURL(enc, rid)
}
func (h *StorageHandler) DecryptStorageURLForTest(enc, rid string) (string, bool) {
	return h.decryptStorageURL(enc, rid)
}

// ── small pure-helper re-exports ────────────────────────────────────────────

// FormatDurationForTest re-exports formatDuration.
func FormatDurationForTest(d time.Duration) string { return formatDuration(d) }

// DecideStorageModeKindForTest re-exports StorageHandler.decideStorageMode and
// returns its (kind, reason) so the unavailable + capability branches can be
// asserted on the REAL handler (not just the stub mirror).
func (h *StorageHandler) DecideStorageModeKindForTest(tier string) (kind, reason string) {
	s := h.decideStorageMode(tier)
	return s.kind, s.reason
}

// SanitizeNameForRequestForTest re-exports sanitizeNameForRequest so the
// invalid-UTF8 (writes 400 invalid_name + ErrResponseWritten) and clean-name
// branches can be driven with a throwaway fiber.Ctx.
func SanitizeNameForRequestForTest(c *fiber.Ctx, name string) (string, error) {
	return sanitizeNameForRequest(c, name)
}

// SignStorageURLForTest re-exports StorageHandler.signStorageURL so the
// missing-config error branches (no bucket/endpoint, no master key) can be
// covered without a real S3 round-trip.
func (h *StorageHandler) SignStorageURLForTest(ctx context.Context, op, objectKey string, ttl time.Duration) (string, time.Time, error) {
	return h.signStorageURL(ctx, op, objectKey, ttl)
}

// FinalizeProvisionForTest re-exports provisionHelper.finalizeProvision (via
// the embedding DBHandler) so its persistence-failure branches — UpdateKeyPrefix
// failure, soft-delete-failure logging, audit-emit failure — can be driven with
// a closed DB without going through a full HTTP provision.
func (h *DBHandler) FinalizeProvisionForTest(ctx context.Context, resource *models.Resource, connectionURL, keyPrefix, prid, requestID, logPrefix string, cleanup func()) error {
	return h.finalizeProvision(ctx, resource, connectionURL, keyPrefix, prid, requestID, logPrefix, cleanup)
}

// EmitProvisionPersistenceFailedAuditForTest re-exports the audit emitter so the
// TeamID-valid branch + audit-store-error log branch can be driven directly.
func EmitProvisionPersistenceFailedAuditForTest(ctx context.Context, db *sql.DB, res *models.Resource, prid, requestID, logPrefix string) {
	emitProvisionPersistenceFailedAudit(ctx, db, res, prid, requestID, logPrefix)
}

// RequireNameForTest re-exports requireName so the invalid-format / too-long /
// name-normalisation branches can be driven with a throwaway fiber.Ctx.
func RequireNameForTest(c *fiber.Ctx, raw string) (string, error) { return requireName(c, raw) }

// CheckProvisionLimitForTest re-exports provisionHelper.checkProvisionLimit
// (via the embedding DBHandler) so the Redis-error branch can be driven with a
// closed redis client.
func (h *DBHandler) CheckProvisionLimitForTest(ctx context.Context, fp string) (bool, error) {
	return h.checkProvisionLimit(ctx, fp)
}

// MarkRecycleSeenForTest re-exports markRecycleSeen for the empty-fp early
// return + redis-error branches.
func (h *DBHandler) MarkRecycleSeenForTest(ctx context.Context, fp string) error {
	return h.markRecycleSeen(ctx, fp)
}

// RecycleSeenForTest re-exports recycleSeen (empty-fp + redis-error).
func (h *DBHandler) RecycleSeenForTest(ctx context.Context, fp string) (bool, error) {
	return h.recycleSeen(ctx, fp)
}

// FindParentsForTest re-exports BulkTwinHandler.findParents so the
// paused-skip / wrong-type-skip / already-a-twin-skip filters can be asserted
// against seeded rows.
func (h *BulkTwinHandler) FindParentsForTest(ctx context.Context, teamID uuid.UUID, sourceEnv string, typeFilter map[string]struct{}) ([]*models.Resource, error) {
	return h.findParents(ctx, teamID, sourceEnv, typeFilter)
}

// ResolveHeadroomForTest re-exports BulkTwinHandler.resolveHeadroom so the
// nil-hook default + negative-clamp branches can be covered.
func (h *BulkTwinHandler) ResolveHeadroomForTest(ctx context.Context, teamID uuid.UUID, resourceType string) int {
	return h.resolveHeadroom(ctx, teamID, resourceType)
}

// NewBulkTwinHandlerPanicsForTest invokes NewBulkTwinHandler with a nil
// sub-handler so the constructor's panic guard can be asserted with
// require.Panics.
func NewBulkTwinHandlerPanicsForTest(db *sql.DB, reg *plans.Registry) {
	_ = NewBulkTwinHandler(db, nil, nil, nil, reg)
}

// NullStrOrEmptyForTest re-exports nullStrOrEmpty.
func NullStrOrEmptyForTest(ns sql.NullString) string { return nullStrOrEmpty(ns) }

// IssueTenantCredsForTest re-exports QueueHandler.issueTenantCreds so the
// error branch (provider returns an error → metric + log + return err) can be
// driven directly: the legacy_open provider errors on an empty ResourceToken.
func (h *QueueHandler) IssueTenantCredsForTest(ctx context.Context, token, subjectPrefix string) (*queueprovider.TenantCreds, error) {
	return h.issueTenantCreds(ctx, token, subjectPrefix)
}

// DeprovisionBestEffortForTest re-exports deprovisionBestEffort so the
// nil-provClient no-op and unknown-resource-type early returns can be covered
// without a live provisioner.
func DeprovisionBestEffortForTest(ctx context.Context, pc *provisioner.Client, token, prid, resourceType, logPrefix string) {
	deprovisionBestEffort(ctx, pc, token, prid, resourceType, logPrefix)
}
