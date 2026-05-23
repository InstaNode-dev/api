package handlers_test

// finalize_provision_provarms_test.go — covers the persistence-failure branches
// of finalizeProvision (provision_helper.go) and emitProvisionPersistenceFailed-
// Audit that the happy-path provisions never reach:
//   - UpdateKeyPrefix failure (closed DB) → persistFailed → cleanup runs
//   - SoftDeleteResource failure logging (closed DB) → logged + swallowed
//   - audit emit failure (closed DB) → logged + swallowed
//   - TeamID.Valid branch in the audit emitter

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func closedPlatformDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("postgres", testDSN())
	require.NoError(t, err)
	require.NoError(t, d.Close())
	return d
}

// finalizeProvision with a CLOSED DB + keyPrefix set: UpdateKeyPrefix fails →
// persistFailed → cleanup closure runs, SoftDeleteResource fails (logged), audit
// emit fails (logged) → returns the persistence-failed sentinel.
func TestFinalizeProvision_KeyPrefixUpdateFailure_RunsCleanup(t *testing.T) {
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "redis"}
	h := handlers.NewDBHandler(closedPlatformDB(t), nil, cfg, nil, plans.Default())

	res := &models.Resource{
		ID:           uuid.New(),
		TeamID:       uuid.NullUUID{UUID: uuid.New(), Valid: true},
		ResourceType: "redis",
		Tier:         "pro",
		Env:          "development",
	}
	cleanupRan := false
	err := h.FinalizeProvisionForTest(context.Background(), res,
		"redis://user:pw@host:6379", "kp_abc", "prid-1", "req-1", "cache.new",
		func() { cleanupRan = true })

	require.Error(t, err, "closed DB must surface a persistence failure")
	assert.True(t, cleanupRan, "persistence failure must run the cleanup closure")
}

// finalizeProvision with a CLOSED DB, no keyPrefix, good AES: encrypt succeeds,
// UpdateConnectionURL fails → persistFailed → cleanup + soft-delete (fails,
// logged) + audit (fails, logged).
func TestFinalizeProvision_ConnURLUpdateFailure_RunsCleanup(t *testing.T) {
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "postgres"}
	h := handlers.NewDBHandler(closedPlatformDB(t), nil, cfg, nil, plans.Default())

	res := &models.Resource{
		ID:           uuid.New(),
		TeamID:       uuid.NullUUID{Valid: false}, // anonymous (no team) branch
		ResourceType: "postgres",
		Tier:         "anonymous",
		Env:          "development",
	}
	cleanupRan := false
	err := h.FinalizeProvisionForTest(context.Background(), res,
		"postgres://u:p@h:5432/db", "", "prid-2", "req-2", "db.new",
		func() { cleanupRan = true })
	require.Error(t, err)
	assert.True(t, cleanupRan)
}

// emitProvisionPersistenceFailedAudit directly: TeamID-valid branch + audit
// store error (closed DB) is logged and swallowed (no panic, returns void).
func TestEmitProvisionPersistenceFailedAudit_TeamIDValid_AuditError(t *testing.T) {
	res := &models.Resource{
		ID:           uuid.New(),
		TeamID:       uuid.NullUUID{UUID: uuid.New(), Valid: true},
		ResourceType: "storage",
		Tier:         "pro",
		Env:          "production",
	}
	// Closed DB → InsertAuditEvent errors → emitter logs + swallows.
	handlers.EmitProvisionPersistenceFailedAuditForTest(context.Background(),
		closedPlatformDB(t), res, "prid-3", "req-3", "storage.new")
}

// emitProvisionPersistenceFailedAudit with an anonymous (no-team) resource so
// the TeamID-invalid branch (teamID stays zero) runs.
func TestEmitProvisionPersistenceFailedAudit_NoTeam(t *testing.T) {
	res := &models.Resource{
		ID:           uuid.New(),
		TeamID:       uuid.NullUUID{Valid: false},
		ResourceType: "postgres",
		Tier:         "anonymous",
		Env:          "development",
	}
	handlers.EmitProvisionPersistenceFailedAuditForTest(context.Background(),
		closedPlatformDB(t), res, "prid-4", "req-4", "db.new")
}
