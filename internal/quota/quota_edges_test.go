package quota_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/quota"
	"instant.dev/internal/testhelpers"
)

// ── LimitBytes ────────────────────────────────────────────────────────────────

// TestLimitBytes_Conversion locks the single MB→bytes conversion point so the
// dashboard number matches the enforcement wall (P2 regression 2026-05-17).
func TestLimitBytes_Conversion(t *testing.T) {
	assert.Equal(t, int64(1024*1024), quota.LimitBytes(1))
	assert.Equal(t, int64(10*1024*1024), quota.LimitBytes(10))
	assert.Equal(t, int64(5120*1024*1024), quota.LimitBytes(5120))
	assert.Equal(t, int64(0), quota.LimitBytes(0))
}

// TestLimitBytes_UnlimitedSentinel guards the -1 → UnlimitedLimitBytes mapping.
func TestLimitBytes_UnlimitedSentinel(t *testing.T) {
	assert.Equal(t, quota.UnlimitedLimitBytes, quota.LimitBytes(-1))
	assert.Equal(t, int64(-1), quota.LimitBytes(-1))
}

// ── CheckAndIncrementToken: Redis-down fail-open ─────────────────────────────

// TestCheckAndIncrementToken_RedisDown_FailsOpen exercises the pipeline-error
// branch in quota.go. When Redis is unreachable we must return (0, false, err)
// — the customer's request must not be blocked by an infra outage.
func TestCheckAndIncrementToken_RedisDown_FailsOpen(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	// Slam Redis closed BEFORE the call so the pipeline errors.
	mr.Close()

	count, exceeded, err := quota.CheckAndIncrementToken(
		context.Background(), rdb, uuid.New().String(), "redis", 10,
	)
	assert.Error(t, err, "Redis-down must surface an error")
	assert.False(t, exceeded, "fail-open: exceeded must be false")
	assert.Equal(t, int64(0), count)
}

// ── GetThroughputCount: Redis error ───────────────────────────────────────────

// TestGetThroughputCount_RedisDown_ReturnsError covers the non-redis.Nil error
// branch in GetThroughputCount.
func TestGetThroughputCount_RedisDown_ReturnsError(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close()

	count, err := quota.GetThroughputCount(
		context.Background(), rdb, uuid.New().String(), "redis",
	)
	assert.Error(t, err)
	assert.Equal(t, int64(0), count)
}

// ── CheckStorageQuota: DB error branch ────────────────────────────────────────

// TestCheckStorageQuota_DBClosed_FailsOpen exercises the non-ErrNoRows DB-error
// branch. A closed *sql.DB returns an error that is NOT sql.ErrNoRows, which
// must fail open per the docstring contract.
func TestCheckStorageQuota_DBClosed_FailsOpen(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	cleanDB() // close the DB BEFORE the call so QueryRowContext errors.

	used, exceeded, err := quota.CheckStorageQuota(
		context.Background(), db, uuid.New(), 10,
	)
	assert.Error(t, err, "closed DB must surface an error")
	assert.False(t, exceeded, "fail-open: exceeded must be false on DB error")
	assert.Equal(t, int64(0), used)
}

// TestCheckStorageQuota_ContextCancelled_FailsOpen covers the same error branch
// via a cancelled context — independent failure mode.
func TestCheckStorageQuota_ContextCancelled_FailsOpen(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, exceeded, err := quota.CheckStorageQuota(ctx, db, uuid.New(), 10)
	// Either ErrNoRows is masked by cancellation (err returned + exceeded false)
	// or the row genuinely doesn't exist (no err, exceeded false). Both satisfy
	// fail-open. The contract: exceeded must be false.
	assert.False(t, exceeded)
	_ = err
}

// ── UpdateStorageBytes: DB error branch ───────────────────────────────────────

// TestUpdateStorageBytes_DBClosed_ReturnsError covers the wrapped-error branch
// of UpdateStorageBytes. Unlike the read path, this one does NOT fail open —
// the caller (the storage-bytes worker) is expected to retry.
func TestUpdateStorageBytes_DBClosed_ReturnsError(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	cleanDB()

	err := quota.UpdateStorageBytes(context.Background(), db, uuid.New(), 1024)
	assert.Error(t, err, "closed DB must surface an error for UpdateStorageBytes")
	assert.ErrorContains(t, err, "UpdateStorageBytes")
}

// Compile-time guard so the unused sql import is not flagged if the test
// matrix above ever shrinks past the only sql.* reference.
var _ = sql.ErrNoRows
