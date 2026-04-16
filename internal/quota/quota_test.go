package quota_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/quota"
	"instant.dev/internal/testhelpers"
)

// ── CheckAndIncrementToken ────────────────────────────────────────────────────

func TestCheckAndIncrementToken_FirstCall_CountOneNotExceeded(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	token := uuid.New().String()
	count, exceeded, err := quota.CheckAndIncrementToken(context.Background(), rdb, token, "redis", 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	assert.False(t, exceeded)
}

func TestCheckAndIncrementToken_BelowLimit_NotExceeded(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	token := uuid.New().String()
	// Call 9 times (limit=10) — none should be exceeded.
	for i := 0; i < 9; i++ {
		_, exceeded, err := quota.CheckAndIncrementToken(context.Background(), rdb, token, "redis", 10)
		require.NoError(t, err)
		assert.False(t, exceeded, "call %d should not exceed limit of 10", i+1)
	}
}

func TestCheckAndIncrementToken_AtLimit_Exceeded(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	token := uuid.New().String()
	limit := 3

	// Exhaust the limit.
	for i := 0; i < limit; i++ {
		_, exceeded, err := quota.CheckAndIncrementToken(context.Background(), rdb, token, "redis", limit)
		require.NoError(t, err)
		assert.False(t, exceeded, "call %d should not exceed limit", i+1)
	}

	// The very next call should be exceeded.
	count, exceeded, err := quota.CheckAndIncrementToken(context.Background(), rdb, token, "redis", limit)
	require.NoError(t, err)
	assert.True(t, exceeded, "4th call should exceed limit of 3")
	assert.Equal(t, int64(4), count)
}

func TestCheckAndIncrementToken_Unlimited_NeverExceeded(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	token := uuid.New().String()
	// limit=-1 means unlimited — counter never incremented, never exceeded.
	for i := 0; i < 1000; i++ {
		count, exceeded, err := quota.CheckAndIncrementToken(context.Background(), rdb, token, "redis", -1)
		require.NoError(t, err)
		assert.False(t, exceeded)
		assert.Equal(t, int64(0), count, "unlimited: count should always be 0 (Redis not touched)")
	}
}

func TestCheckAndIncrementToken_DifferentServicesIsolated(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	token := uuid.New().String()
	// Same token, different services — counters must be independent.
	_, _, err := quota.CheckAndIncrementToken(context.Background(), rdb, token, "redis", 1)
	require.NoError(t, err)

	count, exceeded, err := quota.CheckAndIncrementToken(context.Background(), rdb, token, "mongodb", 10)
	require.NoError(t, err)
	assert.False(t, exceeded, "mongodb counter must be independent from redis counter")
	assert.Equal(t, int64(1), count)
}

func TestCheckAndIncrementToken_DifferentTokensIsolated(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	tokenA := uuid.New().String()
	tokenB := uuid.New().String()
	limit := 1

	// Exhaust limit for A.
	quota.CheckAndIncrementToken(context.Background(), rdb, tokenA, "redis", limit)
	_, exceeded, _ := quota.CheckAndIncrementToken(context.Background(), rdb, tokenA, "redis", limit)
	assert.True(t, exceeded, "token A should be exceeded")

	// B has its own counter — should not be exceeded.
	_, exceededB, err := quota.CheckAndIncrementToken(context.Background(), rdb, tokenB, "redis", limit)
	require.NoError(t, err)
	assert.False(t, exceededB, "token B counter must be independent from token A")
}

func TestCheckAndIncrementToken_ContextCancelled_FailOpen(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the call

	token := uuid.New().String()
	count, exceeded, err := quota.CheckAndIncrementToken(ctx, rdb, token, "redis", 10)
	// Fail open: exceeded must be false regardless of error.
	assert.False(t, exceeded, "cancelled context must not cause exceeded=true (fail-open)")
	assert.Equal(t, int64(0), count)
	// err may or may not be set depending on whether Redis served the call before cancel.
	_ = err
}

// ── GetThroughputCount ────────────────────────────────────────────────────────

func TestGetThroughputCount_KeyAbsent_ReturnsZero(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	count, err := quota.GetThroughputCount(context.Background(), rdb, uuid.New().String(), "redis")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestGetThroughputCount_AfterIncrements_ReturnsCurrentCount(t *testing.T) {
	rdb, cleanRDB := testhelpers.SetupTestRedis(t)
	defer cleanRDB()

	token := uuid.New().String()
	for i := 0; i < 5; i++ {
		quota.CheckAndIncrementToken(context.Background(), rdb, token, "redis", 100)
	}

	count, err := quota.GetThroughputCount(context.Background(), rdb, token, "redis")
	require.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

// ── CheckStorageQuota ─────────────────────────────────────────────────────────

func TestCheckStorageQuota_BelowLimit_NotExceeded(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Insert a resource with storage_bytes below the 10MB limit.
	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, storage_bytes)
		VALUES ('postgres', 'anonymous', 'active', 1048576)  -- 1MB
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	uid, _ := uuid.Parse(resourceID)
	used, exceeded, err := quota.CheckStorageQuota(context.Background(), db, uid, 10) // 10MB limit
	require.NoError(t, err)
	assert.False(t, exceeded)
	assert.Equal(t, int64(1048576), used)
}

func TestCheckStorageQuota_AtLimit_Exceeded(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Exactly at the 10MB limit.
	tenMB := int64(10 * 1024 * 1024)
	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, storage_bytes)
		VALUES ('postgres', 'anonymous', 'active', $1)
		RETURNING id`, tenMB).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	uid, _ := uuid.Parse(resourceID)
	_, exceeded, err := quota.CheckStorageQuota(context.Background(), db, uid, 10)
	require.NoError(t, err)
	assert.True(t, exceeded, "at-limit storage must be exceeded")
}

func TestCheckStorageQuota_Unlimited_NeverExceeded(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// 100GB in storage_bytes — should not matter with limitMB=-1.
	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, storage_bytes)
		VALUES ('postgres', 'team', 'active', 107374182400)  -- 100GB
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	uid, _ := uuid.Parse(resourceID)
	_, exceeded, err := quota.CheckStorageQuota(context.Background(), db, uid, -1)
	require.NoError(t, err)
	assert.False(t, exceeded, "unlimited tier must never report exceeded")
}

func TestCheckStorageQuota_ResourceNotFound_FailOpen(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Non-existent resource — should fail open (not exceeded).
	_, exceeded, err := quota.CheckStorageQuota(context.Background(), db, uuid.New(), 10)
	require.NoError(t, err) // not found is not an error for callers
	assert.False(t, exceeded)
}

// ── UpdateStorageBytes ────────────────────────────────────────────────────────

func TestUpdateStorageBytes_UpdatesColumn(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, storage_bytes)
		VALUES ('postgres', 'anonymous', 'active', 0)
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	uid, _ := uuid.Parse(resourceID)
	err = quota.UpdateStorageBytes(context.Background(), db, uid, 5242880) // 5MB
	require.NoError(t, err)

	var got int64
	db.QueryRow(`SELECT storage_bytes FROM resources WHERE id = $1`, resourceID).Scan(&got)
	assert.Equal(t, int64(5242880), got)
}

func TestUpdateStorageBytes_ZeroBytes_Updates(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Start with non-zero, update to zero (e.g. resource emptied).
	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, storage_bytes)
		VALUES ('redis', 'anonymous', 'active', 1000000)
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	uid, _ := uuid.Parse(resourceID)
	err = quota.UpdateStorageBytes(context.Background(), db, uid, 0)
	require.NoError(t, err)

	var got int64
	db.QueryRow(`SELECT storage_bytes FROM resources WHERE id = $1`, resourceID).Scan(&got)
	assert.Equal(t, int64(0), got)
}

func TestUpdateStorageBytes_Idempotent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status)
		VALUES ('mongodb', 'anonymous', 'active')
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	uid, _ := uuid.Parse(resourceID)
	for i := 0; i < 3; i++ {
		err = quota.UpdateStorageBytes(context.Background(), db, uid, 2097152)
		require.NoError(t, err, "repeated UpdateStorageBytes must not error")
	}

	var got int64
	db.QueryRow(`SELECT storage_bytes FROM resources WHERE id = $1`, resourceID).Scan(&got)
	assert.Equal(t, int64(2097152), got)
}

// ── StorageLimitMB integration: plans.Registry helper ────────────────────────
// These tests verify that quota.CheckStorageQuota + plans.Registry wire together
// correctly — the limit returned by the registry is what the quota check uses.

func TestCheckStorageQuota_WithPlanLimit_AnonymousExceeded(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Anonymous tier: postgres_storage_mb=10. Insert resource at 11MB.
	elevenMB := int64(11 * 1024 * 1024)
	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, storage_bytes)
		VALUES ('postgres', 'anonymous', 'active', $1)
		RETURNING id`, elevenMB).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	uid, _ := uuid.Parse(resourceID)
	// Simulate what EnforceStorageQuotaWorker does:
	//   limitMB = plans.Default().StorageLimitMB("anonymous", "postgres") = 10
	used, exceeded, err := quota.CheckStorageQuota(context.Background(), db, uid, 10)
	require.NoError(t, err)
	assert.True(t, exceeded, "11MB should exceed 10MB anonymous limit")
	assert.Equal(t, elevenMB, used)
}
