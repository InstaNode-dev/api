package cache_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/cache"
)

// newMiniRedis returns a *redis.Client backed by an in-memory miniredis
// instance plus a cleanup func. Used everywhere we need a real-shaped
// Redis without a Docker container.
func newMiniRedis(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return rdb, func() {
		rdb.Close()
		mr.Close()
	}
}

type usagePayload struct {
	Postgres int64 `json:"postgres"`
	Redis    int64 `json:"redis"`
}

// TestGetOrSet_MissRunsFnOnceAndCaches verifies the basic Redis-miss path:
// the first call runs fn, the second call short-circuits to the cache.
func TestGetOrSet_MissRunsFnOnceAndCaches(t *testing.T) {
	rdb, cleanup := newMiniRedis(t)
	defer cleanup()

	var calls atomic.Int32
	fn := func(_ context.Context) (usagePayload, error) {
		calls.Add(1)
		return usagePayload{Postgres: 100, Redis: 50}, nil
	}

	ctx := context.Background()
	v1, err := cache.GetOrSet(ctx, rdb, "test:k1", 60*time.Second, fn)
	require.NoError(t, err)
	assert.Equal(t, usagePayload{Postgres: 100, Redis: 50}, v1)

	v2, err := cache.GetOrSet(ctx, rdb, "test:k1", 60*time.Second, fn)
	require.NoError(t, err)
	assert.Equal(t, usagePayload{Postgres: 100, Redis: 50}, v2)

	assert.Equal(t, int32(1), calls.Load(), "fn should have run exactly once across both calls")
}

// TestGetOrSet_SingleflightCollapsesConcurrentCallers — the headline §10.20
// guarantee: N concurrent identical requests collapse to 1 fn invocation.
// Without singleflight, N callers would race past the empty-cache check and
// all run fn before any of them got to SET. With singleflight, the leader
// runs fn and the followers receive its result.
func TestGetOrSet_SingleflightCollapsesConcurrentCallers(t *testing.T) {
	rdb, cleanup := newMiniRedis(t)
	defer cleanup()

	const concurrency = 20
	var calls atomic.Int32
	// gate holds fn open until every goroutine is in flight, so they all
	// observe the same "cache empty" snapshot. Without it the test races —
	// goroutine #N might run after goroutine #1 already set the cache.
	gate := make(chan struct{})
	fn := func(_ context.Context) (usagePayload, error) {
		<-gate
		calls.Add(1)
		// A small sleep makes the singleflight window visible — the leader
		// is still inside fn when followers arrive. Without it the timing
		// can occasionally let a follower miss the inflight entry.
		time.Sleep(20 * time.Millisecond)
		return usagePayload{Postgres: 42}, nil
	}

	ctx := context.Background()
	results := make(chan usagePayload, concurrency)
	errs := make(chan error, concurrency)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := cache.GetOrSet(ctx, rdb, "test:sf", 60*time.Second, fn)
			results <- v
			errs <- err
		}()
	}
	// Let every goroutine reach the gate before any of them runs fn.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	for v := range results {
		assert.Equal(t, usagePayload{Postgres: 42}, v)
	}
	assert.Equal(t, int32(1), calls.Load(), "singleflight should collapse %d concurrent callers to 1 fn invocation", concurrency)
}

// TestGetOrSet_RedisDownFailsOpen verifies that when Redis errors on GET,
// GetOrSet falls through to fn and returns its result. The cache being
// unreachable must never break the read path.
func TestGetOrSet_RedisDownFailsOpen(t *testing.T) {
	// Point at a closed port — the dial will fail fast.
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // reserved low port, refuses connections
		DialTimeout: 50 * time.Millisecond,
	})
	defer rdb.Close()

	var calls atomic.Int32
	fn := func(_ context.Context) (usagePayload, error) {
		calls.Add(1)
		return usagePayload{Postgres: 7}, nil
	}

	ctx := context.Background()
	v, err := cache.GetOrSet(ctx, rdb, "test:down", 60*time.Second, fn)
	require.NoError(t, err)
	assert.Equal(t, usagePayload{Postgres: 7}, v)
	assert.Equal(t, int32(1), calls.Load(), "fn must run when redis is down")

	// A second call must also reach fn — we bypass singleflight on the
	// Redis-down path to avoid hammering a flapping cache, and the cache
	// itself can't serve the entry. (See §10.20 fail-open contract.)
	v2, err := cache.GetOrSet(ctx, rdb, "test:down", 60*time.Second, fn)
	require.NoError(t, err)
	assert.Equal(t, usagePayload{Postgres: 7}, v2)
	assert.Equal(t, int32(2), calls.Load())
}

// TestGetOrSet_NilClientPassesThrough — a nil *redis.Client means "no cache
// configured"; GetOrSet should still call fn and return its result. Useful
// in tests and in dev configs where Redis isn't wired.
func TestGetOrSet_NilClientPassesThrough(t *testing.T) {
	var calls atomic.Int32
	fn := func(_ context.Context) (usagePayload, error) {
		calls.Add(1)
		return usagePayload{Postgres: 1}, nil
	}
	v, err := cache.GetOrSet(context.Background(), nil, "test:nil", 60*time.Second, fn)
	require.NoError(t, err)
	assert.Equal(t, usagePayload{Postgres: 1}, v)
	assert.Equal(t, int32(1), calls.Load())
}

// TestGetOrSet_FnErrorPropagates — a fn error must not be cached and must
// surface to the caller verbatim.
func TestGetOrSet_FnErrorPropagates(t *testing.T) {
	rdb, cleanup := newMiniRedis(t)
	defer cleanup()

	sentinel := errors.New("aggregate failed")
	fn := func(_ context.Context) (usagePayload, error) {
		return usagePayload{}, sentinel
	}

	_, err := cache.GetOrSet(context.Background(), rdb, "test:err", 60*time.Second, fn)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)

	// Confirm the cache was NOT populated.
	_, ferr := rdb.Get(context.Background(), "test:err").Bytes()
	assert.ErrorIs(t, ferr, redis.Nil)
}

// TestGetOrSet_ZeroValueCachesNegative — fn returning a zero-value T is a
// valid result (e.g. a team with no resources). It must still be cached so
// the next caller doesn't re-run the aggregate.
func TestGetOrSet_ZeroValueCachesNegative(t *testing.T) {
	rdb, cleanup := newMiniRedis(t)
	defer cleanup()

	var calls atomic.Int32
	fn := func(_ context.Context) (usagePayload, error) {
		calls.Add(1)
		return usagePayload{}, nil
	}
	ctx := context.Background()
	_, err := cache.GetOrSet(ctx, rdb, "test:empty", 60*time.Second, fn)
	require.NoError(t, err)
	_, err = cache.GetOrSet(ctx, rdb, "test:empty", 60*time.Second, fn)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load(), "zero-value results must still be cached")
}

// TestGetOrSet_CorruptCacheEntryFallsThrough — if a cache entry was
// serialised under an older shape, json.Unmarshal returns an error and
// GetOrSet treats it as a miss. The next SET heals the entry.
func TestGetOrSet_CorruptCacheEntryFallsThrough(t *testing.T) {
	rdb, cleanup := newMiniRedis(t)
	defer cleanup()

	// Plant a value that doesn't decode as usagePayload.
	require.NoError(t, rdb.Set(context.Background(), "test:corrupt", "not-json", time.Minute).Err())

	var calls atomic.Int32
	fn := func(_ context.Context) (usagePayload, error) {
		calls.Add(1)
		return usagePayload{Postgres: 999}, nil
	}
	v, err := cache.GetOrSet(context.Background(), rdb, "test:corrupt", time.Minute, fn)
	require.NoError(t, err)
	assert.Equal(t, usagePayload{Postgres: 999}, v)
	assert.Equal(t, int32(1), calls.Load())
}

// TestInvalidate_DeletesKey ensures Invalidate clears the cache and a nil
// client is a no-op.
func TestInvalidate_DeletesKey(t *testing.T) {
	rdb, cleanup := newMiniRedis(t)
	defer cleanup()

	fn := func(_ context.Context) (usagePayload, error) {
		return usagePayload{Postgres: 5}, nil
	}
	ctx := context.Background()
	_, err := cache.GetOrSet(ctx, rdb, "test:inv", time.Minute, fn)
	require.NoError(t, err)

	cache.Invalidate(ctx, rdb, "test:inv")
	_, err = rdb.Get(ctx, "test:inv").Bytes()
	assert.ErrorIs(t, err, redis.Nil)

	// nil client → no panic.
	cache.Invalidate(ctx, nil, "test:inv")
}
