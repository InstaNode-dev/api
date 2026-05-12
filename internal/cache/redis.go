// Package cache wraps the Redis client with a typed GetOrSet helper that
// collapses concurrent identical requests via singleflight and fails open
// when Redis is unavailable.
//
// Designed for the §13 eventual-consistency surfaces (billing/usage,
// team/summary) where:
//
//   - The per-team aggregation is expensive enough that N concurrent
//     dashboard tabs should NOT trigger N DB scans — singleflight collapses
//     them to one in-process compute + one cache write.
//   - A Redis outage MUST NOT break the read endpoint (the underlying DB is
//     still authoritative). GetOrSet falls through to fn on every Redis
//     error so the user sees data, just without the cache amortisation.
//   - Hot-path callers prefer a typed result (struct, not []byte). The
//     generic `T any` parameter keeps callers off encoding/json directly.
//
// Real-time paths (POST /db/new quota checks, webhook handlers) MUST NOT
// use this helper — they read fresh per the §13 freshness matrix.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

// group is the per-process singleflight that collapses concurrent calls to
// GetOrSet sharing the same key. Keys live in one global namespace so callers
// must scope them (e.g. "billing:usage:" + teamID).
var group singleflight.Group

// GetOrSet returns the cached value for key when present and fresh.
//
// Miss path (cache empty or returns a NOT FOUND): runs fn under singleflight,
// stores the encoded result with TTL ttl, returns the result.
//
// Failure modes (intentional fail-open semantics):
//
//   - Redis GET errored — log + skip cache, run fn, return its result without
//     attempting another SET (the cache layer is currently broken; don't
//     hammer it). This matches the "Redis down → fall through" cell in the
//     §13 freshness matrix.
//   - JSON unmarshal of the cached value failed — treat as miss. Most likely
//     cause is a serialised value shape change across deploys; the next SET
//     after fn runs heals the cache entry.
//   - fn returned an error — propagate it without touching the cache.
//   - Redis SET errored on the way back — log + return the freshly-computed
//     value anyway. The next call will re-attempt the SET.
//
// Negative caching (fn returned a zero-value T) is allowed and uses the same
// ttl — callers that want a shorter negative TTL should branch outside.
func GetOrSet[T any](
	ctx context.Context,
	rdb *redis.Client,
	key string,
	ttl time.Duration,
	fn func(context.Context) (T, error),
) (T, error) {
	var zero T

	// Fast path: try the cache. A nil client means cache is disabled — go
	// straight to fn without using singleflight (no point — there's nothing
	// to collapse on).
	if rdb != nil {
		raw, err := rdb.Get(ctx, key).Bytes()
		switch {
		case err == nil:
			var out T
			if jerr := json.Unmarshal(raw, &out); jerr == nil {
				return out, nil
			}
			// Corrupt cache entry — treat as miss, log so the shape skew is
			// visible. Don't return the unmarshal error to the caller.
			slog.Warn("cache.get_unmarshal_failed", "key", key, "error", "json decode")
		case errors.Is(err, redis.Nil):
			// True miss — fall through to fn under singleflight.
		default:
			// Redis is unreachable / down. Fail open: run fn without the
			// cache wrapper and skip the SET path entirely so we don't
			// hammer a flapping Redis. Bypassing singleflight here means
			// N concurrent callers will all hit the DB during an outage,
			// which is acceptable — the cache being down IS the
			// degradation, the DB is the source of truth.
			slog.Warn("cache.get_failed_fail_open", "key", key, "error", err.Error())
			return fn(ctx)
		}
	}

	// Miss path: collapse concurrent callers to one fn invocation.
	//
	// singleflight returns (value, error, shared). We ignore `shared`; both
	// the leader and the followers see the same value+error pair. The leader
	// is the only one that touches Redis SET — followers piggyback on the
	// returned value.
	v, err, _ := group.Do(key, func() (interface{}, error) {
		out, fnErr := fn(ctx)
		if fnErr != nil {
			return out, fnErr
		}
		if rdb != nil {
			encoded, jerr := json.Marshal(out)
			if jerr != nil {
				// Encoding failure is a programmer error (T can't be
				// marshalled). Don't poison the cache; log + return the
				// value so the request still succeeds.
				slog.Warn("cache.set_marshal_failed", "key", key, "error", jerr.Error())
				return out, nil
			}
			if setErr := rdb.Set(ctx, key, encoded, ttl).Err(); setErr != nil {
				// Same fail-open as GET: log but return the value.
				slog.Warn("cache.set_failed", "key", key, "error", setErr.Error())
			}
		}
		return out, nil
	})

	if err != nil {
		return zero, err
	}
	// singleflight returns the leader's value via interface{}. The type
	// parameter T is the same for every caller of this key, so the assertion
	// is safe under normal use; a panic here would indicate two callers
	// using the same cache key with different T (a bug in caller code).
	out, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("cache.GetOrSet: type mismatch for key %q", key)
	}
	return out, nil
}

// Invalidate deletes a cache key. Use it from write paths that change the
// underlying aggregate (e.g. a deploy completing should invalidate
// billing:usage:<team>). A nil client is a no-op so callers can wire this
// in without conditional checks.
func Invalidate(ctx context.Context, rdb *redis.Client, key string) {
	if rdb == nil {
		return
	}
	if err := rdb.Del(ctx, key).Err(); err != nil {
		slog.Warn("cache.invalidate_failed", "key", key, "error", err.Error())
	}
}
