// Package quota provides per-resource throughput and storage quota enforcement.
//
// Two control planes are implemented:
//
//  1. Throughput (Redis) — CheckAndIncrementToken atomically increments a daily
//     per-token counter and returns whether the limit is exceeded. Used inline in
//     request handlers (fail-open on Redis error, so a Redis outage never blocks
//     a customer's request).
//
//  2. Storage (Postgres) — CheckStorageQuota reads the resources.storage_bytes
//     column and compares it to the plan limit. The column is kept up-to-date by
//     the UpdateStorageBytesWorker River job. Fails closed on DB error (returns
//     exceeded=false) so a DB hiccup does not block writes.
//
// Redis key format:
//
//	throughput:{service}:{token}:{YYYY-MM-DD}   (25h TTL)
//
// Example:
//
//	exceeded, _ := quota.CheckAndIncrementToken(ctx, rdb, token, "redis", 1000)
//	if exceeded { /* return 429 / upgrade CTA */ }
package quota

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// BytesPerMB is the byte multiplier used everywhere the platform converts a
// plan's *_storage_mb limit into a byte ceiling. Storage limits are quoted in
// MiB (1 MB == 1024*1024 bytes) — NOT the SI 1_000_000. Enforcement
// (CheckStorageQuota) and every UI/serialiser path MUST use this constant so
// the number the dashboard shows is the number that actually trips the wall.
// P2 (2026-05-17): resourceToMap previously multiplied by 1_000_000, so a
// resource at exactly its MiB limit looked ~4.8% under the wall in the UI.
const BytesPerMB int64 = 1024 * 1024

// UnlimitedLimitBytes is the sentinel LimitBytes returns for an unlimited
// (-1 MB) tier. Callers render it as "unlimited" rather than a byte count.
const UnlimitedLimitBytes int64 = -1

// LimitBytes converts a plan storage limit in MiB to a byte ceiling.
// Returns UnlimitedLimitBytes (-1) for the unlimited sentinel; otherwise
// limitMB * BytesPerMB. The single conversion point for MB→bytes so the
// enforcement path and the serialisation path can never drift again.
func LimitBytes(limitMB int) int64 {
	if limitMB == -1 {
		return UnlimitedLimitBytes
	}
	return int64(limitMB) * BytesPerMB
}

// CheckAndIncrementToken atomically increments the daily throughput counter for
// the given token+service pair and reports whether the limit is exceeded.
//
// If limit == -1 the counter is not touched and exceeded is always false.
// Fails open on Redis error: returns (0, false, err) so callers can continue.
//
// The Redis key expires after 25 hours (handles timezone edge cases; each new
// UTC day produces a new key naturally).
func CheckAndIncrementToken(ctx context.Context, rdb *redis.Client, token, service string, limit int) (count int64, exceeded bool, err error) {
	if limit == -1 {
		return 0, false, nil
	}

	date := time.Now().UTC().Format("2006-01-02")
	key := fmt.Sprintf("throughput:%s:%s:%s", service, token, date)

	pipe := rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 25*time.Hour)

	if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
		slog.Error("quota.throughput.redis_error",
			"key", key,
			"error", pipeErr,
		)
		// Fail open — a Redis outage must never block a customer's request.
		return 0, false, fmt.Errorf("quota.CheckAndIncrementToken: redis pipeline: %w", pipeErr)
	}

	count, err = incrCmd.Result()
	if err != nil {
		slog.Error("quota.throughput.incr_result_error", "key", key, "error", err)
		return 0, false, fmt.Errorf("quota.CheckAndIncrementToken: incr result: %w", err)
	}

	return count, count > int64(limit), nil
}

// GetThroughputCount returns the current daily counter value for a token+service
// without incrementing it. Returns 0 if the key does not exist or Redis errors.
// Used for health checks and dashboards.
func GetThroughputCount(ctx context.Context, rdb *redis.Client, token, service string) (int64, error) {
	date := time.Now().UTC().Format("2006-01-02")
	key := fmt.Sprintf("throughput:%s:%s:%s", service, token, date)

	val, err := rdb.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("quota.GetThroughputCount: %w", err)
	}
	return val, nil
}

// CheckStorageQuota reads resources.storage_bytes for the given resource and
// compares it to limitMB.
//
// If limitMB == -1 the check is skipped and exceeded is always false.
// Fails open on DB error (returns exceeded=false) — a transient DB error must
// not block writes.
//
// Returns (bytesUsed, exceeded, error).
func CheckStorageQuota(ctx context.Context, db *sql.DB, resourceID uuid.UUID, limitMB int) (bytesUsed int64, exceeded bool, err error) {
	if limitMB == -1 {
		return 0, false, nil
	}

	err = db.QueryRowContext(ctx,
		`SELECT storage_bytes FROM resources WHERE id = $1`,
		resourceID,
	).Scan(&bytesUsed)
	if err == sql.ErrNoRows {
		return 0, false, nil // resource not found — not our problem here
	}
	if err != nil {
		slog.Error("quota.storage.db_error", "resource_id", resourceID, "error", err)
		// Fail open — a DB hiccup must not block customer writes.
		return 0, false, fmt.Errorf("quota.CheckStorageQuota: %w", err)
	}

	limitBytes := LimitBytes(limitMB)
	return bytesUsed, bytesUsed >= limitBytes, nil
}

// UpdateStorageBytes sets resources.storage_bytes for the given resource.
// Called by UpdateStorageBytesWorker after querying actual infrastructure.
func UpdateStorageBytes(ctx context.Context, db *sql.DB, resourceID uuid.UUID, bytes int64) error {
	_, err := db.ExecContext(ctx,
		`UPDATE resources SET storage_bytes = $1 WHERE id = $2`,
		bytes, resourceID,
	)
	if err != nil {
		return fmt.Errorf("quota.UpdateStorageBytes: %w", err)
	}
	return nil
}
