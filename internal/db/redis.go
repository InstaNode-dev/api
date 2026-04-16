package db

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrRedisConnect is returned when the Redis connection cannot be established.
type ErrRedisConnect struct {
	Cause error
}

func (e *ErrRedisConnect) Error() string {
	return fmt.Sprintf("failed to connect to redis: %v", e.Cause)
}

func (e *ErrRedisConnect) Unwrap() error { return e.Cause }

// ConnectRedis creates and verifies a Redis client. Panics on failure.
func ConnectRedis(redisURL string) *redis.Client {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		panic(&ErrRedisConnect{Cause: fmt.Errorf("invalid redis URL: %w", err)})
	}

	opts.PoolSize = 20
	opts.MinIdleConns = 5
	opts.ConnMaxLifetime = 5 * time.Minute
	opts.ConnMaxIdleTime = 2 * time.Minute

	rdb := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		panic(&ErrRedisConnect{Cause: err})
	}

	slog.Info("db.redis.connected", "addr", opts.Addr, "pool_size", opts.PoolSize)
	return rdb
}
