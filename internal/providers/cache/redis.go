package cache

// Package cache handles Redis namespace provisioning.
// Supports two backends:
//   - "local": shared Redis with key-namespace isolation (prefix {token}:*)
//   - "upstash": Upstash REST API (creates isolated database) — stubbed for now

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// Credentials holds the Redis connection details returned after provisioning.
type Credentials struct {
	// URL is the redis:// connection string the caller can use immediately.
	// For local backend with ACL: redis://usr_{short}:{password}@{host}:6379/0
	// For local backend without ACL: redis://{host}:6379/0
	URL string

	// KeyPrefix is the key namespace for local backend without ACL.
	// Clients must prefix all keys with this value to stay in their namespace.
	// Empty when ACL-based isolation is used.
	KeyPrefix string

	// ProviderResourceID is the backend-specific resource identifier.
	// For k8s-dedicated backend: the namespace name "instant-customer-<token>".
	// Empty for the shared local backend.
	ProviderResourceID string
}

// Provider manages Redis namespace provisioning.
type Provider struct {
	rdb       *redis.Client // admin connection
	backend   string        // "local" or "upstash"
	redisHost string        // Redis host for building connection strings
}

// New creates a Provider.
func New(rdb *redis.Client, backend, redisHost string) *Provider {
	if backend == "" {
		backend = "local"
	}
	if redisHost == "" {
		redisHost = "localhost"
	}
	return &Provider{rdb: rdb, backend: backend, redisHost: redisHost}
}

// Provision creates a namespaced Redis "database" for the given token.
// Local backend: tries Redis ACL (Redis 6+) first. Falls back to key-namespace isolation
// if ACL is unavailable or disabled.
// Returns real credentials the caller can use immediately.
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	switch p.backend {
	case "upstash":
		return p.provisionUpstash(ctx, token, tier)
	default:
		return p.provisionLocal(ctx, token)
	}
}

// provisionLocal attempts ACL-based isolation first, then falls back to
// key-namespace isolation.
func (p *Provider) provisionLocal(ctx context.Context, token string) (*Credentials, error) {
	short := token
	if len(short) > 8 {
		short = short[:8]
	}
	username := fmt.Sprintf("usr_%s", short)
	keyPrefix := fmt.Sprintf("%s:", token)

	// Generate a random password for the ACL user.
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, fmt.Errorf("cache.provisionLocal: generate password: %w", err)
	}
	password := hex.EncodeToString(pwBytes)

	// Try ACL SETUSER (Redis 6+).
	// Pattern: <token>:* allows access to all keys in this token's namespace.
	aclCmd := p.rdb.Do(ctx, "ACL", "SETUSER", username,
		"on",
		">"+password,
		"~"+keyPrefix+"*",
		"+@all",
	)
	if aclCmd.Err() == nil {
		// ACL succeeded — return an isolated user URL.
		url := fmt.Sprintf("redis://%s:%s@%s:6379/0", username, password, p.redisHost)
		return &Credentials{
			URL:       url,
			KeyPrefix: "",
		}, nil
	}

	// ACL failed (Redis < 6 or ACL disabled) — fall back to key-namespace isolation.
	// Return the shared Redis URL. Client must prefix all keys with {token}: to
	// stay in their namespace.
	url := fmt.Sprintf("redis://%s:6379/0", p.redisHost)
	return &Credentials{
		URL:       url,
		KeyPrefix: keyPrefix,
	}, nil
}

// provisionUpstash is a stub for the Upstash REST API backend.
func (p *Provider) provisionUpstash(ctx context.Context, token, tier string) (*Credentials, error) {
	return nil, fmt.Errorf("cache.provisionUpstash: Upstash backend not yet implemented")
}

// StorageBytes returns the estimated memory used by keys with the token prefix.
// Used by UpdateStorageBytesWorker to populate resources.storage_bytes.
// Iterates with SCAN MATCH "{token}:*" COUNT 100, sums MEMORY USAGE for each key.
// Capped at 1000 keys to avoid blocking the Redis event loop.
func (p *Provider) StorageBytes(ctx context.Context, token string) (int64, error) {
	prefix := token + ":*"
	const maxKeys = 1000

	var (
		cursor    uint64
		totalKeys int
		totalBytes int64
	)

	for {
		keys, nextCursor, err := p.rdb.Scan(ctx, cursor, prefix, 100).Result()
		if err != nil {
			return 0, fmt.Errorf("cache.StorageBytes scan: %w", err)
		}

		for _, key := range keys {
			if totalKeys >= maxKeys {
				break
			}
			totalKeys++

			// MEMORY USAGE returns bytes used by the key including metadata.
			// Err is non-nil if the key doesn't exist (just deleted).
			mem, err := p.rdb.MemoryUsage(ctx, key).Result()
			if err != nil {
				// Key was deleted between SCAN and MEMORY USAGE — skip it.
				if strings.Contains(err.Error(), "ERR") || err == redis.Nil {
					continue
				}
				continue
			}
			totalBytes += mem
		}

		cursor = nextCursor
		if cursor == 0 || totalKeys >= maxKeys {
			break
		}
	}

	return totalBytes, nil
}
