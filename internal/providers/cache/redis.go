package cache

// Package cache handles Redis namespace provisioning.
// Supports two backends:
//   - "local": shared Redis with key-namespace isolation (prefix {token}:*)
//   - "upstash": Upstash REST API (creates isolated database) — stubbed for now

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// errNilRedisClient is returned by local-backend operations when the Provider
// was constructed without a Redis admin connection. Provisioning a cache
// resource genuinely requires Redis, so this surfaces as a clean 503 instead
// of a nil-pointer panic.
var errNilRedisClient = errors.New("redis admin client is not configured")

// aclAllowlist is the safe command allowlist applied to every provisioned ACL
// user on the shared Redis backend. It replaces "+@all" which would grant
// dangerous cross-tenant commands such as FLUSHDB, MONITOR, and CONFIG SET.
//
// Design rationale (§3 of DESIGN-P1-A-tier-enforcement.md):
//   - "+@all" on a shared pod allows FLUSHDB (wipes ALL tenants' data),
//     MONITOR (leaks all tenant commands in real time), and CONFIG SET
//     (removes pod-wide memory cap) — multi-tenant isolation failures.
//   - The key-pattern restriction (~{token}:*) does NOT cover admin/dangerous
//     commands; those operate at the server level, not the key level.
//   - "+@scripting" is included so Lua scripts work; Lua calling FLUSHDB is
//     mitigated by the explicit "-flushdb"/"-flushall" deny entries that Redis
//     evaluates before command execution.
//   - "-keys" removes the O(N) cross-tenant key scan; tenants should use SCAN.
var aclAllowlist = []interface{}{
	"+@read",        // GET, MGET, STRLEN, LRANGE, SMEMBERS, HGET, etc.
	"+@write",       // SET, MSET, DEL, LPUSH, SADD, HSET, etc.
	"+@string",      // Explicit string family (belt-and-suspenders with @read/@write)
	"+@hash",        // HSET, HGET, HMSET, etc.
	"+@list",        // LPUSH, LRANGE, etc.
	"+@set",         // SADD, SMEMBERS, etc.
	"+@sortedset",   // ZADD, ZRANGE, etc.
	"+@stream",      // XADD, XREAD — needed for stream workloads
	"+@hyperloglog", // PFADD, PFCOUNT
	"+@geo",         // GEOADD, GEODIST
	"+@pubsub",      // SUBSCRIBE, PUBLISH — needed for pub/sub workloads
	"+@scripting",   // EVAL, EVALSHA — Lua scripting; explicit denies below guard FLUSHDB via Lua
	"-@admin",       // FLUSHALL, DEBUG, SAVE, BGSAVE, CONFIG, etc.
	"-@dangerous",   // MONITOR, KEYS, OBJECT, SORT with STORE, MIGRATE
	"-config",       // CONFIG GET/SET/RESETSTAT — explicit deny even if @admin missed
	"-debug",        // DEBUG SLEEP, DEBUG JMAP
	"-monitor",      // MONITOR — explicit deny (cross-tenant command stream)
	"-flushdb",      // FLUSHDB — explicit deny (wipes ALL tenant data on shared pod)
	"-flushall",     // FLUSHALL — explicit deny
	"-acl",          // ACL SETUSER/DELUSER — prevents ACL self-escalation
	"-keys",         // KEYS — O(N) cross-tenant key scan; tenants must use SCAN
}

// aclUsernamePrefix is the fixed prefix for every ACL user this backend creates.
const aclUsernamePrefix = "usr_"

// legacyACLUsernameTokenLen is the 8-char token slice the OLD (pre-P1-E)
// implementation used to derive the ACL username. Retained only so a Redis
// user created under the old scheme can still be located and deleted.
const legacyACLUsernameTokenLen = 8

// aclUsername derives the ACL username for a resource token. It uses the FULL
// token (P1-E) so two tokens sharing a common prefix never collide on one ACL
// user — the key-prefix already uses the full token, and the username now
// matches it.
func aclUsername(token string) string {
	return aclUsernamePrefix + token
}

// legacyACLUsername reproduces the pre-P1-E username derivation (token[:8]).
// A Deprovision path should try aclUsername(token) first, then fall back to
// this so a user created under the old truncated scheme is still deletable.
func legacyACLUsername(token string) string {
	short := token
	if len(short) > legacyACLUsernameTokenLen {
		short = short[:legacyACLUsernameTokenLen]
	}
	return aclUsernamePrefix + short
}

// Credentials holds the Redis connection details returned after provisioning.
type Credentials struct {
	// URL is the redis:// connection string the caller can use immediately.
	// For local backend with ACL: redis://usr_{token}:{password}@{host}:6379/0
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
	// The local backend genuinely requires a Redis admin connection to create
	// the ACL user / namespace. A nil client means the service is misconfigured
	// (REDIS_URL unset) — return a clean error so the handler responds 503
	// rather than panicking with a nil-pointer dereference. CLAUDE.md #2.
	if p.rdb == nil {
		return nil, fmt.Errorf("cache.provisionLocal: %w", errNilRedisClient)
	}
	// P1-E (2026-05-17): the ACL username must use the FULL token. A previous
	// implementation truncated to token[:8], so two tokens sharing 8 hex
	// characters collided on one ACL user — the second SETUSER silently
	// overwrote the first's password/keyspace grant. The key-prefix already
	// uses the full token; the username now matches it for true isolation.
	username := aclUsername(token)
	keyPrefix := fmt.Sprintf("%s:", token)

	// Generate a random password for the ACL user.
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, fmt.Errorf("cache.provisionLocal: generate password: %w", err)
	}
	password := hex.EncodeToString(pwBytes)

	// Try ACL SETUSER (Redis 6+).
	// Pattern: <token>:* restricts key access to this token's namespace.
	// aclAllowlist replaces "+@all": on a shared pod, "+@all" grants
	// FLUSHDB/MONITOR/CONFIG which are multi-tenant isolation failures.
	// See aclAllowlist declaration for full rationale.
	aclArgs := []interface{}{"ACL", "SETUSER", username, "on", ">" + password, "~" + keyPrefix + "*"}
	aclArgs = append(aclArgs, aclAllowlist...)
	aclCmd := p.rdb.Do(ctx, aclArgs...)
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
	if p.rdb == nil {
		return 0, fmt.Errorf("cache.StorageBytes: %w", errNilRedisClient)
	}
	prefix := token + ":*"
	const maxKeys = 1000

	var (
		cursor     uint64
		totalKeys  int
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
