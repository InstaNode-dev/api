package cache

// redis_unit_test.go is an in-package (white-box) companion to redis_test.go.
// It drives the unexported helpers and the error/fallback branches that the
// black-box redis_test.go cannot reach: nil-client handling, the ACL→key-
// namespace fallback, the Upstash stub, StorageBytes edge cases, and the
// legacy username derivation.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

// testRedis connects to the test Redis (TEST_REDIS_URL) and flushes the
// keyspace, skipping the test if Redis is unreachable. In-package twin of
// testhelpers.SetupTestRedis (avoids the import cycle for white-box tests).
func testRedis(t *testing.T) *redis.Client {
	t.Helper()
	raw := os.Getenv("TEST_REDIS_URL")
	if raw == "" {
		raw = "redis://localhost:6379/15"
	}
	opts, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatalf("parse TEST_REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis unreachable (%v) — set TEST_REDIS_URL", err)
	}
	rdb.FlushDB(context.Background())
	t.Cleanup(func() { rdb.FlushDB(context.Background()); rdb.Close() })
	return rdb
}

func TestNew_Defaults(t *testing.T) {
	p := New(nil, "", "")
	if p.backend != "local" {
		t.Fatalf("empty backend must default to local; got %q", p.backend)
	}
	if p.redisHost != "localhost" {
		t.Fatalf("empty host must default to localhost; got %q", p.redisHost)
	}
	p2 := New(nil, "upstash", "h:6379")
	if p2.backend != "upstash" || p2.redisHost != "h:6379" {
		t.Fatalf("explicit values lost: %+v", p2)
	}
}

func TestACLUsernameDerivation(t *testing.T) {
	// Full-token username (P1-E).
	if got := aclUsername("abcdef0123456789ff"); got != "usr_abcdef0123456789ff" {
		t.Fatalf("aclUsername = %q", got)
	}
	// Legacy username truncates to 8 chars.
	if got := legacyACLUsername("abcdef0123456789"); got != "usr_abcdef01" {
		t.Fatalf("legacyACLUsername(long) = %q", got)
	}
	// Short token: no truncation.
	if got := legacyACLUsername("abc"); got != "usr_abc" {
		t.Fatalf("legacyACLUsername(short) = %q", got)
	}
}

func TestProvision_NilClient(t *testing.T) {
	p := New(nil, "local", "localhost")
	_, err := p.Provision(context.Background(), "tok", "anonymous")
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("nil client must surface a configured error; got %v", err)
	}
}

func TestStorageBytes_NilClient(t *testing.T) {
	p := New(nil, "local", "localhost")
	_, err := p.StorageBytes(context.Background(), "tok")
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("nil client StorageBytes must error; got %v", err)
	}
}

func TestProvision_Upstash_Stub(t *testing.T) {
	p := New(nil, "upstash", "localhost")
	_, err := p.Provision(context.Background(), "tok", "anonymous")
	if err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Fatalf("upstash backend must return not-implemented; got %v", err)
	}
}

// deadClient returns a redis client pointed at a closed port so every command
// (including ACL SETUSER and SCAN) errors. Used to drive the ACL→key-namespace
// fallback and the SCAN error branch.
func deadClient() *redis.Client {
	return redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
}

// TestProvisionLocal_ACLFallback covers the branch where ACL SETUSER fails and
// the provider falls back to shared-URL + key-namespace isolation.
func TestProvisionLocal_ACLFallback(t *testing.T) {
	p := New(deadClient(), "local", "redishost")
	creds, err := p.Provision(context.Background(), "fallback-token", "anonymous")
	if err != nil {
		t.Fatalf("fallback must not error: %v", err)
	}
	if creds.KeyPrefix != "fallback-token:" {
		t.Fatalf("fallback must set KeyPrefix; got %q", creds.KeyPrefix)
	}
	if !strings.HasPrefix(creds.URL, "redis://redishost:6379/0") {
		t.Fatalf("fallback URL must be the shared host; got %q", creds.URL)
	}
}

// TestStorageBytes_ScanError covers the SCAN error return.
func TestStorageBytes_ScanError(t *testing.T) {
	p := New(deadClient(), "local", "localhost")
	_, err := p.StorageBytes(context.Background(), "tok")
	if err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("dead client SCAN must error; got %v", err)
	}
}

// TestStorageBytes_MemoryUsageSkip covers the MEMORY USAGE error/skip branch:
// a key visible to SCAN but gone by the time MEMORY USAGE runs. We make this
// deterministic by setting a key with a very short TTL, letting SCAN observe it,
// then expiring it before the MEMORY USAGE call. Because SCAN buffers the key
// name and the loop calls MEMORY USAGE afterwards, an expired key returns an
// error that the loop must skip without failing the whole call.
func TestStorageBytes_MemoryUsageSkip(t *testing.T) {
	rdb := testRedis(t)
	token := "memskip-token"
	ctx := context.Background()

	// One stable key (counted) plus several that vanish mid-scan.
	if err := rdb.Set(ctx, token+":stable", "value", 0).Err(); err != nil {
		t.Fatalf("seed stable key: %v", err)
	}
	for i := 0; i < 200; i++ {
		_ = rdb.Set(ctx, token+":vanish"+strings.Repeat("x", (i%5)+1)+itoa(i), "v", 0).Err()
	}

	p := New(rdb, "local", "localhost")
	// Race a bulk delete against the scan so a subset of keys disappear between
	// SCAN buffering them and the MEMORY USAGE read — exercising the skip path.
	done := make(chan struct{})
	go func() {
		defer close(done)
		iter := rdb.Scan(ctx, 0, token+":vanish*", 50).Iterator()
		for iter.Next(ctx) {
			rdb.Del(ctx, iter.Val())
		}
	}()
	bytes, err := p.StorageBytes(ctx, token)
	<-done
	if err != nil {
		t.Fatalf("StorageBytes must tolerate vanished keys: %v", err)
	}
	if bytes < 0 {
		t.Fatalf("bytes must be non-negative; got %d", bytes)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
