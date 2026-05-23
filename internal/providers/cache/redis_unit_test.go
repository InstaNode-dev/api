package cache

// redis_unit_test.go is an in-package (white-box) companion to redis_test.go.
// It drives the unexported helpers and the error/fallback branches that the
// black-box redis_test.go cannot reach: nil-client handling, the ACL→key-
// namespace fallback, the Upstash stub, StorageBytes edge cases, and the
// legacy username derivation.

import (
	"context"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

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

// fakeScanner is a deterministic redisScanner: it returns a fixed set of keys
// from SCAN, and reports a configurable subset as missing on MEMORY USAGE. This
// drives the mid-scan vanished-key skip branch with zero timing dependence.
type fakeScanner struct {
	keys      []string         // returned by a single SCAN page (cursor → 0)
	memBytes  map[string]int64 // present keys → byte size
	missing   map[string]bool  // keys that MEMORY USAGE reports gone
	scanError error            // when set, SCAN returns this error
}

func (f *fakeScanner) Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd {
	cmd := redis.NewScanCmd(ctx, nil)
	if f.scanError != nil {
		cmd.SetErr(f.scanError)
		return cmd
	}
	// Single page: return all keys and cursor 0 so the loop terminates.
	cmd.SetVal(f.keys, 0)
	return cmd
}

func (f *fakeScanner) MemoryUsage(ctx context.Context, key string, samples ...int) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	if f.missing[key] {
		// Simulate the key vanishing between SCAN and MEMORY USAGE.
		cmd.SetErr(redis.Nil)
		return cmd
	}
	cmd.SetVal(f.memBytes[key])
	return cmd
}

// TestStorageBytes_MemoryUsageSkip covers the MEMORY USAGE error/skip branch
// deterministically: a fake scanner returns three keys via SCAN but reports the
// middle one as gone (redis.Nil) on MEMORY USAGE. The loop must skip it and sum
// only the two present keys. No timing, no live Redis, no flake.
func TestStorageBytes_MemoryUsageSkip(t *testing.T) {
	f := &fakeScanner{
		keys: []string{"tok:a", "tok:gone", "tok:b"},
		memBytes: map[string]int64{
			"tok:a": 100,
			"tok:b": 250,
		},
		missing: map[string]bool{"tok:gone": true},
	}
	got, err := storageBytes(context.Background(), f, "tok")
	if err != nil {
		t.Fatalf("storageBytes must tolerate a vanished key: %v", err)
	}
	if got != 350 {
		t.Fatalf("want 350 (100+250, skipping the gone key); got %d", got)
	}
}

// TestStorageBytes_TruncationCeiling covers the truncation branch: when the key
// count reaches storageBytesScanCap, scanning stops and the under-report warning
// fires. We lower the cap to 2 (restored on cleanup) so a 3-key fake trips it
// with no 200k write.
func TestStorageBytes_TruncationCeiling(t *testing.T) {
	orig := storageBytesScanCap
	storageBytesScanCap = 2
	t.Cleanup(func() { storageBytesScanCap = orig })

	f := &fakeScanner{
		keys:     []string{"tok:a", "tok:b", "tok:c"},
		memBytes: map[string]int64{"tok:a": 10, "tok:b": 20, "tok:c": 40},
	}
	got, err := storageBytes(context.Background(), f, "tok")
	if err != nil {
		t.Fatalf("storageBytes: %v", err)
	}
	// Only the first 2 keys are counted before the cap halts the scan.
	if got != 30 {
		t.Fatalf("want 30 (cap=2 → only first two keys); got %d", got)
	}
}

// TestStorageBytes_ScanError_Fake covers the SCAN error return via the fake,
// independent of a live dead-port client.
func TestStorageBytes_ScanError_Fake(t *testing.T) {
	f := &fakeScanner{scanError: context.DeadlineExceeded}
	_, err := storageBytes(context.Background(), f, "tok")
	if err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("SCAN error must propagate; got %v", err)
	}
}

// TestProvisionLocal_RandReadFailure covers the crypto/rand failure branch in
// provisionLocal via the randRead seam. We can use a nil-but-non-nil client
// because the RNG failure returns before any Redis command is issued.
func TestProvisionLocal_RandReadFailure(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errBoomRand }
	t.Cleanup(func() { randRead = orig })

	// A live (or dead) non-nil client passes the nil-check; the RNG failure
	// short-circuits before the client is touched.
	p := New(deadClient(), "local", "localhost")
	_, err := p.Provision(context.Background(), "tok", "anonymous")
	if err == nil || !strings.Contains(err.Error(), "generate password") {
		t.Fatalf("randRead failure must surface as generate-password error; got %v", err)
	}
}

var errBoomRand = errBoom("rand exhausted")

type errBoom string

func (e errBoom) Error() string { return string(e) }
