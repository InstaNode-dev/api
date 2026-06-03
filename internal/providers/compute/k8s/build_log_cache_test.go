package k8s

// build_log_cache_test.go — P1-G coverage (bug hunt 2026-05-17 round 2).
//
// The kaniko build Job is reaped 300s after it finishes
// (TTLSecondsAfterFinished). The failure autopsy that reads the build logs
// runs LATER, in the api handler, after Deploy returns. On a slow failure
// path the pod is already GC'd and failure.last_lines comes back empty.
//
// The fix snapshots the kaniko logs into buildLogCache the moment a build
// fails (buildImage → snapshotBuildLogs), while the pod is still alive.
// FetchBuildLogs consults the cache first, so the autopsy gets the build
// output regardless of how late it runs.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

// TestFetchBuildLogs_ReturnsCachedSnapshot verifies that once a failure
// snapshot is in buildLogCache, FetchBuildLogs returns it verbatim — it does
// NOT race a live pod read against the Job TTL.
func TestFetchBuildLogs_ReturnsCachedSnapshot(t *testing.T) {
	p := &K8sProvider{clientset: fake.NewSimpleClientset()}

	want := []string{
		"error building image: error building stage",
		"failed to execute command: exit status 1",
	}
	p.buildLogCache.Store("appcafe1", &buildLogCacheEntry{
		lines:      want,
		capturedAt: time.Now(),
	})

	got, err := p.FetchBuildLogs(context.Background(), "appcafe1")
	if err != nil {
		t.Fatalf("FetchBuildLogs returned error on a cache hit: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("cached snapshot not returned: got %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFetchBuildLogs_StaleCacheEntryEvicted verifies a snapshot older than
// buildLogCacheTTL is not served — it is dropped and the call falls through
// to a live read (which errors here since the fake cluster has no pods).
func TestFetchBuildLogs_StaleCacheEntryEvicted(t *testing.T) {
	p := &K8sProvider{clientset: fake.NewSimpleClientset()}

	p.buildLogCache.Store("appstale1", &buildLogCacheEntry{
		lines:      []string{"old build output"},
		capturedAt: time.Now().Add(-buildLogCacheTTL - time.Minute),
	})

	got, err := p.FetchBuildLogs(context.Background(), "appstale1")
	if err == nil {
		t.Fatalf("expected a live-read error after stale eviction, got lines: %v", got)
	}
	if _, ok := p.buildLogCache.Load("appstale1"); ok {
		t.Error("stale cache entry was not evicted")
	}
}

// TestFetchBuildLogs_NoCacheNoPodFailsSoft verifies the fail-soft contract:
// no cached snapshot AND no live pod → (nil, err), never a panic.
func TestFetchBuildLogs_NoCacheNoPodFailsSoft(t *testing.T) {
	p := &K8sProvider{clientset: fake.NewSimpleClientset()}

	got, err := p.FetchBuildLogs(context.Background(), "appmissing")
	if err == nil {
		t.Fatalf("expected error when no cache + no pod, got: %v", got)
	}
	if got != nil {
		t.Errorf("expected nil lines on failure, got: %v", got)
	}
}

// TestEvictStaleBuildLogs_KeepsFreshDropsStale verifies the eviction sweep
// retains fresh entries and drops only the expired ones.
func TestEvictStaleBuildLogs_KeepsFreshDropsStale(t *testing.T) {
	p := &K8sProvider{clientset: fake.NewSimpleClientset()}

	p.buildLogCache.Store("fresh", &buildLogCacheEntry{
		lines:      []string{"fresh"},
		capturedAt: time.Now(),
	})
	p.buildLogCache.Store("stale", &buildLogCacheEntry{
		lines:      []string{"stale"},
		capturedAt: time.Now().Add(-buildLogCacheTTL - time.Second),
	})

	p.evictStaleBuildLogs()

	if _, ok := p.buildLogCache.Load("fresh"); !ok {
		t.Error("fresh entry was wrongly evicted")
	}
	if _, ok := p.buildLogCache.Load("stale"); ok {
		t.Error("stale entry was not evicted")
	}
}

// TestCapBuildLogCacheSize_EvictsOldestOverCap verifies the size cap: a burst
// of fresh (non-stale) snapshots beyond buildLogCacheMaxEntries is bounded by
// evicting the OLDEST entries first, while the most-recent cap-many survive.
// This is the memory-leak guard the TTL sweep alone does not provide — many
// failures inside one TTL window would otherwise grow the map without bound.
func TestCapBuildLogCacheSize_EvictsOldestOverCap(t *testing.T) {
	p := &K8sProvider{clientset: fake.NewSimpleClientset()}

	base := time.Now()
	overflow := 10
	total := buildLogCacheMaxEntries + overflow
	// All fresh (well within TTL) so eviction is driven purely by the size cap,
	// not by staleness. Older capturedAt for lower indexes → those evict first.
	for i := 0; i < total; i++ {
		key := fmt.Sprintf("app-%04d", i)
		p.buildLogCache.Store(key, &buildLogCacheEntry{
			lines:      []string{key},
			capturedAt: base.Add(time.Duration(i) * time.Second),
		})
	}

	p.capBuildLogCacheSize()

	var count int
	p.buildLogCache.Range(func(_, _ any) bool { count++; return true })
	if count != buildLogCacheMaxEntries {
		t.Fatalf("cache not capped: got %d entries, want %d", count, buildLogCacheMaxEntries)
	}

	// The oldest `overflow` entries (lowest indexes) must be gone; the newest
	// must remain.
	for i := 0; i < overflow; i++ {
		if _, ok := p.buildLogCache.Load(fmt.Sprintf("app-%04d", i)); ok {
			t.Errorf("oldest entry app-%04d should have been evicted", i)
		}
	}
	if _, ok := p.buildLogCache.Load(fmt.Sprintf("app-%04d", total-1)); !ok {
		t.Errorf("newest entry app-%04d was wrongly evicted", total-1)
	}
}

// TestCapBuildLogCacheSize_NoOpUnderCap verifies the cap is a no-op when the
// cache holds fewer than buildLogCacheMaxEntries entries (the common case).
func TestCapBuildLogCacheSize_NoOpUnderCap(t *testing.T) {
	p := &K8sProvider{clientset: fake.NewSimpleClientset()}

	p.buildLogCache.Store("only", &buildLogCacheEntry{
		lines:      []string{"x"},
		capturedAt: time.Now(),
	})

	p.capBuildLogCacheSize()

	if _, ok := p.buildLogCache.Load("only"); !ok {
		t.Error("under-cap entry was wrongly evicted")
	}
}
