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
