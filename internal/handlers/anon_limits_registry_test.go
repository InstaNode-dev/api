package handlers

// anon_limits_registry_test.go — regression test for P2-01 / P2-02
// (BugBash 2026-05-18).
//
// cacheAnonymousLimits and nosqlAnonymousLimits previously returned bare
// integer literals (memory_mb: 5, storage_mb: 5, connections: 2) instead of
// reading plans.Registry — so a plans.yaml edit to the anonymous tier would
// silently drift the anon provisioning response away from the authenticated
// path (convention #3). These tests pin every anon-limit helper to the
// registry so the bare-literal regression cannot return.

import (
	"testing"

	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// TestAnonLimitHelpers_ReadRegistry verifies every per-service anonymous-limit
// helper sources its numbers from plans.Registry, not a hardcoded literal.
func TestAnonLimitHelpers_ReadRegistry(t *testing.T) {
	reg := plans.Default()
	ph := provisionHelper{plans: reg}

	t.Run("cache memory_mb from registry", func(t *testing.T) {
		h := &CacheHandler{provisionHelper: ph}
		got := h.cacheAnonymousLimits()
		want := reg.StorageLimitMB(tierAnonymous, models.ResourceTypeRedis)
		if got["memory_mb"] != want {
			t.Errorf("cacheAnonymousLimits memory_mb = %v, want registry value %v", got["memory_mb"], want)
		}
	})

	t.Run("nosql storage_mb + connections from registry", func(t *testing.T) {
		h := &NoSQLHandler{provisionHelper: ph}
		got := h.nosqlAnonymousLimits()
		wantMB := reg.StorageLimitMB(tierAnonymous, models.ResourceTypeMongoDB)
		wantConn := reg.ConnectionsLimit(tierAnonymous, models.ResourceTypeMongoDB)
		if got["storage_mb"] != wantMB {
			t.Errorf("nosqlAnonymousLimits storage_mb = %v, want registry value %v", got["storage_mb"], wantMB)
		}
		if got["connections"] != wantConn {
			t.Errorf("nosqlAnonymousLimits connections = %v, want registry value %v", got["connections"], wantConn)
		}
	})

	t.Run("db storage_mb + connections from registry", func(t *testing.T) {
		h := &DBHandler{provisionHelper: ph}
		got := h.dbAnonymousLimits()
		wantMB := reg.StorageLimitMB(tierAnonymous, models.ResourceTypePostgres)
		wantConn := reg.ConnectionsLimit(tierAnonymous, models.ResourceTypePostgres)
		if got["storage_mb"] != wantMB {
			t.Errorf("dbAnonymousLimits storage_mb = %v, want registry value %v", got["storage_mb"], wantMB)
		}
		if got["connections"] != wantConn {
			t.Errorf("dbAnonymousLimits connections = %v, want registry value %v", got["connections"], wantConn)
		}
	})
}
