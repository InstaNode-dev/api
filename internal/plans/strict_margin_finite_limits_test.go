package plans_test

// strict_margin_finite_limits_test.go — rule-18 registry-iterating guard for
// the strict-≥80%-margin tier redesign (2026-06-05, PR #262 / common #46).
//
// The redesign retired every "unlimited" (-1) RESOURCE limit to a finite,
// worst-case-costed cap so saturated COGS stays ≥80% margin. The ONLY limit
// field intentionally left at -1 is ProvisionsPerDay (a per-day rate gate on
// paid tiers, not a resource-cost dimension).
//
// This test iterates the LIVE plans.yaml registry (not a hand-typed tier
// list) so that re-introducing a -1 on any costed limit — or adding a new
// tier that ships an unlimited resource cap — fails here rather than silently
// shipping an unbounded-COGS tier. Hand-typed slices would themselves be the
// single-site fallacy rule 18 warns against.

import (
	"os"
	"path/filepath"
	"testing"

	"instant.dev/internal/plans"
)

func TestStrictMargin_NoUnlimitedResourceLimits(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "plans.yaml")
	if _, err := os.Stat(repoRoot); os.IsNotExist(err) {
		t.Skip("plans.yaml not found in repo root — skipping finite-limit guard")
	}
	r, err := plans.Load(repoRoot)
	if err != nil {
		t.Fatalf("load plans.yaml: %v", err)
	}

	all := r.All()
	if len(all) == 0 {
		t.Fatal("registry is empty — plans.yaml failed to populate any tier")
	}

	for name, p := range all {
		l := p.Limits
		// Every integer RESOURCE limit must be finite (>= 0). -1 (unlimited)
		// is forbidden post strict-margin redesign because an unbounded cap
		// breaks the worst-case COGS / ≥80%-margin guarantee. (0 is allowed:
		// it means "feature not available on this tier", e.g. deployments_apps
		// on anonymous/free, vault on free.)
		checks := map[string]int{
			"postgres_storage_mb":     l.PostgresStorageMB,
			"postgres_connections":    l.PostgresConnections,
			"vector_storage_mb":       l.VectorStorageMB,
			"vector_connections":      l.VectorConnections,
			"redis_memory_mb":         l.RedisMemoryMB,
			"redis_commands_per_day":  l.RedisCommandsPerDay,
			"mongodb_storage_mb":      l.MongoStorageMB,
			"mongodb_connections":     l.MongoConnections,
			"mongodb_ops_per_minute":  l.MongoOpsPerMinute,
			"queue_storage_mb":        l.QueueStorageMB,
			"queue_count":             l.QueueCount,
			"storage_storage_mb":      l.StorageStorageMB,
			"webhook_requests_stored": l.WebhookRequestsStored,
			"team_members":            l.TeamMembers,
			"vault_max_entries":       l.VaultMaxEntries,
			"deployments_apps":        l.DeploymentsApps,
			"custom_domains_max":      l.CustomDomainsMax,
			"manual_backups_per_day":  l.ManualBackupsPerDay,
		}
		for field, v := range checks {
			if v < 0 {
				t.Errorf("tier %q: %s = %d — unlimited (-1) resource limits were retired in the strict-80%%-margin redesign; every resource cap must be finite (>= 0)",
					name, field, v)
			}
		}

		// ProvisionsPerDay is the ONLY field intentionally allowed at -1
		// (per-day rate gate, not a resource-cost dimension). Assert it is
		// either finite (>= 0) or exactly -1 — never some other negative.
		if l.ProvisionsPerDay < -1 {
			t.Errorf("tier %q: provisions_per_day = %d — must be -1 (unlimited) or finite (>= 0)",
				name, l.ProvisionsPerDay)
		}
	}
}
