package plans_test

// tier_ladder_invariants_test.go — pinning tests for plans.yaml tier
// ordering. B6-P3 (BugBash 2026-05-20) discovered Growth's
// deployments_apps was set to 5, while Pro's was 10 — a $99/mo tier
// strictly below a $49/mo tier on a customer-facing dimension. This
// test family makes that class of regression a build-time failure.
//
// Per CLAUDE.md rule 18 (registry-iterating regression tests), each
// test iterates the live plans.Registry rather than hand-typed values.

import (
	"path/filepath"
	"runtime"
	"testing"

	"instant.dev/internal/plans"
)

// loadAPIPlansYAML loads the api/plans.yaml authoritative file as a
// Registry. The tier-ladder invariants below test the api's owned YAML
// (the source of truth for production tier limits), not the embedded
// defaultYAML in instant.dev/common/plans (which is the fallback used
// when no file is supplied). Keeping these tests pinned to the live
// api/plans.yaml means a YAML edit landing in CI surfaces the regression
// here, not after the file is rolled into the common embed.
func loadAPIPlansYAML(t *testing.T) *plans.Registry {
	t.Helper()
	// Walk up from the test file to the repo root, then resolve plans.yaml.
	// runtime.Caller(0) returns the test file path; the api repo root is
	// three levels up from this test (internal/plans/<file>).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	yamlPath := filepath.Join(root, "plans.yaml")
	r, err := plans.Load(yamlPath)
	if err != nil {
		t.Fatalf("plans.Load(%s): %v", yamlPath, err)
	}
	return r
}

// TestTierLadder_GrowthBeatsPro asserts every numeric per-tier limit
// where Growth should match-or-exceed Pro. Inversions (Growth < Pro)
// fail the build.
//
// "Unlimited" = -1 in plans.yaml. Treated as +inf for comparison so a
// Growth -1 beats a Pro 10.
func TestTierLadder_GrowthBeatsPro(t *testing.T) {
	r := loadAPIPlansYAML(t)
	pro := r.Get("pro")
	growth := r.Get("growth")
	if pro == nil || growth == nil {
		t.Fatalf("pro or growth missing from default registry")
	}

	// Each dimension below: (name, pro, growth). The compare flips -1
	// to math.MaxInt before the < check so unlimited dominates any
	// finite cap.
	type dim struct {
		name        string
		proValue    int
		growthValue int
	}
	dims := []dim{
		{"deployments_apps", pro.Limits.DeploymentsApps, growth.Limits.DeploymentsApps},
		{"postgres_storage_mb", pro.Limits.PostgresStorageMB, growth.Limits.PostgresStorageMB},
		{"redis_memory_mb", pro.Limits.RedisMemoryMB, growth.Limits.RedisMemoryMB},
		{"mongodb_storage_mb", pro.Limits.MongoStorageMB, growth.Limits.MongoStorageMB},
		{"storage_storage_mb", pro.Limits.StorageStorageMB, growth.Limits.StorageStorageMB},
		{"webhook_requests_stored", pro.Limits.WebhookRequestsStored, growth.Limits.WebhookRequestsStored},
		{"queue_storage_mb", pro.Limits.QueueStorageMB, growth.Limits.QueueStorageMB},
		{"team_members", pro.Limits.TeamMembers, growth.Limits.TeamMembers},
	}
	for _, d := range dims {
		p := normaliseUnlimited(d.proValue)
		g := normaliseUnlimited(d.growthValue)
		if g < p {
			t.Errorf("tier-ladder inversion on %s: pro=%d, growth=%d (growth must match or exceed pro)",
				d.name, d.proValue, d.growthValue)
		}
	}
}

// TestTierLadder_HobbyPlusBeatsHobby asserts Hobby Plus dominates Hobby.
func TestTierLadder_HobbyPlusBeatsHobby(t *testing.T) {
	r := loadAPIPlansYAML(t)
	hobby := r.Get("hobby")
	hp := r.Get("hobby_plus")
	if hobby == nil || hp == nil {
		t.Fatalf("hobby or hobby_plus missing from default registry")
	}
	if normaliseUnlimited(hp.Limits.MongoStorageMB) < normaliseUnlimited(hobby.Limits.MongoStorageMB) {
		t.Errorf("tier-ladder inversion on mongodb_storage_mb: hobby=%d, hobby_plus=%d",
			hobby.Limits.MongoStorageMB, hp.Limits.MongoStorageMB)
	}
	if normaliseUnlimited(hp.Limits.WebhookRequestsStored) < normaliseUnlimited(hobby.Limits.WebhookRequestsStored) {
		t.Errorf("tier-ladder inversion on webhook_requests_stored: hobby=%d, hobby_plus=%d",
			hobby.Limits.WebhookRequestsStored, hp.Limits.WebhookRequestsStored)
	}
}

// TestTierLadder_PaidTiersHaveDeployments asserts every paid tier
// (Hobby and up) exposes at least 1 deployment slot. Anonymous and Free
// are intentionally 0; everyone else must be > 0 (or -1 = unlimited).
func TestTierLadder_PaidTiersHaveDeployments(t *testing.T) {
	r := loadAPIPlansYAML(t)
	for _, name := range []string{"hobby", "hobby_plus", "pro", "growth", "team"} {
		p := r.Get(name)
		if p == nil {
			t.Errorf("tier %q missing from default registry", name)
			continue
		}
		v := p.Limits.DeploymentsApps
		if v == 0 {
			t.Errorf("paid tier %q has deployments_apps=0 — every paid tier must allow at least 1 deploy", name)
		}
	}
}

// TestPlansYAML_B6P3_GrowthDeploymentsAppsAboveProe is the literal
// pinning test for the B6-P3 finding. Fails if a future YAML edit
// regresses Growth's deployments_apps below Pro's.
func TestPlansYAML_B6P3_GrowthDeploymentsAppsAbovePro(t *testing.T) {
	r := loadAPIPlansYAML(t)
	pro := r.Get("pro")
	growth := r.Get("growth")
	if pro == nil || growth == nil {
		t.Fatalf("pro or growth missing from default registry")
	}
	if growth.Limits.DeploymentsApps != -1 && growth.Limits.DeploymentsApps <= pro.Limits.DeploymentsApps {
		t.Errorf("B6-P3 regression: growth.deployments_apps=%d must exceed pro.deployments_apps=%d (or be -1 = unlimited)",
			growth.Limits.DeploymentsApps, pro.Limits.DeploymentsApps)
	}
}

// normaliseUnlimited maps the conventional -1 = unlimited sentinel to a
// very large number so finite limits compare normally and unlimited
// always wins.
func normaliseUnlimited(v int) int {
	if v < 0 {
		return 1 << 30
	}
	return v
}
