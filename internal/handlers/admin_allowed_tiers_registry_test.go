package handlers

// admin_allowed_tiers_registry_test.go — rule-18 drift guard.
//
// adminAllowedTiers (admin_customers.go) is a hand-maintained closed set of
// the tiers an admin may set on a team. The capabilities-contract regression
// (a hardcoded slice that silently dropped hobby_plus for 3h) is the bug class
// this guards: a NEW tier added to plans.yaml must be consciously filed as
// either admin-settable OR explicitly excluded — never silently forgotten.
//
// Per rule 18 the test iterates the LIVE plans registry rather than a
// hand-typed tier list, so adding a tier to plans.yaml reds CI until someone
// makes the decision.

import (
	"testing"

	"instant.dev/internal/plans"
)

func TestAdminAllowedTiers_StaysInSyncWithPlanRegistry(t *testing.T) {
	// Tiers that are deliberately NOT admin-settable, each with the reason.
	// Adding a tier here is the conscious "this is not an admin headline tier"
	// decision the guard forces.
	adminExcluded := map[string]string{
		"anonymous":         "unclaimed default; not a settable account tier",
		"growth":            "upsell-only API tier; admin UI exposes headline tiers only",
		"hobby_plus":        "upsell-only API tier; admin UI exposes headline tiers only",
		"hobby_plus_yearly": "yearly variant of an upsell-only tier",
		"hobby_yearly":      "yearly billing variant; admin sets the monthly headline tier",
		"pro_yearly":        "yearly billing variant; admin sets the monthly headline tier",
		"team_yearly":       "yearly billing variant; admin sets the monthly headline tier",
	}

	all := plans.Default().All()
	if len(all) == 0 {
		t.Fatal("plans registry is empty — cannot validate adminAllowedTiers drift")
	}

	for tier := range all {
		settable := adminAllowedTiers[tier]
		_, excluded := adminExcluded[tier]
		switch {
		case settable && excluded:
			t.Errorf("tier %q is BOTH admin-settable and in the exclude set — contradiction; "+
				"remove it from one (admin_customers.go / this test)", tier)
		case !settable && !excluded:
			t.Errorf("tier %q exists in plans.yaml but is neither in adminAllowedTiers nor the "+
				"documented exclude set — file it on one side (rule 18)", tier)
		}
	}

	// Belt: no stale entry in adminAllowedTiers that no longer exists in the
	// registry (a removed/renamed tier left behind).
	for tier := range adminAllowedTiers {
		if _, ok := all[tier]; !ok {
			t.Errorf("adminAllowedTiers contains %q which is not present in plans.yaml", tier)
		}
	}
	// Belt: no stale exclude entry either.
	for tier := range adminExcluded {
		if _, ok := all[tier]; !ok {
			t.Errorf("adminExcluded test set contains %q which is not present in plans.yaml — "+
				"drop the stale entry", tier)
		}
	}
}
