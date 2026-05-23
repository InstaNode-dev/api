package handlers

// audit_pure_helpers_coverage_test.go — white-box coverage for the pure audit
// helpers: maskEmail (all 4 arms) + tierLookbackDays (allowed/unlimited/blocked
// branches). The handler-level audit tests don't drive every maskEmail arm
// (empty / no-@ / @-at-position-0).

import "testing"

func TestMaskEmail_AllArms(t *testing.T) {
	cases := map[string]string{
		"":                  "",            // empty
		"plainstring":       "p***",        // no @
		"@example.com":      "***@example.com", // @ at position 0
		"alice@example.com": "a***@example.com", // normal
	}
	for in, want := range cases {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestTierLookbackDays_Branches(t *testing.T) {
	// blocked tiers → 0
	for _, tier := range []string{"anonymous", "free"} {
		if got := tierLookbackDays(tier); got != 0 {
			t.Errorf("tierLookbackDays(%q) = %d; want 0 (blocked)", tier, got)
		}
	}
	// unlimited tiers → -1
	for _, tier := range []string{"growth", "team"} {
		if got := tierLookbackDays(tier); got != -1 {
			t.Errorf("tierLookbackDays(%q) = %d; want -1 (unlimited)", tier, got)
		}
	}
	// bounded tiers → positive day count
	for _, tier := range []string{"hobby", "hobby_plus", "pro", "future_unknown_tier"} {
		if got := tierLookbackDays(tier); got <= 0 {
			t.Errorf("tierLookbackDays(%q) = %d; want > 0", tier, got)
		}
	}
}
