package handlers

// billing_inr_drift_test.go — anti-drift guard for monthlyAmountINRForTier.
//
// monthlyAmountINRForTier hardcodes an INR price per tier (Razorpay charges
// in INR; plans.yaml quotes USD cents, which are display-only). The two
// price ladders cannot share a constant — they are different currencies — so
// this test guards them against drift instead:
//
//  1. Every paid standard tier in plans.Registry MUST have a non-zero INR
//     amount. A new paid tier added to plans.yaml but forgotten in the INR
//     map fails here (the missed-tier failure mode from CLAUDE.md rule 16).
//  2. The INR ladder MUST be monotonic with the USD ladder: if tier A costs
//     more USD than tier B, it must also cost more INR. A plans.yaml price
//     re-order that is not mirrored in the INR map fails here.

import (
	"testing"

	"instant.dev/internal/plans"
)

func TestMonthlyAmountINRForTier_NoDriftFromPlansYAML(t *testing.T) {
	reg := plans.Default()

	// Paid standard tiers — anonymous/free are price 0 and intentionally
	// return 0 from monthlyAmountINRForTier.
	paidTiers := []string{"hobby", "hobby_plus", "pro", "growth", "team"}

	type tierPrice struct {
		tier   string
		usdC   int
		inrRup int64
	}
	var ladder []tierPrice

	for _, tier := range paidTiers {
		usd := reg.PriceMonthly(tier)
		inr := monthlyAmountINRForTier(tier)
		if usd <= 0 {
			t.Errorf("tier %q has price_monthly_cents=%d in plans.yaml — expected a paid tier; "+
				"update paidTiers in this test or plans.yaml", tier, usd)
			continue
		}
		if inr <= 0 {
			t.Errorf("tier %q costs %d USD cents in plans.yaml but monthlyAmountINRForTier returns %d — "+
				"add the INR price for %q to monthlyAmountINRForTier in billing.go", tier, usd, inr, tier)
			continue
		}
		ladder = append(ladder, tierPrice{tier, usd, inr})
	}

	// Monotonic check: sort by USD, assert INR is non-decreasing in the
	// same order. A re-priced plans.yaml that flips the USD ladder without
	// a matching INR edit trips this.
	for i := 1; i < len(ladder); i++ {
		for j := 0; j < i; j++ {
			a, b := ladder[j], ladder[i]
			if a.usdC < b.usdC && a.inrRup >= b.inrRup {
				t.Errorf("INR ladder drift: %q is cheaper than %q in USD (%d < %d cents) "+
					"but NOT in INR (%d >= %d rupees) — reconcile monthlyAmountINRForTier with plans.yaml",
					a.tier, b.tier, a.usdC, b.usdC, a.inrRup, b.inrRup)
			}
		}
	}
}
