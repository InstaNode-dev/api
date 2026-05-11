package plans

import "testing"

func TestLookupPlanID(t *testing.T) {
	cases := []struct {
		name     string
		tier     string
		currency string
		cycle    string
		wantID   string
		wantErr  bool
	}{
		{"hobby USD monthly", "hobby", "USD", "monthly", "plan_Sg2YcWj6hM5Ook", false},
		{"hobby USD yearly", "hobby", "USD", "yearly", "plan_Sg2aCGFGoeuxNS", false},
		{"hobby INR monthly", "hobby", "INR", "monthly", "plan_SgT09xZkHcJing", false},
		{"hobby INR yearly", "hobby", "INR", "yearly", "plan_SgTAPVUusjHTB6", false},
		{"lowercase currency works", "hobby", "usd", "monthly", "plan_Sg2YcWj6hM5Ook", false},
		{"mixed case cycle works", "hobby", "USD", "Monthly", "plan_Sg2YcWj6hM5Ook", false},
		{"unknown tier", "pro", "USD", "monthly", "", true},
		{"unknown currency", "hobby", "EUR", "monthly", "", true},
		{"unknown cycle", "hobby", "USD", "daily", "", true},
		{"empty currency", "hobby", "", "monthly", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LookupPlanID(tc.tier, tc.currency, tc.cycle)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got id=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantID {
				t.Fatalf("got %q, want %q", got, tc.wantID)
			}
		})
	}
}

func TestTierFromPlanID(t *testing.T) {
	cases := []struct {
		planID   string
		wantTier string
		wantOK   bool
	}{
		{"plan_Sg2YcWj6hM5Ook", "hobby", true},
		{"plan_Sg2aCGFGoeuxNS", "hobby", true},
		{"plan_SgT09xZkHcJing", "hobby", true},
		{"plan_SgTAPVUusjHTB6", "hobby", true},
		{"plan_SgT0sK508QF1iR", "", false}, // 2,499 typo plan — intentionally absent
		{"plan_does_not_exist", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.planID, func(t *testing.T) {
			tier, ok := TierFromPlanID(tc.planID)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if tier != tc.wantTier {
				t.Fatalf("tier: got %q, want %q", tier, tc.wantTier)
			}
		})
	}
}

// TestRazorpayPlanIDs_AllUnique guards against a future edit accidentally
// pointing two keys at the same plan_id, which would corrupt TierFromPlanID.
func TestRazorpayPlanIDs_AllUnique(t *testing.T) {
	seen := make(map[string]string)
	for key, id := range RazorpayPlanIDs {
		if prev, ok := seen[id]; ok {
			t.Fatalf("duplicate plan_id %q used for both %q and %q", id, prev, key)
		}
		seen[id] = key
	}
}

// TestRazorpayPlanIDs_TypoPlanAbsent is a regression guard: the original
// hobby_inr_yearly plan was ₹2,499 (plan_SgT0sK508QF1iR, typo — negative
// discount vs monthly × 12). The replacement is ₹2,199 (plan_SgTAPVUusjHTB6).
// Razorpay plans cannot be deactivated, so we rely on code to never reference
// the bad one.
func TestRazorpayPlanIDs_TypoPlanAbsent(t *testing.T) {
	const typoPlanID = "plan_SgT0sK508QF1iR"
	for key, id := range RazorpayPlanIDs {
		if id == typoPlanID {
			t.Fatalf("typo plan %q must not be referenced (found at key %q)", typoPlanID, key)
		}
	}
}
