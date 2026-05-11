package plans

import (
	"fmt"
	"strings"
)

// RazorpayPlanIDs maps "{tier}_{currency}_{cycle}" to a Razorpay plan ID.
// Currency and cycle are lowercase.
//
// USD plans charge via international cards (default for non-IST users).
// INR plans charge via Indian-issued cards (shown to Asia/Kolkata timezone).
// Razorpay enforces currency/card matching at payment time.
var RazorpayPlanIDs = map[string]string{
	"hobby_usd_monthly": "plan_Sg2YcWj6hM5Ook",
	"hobby_usd_yearly":  "plan_Sg2aCGFGoeuxNS",
	"hobby_inr_monthly": "plan_SgT09xZkHcJing",
	"hobby_inr_yearly":  "plan_SgTAPVUusjHTB6",
}

// LookupPlanID resolves a Razorpay plan ID from tier, currency, and cycle.
// Returns an error if no plan exists for the combination.
func LookupPlanID(tier, currency, cycle string) (string, error) {
	key := fmt.Sprintf("%s_%s_%s",
		strings.ToLower(tier),
		strings.ToLower(currency),
		strings.ToLower(cycle),
	)
	id, ok := RazorpayPlanIDs[key]
	if !ok {
		return "", fmt.Errorf("no razorpay plan for %s", key)
	}
	return id, nil
}

// TierFromPlanID reverses the map: given a Razorpay plan ID, returns the tier.
// Used by the webhook to determine what tier a subscription belongs to.
func TierFromPlanID(planID string) (string, bool) {
	for key, id := range RazorpayPlanIDs {
		if id == planID {
			tier := strings.SplitN(key, "_", 2)[0]
			return tier, true
		}
	}
	return "", false
}
