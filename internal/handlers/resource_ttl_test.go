package handlers

import (
	"testing"
	"time"
)

func TestResourceExpiryForTier(t *testing.T) {
	now := time.Now().UTC()
	// Ephemeral tiers get a ~24h expiry.
	for _, tier := range []string{"anonymous", "free"} {
		got := resourceExpiryForTier(tier)
		if got == nil {
			t.Fatalf("%s: expected non-nil expiry (24h TTL), got nil", tier)
		}
		d := got.Sub(now)
		if d < 23*time.Hour || d > 25*time.Hour {
			t.Errorf("%s: expiry %v from now; want ~24h", tier, d)
		}
	}
	// Paid tiers are permanent (nil).
	for _, tier := range []string{"hobby", "hobby_plus", "pro", "growth", "team"} {
		if got := resourceExpiryForTier(tier); got != nil {
			t.Errorf("%s: expected nil (permanent), got %v", tier, *got)
		}
	}
}
