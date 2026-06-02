package handlers

import "time"

// ephemeralTierTTL is the lifetime of a newly-provisioned resource on an
// ephemeral (unpaid) tier. Per api/plans.yaml, anonymous and free are both
// "claimed-unpaid, 24h TTL, pay-from-day-one" — they share anonymous's exact
// limits and TTL; the only difference is audience.
const ephemeralTierTTL = 24 * time.Hour

// ephemeralTiers is the set of tiers whose resources auto-expire. Everything
// else (hobby, hobby_plus, pro, growth, team) is a paid tier whose resources
// are permanent until explicitly deleted.
var ephemeralTiers = map[string]bool{
	"anonymous": true,
	"free":      true,
}

// resourceExpiryForTier returns the expires_at to stamp on a newly-provisioned
// resource for the given tier: now()+ephemeralTierTTL for an ephemeral tier,
// nil (permanent) for a paid tier.
//
// Centralizes the TTL policy so every authenticated provision handler applies
// it identically. Closes bug bash 2026-06-02 #4: authenticated free-tier
// provisions hardcoded ExpiresAt=nil, so claimed-unpaid resources never
// expired despite plans.yaml's documented 24h TTL — letting a free user keep
// resources indefinitely without paying. Paid tiers are unaffected (nil).
func resourceExpiryForTier(tier string) *time.Time {
	if !ephemeralTiers[tier] {
		return nil
	}
	t := time.Now().UTC().Add(ephemeralTierTTL)
	return &t
}
