package plans_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"instant.dev/internal/plans"
)

// TestRank_TotalOrder asserts the totally-ordered rank for every known tier.
// Plan ladder is anchored to plans.yaml pricing: anonymous=0, free=1, hobby=2,
// hobby_plus=3, pro=4, growth=5, team=6 (pro $49 < growth $99 < team $199).
func TestRank_TotalOrder(t *testing.T) {
	cases := []struct {
		tier string
		want int
	}{
		{"anonymous", 0},
		{"free", 1},
		{"hobby", 2},
		{"hobby_plus", 3},
		{"pro", 4},
		{"growth", 5},
		{"team", 6},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, plans.Rank(c.tier), "Rank(%q)", c.tier)
	}
}

// TestRank_UnknownTier_ReturnsSentinel guards CLAUDE.md rule 22: a typo or
// new-but-not-registered tier must NOT silently rank as 0 (anonymous) — it
// must return -1 so transition-direction callers can refuse to compare.
func TestRank_UnknownTier_ReturnsSentinel(t *testing.T) {
	for _, tier := range []string{"", "enterprise", "ultra", "garbage"} {
		assert.Equal(t, -1, plans.Rank(tier), "Rank(%q) must be -1", tier)
	}
}

// TestRank_YearlyVariants_NotAutoNormalised documents the contract: yearly
// variants do NOT auto-collapse to their base rank. Callers must pass them
// through CanonicalTier first if they want "pro_yearly" to rank as "pro".
func TestRank_YearlyVariants_NotAutoNormalised(t *testing.T) {
	// pro_yearly is a distinct registry entry, NOT auto-normalised.
	// Whatever its rank is, after CanonicalTier it must match "pro".
	assert.Equal(t, plans.Rank("pro"), plans.Rank(plans.CanonicalTier("pro_yearly")))
	assert.Equal(t, plans.Rank("hobby"), plans.Rank(plans.CanonicalTier("hobby_yearly")))
	assert.Equal(t, plans.Rank("hobby_plus"), plans.Rank(plans.CanonicalTier("hobby_plus_yearly")))
	assert.Equal(t, plans.Rank("team"), plans.Rank(plans.CanonicalTier("team_yearly")))
}

// TestRank_StrictlyIncreasing locks the price ladder invariant: each higher
// tier outranks every lower one. A future PR that re-orders the ladder must
// update this test in the same commit (rule 22).
func TestRank_StrictlyIncreasing(t *testing.T) {
	ladder := []string{"anonymous", "free", "hobby", "hobby_plus", "pro", "growth", "team"}
	for i := 1; i < len(ladder); i++ {
		assert.Greater(t, plans.Rank(ladder[i]), plans.Rank(ladder[i-1]),
			"Rank(%q) must be > Rank(%q)", ladder[i], ladder[i-1])
	}
}
