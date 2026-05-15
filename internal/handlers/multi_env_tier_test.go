package handlers

// multi_env_tier_test.go — coverage for the multiEnvTierAllowed gate that
// every env-aware handler (stack promote, families/bulk-twin, vault copy,
// twin, pause/resume) consults before letting the caller proceed.
//
// 2026-05-15 (W12 pricing pass): hobby_plus was rolled back to
// production-only. Multi-env is now Pro+ only. The W11-era FIX-A6/Q23
// granted hobby_plus the multi-env unlock; the W12 pricing pass walked
// that back to make Pro the cheapest multi-env tier. See the file-level
// comment on multiEnvTierAllowed in stack.go for the why.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMultiEnvTierAllowed_ProAndAbove pins the W12 posture: multi-env is
// Pro+ only. Hobby Plus joins Hobby/Anonymous/Free in the blocked set.
func TestMultiEnvTierAllowed_ProAndAbove(t *testing.T) {
	cases := []struct {
		tier    string
		allowed bool
		reason  string
	}{
		{"anonymous", false, "anonymous has no vault, no multi-env"},
		{"free", false, "free mirrors anonymous"},
		{"hobby", false, "hobby is production-only — Pro is the multi-env unlock"},
		{"hobby_plus", false, "hobby_plus rolled back to production-only on 2026-05-15"},
		{"hobby_plus_yearly", false, "hobby_plus_yearly canonicalizes to hobby_plus"},
		{"pro", true, "pro is the cheapest multi-env tier (W12)"},
		{"pro_yearly", true, "pro_yearly defensive — canonicalizes to pro"},
		{"team", true, "team has no env allowlist (unlimited)"},
		{"team_yearly", true, "team_yearly defensive"},
		{"growth", true, "growth has no env allowlist (unlimited)"},
		{"growth_yearly", true, "growth_yearly defensive — canonicalizer strips _yearly"},
		{"", false, "empty tier defaults to blocked"},
		{"nonsense_tier", false, "unknown tier defaults to blocked"},
	}

	for _, tc := range cases {
		t.Run(tc.tier, func(t *testing.T) {
			assert.Equal(t, tc.allowed, multiEnvTierAllowed(tc.tier),
				"multiEnvTierAllowed(%q): %s", tc.tier, tc.reason)
		})
	}
}
