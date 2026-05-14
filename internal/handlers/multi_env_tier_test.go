package handlers

// multi_env_tier_test.go — coverage for the multiEnvTierAllowed gate that
// every env-aware handler (stack promote, families/bulk-twin, vault copy,
// twin, pause/resume) consults before letting the caller proceed.
//
// FIX-A6 / FIX-Q23 (W11) extended this from `pro | team | growth` to also
// include `hobby_plus` once plans.yaml grew a vault_envs_allowed list of
// development/staging/production for that tier. The test pins the new
// behaviour so a future refactor (e.g. moving the policy to plans.yaml
// `features.multi_env`) does not silently regress.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMultiEnvTierAllowed_HobbyPlusUnlocked is the FIX-A6 lock-in: the
// hobby_plus tier (and its yearly variant, defensively) must clear the
// multi-env gate. Hobby / anonymous / free stay blocked — they only have
// vault_envs_allowed: ["production"], so multi-env workflows are still
// the differentiator that justifies the $19/mo step up.
func TestMultiEnvTierAllowed_HobbyPlusUnlocked(t *testing.T) {
	cases := []struct {
		tier    string
		allowed bool
		reason  string
	}{
		{"anonymous", false, "anonymous has no vault, no multi-env"},
		{"free", false, "free mirrors anonymous"},
		{"hobby", false, "hobby is production-only — multi-env is the upgrade lever"},
		{"hobby_plus", true, "hobby_plus has [development, staging, production] — FIX-A6 unlock"},
		{"hobby_plus_yearly", true, "hobby_plus_yearly defensive — canonicalizes to hobby_plus"},
		{"pro", true, "pro has no env allowlist (unlimited)"},
		{"pro_yearly", true, "pro_yearly defensive"},
		{"team", true, "team has no env allowlist (unlimited)"},
		{"team_yearly", true, "team_yearly defensive"},
		{"growth", true, "growth has no env allowlist (unlimited)"},
		{"growth_yearly", true, "growth_yearly defensive — though no growth_yearly exists today, the canonicalizer still strips _yearly"},
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
