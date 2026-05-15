package handlers

// agent_action_hobby_plus_test.go — coverage for the agent_action strings
// that route off-tier callers to the right upgrade step.
//
// 2026-05-15 (W12 pricing pass): multi-env was rolled back to Pro+. This
// test file was originally the FIX-R16 lock-in for hobby_plus naming;
// the multi-env case now names Pro instead. The deployment-cap routing
// (hobby → hobby_plus) stays put: hobby_plus is still a real internal
// upsell step for the 1-deploy cap, just no longer the multi-env unlock.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAgentActionMultiEnvUpgradeRequired_PointsAtPro pins the W12 update:
// the multi-env wall names Pro because it is now the cheapest tier that
// unlocks staging/production envs. (Was Hobby Plus before 2026-05-15.)
func TestAgentActionMultiEnvUpgradeRequired_PointsAtPro(t *testing.T) {
	got := AgentActionMultiEnvUpgradeRequired
	assert.Contains(t, got, "Pro",
		"multi-env upgrade copy must name Pro — it's the cheapest tier with multi-env vault as of 2026-05-15")
	assert.NotContains(t, got, "Hobby Plus",
		"multi-env upgrade copy must NOT name Hobby Plus — that tier was rolled back to production-only on 2026-05-15")
	assert.Contains(t, got, "$49",
		"multi-env upgrade copy must include the $49/mo Pro price so the LLM agent can quote it to the user")
	assert.Contains(t, got, "https://instanode.dev/",
		"contract: agent_action must contain a full https://instanode.dev/ URL")
}

// TestNewAgentActionDeploymentLimitReached_HobbyPointsAtHobbyPlus pins
// the deploy-cap routing: a hobby caller hitting their 1-deploy cap is
// still nudged to Hobby Plus (2 deploys), not Pro (10 deploys), since
// hobby_plus remains a real upsell step on storage + restore + 2nd
// deploy + custom domain — just no longer on multi-env.
func TestNewAgentActionDeploymentLimitReached_HobbyPointsAtHobbyPlus(t *testing.T) {
	hobbyCopy := newAgentActionDeploymentLimitReached("hobby", 1)
	assert.Contains(t, hobbyCopy, "Hobby Plus",
		"hobby caller hitting deploy cap should be routed to Hobby Plus (closer step)")
	assert.Contains(t, hobbyCopy, "2 deployments",
		"hobby copy must name the Hobby Plus deployment cap (2) so the user knows what they get")

	hobbyPlusCopy := newAgentActionDeploymentLimitReached("hobby_plus", 2)
	assert.Contains(t, hobbyPlusCopy, "Pro",
		"hobby_plus caller hitting deploy cap should be routed up to Pro (next real step)")
	assert.Contains(t, hobbyPlusCopy, "10 deployments")

	// Yearly variants must canonicalize and route the same way.
	hobbyYearlyCopy := newAgentActionDeploymentLimitReached("hobby_yearly", 1)
	assert.Contains(t, hobbyYearlyCopy, "Hobby Plus",
		"hobby_yearly canonicalizes to hobby — same Hobby Plus nudge")

	// Anonymous/free both have a 0-deploy cap. The 402 fires before the
	// caller even reaches /deploy/new, but if it ever does, the copy must
	// still point at the cheapest step that unlocks deploys.
	anonCopy := newAgentActionDeploymentLimitReached("anonymous", 0)
	assert.Contains(t, anonCopy, "Hobby Plus",
		"anonymous caller surfaced this copy should also see the closest unlock")
}

// TestAgentActionMultiEnvUpgradeRequired_UnderTweetCeiling — the U3
// contract requires < 280 chars. The W12 Pro rewrite must stay under
// budget (asserted globally by TestAgentActionContract, but the rewrite
// gets a focused assertion here too so a regression points at this PR).
func TestAgentActionMultiEnvUpgradeRequired_UnderTweetCeiling(t *testing.T) {
	got := AgentActionMultiEnvUpgradeRequired
	assert.Less(t, len(got), 280,
		"AgentActionMultiEnvUpgradeRequired must stay under the 280-char tweet ceiling so the LLM agent reproduces it verbatim. Got %d chars: %q",
		len(got), got)
	assert.True(t, strings.HasPrefix(got, "Tell the user"),
		"U3 contract: must open with 'Tell the user'")
}
