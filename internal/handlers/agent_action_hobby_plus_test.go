package handlers

// agent_action_hobby_plus_test.go — FIX-R16 lock-in: the agent_action
// strings that hobby_plus structurally solves (multi-env workflows,
// hobby's 1-deploy cap) must reference Hobby Plus by name + the $19/mo
// price, not jump the user straight to Pro at $49/mo.
//
// The downstream LLM agent reproduces the agent_action string verbatim to
// the user. If the copy says "Upgrade to Pro" when "Upgrade to Hobby Plus"
// is the closer and cheaper next step, the agent leaks unnecessary money
// out of the wedge.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAgentActionMultiEnvUpgradeRequired_PointsAtHobbyPlus pins the
// FIX-R16 update — the multi-env wall mentions Hobby Plus by name because
// it's the cheapest tier that unlocks staging/production envs.
func TestAgentActionMultiEnvUpgradeRequired_PointsAtHobbyPlus(t *testing.T) {
	got := AgentActionMultiEnvUpgradeRequired
	assert.Contains(t, got, "Hobby Plus",
		"multi-env upgrade copy must name Hobby Plus — it's the cheapest tier with multi-env vault")
	assert.Contains(t, got, "$19",
		"multi-env upgrade copy must include the $19/mo price so the LLM agent can quote it to the user")
	assert.Contains(t, got, "https://instanode.dev/",
		"contract: agent_action must contain a full https://instanode.dev/ URL")
}

// TestNewAgentActionDeploymentLimitReached_HobbyPointsAtHobbyPlus pins
// the routing logic: a hobby caller hitting their 1-deploy cap should be
// nudged to Hobby Plus (2 deploys), not Pro (10 deploys). Pro stays the
// nudge once the caller is already on hobby_plus.
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
// contract requires < 280 chars. The Hobby Plus rewrite must stay under
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
