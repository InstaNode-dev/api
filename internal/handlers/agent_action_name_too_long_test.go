package handlers

// agent_action_name_too_long_test.go — BUG-AUTH-006 regression.
//
// The `name_too_long` agent_action sentence used to say "exceeds 64
// characters" and "Shorten it to a short human label (1-64 chars)" — but
// the cap varies per endpoint:
//
//	- resource names      : 1-64 chars
//	- PAT (API key) names : 1-120 chars
//	- team names          : 1-200 chars
//
// PATs hit 120 → message reads "must be 120 characters or fewer" →
// agent_action contradicts message → agent renders contradiction to user.
// Fix: keep agent_action cap-free; tell the agent to read the
// endpoint-specific limit from `message`.

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentAction_NameTooLong_DoesNotBakeCap(t *testing.T) {
	src, err := os.ReadFile("helpers.go")
	require.NoError(t, err, "helpers.go must be readable from package dir")
	body := string(src)

	// Scope the assertion to just the name_too_long registry entry — not
	// other agent_action sentences in the same file.
	idx := strings.Index(body, `"name_too_long":`)
	require.GreaterOrEqual(t, idx, 0, "name_too_long entry not found in registry")
	end := idx + 600
	if end > len(body) {
		end = len(body)
	}
	window := body[idx:end]

	// BUG-AUTH-006: the sentence must NOT advertise "exceeds 64" or
	// "(1-64 chars)" — those contradict the actual handler caps for PAT
	// names (120) and team names (200).
	assert.NotContains(t, window, "exceeds 64 characters",
		"BUG-AUTH-006: agent_action must not bake the 64-char cap into the sentence")
	assert.NotContains(t, window, "(1-64 chars)",
		"BUG-AUTH-006: agent_action must not bake the 64-char range into the sentence")

	// Positive: the new sentence MUST tell the agent to read the
	// per-endpoint cap from the `message` field.
	assert.Contains(t, window, "message",
		"BUG-AUTH-006: agent_action must direct the agent to read the limit from `message`")
}
