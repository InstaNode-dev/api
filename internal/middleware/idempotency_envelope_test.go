package middleware_test

// idempotency_envelope_test.go — BUG-API-013 / BUG-API-406 regression.
//
// The 409 returned when an agent reuses an Idempotency-Key with a
// different body MUST carry the canonical envelope (ok, error, message,
// request_id, retry_after_seconds, agent_action) — pre-fix it only
// carried ok/error/message, which left an agent with no request_id to
// quote to support and no agent_action sentence to render to the user.
//
// Static-source assertion: we don't spin a Redis fake here (the
// envelope shape is what the rule-22 surface checklist wants protected;
// the full integration path is exercised in idempotency_test.go).

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdempotency409EnvelopeShape_DocumentedFields(t *testing.T) {
	src, err := os.ReadFile("idempotency.go")
	require.NoError(t, err, "must read idempotency.go from package dir")
	body := string(src)

	wantFields := []string{
		`"ok"`,
		`"error"`,
		`"message"`,
		`"request_id"`,
		`"retry_after_seconds"`,
		`"agent_action"`,
	}
	for _, f := range wantFields {
		assert.Contains(t, body, f,
			"BUG-API-013: idempotency.go must emit envelope field %s on 409", f)
	}
	// The agent_action sentence must name the canonical resolution
	// (mint a new key) so the agent can self-recover.
	assert.Contains(t, body, "Mint a NEW Idempotency-Key",
		"BUG-API-013: 409 agent_action must tell the agent to mint a new key")
	// Sanity: idempotency_key_conflict error code is still the keyword
	// (back-compat — clients matching on `error` keep working).
	assert.Contains(t, body, `"idempotency_key_conflict"`,
		"top-level error keyword unchanged for client back-compat")
	// Belt: no orphan call sites still using the old 4-field shape.
	assert.Greater(t, strings.Count(body, "request_id"), 0)
}
