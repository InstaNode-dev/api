package handlers_test

// inject_message_id_final3_test.go — FINAL serial pass #3. Exercises the
// empty-id and unmarshal-error arms of injectMessageID (email_webhooks.go:452,
// 456) plus the happy path — pure function, no DB.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"instant.dev/internal/handlers"
)

func TestInjectMessageIDFinal3_Arms(t *testing.T) {
	body := []byte(`{"event":"delivered"}`)

	// empty messageID → body returned unchanged (email_webhooks.go:452-453).
	assert.Equal(t, body, handlers.InjectMessageIDForTest(body, ""))

	// unparseable body → returned unchanged (email_webhooks.go:456-457).
	bad := []byte(`{not json`)
	assert.Equal(t, bad, handlers.InjectMessageIDForTest(bad, "msg-123"))

	// happy path → message_id injected.
	out := string(handlers.InjectMessageIDForTest(body, "msg-123"))
	assert.True(t, strings.Contains(out, "message_id"), "message_id must be injected, got: %s", out)
	assert.True(t, strings.Contains(out, "msg-123"))
}
