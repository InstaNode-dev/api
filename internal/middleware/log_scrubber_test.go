package middleware_test

// log_scrubber_test.go — verifies that the slog handler wrapper rewrites
// occurrences of ADMIN_PATH_PREFIX with "<ADMIN>" in every log emission.
//
// This is the layer-5 piece of the admin defense-in-depth task. The
// rate-limit + audit middlewares hide the prefix from the wire and from
// audit_log rows. The scrubber hides the prefix from the global slog
// pipeline — request-id middleware, Fiber's request logger, NewRelic
// transaction names that bubble through slog, panic-recovery messages
// that quote OriginalURL, etc.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// captureLogger builds a slog.Logger that emits JSON lines into buf,
// wrapping the JSON handler in the admin-prefix scrubber. Returns the
// logger + the buffer the test reads back from.
func captureLogger(prefix string) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	scrubbed := middleware.NewLogScrubber(base, prefix)
	return slog.New(scrubbed), &buf
}

// readLastLine decodes the most recent JSON record written to buf and
// returns it as a generic map. Lets tests assert on field values without
// caring about the surrounding noise (time, level, source).
func readLastLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	require.NotEmpty(t, lines, "no log line emitted")
	last := lines[len(lines)-1]
	var out map[string]any
	require.NoError(t, json.Unmarshal(last, &out), "last log line: %s", string(last))
	return out
}

// TestLogScrubber_PrefixInURLAttr_Replaced is the canonical case from the
// task brief: "/api/v1/abc123<...>/customers/foo → /api/v1/<ADMIN>/customers/foo".
// We emit a slog.Info line with a "url" string attribute containing the
// admin prefix and assert the persisted record has the prefix replaced
// with the sentinel.
func TestLogScrubber_PrefixInURLAttr_Replaced(t *testing.T) {
	prefix := strings.Repeat("a", 32) // canonical 32-char alphanumeric prefix
	logger, buf := captureLogger(prefix)

	logger.Info("request.received", "url", "/api/v1/"+prefix+"/customers/foo")

	line := readLastLine(t, buf)
	url, _ := line["url"].(string)
	assert.Equal(t, "/api/v1/<ADMIN>/customers/foo", url,
		"the scrubber MUST replace the prefix with <ADMIN> in the persisted URL")
	// And the raw prefix must not appear anywhere in the emitted JSON.
	assert.NotContains(t, buf.String(), prefix,
		"the raw prefix must not appear in any field of the emitted JSON")
}

// TestLogScrubber_PrefixInMessageBody_Replaced — the scrubber must also
// rewrite the record's Message field, not just attributes. Fiber's request
// logger formats the URL into the message string for some configurations.
func TestLogScrubber_PrefixInMessageBody_Replaced(t *testing.T) {
	prefix := strings.Repeat("b", 32)
	logger, buf := captureLogger(prefix)

	logger.Info("hit on /api/v1/" + prefix + "/customers")

	line := readLastLine(t, buf)
	msg, _ := line["msg"].(string)
	assert.Equal(t, "hit on /api/v1/<ADMIN>/customers", msg)
	assert.NotContains(t, buf.String(), prefix)
}

// TestLogScrubber_EmptyPrefix_Passthrough — when ADMIN_PATH_PREFIX is
// empty (admin surface disabled), the scrubber MUST be a pure passthrough.
// No allocation, no sentinel substitution. This is the closed-by-default
// state for dev / CI environments that never set the env var.
func TestLogScrubber_EmptyPrefix_Passthrough(t *testing.T) {
	logger, buf := captureLogger("")

	logger.Info("request.received", "url", "/api/v1/admin/customers")

	line := readLastLine(t, buf)
	url, _ := line["url"].(string)
	assert.Equal(t, "/api/v1/admin/customers", url,
		"with empty secret, the scrubber MUST be a passthrough — no sentinel substitution")
	assert.NotContains(t, buf.String(), "<ADMIN>")
}

// TestLogScrubber_NonStringAttrsUntouched — int / bool / time values must
// pass through unchanged. Only string-valued payloads are scrubbed. This
// pins the contract that the scrubber doesn't accidentally rewrite a
// status code or duration measurement.
func TestLogScrubber_NonStringAttrsUntouched(t *testing.T) {
	prefix := strings.Repeat("c", 32)
	logger, buf := captureLogger(prefix)

	logger.Info("request.received",
		"status", 200,
		"latency_ms", 42,
		"ok", true,
		"path", "/api/v1/"+prefix+"/customers", // string — should scrub
	)

	line := readLastLine(t, buf)
	assert.EqualValues(t, 200, line["status"])
	assert.EqualValues(t, 42, line["latency_ms"])
	assert.Equal(t, true, line["ok"])
	assert.Equal(t, "/api/v1/<ADMIN>/customers", line["path"])
}

// TestLogScrubber_MultipleAttrsAllScrubbed — every string attribute
// carrying the prefix must be scrubbed in one log line, not just the
// first one encountered.
func TestLogScrubber_MultipleAttrsAllScrubbed(t *testing.T) {
	prefix := strings.Repeat("d", 32)
	logger, buf := captureLogger(prefix)

	logger.Info("request.received",
		"path", "/api/v1/"+prefix+"/customers/x",
		"referrer", "https://example.com/api/v1/"+prefix+"/customers",
		"note", "the prefix "+prefix+" appears here too",
	)

	line := readLastLine(t, buf)
	assert.Equal(t, "/api/v1/<ADMIN>/customers/x", line["path"])
	assert.Equal(t, "https://example.com/api/v1/<ADMIN>/customers", line["referrer"])
	assert.Equal(t, "the prefix <ADMIN> appears here too", line["note"])
	assert.NotContains(t, buf.String(), prefix,
		"after scrubbing, the raw prefix must not appear in any field")
}

// TestLogScrubber_NestedGroups_PrefixesScrubbed — slog groups (nested
// attribute namespaces) must also have their string children scrubbed.
// This is the regression test that says: "if a future logger emits the
// admin URL inside a group { request { url } }, the scrubber still
// catches it."
func TestLogScrubber_NestedGroups_PrefixesScrubbed(t *testing.T) {
	prefix := strings.Repeat("e", 32)
	logger, buf := captureLogger(prefix)

	logger.Info("request.received",
		slog.Group("http",
			slog.String("url", "/api/v1/"+prefix+"/customers"),
			slog.String("method", "GET"),
		),
	)
	assert.NotContains(t, buf.String(), prefix,
		"the prefix must not survive scrubbing even inside a slog.Group")
	assert.Contains(t, buf.String(), "<ADMIN>")
}

// TestLogScrubber_JWTPattern_Untouched — REGRESSION test for the contract
// that the new scrubber does NOT break existing scrubs (point 6 of the
// task brief). The scrubber operates ONLY on ADMIN_PATH_PREFIX values;
// JWT-shaped tokens, bearer prefixes, and other secret patterns flow
// through untouched. The codebase has separate (future) machinery for
// those — what we're guarding here is that the admin-prefix scrubber
// doesn't accidentally cargo-cult-redact unrelated strings, e.g. via an
// overly-broad regex.
func TestLogScrubber_JWTPattern_Untouched(t *testing.T) {
	prefix := strings.Repeat("f", 32)
	logger, buf := captureLogger(prefix)

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abc"
	logger.Info("auth",
		"jwt", jwt,
		"path", "/api/v1/"+prefix+"/customers",
	)
	line := readLastLine(t, buf)
	assert.Equal(t, jwt, line["jwt"],
		"the admin-prefix scrubber must NOT touch JWT-shaped strings — only the configured prefix")
	assert.Equal(t, "/api/v1/<ADMIN>/customers", line["path"])
}

// TestScrubAdminPath_Helper — exercise the free-function helper used by
// one-off call sites that want to scrub a string without going through
// the slog handler.
func TestScrubAdminPath_Helper(t *testing.T) {
	prefix := strings.Repeat("g", 32)
	in := "POST /api/v1/" + prefix + "/customers/00000000-0000-0000-0000-000000000000/tier"
	out := middleware.ScrubAdminPath(in, prefix)
	assert.Equal(t, "POST /api/v1/<ADMIN>/customers/00000000-0000-0000-0000-000000000000/tier", out)

	// Empty secret => passthrough.
	assert.Equal(t, in, middleware.ScrubAdminPath(in, ""))
	// Empty input => passthrough.
	assert.Equal(t, "", middleware.ScrubAdminPath("", prefix))
}

// TestLogScrubber_PassesThroughEnabled — wrapping must not alter the
// emitting decision; what the base handler accepts, the wrapper accepts.
func TestLogScrubber_PassesThroughEnabled(t *testing.T) {
	prefix := strings.Repeat("h", 32)
	base := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	scrub := middleware.NewLogScrubber(base, prefix)
	assert.False(t, scrub.Enabled(context.Background(), slog.LevelDebug),
		"Enabled MUST forward the underlying handler's decision")
	assert.True(t, scrub.Enabled(context.Background(), slog.LevelError))
}
