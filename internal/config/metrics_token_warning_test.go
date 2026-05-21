package config

// metrics_token_warning_test.go — SRR security-cluster 2026-05-21 /
// C19 P0 / PB03.
//
// /metrics is publicly readable when METRICS_TOKEN is unset (router
// already has the gate — see router.go:404-416). Silent fallthrough hid
// the live prod gap on 2026-05-21 where the env var was missing for
// weeks. This test locks in the startup-time WARN so a future "minor
// cleanup" of the boot sequence can't accidentally strip the operator
// signal.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	tfyrequire "github.com/stretchr/testify/require"
)

// captureSlog redirects slog to an in-memory buffer for the duration of
// fn, returning the captured JSON log lines. Restores the default
// handler on exit.
func captureSlog(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	defer slog.SetDefault(prev)

	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	fn()
	// Force-flush by emitting (and discarding) one extra record then
	// scanning. JSON handler writes synchronously so this is a no-op
	// belt-and-suspenders.
	_ = context.Background() // silence unused import if go list strips

	var out []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// TestWarnIfMetricsTokenMissing_Prod_EmitsWarning asserts the WARN line
// fires when ENVIRONMENT=production and MetricsToken is empty.
func TestWarnIfMetricsTokenMissing_Prod_EmitsWarning(t *testing.T) {
	cfg := &Config{Environment: "production", MetricsToken: ""}
	logs := captureSlog(t, func() { warnIfMetricsTokenMissing(cfg) })

	tfyrequire.NotEmpty(t, logs, "warnIfMetricsTokenMissing must emit a slog line when prod + token missing")

	found := false
	for _, l := range logs {
		if l["msg"] == "config.metrics_token.missing" && l["level"] == "WARN" {
			found = true
			assert.Contains(t, l["impact"], "publicly readable",
				"impact field must explain why the absent token is a security gap")
			assert.Contains(t, l["fix"], "METRICS_TOKEN",
				"fix field must reference the env var operators need to set")
		}
	}
	assert.True(t, found, "expected a config.metrics_token.missing WARN line; got %v", logs)
}

// TestWarnIfMetricsTokenMissing_DevSilent asserts the WARN is NOT
// emitted in development — open metrics is the intentional dev
// affordance and we don't want to add log noise to every local boot.
func TestWarnIfMetricsTokenMissing_DevSilent(t *testing.T) {
	cfg := &Config{Environment: "development", MetricsToken: ""}
	logs := captureSlog(t, func() { warnIfMetricsTokenMissing(cfg) })
	for _, l := range logs {
		assert.NotEqual(t, "config.metrics_token.missing", l["msg"],
			"dev must not emit the metrics-token WARN")
	}
}

// TestWarnIfMetricsTokenMissing_TokenSet_Silent asserts that once the
// operator sets METRICS_TOKEN, the WARN goes away — i.e. the WARN is a
// remediable signal, not noise.
func TestWarnIfMetricsTokenMissing_TokenSet_Silent(t *testing.T) {
	cfg := &Config{Environment: "production", MetricsToken: "deadbeef" + strings.Repeat("0", 56)}
	logs := captureSlog(t, func() { warnIfMetricsTokenMissing(cfg) })
	for _, l := range logs {
		assert.NotEqual(t, "config.metrics_token.missing", l["msg"],
			"setting METRICS_TOKEN must silence the WARN")
	}
}

// TestWarnIfMetricsTokenMissing_StagingEmits asserts the WARN fires for
// any non-dev environment label — staging is a real prod-shape deploy
// and must be flagged the same way. This prevents the silent-staging
// gap (rule 11 multi-env-gate).
func TestWarnIfMetricsTokenMissing_StagingEmits(t *testing.T) {
	cfg := &Config{Environment: "staging", MetricsToken: ""}
	logs := captureSlog(t, func() { warnIfMetricsTokenMissing(cfg) })

	found := false
	for _, l := range logs {
		if l["msg"] == "config.metrics_token.missing" {
			found = true
		}
	}
	assert.True(t, found, "staging must also emit the WARN — non-dev environments are prod-shape")
}
