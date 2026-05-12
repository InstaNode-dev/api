package logctx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"instant.dev/internal/obsstubs/buildinfo"
	"instant.dev/internal/obsstubs/logctx"
)

// TestHandler_StampsServiceAndCommitID asserts that the logctx.Handler
// wrapper applies the service+commit_id fields to every record without
// the caller having to pass them. This is the contract main.go relies
// on when it sets slog.Default to logctx.NewHandler("api", ...).
func TestHandler_StampsServiceAndCommitID(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	h := logctx.NewHandler("api", inner)
	log := slog.New(h)

	log.Info("hello")

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "api", got["service"])
	require.Equal(t, buildinfo.GitSHA, got["commit_id"])
}

// TestHandler_StampsCtxFields asserts trace_id/team_id/tid are lifted
// off the record context and emitted as JSON fields. This is the
// contract the LoggerContext middleware relies on.
func TestHandler_StampsCtxFields(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	log := slog.New(logctx.NewHandler("api", inner))

	ctx := logctx.WithTraceID(context.Background(), "req-1")
	ctx = logctx.WithTeamID(ctx, "team-1")
	ctx = logctx.WithTaskID(ctx, "tid-1")
	log.InfoContext(ctx, "ping")

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "req-1", got["trace_id"])
	require.Equal(t, "team-1", got["team_id"])
	require.Equal(t, "tid-1", got["tid"])
}

// TestHandler_OmitsEmptyCtxFields confirms unset ctx values are not
// emitted as empty strings — keeps JSON line size reasonable and avoids
// noisy dashboards that filter on `trace_id != ""`.
func TestHandler_OmitsEmptyCtxFields(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	log := slog.New(logctx.NewHandler("api", inner))

	log.Info("ping")

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	_, hasTrace := got["trace_id"]
	_, hasTeam := got["team_id"]
	_, hasTid := got["tid"]
	require.False(t, hasTrace)
	require.False(t, hasTeam)
	require.False(t, hasTid)
}

// TestDefaultLogger_AfterMainSetup mirrors the construction in main.go
// and asserts a JSON line emitted via slog.Default() actually carries
// the enrichment fields. Smoke test for the "slog default with logctx
// wrapper" requirement.
func TestDefaultLogger_AfterMainSetup(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo, AddSource: false})
	wrapped := logctx.NewHandler("api", base)

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(wrapped))

	ctx := logctx.WithTraceID(context.Background(), "smoke-req")
	slog.InfoContext(ctx, "boot")

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "api", got["service"])
	require.Equal(t, "smoke-req", got["trace_id"])

	// Confirm the wrapper exposes its service for reflective checks.
	require.Equal(t, "api", wrapped.Service())
}
