package logctx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newTestHandler builds a logctx Handler over a fresh JSON handler writing to
// the returned buffer. Tests inspect the buffer after each emit. Level is set
// to Debug so nothing is filtered unless the test explicitly disables it.
func newTestHandler(t *testing.T, service string) (*bytes.Buffer, slog.Handler) {
	t.Helper()
	buf := &bytes.Buffer{}
	base := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return buf, NewHandler(service, base)
}

// decode reads the buffer as a single JSON-line slog record and returns the
// parsed map. Fails the test on bad JSON or empty input.
func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		t.Fatal("no log line emitted")
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("malformed log JSON %q: %v", raw, err)
	}
	return out
}

// newRecord constructs a slog.Record at INFO with a fixed message. Tests
// never need the source frame in this package.
func newRecord(msg string) slog.Record {
	return slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
}

// Test 1: with a bare context (no setters called) the handler emits service,
// commit_id, and empty values for the three ctx-sourced fields.
func TestHandler_NoCtx(t *testing.T) {
	buf, h := newTestHandler(t, "api")
	if err := h.Handle(context.Background(), newRecord("hello")); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	rec := decode(t, buf)
	if rec[FieldService] != "api" {
		t.Errorf("service = %v, want api", rec[FieldService])
	}
	// commit_id default is "dev" (see commitID()).
	if rec[FieldCommitID] != "dev" {
		t.Errorf("commit_id = %v, want dev", rec[FieldCommitID])
	}
	for _, f := range []string{FieldTraceID, FieldTID, FieldTeamID} {
		if got, ok := rec[f]; !ok || got != "" {
			t.Errorf("%s = %v present=%v, want empty string present=true", f, got, ok)
		}
	}
}

// Test 2: WithTraceID propagates through Handle.
func TestHandler_WithTraceID(t *testing.T) {
	buf, h := newTestHandler(t, "api")
	ctx := WithTraceID(context.Background(), "abc")
	if err := h.Handle(ctx, newRecord("hello")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rec := decode(t, buf)
	if rec[FieldTraceID] != "abc" {
		t.Errorf("trace_id = %v, want abc", rec[FieldTraceID])
	}
	// Sibling ctx fields untouched stay empty.
	if rec[FieldTID] != "" || rec[FieldTeamID] != "" {
		t.Errorf("sibling fields not empty: tid=%v team_id=%v", rec[FieldTID], rec[FieldTeamID])
	}
}

// Test 3: all three setters compose; all three values reach the record.
func TestHandler_WithAll(t *testing.T) {
	buf, h := newTestHandler(t, "worker")
	ctx := context.Background()
	ctx = WithTraceID(ctx, "trace-xyz")
	ctx = WithTID(ctx, "tid-77")
	ctx = WithTeamID(ctx, "team-42")
	if err := h.Handle(ctx, newRecord("hello")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rec := decode(t, buf)
	if rec[FieldService] != "worker" {
		t.Errorf("service = %v, want worker", rec[FieldService])
	}
	if rec[FieldTraceID] != "trace-xyz" {
		t.Errorf("trace_id = %v, want trace-xyz", rec[FieldTraceID])
	}
	if rec[FieldTID] != "tid-77" {
		t.Errorf("tid = %v, want tid-77", rec[FieldTID])
	}
	if rec[FieldTeamID] != "team-42" {
		t.Errorf("team_id = %v, want team-42", rec[FieldTeamID])
	}
}

// Test 4: nil ctx must NOT panic. The defensive nil checks in keys.go and
// handler.go are load-bearing — slog will hand us a nil ctx from
// (*Logger).Log when callers pass nil.
func TestHandler_NilCtx(t *testing.T) {
	buf, h := newTestHandler(t, "api")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Handle(nil ctx) panicked: %v", r)
		}
	}()
	// Pass an explicitly nil context. The handler must treat it as empty.
	if err := h.Handle(nil, newRecord("hello")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rec := decode(t, buf)
	if rec[FieldTraceID] != "" || rec[FieldTID] != "" || rec[FieldTeamID] != "" {
		t.Errorf("nil ctx produced non-empty fields: %v", rec)
	}
}

// disabledHandler is a stub base handler that always reports Enabled=false.
// Tests use it to verify the wrapper does not override the base's filtering.
type disabledHandler struct{ slog.Handler }

func (disabledHandler) Enabled(context.Context, slog.Level) bool { return false }

// Test 5: when the base handler says Enabled=false, the wrapper says false
// too. The wrapper must never widen the set of emitted records.
func TestHandler_EnabledPassthrough(t *testing.T) {
	base := disabledHandler{Handler: slog.NewJSONHandler(&bytes.Buffer{}, nil)}
	h := NewHandler("api", base)
	if h.Enabled(context.Background(), slog.LevelError) {
		t.Error("wrapper widened Enabled — base said false, wrapper said true")
	}
}

// Bonus: WithAttrs / WithGroup preserve the injected service+commit_id on
// the returned child handler. Belt-and-braces guard against regressions
// where someone refactors the struct and forgets to copy the fields.
func TestHandler_WithAttrsPreservesService(t *testing.T) {
	buf, h := newTestHandler(t, "provisioner")
	child := h.WithAttrs([]slog.Attr{slog.String("extra", "v")})
	if err := child.Handle(context.Background(), newRecord("hi")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rec := decode(t, buf)
	if rec[FieldService] != "provisioner" {
		t.Errorf("WithAttrs dropped service: %v", rec[FieldService])
	}
	if rec["extra"] != "v" {
		t.Errorf("WithAttrs dropped extra attr")
	}
}
