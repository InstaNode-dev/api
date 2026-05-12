// Package logctx provides a slog.Handler wrapper that auto-injects mandatory
// observability fields (service, commit_id, trace_id, tid, team_id) onto every
// log record by reading them from a context.Context.
//
// Setters and getters on this file are the only sanctioned way to put those
// fields onto a context; the handler in handler.go is the only sanctioned way
// to read them off again when emitting a record.
package logctx

import "context"

// Unexported context keys — these prevent collisions with other packages that
// might want to store strings on a context under the same name. Each type is
// a distinct empty struct so equality is identity, not value-based.
type (
	traceIDCtxKey struct{}
	tidCtxKey     struct{}
	teamIDCtxKey  struct{}
)

// WithTraceID returns a copy of ctx carrying the supplied trace_id. The trace
// id is the W3C TraceContext trace ID when an OpenTelemetry span is in flight,
// falling back to the upstream request_id for non-span paths. Passing an empty
// string is permitted and behaves like no annotation — the handler will emit
// an empty trace_id field.
func WithTraceID(ctx context.Context, v string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceIDCtxKey{}, v)
}

// TraceIDFromContext extracts the trace_id previously stored by WithTraceID.
// Returns an empty string when ctx is nil or carries no trace id — callers
// should NEVER panic on a missing field.
func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(traceIDCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// WithTID returns a copy of ctx carrying the supplied tid (River job task ID
// for worker jobs; empty for non-job code paths).
func WithTID(ctx context.Context, v string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, tidCtxKey{}, v)
}

// TIDFromContext extracts the tid previously stored by WithTID. Returns an
// empty string when absent or when ctx is nil.
func TIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(tidCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// WithTeamID returns a copy of ctx carrying the supplied team_id (the JWT
// team_id claim, propagated from the auth middleware).
func WithTeamID(ctx context.Context, v string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, teamIDCtxKey{}, v)
}

// TeamIDFromContext extracts the team_id previously stored by WithTeamID.
// Returns an empty string when absent (unauthenticated request) or when ctx
// is nil.
func TeamIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(teamIDCtxKey{}).(string); ok {
		return v
	}
	return ""
}
