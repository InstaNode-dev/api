// Package logctx is a TEMPORARY local stub of the cross-service
// `instant.dev/common/logctx` package that Track 2 of the observability
// rollout introduces. It provides:
//
//   - Handler: a slog.Handler that wraps another handler and copies a
//     fixed set of fields (service, commit_id, trace_id, team_id, tid)
//     from the record's context onto every emitted log line.
//   - WithTraceID / WithTeamID / WithTaskID: context setters used by the
//     api's LoggerContext Fiber middleware (Track 3) and the worker's
//     ContextForJob helper (Track 4).
//
// TODO(obs-merge): delete this stub and switch imports to
// `instant.dev/common/logctx` once Track 2 lands on master. The exported
// surface here is the contract Track 2 must match.
package logctx

import (
	"context"
	"log/slog"

	"instant.dev/internal/obsstubs/buildinfo"
)

// Context keys are private types so callers cannot collide with the
// keyspace used here. Mirror Track 2's package exactly.
type (
	traceIDKey struct{}
	teamIDKey  struct{}
	taskIDKey  struct{}
)

// WithTraceID returns a child context carrying the given trace / request
// identifier. Empty strings are stored as empty strings (the handler
// elides empty fields, so callers don't need to guard).
func WithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, id)
}

// WithTeamID returns a child context carrying the authenticated team's UUID.
func WithTeamID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, teamIDKey{}, id)
}

// WithTaskID returns a child context carrying a River job task ID.
// Unused in the api service; the worker uses this via ContextForJob.
func WithTaskID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, taskIDKey{}, id)
}

// TraceID returns the trace/request ID stamped on ctx, or "" if unset.
func TraceID(ctx context.Context) string { return stringVal(ctx, traceIDKey{}) }

// TeamID returns the team ID stamped on ctx, or "" if unset.
func TeamID(ctx context.Context) string { return stringVal(ctx, teamIDKey{}) }

// TaskID returns the River task ID stamped on ctx, or "" if unset.
func TaskID(ctx context.Context) string { return stringVal(ctx, taskIDKey{}) }

func stringVal(ctx context.Context, k any) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(k).(string); ok {
		return v
	}
	return ""
}

// Handler is a slog.Handler that wraps an inner handler and decorates each
// record with a fixed set of fields read from the record's context plus
// the service name + commit_id baked in at construction.
//
// The decoration is implemented by calling Handle on a clone with the
// extra attributes attached via WithAttrs, so the inner handler retains
// its native formatting (JSON, text, etc.).
type Handler struct {
	inner   slog.Handler
	service string
}

// NewHandler wraps inner so every emitted record carries:
//
//	service=<service>  commit_id=<buildinfo.GitSHA>
//	trace_id=<ctx>     team_id=<ctx>     tid=<ctx>
//
// service is fixed at construction; commit_id is read from the
// buildinfo stub (overridden at link time in production builds).
func NewHandler(service string, inner slog.Handler) *Handler {
	return &Handler{inner: inner, service: service}
}

// Enabled delegates to the inner handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle copies trace_id / team_id / tid off the record's context (when
// present) and forwards the record with the enrichment attributes
// attached. service and commit_id are always present.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	attrs := []slog.Attr{
		slog.String("service", h.service),
		slog.String("commit_id", buildinfo.GitSHA),
	}
	if v := TraceID(ctx); v != "" {
		attrs = append(attrs, slog.String("trace_id", v))
	}
	if v := TeamID(ctx); v != "" {
		attrs = append(attrs, slog.String("team_id", v))
	}
	if v := TaskID(ctx); v != "" {
		attrs = append(attrs, slog.String("tid", v))
	}
	r.AddAttrs(attrs...)
	return h.inner.Handle(ctx, r)
}

// WithAttrs returns a new Handler whose inner handler has the given
// attrs pre-attached. service/commit_id stay on the outer enrichment.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{inner: h.inner.WithAttrs(attrs), service: h.service}
}

// WithGroup returns a new Handler whose inner handler is grouped.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name), service: h.service}
}

// Service returns the service name this handler stamps on every record.
// Exposed for the smoke test in api/main_test.go.
func (h *Handler) Service() string { return h.service }
