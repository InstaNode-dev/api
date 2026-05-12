// Package logctx provides a context-aware slog.Handler wrapper that injects
// observability fields (service, commit_id, trace_id, team_id, tid) into every
// log record automatically, plus typed context setters/getters for those
// fields.
//
// STUB: this is a minimal vendored copy of what will become
// instant.dev/common/logctx once track 2 of the observability rollout merges.
// After that PR lands, callers should switch their imports to
// instant.dev/common/logctx and this directory should be deleted.
//
// Scope of this stub: only the surface area the provisioner service actually
// uses — NewHandler, WithTraceID, TraceID. The full common/logctx package
// will also expose WithTeamID, WithRequestID, WithTID, etc. — those are not
// needed here yet because the provisioner has no team/auth context.
package logctx

import (
	"context"
	"log/slog"

	"instant.dev/provisioner/internal/_obs_stubs/buildinfo"
)

// ctxKey is a private, comparable type for context keys so we never collide
// with other packages that stash values on the same ctx.
type ctxKey int

const (
	keyTraceID ctxKey = iota
)

// WithTraceID returns a child context with the given W3C trace ID attached.
// Empty traceID is a no-op — the parent context is returned unchanged so
// callers can pipe through values they extracted from gRPC metadata without
// branching on emptiness.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	if traceID == "" {
		return ctx
	}
	return context.WithValue(ctx, keyTraceID, traceID)
}

// TraceID extracts a previously-set trace ID, returning "" when absent.
// Never panics — safe to call on background or unrelated contexts.
func TraceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(keyTraceID).(string)
	return v
}

// handler wraps an underlying slog.Handler and stamps every Record with
// service, commit_id, build_time, version, and ctx-derived trace_id.
type handler struct {
	inner   slog.Handler
	service string
}

// NewHandler returns a slog.Handler that decorates `inner` with mandatory
// observability fields. The returned handler is safe for concurrent use.
//
// Typical wiring in a service's main():
//
//	slog.SetDefault(slog.New(logctx.NewHandler(
//	    "provisioner",
//	    slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}),
//	)))
func NewHandler(service string, inner slog.Handler) slog.Handler {
	return &handler{inner: inner, service: service}
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(
		slog.String("service", h.service),
		slog.String("commit_id", buildinfo.GitSHA),
		slog.String("build_time", buildinfo.BuildTime),
		slog.String("version", buildinfo.Version),
	)
	if tid := TraceID(ctx); tid != "" {
		r.AddAttrs(slog.String("trace_id", tid))
	}
	return h.inner.Handle(ctx, r)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{inner: h.inner.WithAttrs(attrs), service: h.service}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{inner: h.inner.WithGroup(name), service: h.service}
}
