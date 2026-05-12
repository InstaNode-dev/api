// Package logctx is a TEMPORARY STUB for track 2 of the observability rollout
// (OBSERVABILITY-PLAN-2026-05-12.md). The real package will land at
// `instant.dev/common/logctx`. Once track 2 merges, this file is deleted and
// every import is rewritten to point at common.
//
// The stub mirrors only the subset of the future API the worker actually
// calls: NewHandler, WithTID, TIDFromContext, WithTraceID, TraceIDFromContext,
// WithTeamID, TeamIDFromContext. Each setter stamps a value on the ctx; the
// handler injects every value found on the ctx into the slog record.
//
// TODO(obs): delete after track 2 lands; rewrite imports to common/logctx.
package logctx

import (
	"context"
	"log/slog"
)

// ctxKey is the unexported context-key type used by all setters/getters so
// only this package can read or write the values.
type ctxKey int

const (
	keyTID ctxKey = iota + 1
	keyTraceID
	keyTeamID
)

// WithTID returns a new context with the given task / job id stamped on it.
// The slog handler returned by NewHandler will emit it as `tid=<id>` on every
// log line written through a logger that uses the handler.
func WithTID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, keyTID, id)
}

// TIDFromContext returns the value previously set by WithTID, or "" if none.
func TIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(keyTID).(string)
	return v
}

// WithTraceID returns a new context with the given trace id stamped on it.
func WithTraceID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, keyTraceID, id)
}

// TraceIDFromContext returns the value previously set by WithTraceID, or "".
func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(keyTraceID).(string)
	return v
}

// WithTeamID returns a new context with the given team id stamped on it.
func WithTeamID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, keyTeamID, id)
}

// TeamIDFromContext returns the value previously set by WithTeamID, or "".
func TeamIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(keyTeamID).(string)
	return v
}

// Handler wraps an inner slog.Handler and adds service + commit_id + ctx-
// scoped fields (tid, trace_id, team_id) to every record. Fields with an
// empty value are still emitted so log queries can be written against a
// stable schema.
type Handler struct {
	inner    slog.Handler
	service  string
	commitID string
}

// NewHandler returns a slog.Handler that wraps inner. The service name is
// hardcoded per binary ("worker") and the commit_id is read once at
// construction time from buildinfo.GitSHA (no per-record allocation).
func NewHandler(service, commitID string, inner slog.Handler) *Handler {
	return &Handler{inner: inner, service: service, commitID: commitID}
}

// Enabled mirrors the inner handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle adds the per-process and per-context attributes, then delegates.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(
		slog.String("service", h.service),
		slog.String("commit_id", h.commitID),
		slog.String("tid", TIDFromContext(ctx)),
		slog.String("trace_id", TraceIDFromContext(ctx)),
		slog.String("team_id", TeamIDFromContext(ctx)),
	)
	return h.inner.Handle(ctx, r)
}

// WithAttrs returns a new handler whose inner handler has the additional
// attrs attached.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{inner: h.inner.WithAttrs(attrs), service: h.service, commitID: h.commitID}
}

// WithGroup returns a new handler whose inner handler is grouped.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name), service: h.service, commitID: h.commitID}
}
