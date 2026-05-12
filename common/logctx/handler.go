package logctx

import (
	"context"
	"log/slog"
	"os"
)

// Field-name constants — never inline these strings in tests or callers.
// The schema is part of our log contract and grep-ability across services
// requires that every Go file uses the same identifiers.
const (
	FieldService  = "service"
	FieldCommitID = "commit_id"
	FieldTraceID  = "trace_id"
	FieldTID      = "tid"
	FieldTeamID   = "team_id"
)

// commitID returns the build's git SHA. Track 1 of the observability rollout
// adds a real `instant.dev/common/buildinfo` package whose GitSHA var is set
// via `-ldflags -X`. Until that package merges, we fall back to the
// COMMIT_ID env var (set by the Dockerfile / k8s deployment) so this package
// does not block on track 1. The sentinel "dev" matches the buildinfo
// package's planned default so log readers see a single consistent value
// across both implementations.
func commitID() string {
	if v := os.Getenv("COMMIT_ID"); v != "" {
		return v
	}
	return "dev"
}

// Handler wraps an underlying slog.Handler and injects the five mandatory
// observability fields onto every record:
//
//	service    — constant supplied at construction time ("api" / "worker" / "provisioner")
//	commit_id  — git SHA of the running binary (compile-time or env)
//	trace_id   — pulled from ctx via TraceIDFromContext
//	tid        — pulled from ctx via TIDFromContext
//	team_id    — pulled from ctx via TeamIDFromContext
//
// Missing ctx fields are emitted as empty strings — never dropped — so log
// schema is stable across every line. A nil ctx is treated identically to
// context.Background; the handler MUST NOT panic on a nil ctx.
type Handler struct {
	base     slog.Handler
	service  string
	commitID string
}

// NewHandler wraps base so that every record emitted through the wrapper
// carries the five mandatory observability fields. The returned handler is
// safe for concurrent use to the same degree base is.
//
// service is the binary name ("api", "worker", "provisioner") and is emitted
// on every record. base is any slog.Handler — typically slog.NewJSONHandler
// over stdout with AddSource=true.
func NewHandler(service string, base slog.Handler) slog.Handler {
	return &Handler{
		base:     base,
		service:  service,
		commitID: commitID(),
	}
}

// Enabled forwards to the wrapped handler unchanged. Wrapping must not change
// which records get emitted — that decision belongs to the base handler's
// configured level.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle annotates the record with the five mandatory fields and forwards.
// A nil ctx is tolerated — getters return empty strings rather than panic.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	// AddAttrs mutates the record in place; the standard library reserves
	// the right to do this exactly once per Record value, which is fine
	// here because every record reaches the wrapper at most once.
	r.AddAttrs(
		slog.String(FieldService, h.service),
		slog.String(FieldCommitID, h.commitID),
		slog.String(FieldTraceID, TraceIDFromContext(ctx)),
		slog.String(FieldTID, TIDFromContext(ctx)),
		slog.String(FieldTeamID, TeamIDFromContext(ctx)),
	)
	return h.base.Handle(ctx, r)
}

// WithAttrs returns a new wrapper around base.WithAttrs(attrs). The injected
// service / commit_id stay attached to the new wrapper so child loggers
// (built via slog.Logger.With) still carry the mandatory fields.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{
		base:     h.base.WithAttrs(attrs),
		service:  h.service,
		commitID: h.commitID,
	}
}

// WithGroup returns a new wrapper around base.WithGroup(name).
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		base:     h.base.WithGroup(name),
		service:  h.service,
		commitID: h.commitID,
	}
}
