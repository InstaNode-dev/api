package middleware

// log_scrubber.go — slog handler wrapper that replaces the unguessable
// ADMIN_PATH_PREFIX value with the literal sentinel "<ADMIN>" anywhere it
// appears in string attributes on a log record.
//
// Why this exists:
//
//   The admin surface is registered under /api/v1/<ADMIN_PATH_PREFIX>/...
//   That prefix is a SECRET with the same blast radius as a session token
//   (see internal/router/router.go's defense-in-depth comment and
//   internal/config/config.go's AdminPathPrefix doc). Anything that emits
//   the request URL — slog, fiber's request_id stamp, otel spans, NR
//   transactions, panic traces — risks leaking that secret into the log
//   shipper, NR, OTel collector, or stderr. The same risk applies to a
//   401/403/500 from an admin route that bubbles a URL-bearing message
//   through fiber's ErrorHandler.
//
//   To close the leak surface uniformly, we wrap the global slog handler
//   with a Scrubber that walks every record's string attrs and rewrites
//   matches in place. This is one centralized choke-point rather than
//   N hand-scrubbed call sites — which means an engineer adding a new
//   `slog.Info("admin.foo", "url", c.OriginalURL())` line tomorrow can't
//   accidentally leak the prefix.
//
// Match policy:
//
//   Plain substring replacement against the configured secret. Not a
//   regex — the secret is alphanumeric (validated at config-load), so
//   there's no ambiguity. The literal value of the secret is replaced
//   with the literal sentinel "<ADMIN>" everywhere it appears in a
//   string attribute or in the message itself.
//
//   Empty / unset secret → handler is a pure pass-through (no scan, no
//   alloc). This is the closed-by-default state when ADMIN_PATH_PREFIX
//   is unset and the admin surface isn't even registered.
//
// Mirrors the JWT-style "replace secret with sentinel" pattern called out
// in the request_id middleware comment in router.go. The same scrubber
// could later be extended to redact bearer tokens / API keys via a
// matchers slice — we deliberately scope the v1 to ADMIN_PATH_PREFIX so
// the contract under test is minimal and grep-auditable.
//
// Test coverage:
//
//   1. /api/v1/abc123<...>/customers/foo → /api/v1/<ADMIN>/customers/foo
//      (the literal task scrub: prefix replaced inside a URL string attr).
//   2. Empty prefix → string passes through unchanged (no-op handler).
//   3. Multiple attrs all scrubbed (groups, nested, message body itself).
//   4. Non-string attrs untouched (int, bool, time, etc.).

import (
	"context"
	"log/slog"
	"strings"
)

// AdminScrubSentinel is the literal token written in place of any matched
// secret. Named so tests + audits can grep for the one source of truth.
// Mirrors the "<JWT>" / "<REDACTED>" sentinel style — short, unambiguous,
// and a non-URL-safe character ("<") so it never round-trips back into a
// live admin URL.
const AdminScrubSentinel = "<ADMIN>"

// LogScrubber wraps an underlying slog.Handler and rewrites any occurrence
// of secret inside string-valued attributes (and the message body) to
// AdminScrubSentinel before forwarding to the wrapped handler.
//
// Construct with NewLogScrubber. A zero LogScrubber is NOT safe — the
// nil base handler would panic on Handle.
type LogScrubber struct {
	base   slog.Handler
	secret string
}

// NewLogScrubber returns a slog.Handler that scrubs every occurrence of
// secret in every string attribute / message body before delegating to
// base. When secret is empty the returned handler is base unchanged —
// the scrubber adds zero overhead when ADMIN_PATH_PREFIX isn't set.
//
// base must not be nil. The expected wiring at main() is:
//
//	jsonH := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{...})
//	ctxH  := logctx.NewHandler("api", jsonH)
//	scrub := middleware.NewLogScrubber(ctxH, cfg.AdminPathPrefix)
//	slog.SetDefault(slog.New(scrub))
//
// Placing the scrubber on the OUTSIDE of the logctx handler is intentional:
// the scrub runs LAST, after every field (including the context-injected
// trace_id / team_id / service) is finalised, so a stray prefix value
// stamped through the context path also gets caught.
func NewLogScrubber(base slog.Handler, secret string) slog.Handler {
	if secret == "" {
		// Pass-through: nothing to scrub, don't introduce overhead.
		return base
	}
	return &LogScrubber{base: base, secret: secret}
}

// Enabled forwards to the wrapped handler unchanged — the wrapper must
// never change which records are emitted; that's the base handler's
// decision (per slog.Handler contract).
func (h *LogScrubber) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle scrubs the record before forwarding. The slog.Record is mutated
// in place via a builder pattern: we re-walk every attribute and rebuild
// the record with sanitized string values. Non-string values pass through
// untouched. The Message field is also scrubbed.
func (h *LogScrubber) Handle(ctx context.Context, r slog.Record) error {
	// Fast path: if the message + any attrs don't reference the secret
	// at all, we can skip the rebuild and forward the record unchanged.
	// (Common case — the secret is the admin prefix, only a tiny fraction
	// of records touch it.)
	if !h.containsSecret(r) {
		return h.base.Handle(ctx, r)
	}

	// Slow path: scrub the message + attrs. We can't mutate r.Attrs
	// directly (slog.Record doesn't expose a setter), so we rebuild a
	// fresh Record with the sanitized values.
	scrubbed := slog.NewRecord(r.Time, r.Level, h.scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		scrubbed.AddAttrs(h.scrubAttr(a))
		return true
	})
	return h.base.Handle(ctx, scrubbed)
}

// WithAttrs returns a new wrapper. We scrub the supplied attrs eagerly so
// child loggers (built via slog.Logger.With) carry sanitized fields. The
// secret is preserved on the new wrapper so subsequent Handle calls keep
// scrubbing.
func (h *LogScrubber) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = h.scrubAttr(a)
	}
	return &LogScrubber{base: h.base.WithAttrs(scrubbed), secret: h.secret}
}

// WithGroup returns a new wrapper around base.WithGroup. The secret is
// preserved on the new wrapper.
func (h *LogScrubber) WithGroup(name string) slog.Handler {
	return &LogScrubber{base: h.base.WithGroup(name), secret: h.secret}
}

// containsSecret reports whether the record's message or any string
// attribute contains the secret. Lets the fast path skip the rebuild
// allocation for records that don't touch the admin prefix at all.
func (h *LogScrubber) containsSecret(r slog.Record) bool {
	if strings.Contains(r.Message, h.secret) {
		return true
	}
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if h.attrContainsSecret(a) {
			found = true
			return false // stop iteration
		}
		return true
	})
	return found
}

// attrContainsSecret reports whether a single Attr's string-valued payload
// contains the secret. Recurses into LogValuer / Group attrs so a nested
// group that stuffs the prefix into a sub-field still gets caught.
func (h *LogScrubber) attrContainsSecret(a slog.Attr) bool {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return strings.Contains(v.String(), h.secret)
	case slog.KindGroup:
		for _, ga := range v.Group() {
			if h.attrContainsSecret(ga) {
				return true
			}
		}
	}
	return false
}

// scrubAttr returns a copy of a with every string-valued payload run
// through scrub. Non-string kinds pass through unchanged.
func (h *LogScrubber) scrubAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if !strings.Contains(s, h.secret) {
			return a
		}
		return slog.String(a.Key, h.scrub(s))
	case slog.KindGroup:
		groupAttrs := v.Group()
		scrubbed := make([]slog.Attr, len(groupAttrs))
		anyChanged := false
		for i, ga := range groupAttrs {
			scrubbed[i] = h.scrubAttr(ga)
			// Cheap heuristic: a scrubbed string attr has a different
			// raw String() than the source. For non-string kinds the
			// rebuild is a no-op, so they're trivially "unchanged."
			if ga.Value.Kind() == slog.KindString &&
				ga.Value.String() != scrubbed[i].Value.String() {
				anyChanged = true
			}
		}
		if !anyChanged {
			return a
		}
		// Re-wrap as a group attr. slog has no GroupValue helper that takes
		// []Attr; build via slog.Group which takes ...any.
		anyArgs := make([]any, len(scrubbed))
		for i, ga := range scrubbed {
			anyArgs[i] = ga
		}
		return slog.Group(a.Key, anyArgs...)
	}
	return a
}

// scrub does the literal substring replacement. Public-facing callers
// should use the handler — this exists for the rare case (tests, an ad-hoc
// log line in a hot path) where a caller wants the raw transform.
func (h *LogScrubber) scrub(s string) string {
	if h.secret == "" {
		return s
	}
	return strings.ReplaceAll(s, h.secret, AdminScrubSentinel)
}

// ScrubAdminPath is a free-function helper for callers that want to scrub
// a single string without going through the slog pipeline. Useful for one-
// off bug reports / panic-recovery messages. Returns s unchanged when
// secret is empty.
func ScrubAdminPath(s, secret string) string {
	if secret == "" || s == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, AdminScrubSentinel)
}
