package middleware

// admin_audit.go — after-response middleware that writes a structured
// `admin.access` audit_log row for every hit on an admin route, regardless
// of whether the request succeeded or was rejected.
//
// This is the FOURTH defense-in-depth layer (third gate is rate-limit,
// second is allowlist, first is path prefix): observability.
//
//   - On a successful admin call (200/201/...), we get a forensic record
//     of who hit what and when.
//   - On a 403 from the rate-limiter OR the allowlist check, we get the
//     same record — so brute-force probing is loudly visible in the audit
//     log even though the response body claims "not an admin." The
//     operator can grep `kind = 'admin.access' AND http_status = 403` to
//     find probing patterns by IP / UA in minutes.
//
// Path storage policy: we store the URL SUFFIX (e.g. "customers/:team_id/
// tier"), never the full path. The ADMIN_PATH_PREFIX is a secret with
// the same blast radius as a session token — writing it into audit_log
// rows would defeat the whole point of the prefix gate (any DB-read
// access would expose the secret to a future engineer / BI consumer).
// The suffix is built by stripping a known leading "/api/v1/<prefix>/"
// before persistence; if the strip fails (defensive: shouldn't happen in
// production) we substitute the literal sentinel "<INVALID>" rather than
// leak the full path.
//
// User-agent storage policy: capped at 120 chars and run through the
// admin-prefix scrubber. UAs can carry hand-crafted strings that an
// attacker uses to fingerprint their own session — capping the field
// prevents log-injection-style abuse, and scrubbing prevents the prefix
// from leaking if someone accidentally puts a URL in their UA.

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/models"
)

const (
	// adminUAMaxLen caps how much of the user-agent string we persist.
	// Long enough to identify a real client ("Mozilla/5.0 (Macintosh; Intel
	// Mac OS X 10_15_7) AppleWebKit/..."), short enough that a malicious
	// 4KB UA can't bloat audit_log rows or grief log-shipper budgets.
	adminUAMaxLen = 120

	// adminAuditDeniedReasonRateLimit / adminAuditDeniedReasonAllowlistMiss
	// are the values written into the `denied_by` metadata field when a
	// 403 is recorded. Lets a BI consumer split brute-force probes
	// (rate_limit) from "real user not on allowlist" (allowlist_miss).
	// Persisted INTERNALLY in audit_log metadata — never echoed in HTTP
	// responses, so the probe-vs-not-admin response shape stays identical
	// on the wire.
	adminAuditDeniedReasonRateLimit    = "rate_limit"
	adminAuditDeniedReasonAllowlistMiss = "allowlist_miss"
	adminAuditDeniedReasonNone          = "" // success
)

// AdminAuditMetadata is the typed shape of the audit_log.metadata blob
// written by AdminAuditEmit. Promoted to a named struct so the audit
// schema is a typed contract — a future BI consumer reads this in one
// place, not by guessing at map shapes.
//
// IMPORTANT: PathSuffix MUST NOT contain the ADMIN_PATH_PREFIX. The
// audit middleware strips it before populating this field. The test
// suite grep-asserts this invariant against the persisted blob.
type AdminAuditMetadata struct {
	// Email is the JWT email of the caller, lowercased. Empty string when
	// the caller had no JWT (e.g. probe with no Authorization header that
	// got 403'd by RequireAdmin). Operator-relevant: an empty email on a
	// 403 means "fully anonymous probe;" a populated email on a 403 means
	// "a real signed-in user is probing — investigate."
	Email string `json:"email"`

	// IP is the source IP as resolved by the fingerprint middleware.
	// Same source as the rate-limit key — lets the operator pivot
	// audit_log rows to rate-limit metrics.
	IP string `json:"ip"`

	// PathSuffix is the URL path with the secret prefix stripped, e.g.
	// "customers/:team_id/tier". Persisting the raw matched path
	// (.Params(), if known) would be ideal but Fiber's path-template is
	// not directly readable post-match — we use the raw URL path and rely
	// on the strip to remove the prefix. The remaining suffix is generic
	// (no UUIDs interpolated) because team_id values come from the URL.
	// For sortability + grouping, downstream BI can normalize UUID
	// segments to ":id" with a simple regex.
	PathSuffix string `json:"path_suffix"`

	// HTTPStatus is the response code that the handler / middleware
	// returned to the caller. Drives the "did this hit succeed" pivot.
	HTTPStatus int `json:"http_status"`

	// UserAgentBrief is the first 120 chars of the User-Agent header,
	// scrubbed of the admin prefix (paranoia: the prefix should NEVER
	// appear in a UA, but if a hand-crafted client puts a URL in its UA
	// we'd otherwise persist it). Never trusted as identification — UAs
	// are client-supplied. Forensic value only.
	UserAgentBrief string `json:"user_agent_brief"`

	// DeniedBy explains the 403 cause. Empty on success. Internal only —
	// never echoed in HTTP responses (would leak probe-vs-not-admin).
	// One of: "", "rate_limit", "allowlist_miss".
	DeniedBy string `json:"denied_by,omitempty"`
}

// AdminAuditEmit returns a Fiber middleware that fires AFTER the rest of
// the admin chain (response written, status known) and writes one
// `admin.access` audit row capturing the request shape.
//
// adminPathPrefix is the unguessable secret (cfg.AdminPathPrefix). It MUST
// match what's mounted in router.go — the middleware uses it to strip the
// prefix out of the persisted path. An empty prefix is invalid for this
// middleware (the admin routes wouldn't even register); for safety we
// degrade to a no-op rather than panic.
//
// db may be nil only in tests. The middleware skips the insert in that
// case so a partial-app test rig isn't forced to wire a real DB connection.
func AdminAuditEmit(db *sql.DB, adminPathPrefix string) fiber.Handler {
	if adminPathPrefix == "" {
		// Admin routes wouldn't even register without a prefix. If this
		// middleware is wired without one, we'd otherwise leak the full
		// path into audit rows — pass through is safer than guess.
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	return func(c *fiber.Ctx) error {
		// Run the rest of the chain first so we capture the final status.
		// We can't use OnResponse because the handler may set the status
		// directly; the err return path also matters for fiber's
		// ErrResponseWritten contract.
		err := c.Next()

		// Always emit — success AND 403. The probe-visibility argument
		// is the whole point. Errors that bubble up to fiber's
		// ErrorHandler still surface a status code; ErrResponseWritten
		// is the canonical "handler wrote the response itself" sentinel.
		status := c.Response().StatusCode()
		meta := buildAdminAuditMetadata(c, adminPathPrefix, status)

		// Resolve team_id: prefer the URL :team_id param (the admin
		// endpoints target a specific team), fall back to the caller's
		// own team. audit_log.team_id is FK-constrained to teams(id) and
		// NOT NULL — when neither source resolves we cannot write to
		// audit_log without violating the constraint, so the row is
		// skipped (the slog warn lands instead so brute-force probes
		// without a team context are still operator-visible via log
		// search).
		teamID := adminAuditTeamID(c)

		// If db is nil (test path) OR team_id is unresolvable, short-
		// circuit the DB write. We still computed the metadata so a test
		// can intercept via locals if needed.
		if db != nil && teamID != uuid.Nil {
			payload, _ := json.Marshal(meta)
			summary := adminAuditSummary(meta)
			// Fire-and-forget: an audit write failure must never block the
			// admin request. We swallow the error after logging — matches
			// the contract documented on models.InsertAuditEvent.
			if ierr := models.InsertAuditEvent(c.Context(), db, models.AuditEvent{
				TeamID:   teamID,
				Actor:    "admin",
				Kind:     models.AuditKindAdminAccess,
				Summary:  summary,
				Metadata: payload,
			}); ierr != nil {
				slog.Error("admin_audit.insert_failed",
					"error", ierr,
					"team_id", teamID,
					"http_status", status,
				)
			}
		} else if db != nil && teamID == uuid.Nil {
			// Probe with no team context — log it so an operator can
			// still find brute-force activity by grepping slog. Same
			// fields as the persisted audit row (sans team_id).
			slog.Warn("admin_audit.no_team_context",
				"email", meta.Email,
				"ip", meta.IP,
				"path_suffix", meta.PathSuffix,
				"http_status", meta.HTTPStatus,
				"denied_by", meta.DeniedBy,
				"user_agent_brief", meta.UserAgentBrief,
			)
		}

		// Stash on locals so tests can read the computed metadata without
		// querying the DB (used by AdminAuditMetadataFromLocals).
		c.Locals(localKeyAdminAuditMeta, meta)
		return err
	}
}

// localKeyAdminAuditMeta is the Fiber locals key holding the AdminAuditMetadata
// produced by AdminAuditEmit. Exposed via AdminAuditMetadataFromLocals so
// tests + downstream middleware can inspect the audit decision without a
// DB round-trip.
const localKeyAdminAuditMeta = "admin_audit_meta"

// AdminAuditMetadataFromLocals returns the AdminAuditMetadata stamped by
// AdminAuditEmit, if present. Returns the zero value + false otherwise.
func AdminAuditMetadataFromLocals(c *fiber.Ctx) (AdminAuditMetadata, bool) {
	v, ok := c.Locals(localKeyAdminAuditMeta).(AdminAuditMetadata)
	return v, ok
}

// buildAdminAuditMetadata assembles the AdminAuditMetadata for the current
// request. Pure function over the request — easy to unit-test.
func buildAdminAuditMetadata(c *fiber.Ctx, adminPathPrefix string, status int) AdminAuditMetadata {
	email := strings.ToLower(strings.TrimSpace(GetEmail(c)))
	ip := strings.TrimSpace(c.IP())
	suffix := adminAuditPathSuffix(c.Path(), adminPathPrefix)
	ua := c.Get(fiber.HeaderUserAgent)
	ua = ScrubAdminPath(ua, adminPathPrefix)
	if len(ua) > adminUAMaxLen {
		ua = ua[:adminUAMaxLen]
	}
	deniedBy := adminAuditDeniedReasonNone
	if status == fiber.StatusForbidden {
		// Rate-limit beat allowlist? Read the locals flag set by
		// AdminRateLimit. Else assume allowlist_miss (the only other 403
		// path on this group).
		if IsAdminRateLimited(c) {
			deniedBy = adminAuditDeniedReasonRateLimit
		} else {
			deniedBy = adminAuditDeniedReasonAllowlistMiss
		}
	}
	return AdminAuditMetadata{
		Email:          email,
		IP:             ip,
		PathSuffix:     suffix,
		HTTPStatus:     status,
		UserAgentBrief: ua,
		DeniedBy:       deniedBy,
	}
}

// adminAuditPathSuffix strips a leading "/api/v1/<prefix>/" from path,
// returning just the admin sub-path (e.g. "customers/:team_id/tier").
//
// The strip is deliberately strict — if the path doesn't start with the
// expected prefix template we return a sentinel rather than the raw path,
// to prevent accidentally leaking the prefix into audit rows on a
// misconfigured router. The sentinel value "<INVALID>" is distinct from
// the LogScrubber sentinel "<ADMIN>" so an operator scanning audit rows
// can tell the two paths apart.
func adminAuditPathSuffix(path, prefix string) string {
	if prefix == "" {
		return adminAuditSuffixInvalid
	}
	// Canonical mount in router.go is /api/v1/<prefix>/...
	expected := "/api/v1/" + prefix + "/"
	if !strings.HasPrefix(path, expected) {
		// Also tolerate the no-trailing-slash terminal case
		// (a request to /api/v1/<prefix>, no further segments). Unlikely
		// in practice — admin endpoints all have sub-paths — but defended.
		if path == "/api/v1/"+prefix {
			return "" // empty suffix == bare prefix hit
		}
		return adminAuditSuffixInvalid
	}
	return strings.TrimPrefix(path, expected)
}

// adminAuditSuffixInvalid is the sentinel persisted when path stripping
// fails. Distinct from the LogScrubber sentinel so the operator can
// search audit rows for misconfigured strips ("DeniedBy=... PathSuffix=<INVALID>")
// separately from log lines.
const adminAuditSuffixInvalid = "<INVALID>"

// adminAuditTeamID prefers the URL :team_id param (admin endpoints address
// a specific team) and falls back to (a) parsing a UUID-shaped segment
// directly from the URL path, then (b) the caller's own team from the
// JWT. Returns uuid.Nil when none of the three resolve.
//
// Why parse the URL path directly: Fiber's group-level middleware runs
// BEFORE the matched route's handler-level binding populates Params (the
// :team_id placeholder is associated with the leaf handler, not the
// group chain). The audit middleware is wired at the group level so we
// don't see Params yet. Rather than wire the audit middleware on every
// individual route, we parse the path with the well-known shape
// "customers/<uuid>/...". When the path doesn't carry a team-scoped
// :team_id (e.g. GET /customers list), this returns uuid.Nil and the
// audit row falls back to the caller's JWT team_id.
func adminAuditTeamID(c *fiber.Ctx) uuid.UUID {
	if raw := c.Params("team_id"); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			return id
		}
	}
	if id := parseTeamIDFromAdminPath(c.Path()); id != uuid.Nil {
		return id
	}
	if raw := GetTeamID(c); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			return id
		}
	}
	return uuid.Nil
}

// parseTeamIDFromAdminPath looks for a "/customers/<uuid>" segment pair
// anywhere in path and returns the parsed UUID. The admin surface mounts
// all team-scoped endpoints under /customers/:team_id/..., so any path
// matching that pattern carries the team in segment 1 after "customers".
//
// Returns uuid.Nil when:
//
//   - path has no "customers/" segment (e.g. the bare /customers list);
//   - the segment after "customers/" isn't a parseable UUID.
//
// The parse is intentionally generic over the prefix: we don't strip
// ADMIN_PATH_PREFIX here. The "customers" anchor is enough to
// disambiguate and avoids passing the secret prefix into this helper
// (one fewer place the prefix needs to travel).
func parseTeamIDFromAdminPath(path string) uuid.UUID {
	idx := strings.Index(path, "/customers/")
	if idx < 0 {
		return uuid.Nil
	}
	rest := path[idx+len("/customers/"):]
	// First segment after /customers/. Trim a trailing slash + further
	// segments so e.g. "abc/tier" resolves to just "abc".
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	if id, err := uuid.Parse(rest); err == nil {
		return id
	}
	return uuid.Nil
}

// adminAuditSummary builds the human-readable one-liner persisted as
// audit_log.summary. Stays under 200 chars — the dashboard truncates
// longer values.
func adminAuditSummary(m AdminAuditMetadata) string {
	who := m.Email
	if who == "" {
		who = "anonymous"
	}
	suffix := m.PathSuffix
	if suffix == "" {
		suffix = "(root)"
	}
	if m.DeniedBy != "" {
		return who + " denied (" + m.DeniedBy + ") on " + suffix
	}
	return who + " accessed " + suffix
}

// AdminAuditEnsureMetadataNoPrefix is a defensive grep-time helper for
// tests — it asserts that a marshaled AdminAuditMetadata contains zero
// occurrences of the prefix. We expose this in package-public form so
// any test file (handler-level, router-level, middleware-level) can
// reach for the same invariant check.
//
// Returns true when the metadata is prefix-free, false otherwise.
func AdminAuditEnsureMetadataNoPrefix(meta AdminAuditMetadata, prefix string) bool {
	if prefix == "" {
		return true
	}
	blob, _ := json.Marshal(meta)
	return !strings.Contains(string(blob), prefix)
}

// adminAuditCtxKey is the context key used internally to thread the
// metadata down to error handlers if needed. Kept opaque to prevent
// callers from stuffing data onto the same key by accident.
type adminAuditCtxKey struct{}

// _ ensures adminAuditCtxKey is materialised at compile time (paranoia
// for the dead-code linter).
var _ = context.WithValue(context.Background(), adminAuditCtxKey{}, nil)

// AdminAuditPathSuffixForTest is a test-only export of the internal
// adminAuditPathSuffix helper. Test files in the middleware_test package
// need to exercise the strip logic without going through a full Fiber
// app; making the helper public-but-marked-internal lets us pin the
// contract in unit tests without inviting external callers.
//
// DO NOT call this from production code paths — the strip is an internal
// detail of AdminAuditEmit and may change shape.
func AdminAuditPathSuffixForTest(path, prefix string) string {
	return adminAuditPathSuffix(path, prefix)
}
