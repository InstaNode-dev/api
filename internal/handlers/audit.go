package handlers

// audit.go — GET /api/v1/audit + GET /api/v1/audit.csv — customer-facing
// audit log export. Replaces the prior in-handler "Recent Activity" feed:
// the new shape adds cursor pagination, tier-derived lookback gates,
// time-range filters, actor-email redaction, and admin.* exclusion.
//
// Two surfaces share the same filter/scope/redaction code:
//
//	GET /api/v1/audit       → JSON, paginated, dashboard-friendly
//	GET /api/v1/audit.csv   → text/csv, streamed, SIEM-friendly
//
// Compliance contract (W7-C): Team-tier customers need a complete trail
// of who accessed their data + when. The endpoint returns every row
// where team_id = caller_team OR (metadata.resource_id resolves to a
// resource the caller owns). Internal-only rows (kind starts admin.*)
// are NEVER returned — those are reserved for the operator audit feed
// at /api/v1/<admin-prefix>/customers and would leak the operator
// tooling shape.
//
// Redaction: actor emails are partially redacted to first-char +
// domain ("m***@example.com"). This balances compliance traceability
// (the buyer can see "an account at our company accessed this") against
// gratuitous PII exposure. The row's user_id stays in full so the
// buyer can correlate against their own team-membership records.
//
// Tier lookback floor (in days):
//
//	anonymous / free  → 402 upgrade_required
//	hobby             → 30  days
//	pro               → 90  days
//	growth / team     → unlimited (0 = no floor)
//
// The floor is independent of the caller's `?since=` filter — if they
// pass a wider window, the floor still wins. The response body echoes
// the resolved lookback_days so the caller knows what they got.

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// auditDefaultLimit is the default `?limit` for JSON callers. CSV
// callers always stream — the limit is still applied so a single call
// can't sweep more than auditMaxLimitQuery rows even via the CSV path
// (no in-memory buffer is constructed, but the SQL LIMIT protects the
// DB).
const auditDefaultLimit = 50

// auditMaxLimitQuery caps `?limit` regardless of what the client asks
// for. Mirrors models.AuditExportMaxLimit so callers can't bypass it.
const auditMaxLimitQuery = models.AuditExportMaxLimit

// tierLookbackSeconds returns the audit-history floor for a team's
// plan tier, in seconds. Returns (seconds, allowed). When allowed is
// false the caller MUST be sent the 402 upgrade response — the
// anonymous/free tier never reaches the underlying query.
func tierLookbackSeconds(planTier string) (int64, bool) {
	switch planTier {
	case "anonymous", "free":
		return 0, false
	case "hobby":
		return 30 * 24 * 3600, true
	case "pro":
		return 90 * 24 * 3600, true
	case "growth", "team":
		return 0, true // unlimited
	default:
		// Unknown tiers (forward compat — e.g. a future "scale" tier
		// the handler hasn't been taught about) default to the
		// hobby floor rather than 402'ing. Conservative on the
		// disclosure axis; agents that hit this should still see
		// data, just bounded.
		return 30 * 24 * 3600, true
	}
}

// tierLookbackDays is the JSON-friendly mirror of tierLookbackSeconds.
// Returns -1 for unlimited so the wire shape stays "number or sentinel"
// rather than "number or null" (CSV serialisation prefers a number).
func tierLookbackDays(planTier string) int {
	secs, allowed := tierLookbackSeconds(planTier)
	if !allowed {
		return 0
	}
	if secs == 0 {
		return -1
	}
	return int(secs / (24 * 3600))
}

// AuditHandler serves the customer-facing audit export endpoints.
type AuditHandler struct {
	db *sql.DB
}

// NewAuditHandler constructs an AuditHandler.
func NewAuditHandler(db *sql.DB) *AuditHandler {
	return &AuditHandler{db: db}
}

// parsedAuditQuery is the shape both List and ListCSV consume after
// query-string parsing. Centralised so the two endpoints can't drift on
// filter semantics — a bug in one would silently violate the contract
// that "the CSV is the same shape as the JSON".
type parsedAuditQuery struct {
	teamID     uuid.UUID
	limit      int
	before     time.Time
	kind       string
	since      time.Time
	until      time.Time
	lookbackS  int64
	tier       string
	httpStatus int    // non-zero means the caller already failed parse — handler returns immediately
	httpError  string // canonical error code for respondError when httpStatus != 0
	httpMsg    string
}

// parseAuditQuery validates the query string and resolves the tier
// lookback floor. On any tier-gate or parse failure, the returned
// struct has httpStatus != 0 and the caller MUST short-circuit with
// respondError(c, httpStatus, httpError, httpMsg). The function never
// writes to c itself, so it composes cleanly under both List and
// ListCSV.
func (h *AuditHandler) parseAuditQuery(c *fiber.Ctx) parsedAuditQuery {
	out := parsedAuditQuery{}

	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		out.httpStatus = fiber.StatusUnauthorized
		out.httpError = "unauthorized"
		out.httpMsg = "Authentication required"
		return out
	}
	out.teamID = teamID

	// Resolve the team's plan tier to decide the lookback floor + 402
	// gate. We deliberately read the live team row rather than trust a
	// claim in the JWT — a customer that downgrades mid-session must
	// not keep their old lookback window.
	team, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		out.httpStatus = fiber.StatusServiceUnavailable
		out.httpError = "team_lookup_failed"
		out.httpMsg = "Failed to look up your team"
		return out
	}
	out.tier = team.PlanTier

	lookbackS, allowed := tierLookbackSeconds(team.PlanTier)
	if !allowed {
		out.httpStatus = fiber.StatusPaymentRequired
		out.httpError = "upgrade_required"
		out.httpMsg = "Audit log export requires the Hobby plan or higher. " +
			"Your team is on the " + team.PlanTier + " plan."
		return out
	}
	out.lookbackS = lookbackS

	// limit: default auditDefaultLimit, cap at auditMaxLimitQuery,
	// reject negatives by clamping to default.
	limit := auditDefaultLimit
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > auditMaxLimitQuery {
		limit = auditMaxLimitQuery
	}
	out.limit = limit

	// kind: exact match. Empty string means "no filter" — the model
	// already excludes admin.* rows so we don't pre-validate.
	out.kind = strings.TrimSpace(c.Query("kind"))

	if raw := strings.TrimSpace(c.Query("before")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			out.httpStatus = fiber.StatusBadRequest
			out.httpError = "invalid_before"
			out.httpMsg = "?before must be RFC3339 (e.g. 2026-05-13T12:34:56Z)"
			return out
		}
		out.before = t
	}
	if raw := strings.TrimSpace(c.Query("since")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			out.httpStatus = fiber.StatusBadRequest
			out.httpError = "invalid_since"
			out.httpMsg = "?since must be RFC3339"
			return out
		}
		out.since = t
	}
	if raw := strings.TrimSpace(c.Query("until")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			out.httpStatus = fiber.StatusBadRequest
			out.httpError = "invalid_until"
			out.httpMsg = "?until must be RFC3339"
			return out
		}
		out.until = t
	}

	return out
}

// List handles GET /api/v1/audit. See file header for the contract.
func (h *AuditHandler) List(c *fiber.Ctx) error {
	q := h.parseAuditQuery(c)
	if q.httpStatus != 0 {
		return respondError(c, q.httpStatus, q.httpError, q.httpMsg)
	}

	events, err := models.ListAuditEventsForCustomerExport(c.Context(), h.db, models.AuditCustomerExportQuery{
		TeamID:    q.teamID,
		Limit:     q.limit,
		Before:    q.before,
		Kind:      q.kind,
		Since:     q.since,
		Until:     q.until,
		LookbackS: q.lookbackS,
	})
	if err != nil {
		slog.Error("audit.list.failed", "error", err, "team_id", q.teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to list audit events")
	}

	// Build the masked-email map in one DB round-trip rather than per
	// event. The fan-out is bounded by `limit` (default 50, max 200)
	// so a single IN-list query is cheaper than N point-lookups.
	emailByUserID := lookupMaskedEmails(c.Context(), h.db, events)

	items := make([]fiber.Map, 0, len(events))
	for _, ev := range events {
		items = append(items, auditEventToMap(ev, emailByUserID))
	}

	var nextCursor interface{} = nil
	if len(events) == q.limit && len(events) > 0 {
		// The page is full — there might be more. The cursor is the
		// oldest row's created_at; the next call passes this as
		// ?before=. We deliberately use created_at (not id) because
		// the model orders by created_at DESC; using id could
		// reorder rows that landed in the same microsecond.
		nextCursor = events[len(events)-1].CreatedAt.UTC().Format(time.RFC3339Nano)
	}

	return c.JSON(fiber.Map{
		"ok":             true,
		"items":          items,
		"total_returned": len(items),
		"next_cursor":    nextCursor,
		"lookback_days":  tierLookbackDays(q.tier),
		"tier":           q.tier,
	})
}

// ListCSV handles GET /api/v1/audit.csv. Streams the response so a
// Team-tier customer with months of history doesn't OOM the api pod.
// Same filter/scope/redaction rules as List.
//
// Implementation: we run a regular paginated query (LIMIT applies) but
// write rows to the response as they're scanned via fasthttp's
// SetBodyStreamWriter — at most one row is held in memory at a time.
func (h *AuditHandler) ListCSV(c *fiber.Ctx) error {
	q := h.parseAuditQuery(c)
	if q.httpStatus != 0 {
		return respondError(c, q.httpStatus, q.httpError, q.httpMsg)
	}

	// CSV does not support cursor pagination meaningfully (the customer
	// downloads the whole window). We still honour `limit` so a buggy
	// caller can't ask for 10M rows. Default to AuditExportMaxLimit
	// when no limit was passed — for CSV that's a reasonable per-call
	// chunk; the caller can paginate via `before`/`since` for more.
	if c.Query("limit") == "" {
		q.limit = auditMaxLimitQuery
	}

	events, err := models.ListAuditEventsForCustomerExport(c.Context(), h.db, models.AuditCustomerExportQuery{
		TeamID:    q.teamID,
		Limit:     q.limit,
		Before:    q.before,
		Kind:      q.kind,
		Since:     q.since,
		Until:     q.until,
		LookbackS: q.lookbackS,
	})
	if err != nil {
		slog.Error("audit.csv.query_failed", "error", err, "team_id", q.teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to stream audit events")
	}

	emailByUserID := lookupMaskedEmails(c.Context(), h.db, events)

	c.Set("Content-Type", "text/csv; charset=utf-8")
	c.Set("Content-Disposition", `attachment; filename="audit.csv"`)

	// fasthttp's stream writer hands us a *bufio.Writer; we encode one
	// row at a time and flush after each — clients see chunks land as
	// the query progresses. The events slice is bounded by `limit` so
	// memory is O(limit) even with the in-memory slice; the streaming
	// path keeps the kernel send buffer drained as we encode, which
	// is what matters when limit is at the 200 max for a Team-tier
	// customer with deep history.
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		csvW := csv.NewWriter(w)
		_ = csvW.Write([]string{
			"id", "kind", "created_at", "actor", "actor_user_id",
			"actor_email_masked", "resource_id", "resource_type",
			"summary", "metadata",
		})
		csvW.Flush()
		_ = w.Flush()

		for _, ev := range events {
			actorUserID := ""
			actorEmailMasked := ""
			if ev.UserID.Valid {
				actorUserID = ev.UserID.UUID.String()
				actorEmailMasked = emailByUserID[actorUserID]
			}
			resourceID := ""
			if ev.ResourceID.Valid {
				resourceID = ev.ResourceID.UUID.String()
			}
			metaStr := ""
			if len(ev.Metadata) > 0 {
				metaStr = string(ev.Metadata)
			}
			_ = csvW.Write([]string{
				ev.ID.String(),
				ev.Kind,
				ev.CreatedAt.UTC().Format(time.RFC3339Nano),
				ev.Actor,
				actorUserID,
				actorEmailMasked,
				resourceID,
				ev.ResourceType,
				ev.Summary,
				metaStr,
			})
			csvW.Flush()
			_ = w.Flush()
		}
	})

	return nil
}

// auditEventToMap renders an AuditEvent into the public JSON shape.
// emailByUserID is the precomputed actor_user_id → masked-email map;
// missing entries (deleted users, system actors with no user_id) render
// as null on the wire.
func auditEventToMap(ev *models.AuditEvent, emailByUserID map[string]string) fiber.Map {
	item := fiber.Map{
		"id":                 ev.ID,
		"kind":               ev.Kind,
		"created_at":         ev.CreatedAt,
		"metadata":           nil,
		"actor_user_id":      nil,
		"actor_email_masked": nil,
	}
	if ev.UserID.Valid {
		uid := ev.UserID.UUID.String()
		item["actor_user_id"] = uid
		if masked, ok := emailByUserID[uid]; ok && masked != "" {
			item["actor_email_masked"] = masked
		}
	}
	if len(ev.Metadata) > 0 {
		var meta interface{}
		if err := json.Unmarshal(ev.Metadata, &meta); err == nil {
			item["metadata"] = meta
		}
	}
	return item
}

// lookupMaskedEmails fans the user_ids from `events` into a single
// SELECT against users, returning a uid-string → masked-email map.
// Failures degrade to an empty map — the handler still returns rows
// with actor_email_masked = null, which is the documented "user not
// found" shape.
func lookupMaskedEmails(ctx context.Context, db *sql.DB, events []*models.AuditEvent) map[string]string {
	out := make(map[string]string)
	if len(events) == 0 {
		return out
	}

	// Collect unique user_ids (a single user often appears across many
	// rows). Skip rows with no actor_user_id (system actors).
	seen := make(map[string]struct{})
	ids := make([]interface{}, 0, len(events))
	for _, ev := range events {
		if !ev.UserID.Valid {
			continue
		}
		s := ev.UserID.UUID.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		ids = append(ids, s)
	}
	if len(ids) == 0 {
		return out
	}

	// Build a parameterised IN list. PostgreSQL has no native list
	// param so we splat into $1, $2, … and pass each value via args.
	// Safe: ids[i] are uuid.String() values, never user input.
	placeholders := make([]byte, 0, len(ids)*5)
	for i := range ids {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '$')
		placeholders = strconv.AppendInt(placeholders, int64(i+1), 10)
	}
	q := "SELECT id::text, email FROM users WHERE id::text IN (" + string(placeholders) + ")"

	rows, err := db.QueryContext(ctx, q, ids...)
	if err != nil {
		slog.Warn("audit.email_lookup_failed", "error", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, email string
		if err := rows.Scan(&id, &email); err != nil {
			continue
		}
		out[id] = maskEmail(email)
	}
	return out
}

// maskEmail redacts an email to "first-char + *** + @domain".
//
//	"alice@example.com"     → "a***@example.com"
//	"a@example.com"         → "a***@example.com"   (single-char local part)
//	""                       → ""                   (no email, no row)
//	"weirdvalue"             → "w***"               (no @ — fall back to local-mask)
//
// The mask runs server-side so the wire shape never carries the
// unredacted email. Test cases must assert this.
func maskEmail(email string) string {
	if email == "" {
		return ""
	}
	at := strings.IndexByte(email, '@')
	if at < 0 {
		// No @ — mask everything after the first char. Defensive:
		// the column is TEXT and could carry historical garbage rows.
		return string(email[0]) + "***"
	}
	if at == 0 {
		// "@example.com" — no local part. Render as "***@domain".
		return "***" + email[at:]
	}
	return string(email[0]) + "***" + email[at:]
}
