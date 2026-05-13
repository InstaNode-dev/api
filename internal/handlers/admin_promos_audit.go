package handlers

// admin_promos_audit.go — consolidated lifecycle view of admin-issued
// promo codes. Two endpoints:
//
//	GET /<admin-prefix>/promos/audit    — paginated event stream
//	GET /<admin-prefix>/promos/stats    — totals + leaderboards (cached)
//
// Why they live here and not on AdminCustomersHandler: scoping. The
// customer-detail surface answers "what's going on with team X." This
// surface answers "what's going on across all promo activity." Two
// different aggregation grains, two different handlers.
//
// Freshness contract (§13 matrix):
//
//   /audit  — live SQL each call. Admin views are low-frequency and the
//             event stream must show "issued at 3 sec ago" with no delay.
//             No cache.
//   /stats  — Redis-cached 5 min per request. Aggregates walk every row
//             in admin_promo_codes (twice — once for totals, once for the
//             leaderboards). The dashboard polls this on mount + tile
//             refresh; "5 min stale" is the right tradeoff for a numeric
//             tile that doesn't drive any mutating UX. Eventually consistent.

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/cache"
	"instant.dev/internal/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// Named constants — every magic value the handler reads from the query
// string or writes to Redis lives here, not inline.
// ─────────────────────────────────────────────────────────────────────────────

// promoAuditDefaultLimit / promoAuditMaxLimit mirror the admin-customers
// list endpoint's pagination shape so a future shared admin pagination
// helper is a drop-in.
const (
	promoAuditDefaultLimit = 50
	promoAuditMaxLimit     = 500
)

// promoStatsCacheKey is the Redis key used by /promos/stats. Global (no
// per-team scope) because the endpoint is platform-wide.
const promoStatsCacheKey = "admin:promos:stats"

// PromoStatsCacheTTL is the freshness window for GET /admin/promos/stats.
// Exported so tests can build their assertions against the same constant
// rather than a hard-coded duration that would silently drift.
const PromoStatsCacheTTL = 5 * time.Minute

// Query-param key names. Centralized so a typo in one place can't silently
// disable a filter.
const (
	promoAuditQuerySince         = "since"
	promoAuditQueryLimit         = "limit"
	promoAuditQueryOffset        = "offset"
	promoAuditQueryIssuedByEmail = "issued_by_email"
	promoAuditQueryEventType     = "event_type"
)

// ─────────────────────────────────────────────────────────────────────────────
// Handler
// ─────────────────────────────────────────────────────────────────────────────

// AdminPromosAuditHandler serves /admin/promos/{audit,stats}. Both
// endpoints sit behind the same RequireAdmin + unguessable-prefix gates
// as the rest of admin_customers.go (wired in internal/router/router.go).
//
// rdb may be nil — when Redis isn't configured, GET /promos/stats falls
// through to a live DB compute per call (same fail-open posture as
// TeamSummaryHandler).
type AdminPromosAuditHandler struct {
	db  *sql.DB
	rdb *redis.Client
}

// NewAdminPromosAuditHandler wires the handler. rdb may be nil; the
// cache helper degrades to a pass-through in that case.
func NewAdminPromosAuditHandler(db *sql.DB, rdb *redis.Client) *AdminPromosAuditHandler {
	return &AdminPromosAuditHandler{db: db, rdb: rdb}
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/promos/audit
// ─────────────────────────────────────────────────────────────────────────────

// promoAuditRow is the public JSON shape for one event in the audit feed.
//
// The field order matches the brief: event_type first so a scanning admin
// sees the lifecycle phase before the code, then the routing fields
// (code/team_id/team_email/issued_by_email), then the promo terms
// (kind/value/applies_to), then the three lifecycle timestamps.
//
// RedeemedAt / ExpiredAt are nullable in the DB; we surface them as
// *time.Time so the JSON consumer gets `null` rather than a sentinel
// "0001-01-01T00:00:00Z" — clearer for the dashboard's "—" rendering.
type promoAuditRow struct {
	EventType     string     `json:"event_type"`
	Code          string     `json:"code"`
	TeamID        string     `json:"team_id,omitempty"`
	TeamEmail     string     `json:"team_email"`
	IssuedByEmail string     `json:"issued_by_email"`
	Kind          string     `json:"kind"`
	Value         int        `json:"value"`
	AppliesTo     int        `json:"applies_to,omitempty"`
	IssuedAt      time.Time  `json:"issued_at"`
	RedeemedAt    *time.Time `json:"redeemed_at,omitempty"`
	ExpiredAt     *time.Time `json:"expired_at,omitempty"`
	EventAt       time.Time  `json:"event_at"`
}

// Audit handles GET /admin/promos/audit.
//
// Query params (all optional):
//
//	since=RFC3339      — drop events older than this timestamp.
//	limit=N            — 1..promoAuditMaxLimit (default: promoAuditDefaultLimit).
//	offset=N           — >= 0 (default: 0).
//	issued_by_email=X  — case-insensitive exact match on issuer.
//	event_type=Y       — one of "issued" / "redeemed" / "expired".
//
// Response: { ok, events: [...], count }.
//
// `count` is the length of the returned page (not the unfiltered total) so
// the dashboard can detect "end of pagination" without a second query. A
// total-count column would require a COUNT(*) OVER () or a second query;
// neither is worth it for an admin tool that paginates by hand.
func (h *AdminPromosAuditHandler) Audit(c *fiber.Ctx) error {
	since, err := parsePromoAuditSince(c.Query(promoAuditQuerySince))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_since",
			"since must be RFC3339 (e.g. 2026-04-01T00:00:00Z)")
	}

	eventType := strings.ToLower(strings.TrimSpace(c.Query(promoAuditQueryEventType)))
	if eventType != "" && !models.IsValidPromoAuditEvent(eventType) {
		return respondError(c, fiber.StatusBadRequest, "invalid_event_type",
			"event_type must be one of: issued, redeemed, expired")
	}

	// Issuer-email filter is lowercased so the comparison can hit a
	// functional index later (and so case-mismatch on env-stamped emails
	// doesn't silently drop the row).
	issuer := strings.ToLower(strings.TrimSpace(c.Query(promoAuditQueryIssuedByEmail)))

	limit := adminParseLimit(c.Query(promoAuditQueryLimit), promoAuditDefaultLimit, promoAuditMaxLimit)
	offset := adminParseOffset(c.Query(promoAuditQueryOffset))

	events, err := models.ListPromoAuditEvents(c.Context(), h.db, models.ListPromoAuditEventsParams{
		Since:         since,
		Limit:         limit,
		Offset:        offset,
		IssuedByEmail: issuer,
		EventType:     eventType,
	})
	if err != nil {
		slog.Error("admin.promos.audit.query_failed", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to load promo audit events")
	}

	out := make([]promoAuditRow, 0, len(events))
	for _, e := range events {
		row := promoAuditRow{
			EventType:     e.EventType,
			Code:          e.Code,
			TeamEmail:     e.TeamEmail,
			IssuedByEmail: e.IssuedByEmail,
			Kind:          e.Kind,
			Value:         e.Value,
			AppliesTo:     e.AppliesTo,
			IssuedAt:      e.IssuedAt,
			EventAt:       e.EventAt,
		}
		if e.TeamID.Valid {
			row.TeamID = e.TeamID.UUID.String()
		}
		if e.RedeemedAt.Valid {
			t := e.RedeemedAt.Time
			row.RedeemedAt = &t
		}
		if e.ExpiredAt.Valid {
			t := e.ExpiredAt.Time
			row.ExpiredAt = &t
		}
		out = append(out, row)
	}

	return c.JSON(fiber.Map{
		"ok":     true,
		"events": out,
		"count":  len(out),
	})
}

// parsePromoAuditSince accepts:
//
//	""                 → (zero time, no filter)
//	"2026-04-01"       → midnight UTC on that date (date-only convenience)
//	"2026-04-01T00:..."→ RFC3339 timestamp
//
// Anything else → error so the handler can surface a clean 400. We bother
// with the date-only shorthand because `?since=2026-04-01` is the natural
// thing a human types in a URL — RFC3339 with a Z suffix is friction.
func parsePromoAuditSince(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return t, nil
	}
	return time.Time{}, errInvalidPromoAuditSince
}

// errInvalidPromoAuditSince is a typed sentinel so a future test can
// errors.Is against it. The handler converts it into the 400 response —
// callers never see the error directly.
var errInvalidPromoAuditSince = errors.New("invalid since")

// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/promos/stats
// ─────────────────────────────────────────────────────────────────────────────

// promoStatsResponse is the cached payload. Wrapping models.PromoStats
// here (rather than caching the model struct directly) gives the response
// `ok` + `as_of` + `freshness_seconds` fields without polluting the model
// with HTTP-shape concerns.
type promoStatsResponse struct {
	OK               bool             `json:"ok"`
	FreshnessSeconds int              `json:"freshness_seconds"`
	AsOf             string           `json:"as_of"`
	Stats            models.PromoStats `json:"stats"`
}

// Stats handles GET /admin/promos/stats.
//
// Caching: 5 min in Redis under promoStatsCacheKey. Concurrent callers
// collapse via singleflight (see internal/cache.GetOrSet). On Redis
// outage we fall through to a live DB compute — never 500.
//
// Response sets `Cache-Control: private, max-age=300` so a future
// browser-side cache (or a proxy) can avoid the round-trip too.
func (h *AdminPromosAuditHandler) Stats(c *fiber.Ctx) error {
	payload, err := cache.GetOrSet(c.Context(), h.rdb, promoStatsCacheKey, PromoStatsCacheTTL,
		func(ctx context.Context) (promoStatsResponse, error) {
			stats, cerr := models.ComputePromoStats(ctx, h.db)
			if cerr != nil {
				return promoStatsResponse{}, cerr
			}
			return promoStatsResponse{
				OK:               true,
				FreshnessSeconds: int(PromoStatsCacheTTL.Seconds()),
				AsOf:             time.Now().UTC().Format(time.RFC3339Nano),
				Stats:            stats,
			}, nil
		})
	if err != nil {
		slog.Error("admin.promos.stats.compute_failed", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to compute promo stats")
	}

	c.Set("Cache-Control", "private, max-age=300")
	return c.JSON(payload)
}
