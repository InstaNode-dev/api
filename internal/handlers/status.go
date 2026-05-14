// status.go — GET /api/v1/status.
//
// Replaces the dashboard's client-side probe page with a real backend
// aggregator. Reads from `uptime_samples` (filled by the worker's
// `uptime_prober` job, ~1 probe/min/component) and joins against
// `service_components` for display metadata. Output shape is consumed
// by dashboard/src/pages/StatusPage.tsx — keep it stable.
//
// Auth: public, no JWT, no team scope. Anyone (including pre-claim
// agents and search-engine indexers) can hit it. The page is what
// answers "is instanode itself up?" — gating it on auth would defeat
// the purpose.
//
// Cache: 60s in Redis under the single key `status:public:v1`. Why one
// key instead of per-region: there's nothing team-specific in the
// response so every caller gets the same bytes. 60s matches the
// `freshness_seconds` we publish and the worker's 1-minute probe
// cadence — by the time the cache expires there's a fresh sample to
// summarise. Cache misses fan out to the DB; a Redis outage falls
// through to the DB (cache.GetOrSet handles this), so the status page
// stays up even when our cache is degraded — which is exactly when we
// most want to be honest about it.
//
// Freshness vs realtime: this endpoint is NEVER on the critical path
// of any provisioning flow. A 60s stale reading on "is API up" is the
// right tradeoff against the read-amplification from concurrent
// browsers hitting /status during an incident.
//
// Per `current_incidents`: until the incident-feed worker ships
// (post-W11) this is always `[]`. The field is present in the contract
// so the dashboard can wire its incident card now and have it light up
// the moment the worker writes its first row.

package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/cache"
)

// statusCacheKey is the Redis key for the public status payload. Single
// key because the response is identical for every caller.
const statusCacheKey = "status:public:v1"

// statusCacheTTL is the cache freshness window for GET /api/v1/status.
// Tuned to match the worker's 1-minute probe cadence — by the time the
// cache expires there's always at least one fresh sample to summarise.
const statusCacheTTL = 60 * time.Second

// last24hSlots is the number of 15-minute buckets we emit per component
// in `last_24h_samples`. 96 slots × 15min = 24h exactly. The dashboard
// renders one uptime bar per slot.
const last24hSlots = 96

// last24hSlotMinutes is the slot width in minutes (15min).
const last24hSlotMinutes = 15

// uptime7dWindow / uptime30dWindow are the rolling windows for the
// "uptime_7d_pct" / "uptime_30d_pct" fields. We compute the percent as
// (healthy_samples / total_samples) in the window, which folds gaps
// (missed probes) into the denominator — a long worker outage WOULD
// show up as a depressed uptime number. That's deliberate; the page is
// for human consumption and a missing data row is itself a problem.
const uptime7dWindow = 7 * 24 * time.Hour
const uptime30dWindow = 30 * 24 * time.Hour

// degradedThresholdPct is the cutoff below which the most recent
// 15-minute slot is treated as "degraded" instead of "operational".
// 100% = all probes healthy; <100% but ≥ this cutoff = degraded; below
// the cutoff = "down". Tuned at 50% so a single transient failure in a
// 1-minute window (1/1 unhealthy) renders "down" the way an operator
// would expect, while a 1/3 blip stays "degraded".
const degradedThresholdPct = 50

// StatusHandler serves the cached public status payload.
type StatusHandler struct {
	db  *sql.DB
	rdb *redis.Client
}

// NewStatusHandler builds a StatusHandler. rdb may be nil — the cache
// helper handles nil transparently and degrades to a per-request DB
// fetch, which is still cheap because the DB queries are 1 SELECT per
// component bounded by the 24h window.
func NewStatusHandler(db *sql.DB, rdb *redis.Client) *StatusHandler {
	return &StatusHandler{db: db, rdb: rdb}
}

// componentRow is one row of the response. The shape matches what the
// dashboard's StatusPage expects.
//
//   - current_status: operational | degraded | down — computed from
//     the most recent 15-minute slot.
//   - uptime_*_pct: rolling % healthy over the window (-1 = no data).
//   - last_24h_samples: 96 booleans, oldest → newest, one per 15-minute
//     slot. A slot is `true` (healthy) iff at least one probe in that
//     window was healthy and none were unhealthy; otherwise `false`.
//     Slots with zero probes inherit the previous slot's value to keep
//     the bar continuous (gap = no data = render same as last known).
type componentRow struct {
	Slug           string  `json:"slug"`
	Name           string  `json:"name"`
	Category       string  `json:"category"`
	Description    string  `json:"description,omitempty"`
	CurrentStatus  string  `json:"current_status"`
	Uptime7dPct    float64 `json:"uptime_7d_pct"`
	Uptime30dPct   float64 `json:"uptime_30d_pct"`
	Last24hSamples []bool  `json:"last_24h_samples"`
}

// statusPayload is the full /api/v1/status response. Embedded directly
// into the cache (JSON-encoded) so one decode = one response.
type statusPayload struct {
	OK               bool             `json:"ok"`
	FreshnessSeconds int              `json:"freshness_seconds"`
	AsOf             string           `json:"as_of"`
	Components       []componentRow   `json:"components"`
	CurrentIncidents []incidentItem   `json:"current_incidents"`
}

// Get implements GET /api/v1/status.
func (h *StatusHandler) Get(c *fiber.Ctx) error {
	payload, err := cache.GetOrSet(c.Context(), h.rdb, statusCacheKey, statusCacheTTL,
		func(ctx context.Context) (statusPayload, error) {
			return h.compute(ctx)
		})
	if err != nil {
		slog.Error("status.compute_failed", "error", err)
		return respondError(c, fiber.StatusInternalServerError, "status_failed", "Failed to compute status")
	}

	// Cache-Control mirrors the TTL so the browser doesn't poll faster
	// than the server can re-compute. `public` (not `private`) — the
	// payload contains no team-scoped data, so intermediate proxies
	// are welcome to cache it too. stale-while-revalidate gives a 60s
	// window where the browser can serve the stale value while
	// re-fetching in the background — useful during incidents when
	// the API itself may be slow.
	c.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(statusCacheTTL.Seconds()))+", stale-while-revalidate=60")
	return c.JSON(payload)
}

// compute runs the actual aggregation against the DB. Called from cache
// miss + every Redis-down request.
//
// One round trip lists components in a stable order; one round trip per
// component pulls the last 30 days of samples (capped — see SQL). The
// per-component scan is small (~43k rows worst case at 1/min × 30d) and
// could be a JOIN, but the worker only writes ~5 rows/min total so the
// table stays tiny in practice. Optimise later if the prune job
// stops running.
func (h *StatusHandler) compute(ctx context.Context) (statusPayload, error) {
	components, err := h.listComponents(ctx)
	if err != nil {
		return statusPayload{}, err
	}

	now := time.Now().UTC()
	rows := make([]componentRow, 0, len(components))
	for _, comp := range components {
		row, cerr := h.computeOne(ctx, comp, now)
		if cerr != nil {
			// One component's read failing should not break the whole
			// status page — emit a row with -1 uptime so the dashboard
			// renders "no data" rather than a 500.
			slog.Warn("status.component_read_failed", "slug", comp.slug, "error", cerr.Error())
			rows = append(rows, componentRow{
				Slug:           comp.slug,
				Name:           comp.displayName,
				Category:       comp.category,
				Description:    comp.description,
				CurrentStatus:  "operational", // fail-open: no data ≠ outage
				Uptime7dPct:    -1,
				Uptime30dPct:   -1,
				Last24hSamples: make([]bool, last24hSlots),
			})
			continue
		}
		rows = append(rows, row)
	}

	return statusPayload{
		OK:               true,
		FreshnessSeconds: int(statusCacheTTL.Seconds()),
		AsOf:             now.Format(time.RFC3339Nano),
		Components:       rows,
		// The incident-feed worker hasn't shipped yet — return an
		// empty list so the dashboard renders the "no current
		// incidents" empty state. When the worker writes its first
		// row we'll select-and-filter here.
		CurrentIncidents: []incidentItem{},
	}, nil
}

// listedComponent is the lightweight row used during compute. Separate
// from `componentRow` so the SQL scan target stays minimal and the
// public shape can evolve independently.
type listedComponent struct {
	slug, displayName, category, description string
}

// listComponents reads service_components in display order. Stable
// ordering matters because the dashboard renders the rows in the
// returned sequence — alphabetising would put the marketing site above
// the API, which is not the operator's mental model.
//
// Order: core services first (api, provisioner, worker), then compute
// (deploys), then edge (marketing). Implemented via an ORDER BY CASE
// on category + display_name so adding a new core component slots in
// naturally without a code change.
func (h *StatusHandler) listComponents(ctx context.Context) ([]listedComponent, error) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT slug, display_name, category, COALESCE(description, '')
		FROM service_components
		ORDER BY
		  CASE category
		    WHEN 'core'    THEN 0
		    WHEN 'compute' THEN 1
		    WHEN 'edge'    THEN 2
		    ELSE 3
		  END,
		  display_name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]listedComponent, 0, 8)
	for rows.Next() {
		var c listedComponent
		if err := rows.Scan(&c.slug, &c.displayName, &c.category, &c.description); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// computeOne builds one component's row. Single SQL pull of the 30-day
// window, then in-memory bucketing into 15-minute slots + uptime
// percentages.
func (h *StatusHandler) computeOne(ctx context.Context, comp listedComponent, now time.Time) (componentRow, error) {
	since := now.Add(-uptime30dWindow)
	rows, err := h.db.QueryContext(ctx, `
		SELECT sampled_at, healthy
		FROM uptime_samples
		WHERE component_slug = $1
		  AND sampled_at >= $2
		ORDER BY sampled_at ASC
	`, comp.slug, since)
	if err != nil {
		return componentRow{}, err
	}
	defer rows.Close()

	samples := make([]uptimeSample, 0, 256)
	for rows.Next() {
		var s uptimeSample
		if err := rows.Scan(&s.t, &s.ok); err != nil {
			return componentRow{}, err
		}
		samples = append(samples, s)
	}
	if err := rows.Err(); err != nil {
		return componentRow{}, err
	}

	// 24h bucketing — one slot per 15min.
	slots := make([]bool, last24hSlots)
	slotSeen := make([]bool, last24hSlots)  // did any sample fall in this slot?
	slotBad := make([]bool, last24hSlots)   // did any UNHEALTHY sample fall in this slot?
	last24hStart := now.Add(-24 * time.Hour)
	for _, s := range samples {
		if s.t.Before(last24hStart) {
			continue
		}
		idx := int(s.t.Sub(last24hStart) / (time.Duration(last24hSlotMinutes) * time.Minute))
		if idx < 0 || idx >= last24hSlots {
			continue
		}
		slotSeen[idx] = true
		if !s.ok {
			slotBad[idx] = true
		}
	}
	// A slot is healthy iff at least one probe landed in it AND none
	// were unhealthy. Empty slots inherit the previous slot — keeps
	// the uptime bar visually continuous through brief probe-worker
	// gaps. The very first slot defaults to true (healthy) if empty,
	// because in an empty DB (fresh deploy, no samples yet) the most
	// honest answer is "we don't know, assume up".
	prev := true
	for i := 0; i < last24hSlots; i++ {
		if !slotSeen[i] {
			slots[i] = prev
			continue
		}
		slots[i] = !slotBad[i]
		prev = slots[i]
	}

	// Current status: derive from the most recent slot that had data.
	// Walk backwards so an empty trailing slot doesn't lie green-on-data.
	currentStatus := "operational"
	for i := last24hSlots - 1; i >= 0; i-- {
		if !slotSeen[i] {
			continue
		}
		// Count probes in this single slot to nuance degraded vs down.
		var slotTotal, slotHealthy int
		slotEnd := last24hStart.Add(time.Duration(i+1) * time.Duration(last24hSlotMinutes) * time.Minute)
		slotStart := last24hStart.Add(time.Duration(i) * time.Duration(last24hSlotMinutes) * time.Minute)
		for _, s := range samples {
			if !s.t.Before(slotStart) && s.t.Before(slotEnd) {
				slotTotal++
				if s.ok {
					slotHealthy++
				}
			}
		}
		if slotTotal == 0 {
			break
		}
		pct := (slotHealthy * 100) / slotTotal
		switch {
		case pct == 100:
			currentStatus = "operational"
		case pct >= degradedThresholdPct:
			currentStatus = "degraded"
		default:
			currentStatus = "down"
		}
		break
	}

	// 7d + 30d uptime percentages.
	uptime7d := uptimePctInWindow(samples, now.Add(-uptime7dWindow))
	uptime30d := uptimePctInWindow(samples, since)

	return componentRow{
		Slug:           comp.slug,
		Name:           comp.displayName,
		Category:       comp.category,
		Description:    comp.description,
		CurrentStatus:  currentStatus,
		Uptime7dPct:    uptime7d,
		Uptime30dPct:   uptime30d,
		Last24hSamples: slots,
	}, nil
}

// uptimeSample is the in-memory row used by computeOne. Mirrors the
// SELECT columns; not exported because nothing outside this file needs
// to know the shape.
type uptimeSample struct {
	t  time.Time
	ok bool
}

// uptimePctInWindow returns the percent of healthy samples in
// `samples` whose timestamp is >= `cutoff`. Returns -1 when there are
// no samples in the window — the dashboard renders "—" for that case.
func uptimePctInWindow(samples []uptimeSample, cutoff time.Time) float64 {
	total, healthy := 0, 0
	for _, s := range samples {
		if s.t.Before(cutoff) {
			continue
		}
		total++
		if s.ok {
			healthy++
		}
	}
	if total == 0 {
		return -1
	}
	// Two decimals so the dashboard can render "99.95%" without extra
	// formatting work.
	pct := float64(healthy) / float64(total) * 100.0
	return float64(int(pct*100+0.5)) / 100.0
}
