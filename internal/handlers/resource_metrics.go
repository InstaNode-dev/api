package handlers

// resource_metrics.go — GET /api/v1/resources/:id/metrics
//
// Customer-facing resource metrics. Replaces the dashboard's `status="gap"`
// placeholder on ResourceDetailPage's Metrics tab. Returns aggregated time-series
// (latency p50/p95/p99, active connections, storage_bytes, error_rate_pct) over a
// caller-chosen window — tier-gated so anonymous / free callers can't pull the
// feature without upgrading.
//
// ── DATA SOURCE ─────────────────────────────────────────────────────────────
// Option C, stub variant. The W5-A heartbeat prober that will write per-probe
// rows into a `resource_metrics` table is not yet committed — so this handler
// returns synthetic empty arrays + an explicit `data_source: "stub"` field. The
// API SHAPE matches the eventual Option C / Option A reality, so the dashboard
// can render the layout today and the implementation can swap in real samples
// without touching the wire format.
//
// TODO(W7F-followup): replace generateStubMetrics with one of:
//   - Option A: NerdGraph NRQL against NRDB. Requires NR_INSIGHTS_QUERY_KEY in
//     instant-secrets. The query is `SELECT percentile(duration, 50, 95, 99)
//     FROM Metric WHERE entity.name = '<resource-token>' SINCE <window>
//     TIMESERIES <bucket>`. Operator dep: NR_INSIGHTS_QUERY_KEY must land in
//     instant-secrets and be exposed via env so the handler can construct the
//     NerdGraph client.
//   - Option C (real): once W5-A's prober.go writes probe rows into
//     resource_metrics(team_id, resource_id, observed_at, latency_ms,
//     connections, storage_bytes, ok bool), this handler bucket-aggregates
//     them server-side. Coarser than Option A (per-probe granularity is
//     ≥30s) but no third-party dep.
//
// ── TIER GATE ───────────────────────────────────────────────────────────────
// anonymous / free: 402 upgrade_required + agent_action (this is a Pro
//   differentiator — the P3 founder's blocker, RETRO-2026-05-13)
// hobby           : max 1h window (paid tier but ceiling is tight to keep
//                   NRDB scan cost bounded once Option A lands)
// pro             : max 24h window
// growth / team   : max 7d (604800s) window
//
// Over-limit window param returns 402 with agent_action that names the
// caller's current tier + the ceiling. We deliberately do NOT silently clamp
// — the agent should learn the real wall instead of guessing the data is "all"
// when it's actually capped.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/safego"
)

// metricsDefaultWindow is the window the dashboard requests when the user
// hasn't explicitly chosen one. Matches the Metrics tab's "Metrics · 1h"
// default header.
const metricsDefaultWindow = 1 * time.Hour

// metricsSampleInterval is the bucket width every response uses. Held
// constant across tiers because the dashboard's chart x-axis math assumes
// a fixed step; tier-gated WINDOW changes how many samples come back, not
// the bucket size.
const metricsSampleInterval = 60 * time.Second

// metricsMaxSamples is a hard cap on how many samples the handler will
// generate (or, once Option A lands, request from NerdGraph). Belt-and-braces
// against a future per-tier window cap drift accidentally producing a
// half-megabyte JSON body.
const metricsMaxSamples = 10_080 // 7 days at 1-minute buckets

// metricsTierWindowCap returns the upper bound (in seconds) on the window
// param for a given tier. Anonymous / free are 0 — they hit the 402 wall
// before the window check ever runs. Unknown tiers fall back to the hobby
// ceiling (the smallest non-zero cap) to fail safe.
func metricsTierWindowCap(tier string) int64 {
	switch tier {
	case "anonymous", "free":
		return 0
	case "hobby":
		return int64((1 * time.Hour).Seconds()) // 3600
	case "pro":
		return int64((24 * time.Hour).Seconds()) // 86400
	case "growth", "team":
		return int64((7 * 24 * time.Hour).Seconds()) // 604800
	default:
		return int64((1 * time.Hour).Seconds())
	}
}

// metricsTierHumanCap is what the agent_action prose says about the wall.
// Mirrors the cap returned by metricsTierWindowCap; held separately so the
// copy reads naturally ("1h" instead of "3600 seconds").
func metricsTierHumanCap(tier string) string {
	switch tier {
	case "hobby":
		return "1h"
	case "pro":
		return "24h"
	case "growth", "team":
		return "7d"
	default:
		return "1h"
	}
}

// AgentActionMetricsRequiresUpgrade is returned in the 402 body when an
// anonymous / free caller hits GET /api/v1/resources/:id/metrics. The
// resource observability tile is part of the Pro value prop — the P3 founder
// persona's chief blocker — so the agent_action names that explicitly.
const AgentActionMetricsRequiresUpgrade = "Tell the user resource metrics (p50/p95/p99 latency, connections, storage) require the Pro plan. Upgrade at https://instanode.dev/pricing — takes 30 seconds, then retry the metrics query."

// newAgentActionMetricsWindowTooLarge builds the 402 copy returned when a
// hobby caller asks for ?window=24h. Names the caller's current tier + the
// ceiling so the LLM can re-articulate the exact wall to the user instead
// of a generic "upgrade" prose.
func newAgentActionMetricsWindowTooLarge(currentTier, currentCap string) string {
	return fmt.Sprintf(
		"Tell the user the %s plan caps metrics windows at %s; longer windows require Pro. Upgrade at https://instanode.dev/pricing — takes 30 seconds.",
		currentTier, currentCap,
	)
}

// Metrics handles GET /api/v1/resources/:id/metrics.
//
// Query params:
//
//	?window=<duration>   — e.g. "1h", "24h", "30m". Default 1h. Capped by tier.
//
// Response shape (see openapi.go for the contract):
//
//	{
//	  "ok": true,
//	  "resource_id":       "<uuid>",
//	  "resource_type":     "postgres",
//	  "window_seconds":    3600,
//	  "samples_count":     60,
//	  "sample_interval_seconds": 60,
//	  "metrics": {
//	    "latency_p50_ms":      [...],
//	    "latency_p95_ms":      [...],
//	    "latency_p99_ms":      [...],
//	    "connections_active": [...],
//	    "storage_bytes":       [...],
//	    "error_rate_pct":      [...]
//	  },
//	  "data_source": "stub"  // present until Option A or real Option C ships
//	}
//
// Errors:
//
//	400 invalid_id          — :id is not a valid UUID
//	400 invalid_window      — ?window= unparseable, non-positive, or > 7d
//	401 unauthorized        — no session
//	402 upgrade_required    — anonymous / free tier OR window > tier cap
//	404 not_found           — resource doesn't exist OR caller's team
//	                          doesn't own it (cross-team existence stays opaque)
//	503 fetch_failed        — DB lookup failed
func (h *ResourceHandler) Metrics(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)
	ctx := c.UserContext()

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(ctx, h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("resource.metrics.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}

	if !resource.TeamID.Valid || resource.TeamID.UUID != teamID {
		// 404 not 403: never confirm the existence of resources owned by
		// other teams (or unclaimed anonymous resources).
		return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
	}

	// Tier-gate is read from the team's plan_tier — NOT resource.Tier — so a
	// hobby-team's pro-tier-snapshot resource (post-downgrade) still falls
	// under the team's current plan ceiling. This matches the user-visible
	// billing relationship: "what's my plan", not "what was this resource
	// provisioned under".
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		slog.Error("resource.metrics.team_lookup_failed",
			"error", err, "team_id", teamID, "request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	tierCap := metricsTierWindowCap(team.PlanTier)
	if tierCap == 0 {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			"upgrade_required",
			"Resource metrics require the Pro plan or higher. Your team is on the "+team.PlanTier+" plan.",
			AgentActionMetricsRequiresUpgrade,
			"https://instanode.dev/pricing",
		)
	}

	windowSeconds, parseErr := parseMetricsWindow(c.Query("window"))
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_window", parseErr.Error())
	}
	if windowSeconds > tierCap {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			"upgrade_required",
			fmt.Sprintf("Your %s plan caps metrics windows at %s. Upgrade for a longer window.",
				team.PlanTier, metricsTierHumanCap(team.PlanTier)),
			newAgentActionMetricsWindowTooLarge(team.PlanTier, metricsTierHumanCap(team.PlanTier)),
			"https://instanode.dev/pricing",
		)
	}

	// Build the response. The synthetic-data path is fully deterministic per
	// (resource_id, window) — same input produces same output — so the
	// dashboard's polling doesn't show a thrashing chart while the stub is
	// live, but each resource has a distinct shape (no two postgres tiles
	// look identical). When Option A or real Option C lands, replace this
	// call site with the real fetch.
	samples := generateStubMetrics(resource.ID, windowSeconds)
	dataSource := "stub"

	// Fire-and-forget audit emit. Best-effort: a Postgres outage must not
	// fail the metrics call. Mirrors the pause/resume pattern (resource.go
	// line ~552). Metadata is small JSON — keep it predictable so the Loops
	// forwarder doesn't have to fan-out parse logic per row.
	auditMeta, _ := json.Marshal(map[string]any{
		"resource_id":    resource.ID,
		"window_seconds": windowSeconds,
		"samples_count":  samples.count,
		"data_source":    dataSource,
	})
	safego.Go("resource_metrics.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamID,
			Actor:        "user",
			Kind:         models.AuditKindResourceMetricsQueried,
			ResourceType: resource.ResourceType,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "queried metrics for <strong>" + resource.ResourceType + "</strong> <code>" + token.String()[:8] + "</code>",
			Metadata:     auditMeta,
		})
	})

	return c.JSON(fiber.Map{
		"ok":                      true,
		"resource_id":             resource.ID,
		"resource_type":           resource.ResourceType,
		"window_seconds":          windowSeconds,
		"samples_count":           samples.count,
		"sample_interval_seconds": int64(metricsSampleInterval.Seconds()),
		"metrics":                 samples.series,
		"data_source":             dataSource,
	})
}

// parseMetricsWindow parses a ?window= query value like "1h" / "24h" / "30m"
// and returns the resolved window in seconds. An empty / missing string
// defaults to metricsDefaultWindow. Negative durations, "0", and durations
// exceeding the 7d backstop are rejected — the per-tier cap is checked by
// the caller against the returned value.
//
// Rejecting > 7d here rather than per-tier means an operator who later adds
// a plan with an 8d ceiling has to update this floor too — a deliberate
// re-think gate, not an oversight.
func parseMetricsWindow(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return int64(metricsDefaultWindow.Seconds()), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		// Allow a bare number-of-seconds variant for ergonomics — "3600"
		// instead of "1h" — without unlocking nanos / picos parsing.
		if n, nerr := strconv.ParseInt(raw, 10, 64); nerr == nil {
			d = time.Duration(n) * time.Second
		} else {
			return 0, fmt.Errorf("window must be a duration like 1h, 30m, or 24h — got %q", raw)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("window must be positive (got %s)", d)
	}
	secs := int64(d.Seconds())
	const sevenDaysSeconds = int64(7 * 24 * 60 * 60)
	if secs > sevenDaysSeconds {
		return 0, fmt.Errorf("window exceeds the 7d hard maximum (got %s)", d)
	}
	return secs, nil
}

// metricsSamples is the de-structured form the handler builds — separated so
// the audit-emit step can read samples.count without re-iterating the maps.
type metricsSamples struct {
	count  int
	series map[string][]float64
}

// generateStubMetrics returns deterministic synthetic samples for the given
// (resourceID, windowSeconds). The pattern is "looks plausible at a glance"
// — slow sinusoidal trend on latency, mild noise on connections, monotonic
// storage growth — so the dashboard layout renders against shape that
// resembles the eventual real data.
//
// Determinism contract: same (resourceID, windowSeconds) MUST return the
// same series. The W7F dashboard polls every 60s; without determinism the
// chart would visibly jitter every poll while the stub is live. Once Option
// A / real Option C lands, that polling fetch returns real (changing) data
// and determinism stops mattering.
func generateStubMetrics(resourceID uuid.UUID, windowSeconds int64) metricsSamples {
	bucket := int64(metricsSampleInterval.Seconds())
	n := int(windowSeconds / bucket)
	if n < 1 {
		n = 1
	}
	if n > metricsMaxSamples {
		n = metricsMaxSamples
	}

	// Per-resource seed: same resource → same shape across polls.
	h := fnv.New64a()
	_, _ = h.Write(resourceID[:])
	seed := h.Sum64()

	p50 := make([]float64, n)
	p95 := make([]float64, n)
	p99 := make([]float64, n)
	conn := make([]float64, n)
	stor := make([]float64, n)
	errp := make([]float64, n)

	// Centered baselines, chosen to look plausible for a small-resource tier:
	//   - p50 ~ 2ms, p95 ~ 8ms, p99 ~ 18ms
	//   - connections ~ 3 of 5
	//   - storage_bytes climbing from ~1MB toward ~5MB across the window
	//   - error_rate near 0 with occasional 0.1-0.3% blips
	for i := 0; i < n; i++ {
		phase := float64(i) / float64(metricsMaxInt(n, 1))
		// Use seed to phase-shift each resource so two tiles don't line up.
		shift := float64(seed%1000) / 1000.0
		s := math.Sin(2*math.Pi*(phase+shift)) * 0.5

		p50[i] = round2(2.0 + 0.3*s)
		p95[i] = round2(8.0 + 1.5*s)
		p99[i] = round2(18.0 + 4.0*s)
		conn[i] = round2(3.0 + 0.8*s)
		// Storage: monotonically increases through the window. Real Option C
		// will see flat plateaus + occasional bumps, but a smooth ramp is
		// closer to what dev workloads look like.
		stor[i] = round2(1_048_576 + phase*4_194_304) // ~1MB → ~5MB
		// Error rate: mostly 0 with a tiny phase-shifted blip.
		errp[i] = round2(math.Max(0, 0.1*s))
	}

	return metricsSamples{
		count: n,
		series: map[string][]float64{
			"latency_p50_ms":     p50,
			"latency_p95_ms":     p95,
			"latency_p99_ms":     p99,
			"connections_active": conn,
			"storage_bytes":      stor,
			"error_rate_pct":     errp,
		},
	}
}

// round2 rounds to 2 decimal places. Keeps the JSON payload small + the
// chart axis labels not noisy. File-local helper.
func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

// metricsMaxInt is a tiny shim because math.Max only works on float64 and we
// don't want to dance with type conversions in the hot loop. Prefixed with
// the file name to avoid shadowing builtins / package globals.
func metricsMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
