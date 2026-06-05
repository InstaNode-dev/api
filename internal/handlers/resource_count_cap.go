package handlers

// resource_count_cap.go — shared per-service resource-count cap enforcement
// (Task #55). Closes the strict-≥80%-margin hole where only queue_count was
// capped: a tenant could create MANY postgres/redis/mongo/etc. resources each
// at the per-resource size cap and blow the saturated-COGS bound.
//
// The check mirrors the always-on queue_count A6 block in queue.go exactly
// (count active resources of the type for the team, compare to the per-tier cap
// from plans.yaml, return 402 + agent_action + increment a *LimitBlocked
// metric) — but is FLAG-GATED behind cfg.ResourceCountCapsEnabled
// (RESOURCE_COUNT_CAPS_ENABLED, default OFF). When the flag is off the function
// returns (nil) immediately and NO count query runs, so enforcement is fully
// inert and shipping it cannot surprise-break an existing heavy tenant.
//
// queue.go keeps its own inline block (always-on, predates this flag) — this
// helper covers the five newly-capped services (postgres/vector/redis/mongodb/
// storage) so adding a service is one call site, not a copy-pasted block.

import (
	"fmt"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/metrics"
	"instant.dev/internal/models"
)

// enforceResourceCountCap rejects a provision when the team is already at or
// above its per-tier active-resource count for the given service.
//
// Behaviour:
//   - flag OFF (default) → returns (false, nil): caller proceeds, NO query runs.
//   - limit < 0 (unlimited / fail-open) → returns (false, nil).
//   - count query error → returns (true, 503): fail CLOSED on the count is
//     intentional here (unlike Redis rate-limit fail-open) because the count is
//     a cheap indexed COUNT on platform_db; a DB outage already fails the
//     provision downstream, and we must not let a count-query blip silently
//     bypass a cost cap when the operator has explicitly enabled enforcement.
//   - existing >= limit → returns (true, 402 + agent_action) and increments the
//     metric.
//   - under cap → returns (false, nil): caller proceeds.
//
// The bool is "handled": when true the caller MUST return the returned error
// (which is the fiber response) and not continue provisioning.
//
// service is the resources.resource_type value AND the plans.ResourceCountLimit
// key (postgres/vector/redis/mongodb/storage) — they are the same string set.
func (h *provisionHelper) enforceResourceCountCap(
	c *fiber.Ctx, teamID uuid.UUID, planTier, service, requestID string,
) (handled bool, err error) {
	// Flag OFF (or a misconfigured handler with no cfg/registry) → fully inert.
	// No query, no behavior change. This is the proven-inert path
	// (TestResourceCountCap_FlagOffIsInert).
	if h.cfg == nil || !h.cfg.ResourceCountCapsEnabled || h.plans == nil {
		return false, nil
	}

	limit := h.plans.ResourceCountLimit(planTier, service)
	if limit < 0 {
		// Unlimited (or fail-open zero-fallback / unknown tier) — no cap.
		return false, nil
	}

	ctx := c.UserContext()
	existing, countErr := models.CountActiveResourcesByTeamAndType(ctx, h.db, teamID, service)
	if countErr != nil {
		slog.Error("provision.count_cap.count_failed",
			"error", countErr, "service", service, "team_id", teamID.String(), "request_id", requestID)
		return true, respondError(c, fiber.StatusServiceUnavailable, "quota_check_failed",
			fmt.Sprintf("Failed to check %s quota", service))
	}
	if existing >= limit {
		metrics.ResourceCountLimitBlocked.WithLabelValues(service, planTier).Inc()
		return true, respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			service+"_limit_reached",
			fmt.Sprintf("Your %s plan allows %d %s resource(s). Upgrade at %s", planTier, limit, service, DefaultPricingURL),
			fmt.Sprintf("Tell the user they've hit the %s tier %s cap (%d). Upgrade at %s for a higher limit.", planTier, service, limit, DefaultPricingURL),
			DefaultPricingURL,
		)
	}
	return false, nil
}
