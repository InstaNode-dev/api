package handlers

// billing_promotion.go — POST /api/v1/billing/promotion/validate.
//
// HTTP wrapper around plans.Registry.ValidatePromotion. The dashboard's
// PromoCodePanel (PR #38) submits a {code, plan} pair to this endpoint and
// renders the discount badge or the red invalid-state from the response.
//
// Contract:
//
//   • 200 + ok:true  — code is valid for the requested plan; includes the
//                      structured `discount` payload mapped from the
//                      plans.Promotion struct.
//   • 200 + ok:false — code is invalid / wrong plan / expired. We return 200
//                      (not 400) so the dashboard renders the red state
//                      through its normal "happy path" parser, without a
//                      catch on the fetch promise. The `agent_action` field
//                      gives MCP / CLI callers the LLM-ready copy.
//   • 400            — request body itself is malformed (empty code, bad
//                      JSON). Distinct from the ok:false path so the
//                      dashboard can surface a developer-error toast instead
//                      of the user-error red banner.
//   • 401            — RequireAuth gate. Promo validation requires a
//                      session because the rate-limiter scopes by team.
//   • 429            — team is hammering this endpoint (>30/hr). Prevents
//                      brute-forcing the seed codes.
//
// Rate-limit implementation lives inline (not the existing
// middleware.RateLimit which is fingerprint-scoped per-day). Per-team
// per-hour bucket: INCR with EXPIRE 1h on first hit, fail-open on Redis
// errors so a cache outage doesn't block valid checkouts.

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
)

// promotionValidationsPerHour caps how many times a single team can hit
// POST /api/v1/billing/promotion/validate per rolling hour. 30 covers a
// human iterating through "did I type that right?" with margin while
// making a brute-force walk through the seed-code namespace impractical.
const promotionValidationsPerHour = 30

// BillingPromotionHandler serves POST /api/v1/billing/promotion/validate.
//
// Separate from BillingHandler so the (rdb, plans) dependency is visible at
// the constructor boundary — BillingHandler proper deals with Razorpay
// state and doesn't need the plan registry today. Splitting also keeps the
// existing billing test rig (which constructs BillingHandler with nil DB)
// untouched.
type BillingPromotionHandler struct {
	rdb   *redis.Client
	plans *plans.Registry
}

// NewBillingPromotionHandler constructs a BillingPromotionHandler. rdb may
// be nil — the rate-limiter then fails open (every request passes).
func NewBillingPromotionHandler(rdb *redis.Client, planRegistry *plans.Registry) *BillingPromotionHandler {
	return &BillingPromotionHandler{rdb: rdb, plans: planRegistry}
}

// promotionValidateRequest is the JSON body for POST
// /api/v1/billing/promotion/validate.
type promotionValidateRequest struct {
	// Code is the user-supplied promotion code. Case-insensitive — the
	// registry uppercases on lookup.
	Code string `json:"code"`
	// Plan is the target tier the user is about to subscribe to (the plan
	// the discount must apply to). Required because the same code may
	// apply to pro-only and the user is on the hobby checkout.
	Plan string `json:"plan"`
}

// promotionDiscount is the JSON shape of the discount payload returned on
// the success path. The fields are mapped 1:1 from plans.Promotion:
//
//   • Kind        — always "percent_off" (plans.Promotion only carries
//                   DiscountPercent today; if amount_off variants are
//                   added later, switch on a new struct field).
//   • Value       — DiscountPercent.
//   • AppliesTo   — the list of tier names the code applies to.
//   • MaxUses     — registry-level cap (-1 = unlimited). The dashboard
//                   surfaces "first 1000 signups" copy from this.
//   • Description — operator-facing label; safe to render in the UI.
//
// The brief spec floated an `applies_to: int` + `unit: "months"` shape;
// the actual struct has no such fields, so we keep `applies_to` as the
// []string of plan tiers (which is what the struct carries). See the
// PR description for the divergence note.
type promotionDiscount struct {
	Kind        string   `json:"kind"`
	Value       int      `json:"value"`
	AppliesTo   []string `json:"applies_to"`
	MaxUses     int      `json:"max_uses"`
	Description string   `json:"description,omitempty"`
}

// promotionValidateResponse is the canonical JSON envelope. Only one of
// Discount / Error+Message+AgentAction is populated per response.
type promotionValidateResponse struct {
	OK          bool               `json:"ok"`
	Code        string             `json:"code,omitempty"`
	Discount    *promotionDiscount `json:"discount,omitempty"`
	ValidUntil  string             `json:"valid_until,omitempty"`
	Error       string             `json:"error,omitempty"`
	Message     string             `json:"message,omitempty"`
	AgentAction string             `json:"agent_action,omitempty"`
}

// ValidatePromotion handles POST /api/v1/billing/promotion/validate.
//
// Status codes:
//   - 200  ok:true + discount  — valid code for the given plan
//   - 200  ok:false + error    — invalid / wrong plan / expired / exhausted
//   - 400  invalid_body        — empty code, missing fields, bad JSON
//   - 401  unauthorized        — no/invalid session (RequireAuth)
//   - 429  rate_limit_exceeded — >30 validations in the trailing hour
func (h *BillingPromotionHandler) ValidatePromotion(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	var body promotionValidateRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}
	code := strings.TrimSpace(body.Code)
	plan := strings.ToLower(strings.TrimSpace(body.Plan))
	if code == "" {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Field 'code' is required")
	}
	if plan == "" {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Field 'plan' is required")
	}

	// Rate-limit BEFORE consulting the registry. Brute-force protection
	// only works if we stop the request before answering "yes/no" on the
	// code. Fail-open on Redis errors — a cache outage must not block a
	// user who's about to pay.
	exceeded, rlErr := h.incrementRateLimit(c, teamID)
	if rlErr != nil {
		slog.Warn("billing.promotion.validate.rate_limit_redis_error",
			"error", rlErr,
			"team_id", teamID,
			"request_id", middleware.GetRequestID(c),
		)
		// fall through — fail open
	} else if exceeded {
		return respondError(c, fiber.StatusTooManyRequests, "rate_limit_exceeded",
			fmt.Sprintf("Promotion validation rate limit reached (%d/hour). Try again later.", promotionValidationsPerHour))
	}

	// Registry handles case-insensitive lookup + plan applicability +
	// expiry parsing. Errors are typed-as-strings today; we map by
	// substring so the response carries a structured `error` field
	// regardless of the registry's wording.
	promo, validateErr := h.plans.ValidatePromotion(code, plan)
	if validateErr != nil {
		errKind, message := classifyPromotionError(validateErr, code, plan)
		return c.JSON(promotionValidateResponse{
			OK:          false,
			Error:       errKind,
			Message:     message,
			AgentAction: AgentActionPromotionInvalid,
		})
	}

	resp := promotionValidateResponse{
		OK:   true,
		Code: strings.ToUpper(code),
		Discount: &promotionDiscount{
			Kind:        "percent_off",
			Value:       promo.DiscountPercent,
			AppliesTo:   promo.AppliesTo,
			MaxUses:     promo.MaxUses,
			Description: promo.Description,
		},
	}
	// ValidUntil mirrors Promotion.ExpiresAt (YYYY-MM-DD → ISO at end of
	// day UTC). Empty string in the struct means "never expires" → we
	// omit the field. We pick end-of-day (23:59:59Z) over start-of-day so
	// "expires_at: 2026-12-31" displays as "valid through Dec 31",
	// matching what an operator means when writing the YAML.
	if promo.ExpiresAt != "" {
		if t, parseErr := time.Parse("2006-01-02", promo.ExpiresAt); parseErr == nil {
			resp.ValidUntil = t.UTC().Add(24*time.Hour - time.Second).Format(time.RFC3339)
		}
	}
	return c.JSON(resp)
}

// classifyPromotionError maps the registry's error strings to a stable
// machine-readable code + a user-facing message. The registry uses
// fmt.Errorf with substring patterns ("not found", "has expired", "does
// not apply") — keeping the classification in one place isolates the
// HTTP handler from registry wording changes.
func classifyPromotionError(err error, code, plan string) (kind, message string) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "expired"):
		return "promotion_expired",
			fmt.Sprintf("Promotion code %q has expired.", strings.ToUpper(code))
	case strings.Contains(msg, "exhausted"):
		// Registry doesn't currently emit this, but we keep the branch so
		// adding max_uses tracking later doesn't require a handler change.
		return "promotion_exhausted",
			fmt.Sprintf("Promotion code %q is no longer available.", strings.ToUpper(code))
	case strings.Contains(msg, "does not apply"):
		return "promotion_invalid",
			fmt.Sprintf("Promotion code %q is not valid for the %s plan.", strings.ToUpper(code), plan)
	default:
		// "not found" + any future "invalid" wording.
		return "promotion_invalid",
			fmt.Sprintf("Promotion code %q is not valid for the %s plan.", strings.ToUpper(code), plan)
	}
}

// incrementRateLimit increments the team's hourly counter and reports
// whether the limit has been exceeded. Bucket key is rotated each clock
// hour (UTC); EXPIRE 1h+5min covers the bucket without overlap. Returns
// (exceeded, error) — callers must fail open on a non-nil error.
//
// Note: We deliberately do not use middleware.RateLimit here because that
// helper buckets per-fingerprint per-day, not per-team per-hour. The two
// counters serve different threat models (anonymous abuse vs.
// authenticated brute-force of a small code namespace).
func (h *BillingPromotionHandler) incrementRateLimit(c *fiber.Ctx, teamID uuid.UUID) (bool, error) {
	if h.rdb == nil {
		// No Redis configured (test path) — pass.
		return false, nil
	}
	now := time.Now().UTC()
	bucket := now.Format("2006-01-02T15") // hourly bucket
	key := fmt.Sprintf("promo_validate:%s:%s", teamID.String(), bucket)
	ctx := c.Context()
	pipe := h.rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 65*time.Minute) // covers the bucket with margin
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("rate-limit pipeline: %w", err)
	}
	count, err := incrCmd.Result()
	if err != nil {
		return false, fmt.Errorf("rate-limit incr: %w", err)
	}
	return count > int64(promotionValidationsPerHour), nil
}
