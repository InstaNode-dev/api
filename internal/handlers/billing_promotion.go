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
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// promotionValidationsPerHour caps how many times a single team can hit
// POST /api/v1/billing/promotion/validate per rolling hour. 30 covers a
// human iterating through "did I type that right?" with margin while
// making a brute-force walk through the seed-code namespace impractical.
const promotionValidationsPerHour = 30

// BillingPromotionHandler serves POST /api/v1/billing/promotion/validate.
//
// Separate from BillingHandler so the (db, rdb, plans) dependency is visible
// at the constructor boundary — BillingHandler proper deals with Razorpay
// state. Splitting also keeps the existing billing test rig untouched.
//
// The handler unifies two promotion-code sources: the static plans-yaml
// registry (broadcast codes like TWITTER15 / LAUNCH50) and the admin-issued
// single-use codes in the admin_promo_codes table (one-off codes scoped to
// a single team). Callers see one endpoint, one response shape; the
// handler dispatches internally based on which source the code lives in.
type BillingPromotionHandler struct {
	db    *sql.DB
	rdb   *redis.Client
	plans *plans.Registry
}

// NewBillingPromotionHandler constructs a BillingPromotionHandler. rdb may
// be nil — the rate-limiter then fails open (every request passes). db may
// be nil too — the admin-code fallback is skipped (the handler then behaves
// exactly like the PR #47 plans-yaml-only path, preserving backwards
// compatibility with the existing billing_promotion_test.go rig).
func NewBillingPromotionHandler(db *sql.DB, rdb *redis.Client, planRegistry *plans.Registry) *BillingPromotionHandler {
	return &BillingPromotionHandler{db: db, rdb: rdb, plans: planRegistry}
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
	if validateErr == nil {
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

	// Plans-yaml said the code is unknown / expired / wrong plan. For the
	// "unknown" case the user may have been given an admin-issued single-use
	// code instead — fall back to the admin_promo_codes table before
	// declaring the code invalid. For expired/wrong-plan results from the
	// plans-yaml side, we DON'T fall through: those mean the code exists in
	// the plans registry but isn't usable, and re-trying the same code as
	// an admin lookup would only succeed if an admin happened to issue a
	// code with the same name (vanishingly unlikely, but the semantics
	// would be wrong — the user typed a plans-yaml code and saw the wrong
	// reason).
	if !isPromoNotFoundError(validateErr) || h.db == nil {
		errKind, message := classifyPromotionError(validateErr, code, plan)
		return c.JSON(promotionValidateResponse{
			OK:          false,
			Error:       errKind,
			Message:     message,
			AgentAction: AgentActionPromotionInvalid,
		})
	}

	// Admin-code fallback. Single-row lookup scoped to the caller's team —
	// cross-team codes are invisible (we don't reveal their existence on
	// purpose; see GetAdminPromoCodeByCode docstring).
	adminResp, adminErr := h.lookupAdminPromotion(c, teamID, code, plan)
	if adminErr != nil {
		// Transient DB failure on the admin lookup. Surface as "invalid"
		// rather than a 503 — the user can re-try later, and a brownout on
		// the rare admin-code path must not block checkout for the much
		// more common plans-yaml path. Log loudly so ops sees it.
		slog.Warn("billing.promotion.validate.admin_lookup_failed",
			"error", adminErr,
			"team_id", teamID,
			"request_id", middleware.GetRequestID(c),
		)
		return c.JSON(promotionValidateResponse{
			OK:          false,
			Error:       "promotion_invalid",
			Message:     fmt.Sprintf("Promotion code %q is not valid for the %s plan.", strings.ToUpper(code), plan),
			AgentAction: AgentActionPromotionInvalid,
		})
	}
	return c.JSON(adminResp)
}

// isPromoNotFoundError returns true when the registry's ValidatePromotion
// returned a "not found" error (vs. expired/wrong-plan). Substring match
// because the registry uses fmt.Errorf with stable wording — keeping the
// check in one place isolates this handler from registry rewording.
func isPromoNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found")
}

// lookupAdminPromotion handles the admin_promo_codes fallback path on the
// "code not found in plans-yaml" branch. Returns one of:
//
//   - (response, nil)            — the response to send (could be success or
//                                  one of the ok:false branches:
//                                  promotion_invalid / promotion_expired /
//                                  promotion_already_used).
//   - (response{}, <DB error>)   — transient DB failure. Caller decides
//                                  whether to surface this as 503 or fold
//                                  into a generic "invalid" response.
//
// Single-use enforcement happens at validate time AND again at the webhook
// (UPDATE ... WHERE used_at IS NULL) so a race can't double-spend a code.
// This validate-time check is the friendly path: tell the user the code
// is already redeemed *before* they pay.
func (h *BillingPromotionHandler) lookupAdminPromotion(c *fiber.Ctx, teamID uuid.UUID, code, plan string) (promotionValidateResponse, error) {
	row, err := models.GetAdminPromoCodeByCode(c.Context(), h.db, code, teamID)
	if err != nil {
		if errors.Is(err, models.ErrAdminPromoCodeNotFound) {
			// Cross-team codes also surface as "not found" here — we don't
			// disclose their existence. Same response as a plain-unknown
			// code from the plans-yaml path.
			return promotionValidateResponse{
				OK:          false,
				Error:       "promotion_invalid",
				Message:     fmt.Sprintf("Promotion code %q is not valid for the %s plan.", strings.ToUpper(code), plan),
				AgentAction: AgentActionPromotionInvalid,
			}, nil
		}
		// Transient DB failure — let caller decide.
		return promotionValidateResponse{}, err
	}

	upperCode := strings.ToUpper(strings.TrimSpace(code))

	// Single-use: if used_at is set, surface the "already redeemed" branch
	// with its distinct agent_action sentence. The dashboard renders the
	// red state via the normal ok:false parser.
	if row.UsedAt.Valid {
		return promotionValidateResponse{
			OK:          false,
			Code:        upperCode,
			Error:       "promotion_already_used",
			Message:     fmt.Sprintf("Promotion code %q has already been redeemed.", upperCode),
			AgentAction: AgentActionPromotionAlreadyUsed,
		}, nil
	}

	// Expired admin code → distinct "promotion_expired" surface so the
	// dashboard can show "this code has expired" copy. Comparing on UTC
	// avoids the clock-skew edge case at the second around expiry.
	if !row.ExpiresAt.IsZero() && time.Now().UTC().After(row.ExpiresAt) {
		return promotionValidateResponse{
			OK:          false,
			Code:        upperCode,
			Error:       "promotion_expired",
			Message:     fmt.Sprintf("Promotion code %q has expired.", upperCode),
			AgentAction: AgentActionPromotionExpired,
		}, nil
	}

	// Plan-applicability for admin codes:
	//
	// admin_promo_codes.applies_to is INTEGER (per migration 021) and is
	// documented (openapi.go) as the percent_off cap in cents — NOT a tier
	// list. Admin codes are scoped to a team, not a plan: any plan the team
	// chooses to subscribe to may apply the code. We therefore do not
	// reject the validate request based on the requested plan; we echo
	// back the plan that was asked for in the discount.applies_to field
	// so the dashboard's PromoCodePanel renders "applies to <plan>"
	// uniformly across both code sources. The plan filter on plans-yaml
	// codes (LAUNCH50 → pro/team only) still works because those codes
	// take the plans-yaml branch above.
	return promotionValidateResponse{
		OK:       true,
		Code:     upperCode,
		Discount: adminPromoDiscount(row, plan),
		// ValidUntil reflects the admin code's expires_at, full RFC3339
		// timestamp (vs. the YYYY-MM-DD coarseness of plans-yaml codes).
		ValidUntil: row.ExpiresAt.UTC().Format(time.RFC3339),
	}, nil
}

// adminPromoDiscount maps an AdminPromoCode row onto the response.discount
// shape that PR #47 introduced for plans-yaml codes. The mapping is:
//
//   • Kind  — passthrough of admin_promo_codes.kind (one of percent_off /
//             first_month_free / amount_off). The dashboard already
//             expects "percent_off" today; first_month_free / amount_off
//             extend that enum.
//   • Value — admin_promo_codes.value. For percent_off this is 1..100; for
//             amount_off this is cents; for first_month_free this is
//             ignored at billing time (Razorpay free-period coupon).
//   • AppliesTo — echoed as []string{plan} because admin codes apply to
//             any plan the team subscribes to (the field is structural
//             parity with plans-yaml; the actual filter is by team_id).
//   • MaxUses — 1 for admin codes (single-use is the whole point of the
//             admin_promo_codes table; plans-yaml uses -1 / 1000 etc.).
//   • Description — synthesized human-readable copy for the dashboard's
//             "applies to X" line; admin codes don't carry a description
//             column, so we generate a stable one from kind + value.
func adminPromoDiscount(row *models.AdminPromoCode, plan string) *promotionDiscount {
	return &promotionDiscount{
		Kind:        row.Kind,
		Value:       row.Value,
		AppliesTo:   []string{plan},
		MaxUses:     1,
		Description: adminPromoDescription(row),
	}
}

// adminPromoDescription returns the "applies to X" human-readable copy the
// dashboard's PromoCodePanel renders. Stable phrasing per kind so the
// dashboard's tests can match on substring without coupling to the value.
func adminPromoDescription(row *models.AdminPromoCode) string {
	switch row.Kind {
	case models.PromoKindPercentOff:
		return fmt.Sprintf("%d%% off (admin-issued, single use)", row.Value)
	case models.PromoKindFirstMonthFree:
		return "First month free (admin-issued, single use)"
	case models.PromoKindAmountOff:
		// Value is cents; show as a rounded-dollar approximation. The
		// actual charge math happens server-side at webhook time, so this
		// copy is purely for the UI.
		return fmt.Sprintf("$%.2f off (admin-issued, single use)", float64(row.Value)/100)
	default:
		// Unknown kind — should be impossible given the DB CHECK constraint
		// in migration 021, but defensive copy beats a panic.
		return "Admin-issued promo code (single use)"
	}
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
