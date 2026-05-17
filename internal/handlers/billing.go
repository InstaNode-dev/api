package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	razorpay "github.com/razorpay/razorpay-go"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"instant.dev/internal/circuit"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/razorpaybilling"
)

// checkoutNoteAdminPromoCodeID is the Razorpay subscription `notes` key we
// use to round-trip an admin_promo_codes.id from checkout to the activation
// webhook. The webhook reads this exact key to look up the row to mark used.
// Kept as a named constant (per the project's named-constants convention) so
// the checkout side and the webhook side cannot drift.
const checkoutNoteAdminPromoCodeID = "admin_promo_code_id"

// checkoutInflightTTL bounds the server-side dedup window for a team's
// concurrent /api/v1/billing/checkout calls. ~60s is well within the
// time it takes a user to read the Razorpay hosted-checkout response,
// realise it loaded, and (mistakenly) double-tap or re-submit. The TTL
// also caps the worst case where the first caller crashes mid-flight —
// after 60s a retry is allowed without operator intervention.
const checkoutInflightTTL = 60 * time.Second

// checkoutInflightKeyPrefix is the Redis key prefix for the per-team
// SETNX dedup guard. Scoped by team_id (not user) so a second user on
// the same team also bounces — the subscription belongs to the team.
const checkoutInflightKeyPrefix = "team_checkout_inflight:"

// BillingHandler handles billing and Razorpay webhook endpoints.
type BillingHandler struct {
	db    *sql.DB
	cfg   *config.Config
	email *email.Client

	// rdb is the Redis client used by the BB2-D5 server-side dedup guard
	// on CreateCheckoutAPI (the SETNX `team_checkout_inflight:<team_id>`
	// belt). Nil-safe: if unset, the guard fails open and the call
	// proceeds — Redis outages must never block paid upgrades. The
	// router wires this via WithRedis() at handler construction time;
	// tests that don't exercise the guard can leave it nil.
	rdb *redis.Client

	// FetchSubscriptionDetails fetches a Razorpay subscription + its latest
	// paid invoice for billing-state aggregation. Set in tests to substitute
	// a fake (the production default goes through razorpaybilling.Portal).
	// Returning (nil, nil) is valid and means "no details available" —
	// callers should default the relevant response fields.
	FetchSubscriptionDetails func(subscriptionID string) (*razorpaybilling.SubscriptionDetails, error)
}

// NewBillingHandler constructs a BillingHandler.
func NewBillingHandler(db *sql.DB, cfg *config.Config, emailClient *email.Client) *BillingHandler {
	h := &BillingHandler{db: db, cfg: cfg, email: emailClient}
	// Default to the real Razorpay portal; tests override this field directly.
	h.FetchSubscriptionDetails = func(subID string) (*razorpaybilling.SubscriptionDetails, error) {
		portal := &razorpaybilling.Portal{DB: h.db, Cfg: h.cfg}
		return portal.FetchSubscriptionDetails(subID)
	}
	return h
}

// WithRedis wires a Redis client onto the handler for the BB2-D5 checkout
// dedup guard. Returns the receiver for fluent construction at the router
// boundary. Calling this is OPTIONAL — when the field is nil the guard
// fails open (proceeds without dedup) which preserves backwards-compatible
// behaviour for tests that construct the handler without Redis.
func (h *BillingHandler) WithRedis(rdb *redis.Client) *BillingHandler {
	h.rdb = rdb
	return h
}

// checkoutRequest is the request body for POST /api/v1/billing/checkout.
//
// PlanFrequency selects between the monthly and yearly Razorpay plan_id for
// the requested tier. Accepted values: "monthly" (default when empty),
// "yearly". Any other value is rejected as 400 invalid_frequency. The team's
// canonical tier (the value stored on teams.plan_tier) is unchanged by
// frequency — only the underlying Razorpay subscription differs.
//
// PromotionCode is an optional admin-issued promo code (one of the rows in
// admin_promo_codes). When set, we resolve the code's DB row server-side and
// stamp its id into the Razorpay subscription `notes` field for future
// tracking. The webhook handler does NOT mark used_at on the code (Slice 3
// interim fix — DESIGN-P1-B-billing-resilience.md §5 Option B): no Razorpay
// Offer (offer_id) is attached to the subscription, so no discount is applied
// and consuming the code at webhook time would be a financial broken promise.
// Codes remain available until Option A (real Razorpay Offers) is wired.
// Plans-yaml codes (LAUNCH50 etc.) are still allowed in this field but
// produce no notes side-effect — they're handled at validate-time via
// plans.Registry and never need DB tracking.
type checkoutRequest struct {
	Plan          string `json:"plan"`
	PlanFrequency string `json:"plan_frequency"`
	PromotionCode string `json:"promotion_code"`
}

// razorpayPlanIDs returns the configured monthly Razorpay plan_id for each
// tier. Used by ChangePlanAPI which today supports monthly-only plan
// changes; yearly changes go through a new checkout subscription.
func (h *BillingHandler) razorpayPlanIDs() map[string]string {
	m := make(map[string]string)
	if h.cfg.RazorpayPlanIDHobby != "" {
		m["hobby"] = h.cfg.RazorpayPlanIDHobby
	}
	if h.cfg.RazorpayPlanIDHobbyPlus != "" {
		m["hobby_plus"] = h.cfg.RazorpayPlanIDHobbyPlus
	}
	if h.cfg.RazorpayPlanIDPro != "" {
		m["pro"] = h.cfg.RazorpayPlanIDPro
	}
	if h.cfg.RazorpayPlanIDTeam != "" {
		m["team"] = h.cfg.RazorpayPlanIDTeam
	}
	return m
}

// razorpayPlanIDFor returns the configured plan_id for (tier, frequency)
// where frequency is "monthly" or "yearly". Returns "" when the tier or
// frequency has no plan_id configured (operator hasn't created it in the
// Razorpay dashboard yet) — callers must surface 503 billing_not_configured.
func (h *BillingHandler) razorpayPlanIDFor(tier, frequency string) string {
	switch tier {
	case "hobby":
		if frequency == "yearly" {
			return h.cfg.RazorpayPlanIDHobbyYearly
		}
		return h.cfg.RazorpayPlanIDHobby
	case "hobby_plus":
		// W11 mid-tier. Plan IDs default to "" until the operator
		// creates the RAZORPAY_PLAN_ID_HOBBY_PLUS / _ANNUAL plans in
		// the Razorpay dashboard — callers see 503 billing_not_configured
		// when the corresponding env var is unset.
		if frequency == "yearly" {
			return h.cfg.RazorpayPlanIDHobbyPlusYearly
		}
		return h.cfg.RazorpayPlanIDHobbyPlus
	case "pro":
		if frequency == "yearly" {
			return h.cfg.RazorpayPlanIDProYearly
		}
		return h.cfg.RazorpayPlanIDPro
	case "team":
		if frequency == "yearly" {
			return h.cfg.RazorpayPlanIDTeamYearly
		}
		return h.cfg.RazorpayPlanIDTeam
	}
	return ""
}

// planIDToTierFallback is the tier returned when a Razorpay plan_id cannot be
// mapped to any configured tier. Deliberately the LOWEST paid tier (hobby)
// rather than "pro": an env-var typo may result in a $9 Hobby grant instead
// of a $49 Pro grant — 5× smaller blast radius — and the discrepancy will be
// caught and corrected upward by the billing reconciler on its next tick.
//
// DO NOT change this to "pro". See DESIGN-P1-B-billing-resilience.md §4.
const planIDToTierFallback = "hobby"

// planIDToTier maps a Razorpay plan_id back to a canonical instant.dev tier
// name. Recognises both monthly and yearly plan IDs and returns the bare
// tier (e.g. "pro") in either case — the webhook stores canonical tiers on
// teams.plan_tier so limits resolution stays cycle-agnostic.
//
// Fail-safe default: returns planIDToTierFallback ("hobby") — the lowest paid
// tier — when the plan_id is empty or does not match any configured env var.
// An slog.Error is emitted so New Relic can alert on misconfiguration; the
// reconciler will correct the tier upward within 15 minutes once the env var
// is fixed.
//
// An empty planID never matches anything: in development some env vars may
// be "" and we must not silently classify a missing/empty webhook plan_id
// or coincidentally-empty cfg slot as the matching tier.
func (h *BillingHandler) planIDToTier(planID string) string {
	if planID == "" {
		slog.Error("billing.plan_id_to_tier.empty",
			"fallback_tier", planIDToTierFallback,
			"action", "Check RAZORPAY_PLAN_ID_* env vars — an empty plan_id will be treated as "+planIDToTierFallback,
		)
		return planIDToTierFallback
	}
	// Explicit per-tier comparison to skip empty cfg slots — an unconfigured
	// yearly variant should not consume a "" webhook plan_id and steal its
	// canonical-tier mapping from another configured cfg value.
	if h.cfg.RazorpayPlanIDTeam != "" && planID == h.cfg.RazorpayPlanIDTeam {
		return "team"
	}
	if h.cfg.RazorpayPlanIDTeamYearly != "" && planID == h.cfg.RazorpayPlanIDTeamYearly {
		return "team"
	}
	if h.cfg.RazorpayPlanIDPro != "" && planID == h.cfg.RazorpayPlanIDPro {
		return "pro"
	}
	if h.cfg.RazorpayPlanIDProYearly != "" && planID == h.cfg.RazorpayPlanIDProYearly {
		return "pro"
	}
	if h.cfg.RazorpayPlanIDHobbyPlus != "" && planID == h.cfg.RazorpayPlanIDHobbyPlus {
		return "hobby_plus"
	}
	if h.cfg.RazorpayPlanIDHobbyPlusYearly != "" && planID == h.cfg.RazorpayPlanIDHobbyPlusYearly {
		return "hobby_plus"
	}
	if h.cfg.RazorpayPlanIDHobby != "" && planID == h.cfg.RazorpayPlanIDHobby {
		return "hobby"
	}
	if h.cfg.RazorpayPlanIDHobbyYearly != "" && planID == h.cfg.RazorpayPlanIDHobbyYearly {
		return "hobby"
	}
	// No configured plan_id matched. Log at Error level so NR picks this up as
	// a critical alert — the operator must fix RAZORPAY_PLAN_ID_* env vars.
	// The reconciler will detect and correct the tier mismatch within 15 min.
	slog.Error("billing.plan_id_to_tier.unrecognised",
		"plan_id", planID,
		"fallback_tier", planIDToTierFallback,
		"action", "Check RAZORPAY_PLAN_ID_* env vars — an unknown plan_id will be treated as "+planIDToTierFallback,
	)
	return planIDToTierFallback
}

// CreateCheckoutAPI handles POST /api/v1/billing/checkout (and the legacy
// alias POST /billing/checkout). Creates a Razorpay subscription and returns
// the hosted payment short_url plus the subscription_id.
//
// Requires a valid session JWT in the Authorization: Bearer header (enforced
// by RequireAuth middleware).
//
// Response: {"ok": true, "short_url": "...", "subscription_id": "..."}
//
// Status codes:
//   - 400  invalid plan / invalid body
//   - 401  no/invalid session (RequireAuth handles this)
//   - 502  Razorpay rejected the create-subscription call
//   - 503  RAZORPAY_KEY_ID/SECRET or the requested tier's plan_id not configured
func (h *BillingHandler) CreateCheckoutAPI(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)
	teamIDStr := middleware.GetTeamID(c)

	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	// BB2-D5 server-side dedup belt. Two rapid concurrent POSTs (cross-tab
	// click, mobile double-tap, retried form submit) each call Razorpay
	// independently today and create TWO subscriptions — a real revenue
	// loss path because the user is charged for whichever short_url they
	// actually open. The dashboard's single-tab `checkoutLoading` guard is
	// client-only and bypassed by any of the above; this Redis SETNX is
	// the load-bearing fix.
	//
	// Contract:
	//   - Atomic SETNX (`team_checkout_inflight:<team_id>`, TTL 60s).
	//   - SETNX=1 (key created) → proceed. We hold the key for the entire
	//     Razorpay call duration; the TTL auto-clears so a crashed/timed-
	//     out first caller never wedges a team's checkout indefinitely.
	//   - SETNX=0 (key already held) → return 409 checkout_in_flight with
	//     a structured agent_action so the caller knows to wait + refresh.
	//   - Redis error → fail OPEN with a WARN log. A Redis outage must
	//     NEVER block a paid upgrade; the cost of an extremely rare
	//     duplicate during a Redis brownout is far below the cost of
	//     blocking every paying customer. The Idempotency-Key middleware
	//     on this route is the braces — when present it dedupes
	//     regardless of Redis health.
	guardCtx := c.Context()
	guardKey := checkoutInflightKeyPrefix + teamID.String()
	if h.rdb != nil {
		ok, setErr := h.rdb.SetNX(guardCtx, guardKey, requestID, checkoutInflightTTL).Result()
		if setErr != nil {
			// Fail open — a Redis brownout must not block paying customers.
			// The Idempotency-Key braces and the dashboard single-tab guard
			// still apply on this path.
			slog.Warn("billing.checkout.dedup_setnx_failed_open",
				"error", setErr,
				"team_id", teamID,
				"request_id", requestID,
			)
		} else if !ok {
			// Another caller is already creating a checkout for this team.
			// Surface retry_after_seconds = 60 directly (the helper's default
			// is nil on 409s — see defaultRetryAfterSeconds — but agents
			// branching on this status DO want a wait hint). Emit the
			// envelope inline rather than threading a fourth helper.
			slog.Info("billing.checkout.dedup_blocked",
				"team_id", teamID,
				"request_id", requestID,
			)
			retry := int(checkoutInflightTTL / time.Second)
			_ = c.Status(fiber.StatusConflict).JSON(ErrorResponse{
				OK:                false,
				Error:             "checkout_in_flight",
				Message:           "A checkout is already being created for this team. Wait ~60s and retry, or visit /dashboard to find the existing pending subscription.",
				RequestID:         requestID,
				RetryAfterSeconds: &retry,
				AgentAction:       "Tell the user a checkout is already being created. They should wait ~60 seconds and refresh — the existing checkout link will appear in the dashboard.",
			})
			return ErrResponseWritten
		} else {
			defer func() {
				// Release the guard on the way out so a retry after a
				// 4xx (e.g. invalid plan) doesn't have to wait the full
				// 60s. The TTL is the safety net for crashed callers; the
				// defer is the fast-path for normal completion. Use a
				// background context so a cancelled request still clears.
				if delErr := h.rdb.Del(context.Background(), guardKey).Err(); delErr != nil {
					slog.Warn("billing.checkout.dedup_release_failed",
						"error", delErr,
						"team_id", teamID,
						"request_id", requestID,
					)
				}
			}()
		}
	}

	var body checkoutRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}

	plan := strings.ToLower(strings.TrimSpace(body.Plan))
	// plan_frequency selects monthly vs yearly Razorpay plan_id. Empty maps
	// to "monthly" so existing callers (which never set the field) keep
	// today's behaviour. Anything other than monthly|yearly is rejected so
	// a typo doesn't silently fall back to the wrong cycle.
	frequency := strings.ToLower(strings.TrimSpace(body.PlanFrequency))
	if frequency == "" {
		frequency = "monthly"
	}
	if frequency != "monthly" && frequency != "yearly" {
		return respondError(c, fiber.StatusBadRequest, "invalid_frequency",
			"plan_frequency must be 'monthly' or 'yearly'")
	}

	switch plan {
	case "hobby", "hobby_plus", "pro":
		// fall through — plan_id is resolved by razorpayPlanIDFor below.
	case "team":
		// Team tier is under development — block customer-initiated
		// subscribe via the public API. The internal /internal/set-tier
		// endpoint still works for ops use. Drop this guard when team
		// launches (and revert the public pricing UI).
		return respondError(c, fiber.StatusBadRequest, "tier_unavailable",
			"Team tier is under active development. Email support@instanode.dev to join the early access list.")
	default:
		return respondError(c, fiber.StatusBadRequest, "invalid_plan", "plan must be 'hobby', 'hobby_plus', or 'pro'")
	}
	planID := h.razorpayPlanIDFor(plan, frequency)

	if h.cfg.RazorpayKeyID == "" || h.cfg.RazorpayKeySecret == "" || planID == "" {
		slog.Warn("billing.checkout.not_configured",
			"team_id", teamID,
			"plan", plan,
			"plan_frequency", frequency,
			"key_set", h.cfg.RazorpayKeyID != "",
			"secret_set", h.cfg.RazorpayKeySecret != "",
			"plan_id_set", planID != "",
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "billing_not_configured", "Razorpay credentials/plans not configured for this environment")
	}

	client := razorpay.NewClient(h.cfg.RazorpayKeyID, h.cfg.RazorpayKeySecret)

	// total_count is the number of billing cycles before the subscription
	// auto-completes. Monthly: 12 cycles ≈ 12 months. Yearly: 1 cycle ≈ 1
	// year. cancel-at-cycle-end exits earlier via the cancelled webhook.
	totalCount := 12
	if frequency == "yearly" {
		totalCount = 1
	}
	notes := map[string]interface{}{
		"team_id":        teamID.String(),
		"plan":           plan,
		"plan_frequency": frequency,
	}

	// Admin-code redemption: if the caller supplied a promotion_code and it
	// matches an admin_promo_codes row for THIS team, stamp the row's id
	// into the subscription notes so the webhook handler can mark used_at
	// on activation. Cross-team codes don't match (the lookup is scoped by
	// team_id). Plans-yaml codes (LAUNCH50 etc.) also don't match — those
	// flow through the plans registry and need no DB bookkeeping.
	//
	// Failures here are best-effort: an unknown code, an already-used code,
	// or a transient DB error should not block the checkout itself.
	// /promotion/validate is the user-facing gate that surfaces the
	// "already used / expired" copy. This branch only writes the bookkeeping
	// hook used by the activation webhook.
	if rawCode := strings.TrimSpace(body.PromotionCode); rawCode != "" && h.db != nil {
		row, lookupErr := models.GetAdminPromoCodeByCode(c.Context(), h.db, rawCode, teamID)
		switch {
		case lookupErr == nil && !row.UsedAt.Valid && !row.ExpiresAt.IsZero() && time.Now().UTC().Before(row.ExpiresAt):
			notes[checkoutNoteAdminPromoCodeID] = row.ID.String()
		case lookupErr == nil:
			// Row exists but is expired / used — leave notes untouched. The
			// /promotion/validate gate should have caught this; if the
			// client bypassed it, we silently drop the bookkeeping.
			slog.Info("billing.checkout.promo_code_unusable",
				"team_id", teamID,
				"code", strings.ToUpper(rawCode),
				"used", row.UsedAt.Valid,
				"expired", time.Now().UTC().After(row.ExpiresAt),
				"request_id", requestID,
			)
		case errors.Is(lookupErr, models.ErrAdminPromoCodeNotFound):
			// Unknown / cross-team / plans-yaml code — no DB bookkeeping
			// needed. Plans-yaml codes flow through Razorpay's own
			// offer/coupon channel if configured server-side.
		default:
			// Transient DB failure on the lookup — log but proceed with
			// checkout. Better to let the user pay than block on a brownout
			// in the bookkeeping path.
			slog.Warn("billing.checkout.promo_code_lookup_failed",
				"error", lookupErr,
				"team_id", teamID,
				"request_id", requestID,
			)
		}
	}

	subBody := map[string]interface{}{
		"plan_id":         planID,
		"total_count":     totalCount,
		"quantity":        1,
		"customer_notify": 1,
		"notes":           notes,
	}

	// Wrap the outbound Subscription.Create with the package-level
	// Razorpay circuit breaker. When Razorpay is hosed, return 503
	// billing_provider_unavailable instead of waiting on the HTTP
	// timeout — agents see a clear "retry in 60s" signal.
	sub, err := razorpaybilling.CallWithBreaker(func() (map[string]any, error) {
		return client.Subscription.Create(subBody, nil)
	})
	if err != nil {
		if errors.Is(err, circuit.ErrOpen) {
			slog.Error("billing.checkout.razorpay_circuit_open",
				"team_id", teamID,
				"plan", plan,
				"request_id", requestID,
			)
			return respondError(c, fiber.StatusServiceUnavailable, "billing_provider_unavailable",
				"The billing provider is temporarily unavailable. Retry in 60 seconds — see https://instanode.dev/status for live status.")
		}
		slog.Error("billing.checkout.subscription_create_failed",
			"error", err,
			"team_id", teamID,
			"plan", plan,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusBadGateway, "razorpay_error", "Razorpay rejected the subscription create call: "+err.Error())
	}

	subID, _ := sub["id"].(string)
	shortURL, _ := sub["short_url"].(string)

	if subID == "" || shortURL == "" {
		slog.Error("billing.checkout.razorpay_response_incomplete",
			"team_id", teamID,
			"plan", plan,
			"sub_id_set", subID != "",
			"short_url_set", shortURL != "",
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusBadGateway, "razorpay_error", "Razorpay returned an incomplete subscription response")
	}

	// Persist subscription ID early for traceability; non-fatal if it fails — the
	// subscription.charged webhook will fall back to notes.team_id (or a DB lookup
	// by sub_id once persisted via that webhook path).
	if updateErr := models.UpdateRazorpaySubscriptionID(c.Context(), h.db, teamID, subID); updateErr != nil {
		slog.Error("billing.checkout.update_subscription_id_failed",
			"error", updateErr,
			"team_id", teamID,
			"subscription_id", subID,
			"request_id", requestID,
		)
	}

	slog.Info("billing.checkout.created",
		"team_id", teamID,
		"plan", plan,
		"plan_frequency", frequency,
		"subscription_id", subID,
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{
		"ok":              true,
		"short_url":       shortURL,
		"subscription_id": subID,
	})
}

// ── Razorpay webhook payload structs ─────────────────────────────────────────

type rzpWebhookEvent struct {
	// ID is the canonical event identifier Razorpay assigns to every
	// webhook (sent in both the `X-Razorpay-Event-Id` header and the body
	// `id` field). Used for replay protection — see razorpay_webhook_events
	// table + processedRazorpayEvent helper below.
	ID      string          `json:"id"`
	Event   string          `json:"event"`
	Payload rzpEventPayload `json:"payload"`
}

type rzpEventPayload struct {
	Subscription *rzpEntityWrapper `json:"subscription"`
	Payment      *rzpEntityWrapper `json:"payment"`
}

type rzpEntityWrapper struct {
	Entity json.RawMessage `json:"entity"`
}

type rzpSubscriptionEntity struct {
	ID        string            `json:"id"`
	PlanID    string            `json:"plan_id"`
	Status    string            `json:"status"`
	Notes     map[string]string `json:"notes"`
	PaidCount *int64            `json:"paid_count"`
}

type rzpPaymentEntity struct {
	ID               string `json:"id"`
	Amount           int64  `json:"amount"`
	Currency         string `json:"currency"`
	Email            string `json:"email"`
	AttemptCount     int    `json:"attempt_count"`
	ErrorDescription string `json:"error_description"`
}

// RazorpayWebhook handles POST /razorpay/webhook.
// Always returns 200 on success — Razorpay retries on non-2xx.
func (h *BillingHandler) RazorpayWebhook(c *fiber.Ctx) error {
	payload := c.Body()
	sig := c.Get("X-Razorpay-Signature")

	if !verifyRazorpaySignature(payload, sig, h.cfg.RazorpayWebhookSecret) {
		slog.Error("billing.webhook.signature_failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":    false,
			"error": "invalid_signature",
		})
	}

	var event rzpWebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		slog.Error("billing.webhook.parse_failed", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":    false,
			"error": "invalid_payload",
		})
	}

	ctx, span := otel.Tracer("instant.dev/handlers").Start(c.UserContext(), "billing.razorpay_webhook",
		trace.WithAttributes(attribute.String("rzp.event", event.Event)))
	defer span.End()

	// Replay protection: Razorpay sends a unique event_id in the
	// `X-Razorpay-Event-Id` header (canonical) and in the body `id` field
	// (fallback). The signature check above proves the payload came from
	// Razorpay, but signed payloads can be re-POSTed N times — each replay
	// would re-fire the state machine.
	//
	// P4 (bug-hunt 2026-05-17): the dedup is an ATOMIC CLAIM at the START,
	// not a SELECT-EXISTS-then-INSERT-post-dispatch. The earlier Wave-3
	// shape had a TOCTOU window: two concurrent deliveries of the same
	// event both passed the EXISTS read and both dispatched → double
	// upgrade-audit / double dunning email. We now `INSERT … ON CONFLICT
	// DO NOTHING` up-front and inspect RowsAffected:
	//   - 1 row  → THIS request owns the event; proceed to dispatch.
	//   - 0 rows → another concurrent delivery (or an earlier successful
	//              one) already owns it → 200 {"deduped":true}, no dispatch.
	// event_id is the PRIMARY KEY of razorpay_webhook_events, so the
	// INSERT is the single serialization point — the database, not the
	// handler, decides the winner.
	//
	// Wave-3's retry intent is PRESERVED: if THIS request claimed the row
	// but processing then fails (a 500-return path), we DELETE the claim
	// row before returning 500 (see deleteRazorpayWebhookClaim) so
	// Razorpay's retry re-claims and re-processes the event normally.
	// A successful dispatch leaves the claim row in place, so genuine
	// replays stay suppressed.
	eventID := c.Get("X-Razorpay-Event-Id")
	if eventID == "" {
		eventID = event.ID
	}
	// claimedHere tracks whether THIS request inserted the dedup row, so
	// the 500-return paths below know they own the row and must delete it
	// to keep Razorpay's retry working.
	claimedHere := false
	if eventID != "" && h.db != nil {
		res, err := h.db.ExecContext(ctx,
			`INSERT INTO razorpay_webhook_events (event_id, event_type) VALUES ($1, $2) ON CONFLICT (event_id) DO NOTHING`,
			eventID, event.Event,
		)
		if err != nil {
			// Fail open — log and continue WITHOUT a claim. A dedup write
			// failure is far less bad than swallowing a real subscription
			// state change. claimedHere stays false: a later failure will
			// not try to delete a row we never inserted.
			slog.Warn("billing.webhook.dedup_claim_failed", "error", err, "event_id", eventID)
		} else if n, _ := res.RowsAffected(); n == 0 {
			// Another concurrent delivery (or an earlier successful one)
			// already owns this event. Return 200 without dispatching so
			// the state machine fires exactly once.
			span.SetAttributes(attribute.Bool("rzp.replay_blocked", true))
			slog.Info("billing.webhook.replay_blocked", "event_id", eventID, "event_type", event.Event)
			return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "deduped": true})
		} else {
			claimedHere = true
		}
	} else if eventID == "" {
		// No event_id available — log and proceed. Razorpay always sends
		// one in current API versions; absence indicates either a test
		// fixture or a non-Razorpay forged payload (signature would have
		// already failed in that case).
		slog.Warn("billing.webhook.no_event_id", "event_type", event.Event)
	}

	switch event.Event {
	case "subscription.activated":
		// subscription.activated fires when the card/mandate is authorised
		// (Razorpay lifecycle: created → authenticated → active). For Indian
		// payment methods (UPI, NACH), the first charge may be delayed hours
		// or days after activation. Routing to handleSubscriptionCharged is
		// safe because that function is idempotent (UpgradeTeamAllTiers is
		// idempotent at the DB level; the dedup table entry uses the unique
		// event_id so activated and the later charged event do not collide).
		// Return 500 on failure so Razorpay retries — same contract as charged.
		if upgradeErr := h.handleSubscriptionCharged(ctx, c, event); upgradeErr != nil {
			slog.Error("billing.webhook.subscription_activated.upgrade_failed",
				"error", upgradeErr, "event_id", eventID)
			// P4: processing failed — release the claim so Razorpay's
			// retry re-claims and re-processes this event. Without this
			// the up-front claim would permanently swallow the retry.
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok":    false,
				"error": "upgrade_failed",
			})
		}
	case "subscription.charged":
		if upgradeErr := h.handleSubscriptionCharged(ctx, c, event); upgradeErr != nil {
			slog.Error("billing.webhook.subscription_charged.upgrade_failed",
				"error", upgradeErr, "event_id", eventID)
			// P4: release the claim on failure — see the activated branch.
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok":    false,
				"error": "upgrade_failed",
			})
		}
	case "subscription.cancelled":
		h.handleSubscriptionCancelled(ctx, c, event)
	case "subscription.charged_failed":
		// Razorpay's documented event name for a failed subscription
		// charge. Triggers the dunning state machine — see
		// handleSubscriptionChargeFailed for the 7-day grace contract.
		h.handleSubscriptionChargeFailed(ctx, c, event)
	case "payment.failed":
		// Legacy single-payment failure email path. When the failed
		// payment belongs to an active subscription we ALSO open a
		// grace period (idempotent — partial-unique index swallows
		// duplicate calls). See handlePaymentFailed below.
		h.handlePaymentFailed(ctx, c, event)
	default:
		span.SetAttributes(attribute.String("rzp.event.unhandled", "true"))
	}

	// Dispatch succeeded (no 500-return path was taken). The dedup claim
	// row inserted up-front (P4) is left in place so genuine replays of
	// this same event are suppressed on subsequent deliveries. Nothing to
	// write here — the claim already happened at the start of the handler.

	// Always return 200 to Razorpay.
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
}

// deleteRazorpayWebhookClaim releases the dedup claim row for eventID when
// webhook processing failed and the handler is about to return HTTP 500.
//
// P4: the dedup row is now claimed ATOMICALLY at the start of
// RazorpayWebhook (INSERT … ON CONFLICT DO NOTHING). If processing then
// fails, the claim must be released so Razorpay's retry can re-claim and
// re-process the event — otherwise the up-front claim would permanently
// swallow a paying customer's upgrade. This is the mechanism that
// preserves Wave-3's "a failed event retries" intent under the new
// race-free claim model.
//
// Only deletes when claimedHere is true — i.e. THIS request actually
// inserted the row. If the claim INSERT itself failed (fail-open) or a
// concurrent delivery owned the row, claimedHere is false and we must NOT
// delete: that row belongs to another in-flight delivery, and deleting it
// would re-open the very TOCTOU window this fix closes.
//
// Best-effort: a delete failure is logged at WARN. Worst case the event is
// not retried until Razorpay's own redelivery schedule or the billing
// reconciler corrects the tier — strictly better than a wrong delete.
func (h *BillingHandler) deleteRazorpayWebhookClaim(ctx context.Context, eventID string, claimedHere bool) {
	if !claimedHere || eventID == "" || h.db == nil {
		return
	}
	if _, err := h.db.ExecContext(ctx,
		`DELETE FROM razorpay_webhook_events WHERE event_id = $1`,
		eventID,
	); err != nil {
		slog.Warn("billing.webhook.dedup_claim_release_failed", "error", err, "event_id", eventID)
	}
}

// verifyRazorpaySignature checks HMAC-SHA256(key=secret, msg=rawBody) == signature.
func verifyRazorpaySignature(body []byte, signature, secret string) bool {
	if secret == "" || signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1
}

// handleSubscriptionCharged processes subscription.charged events (payment confirmed → upgrade).
// Returns a non-nil error on critical failures so the caller can return HTTP 500,
// causing Razorpay to retry the webhook delivery. Best-effort steps (subscription ID
// storage, audit emit, grace recovery, promo redemption) are fail-open.
func (h *BillingHandler) handleSubscriptionCharged(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.charged.parse_failed")
		return nil // malformed payload — retrying won't help; swallow
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		slog.Error("billing.subscription.charged.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return nil // team not found — retrying won't help; swallow
	}

	tier := h.planIDToTier(sub.PlanID)

	// Tier validation guard: verify the resolved tier exists in the plans
	// registry before writing it to the DB. A tier rename or a future
	// plans.yaml change could otherwise introduce an unknown string into
	// teams.plan_tier, breaking limits resolution everywhere.
	// Fail-safe: log Error + return nil (swallow). Razorpay retrying won't
	// help — the fix is an env-var or plans.yaml update by the operator.
	if _, tierKnown := plans.Default().All()[tier]; !tierKnown {
		slog.Error("billing.subscription.charged.unknown_tier",
			"plan_id", sub.PlanID,
			"resolved_tier", tier,
			"team_id", teamID,
			"action", "Resolved tier is not in plans.yaml — check RAZORPAY_PLAN_ID_* env vars and plans.yaml",
		)
		return nil
	}

	// Snapshot the prior tier BEFORE the update so we can classify the
	// transition as upgrade / downgrade / same. A miss here just means we
	// emit no audit row and the Loops lifecycle email is skipped — the
	// upgrade itself proceeds.
	fromTier := ""
	if team, lookupErr := models.GetTeamByID(ctx, h.db, teamID); lookupErr == nil && team != nil {
		fromTier = team.PlanTier
	}

	// Atomically upgrade the team tier + all resources, deployments, and stacks.
	// Returns an error on failure — caller will return HTTP 500 so Razorpay retries.
	if upgradeErr := models.UpgradeTeamAllTiers(ctx, h.db, teamID, tier); upgradeErr != nil {
		slog.Error("billing.subscription.charged.upgrade_all_tiers_failed",
			"error", upgradeErr, "team_id", teamID, "tier", tier)
		return upgradeErr
	}

	// Store subscription ID for future lookups.
	if sub.ID != "" {
		if updateErr := models.UpdateRazorpaySubscriptionID(ctx, h.db, teamID, sub.ID); updateErr != nil {
			slog.Error("billing.subscription.charged.update_sub_id_failed",
				"error", updateErr, "team_id", teamID)
		}
	}

	slog.Info("billing.subscription.charged",
		"team_id", teamID, "plan_tier", tier, "subscription_id", sub.ID)
	metrics.ConversionFunnel.WithLabelValues("paid").Inc()

	// Best-effort audit emit for the Loops forwarder. Fail-open: an audit
	// error must not undo the tier update we already committed.
	emitSubscriptionChangeAudit(ctx, h.db, teamID, fromTier, tier, sub.ID)

	// Dunning recovery path: a successful charge during an active grace
	// window means the customer's card recovered before the 7-day clock
	// elapsed. Flip the grace row to 'recovered' and emit the audit row
	// the Brevo forwarder picks up for the "back in good standing" email.
	// Fail-open: a recovery-flip miss does not roll back the tier update.
	maybeRecoverPaymentGrace(ctx, h.db, teamID, sub.ID)

	// Promo-code redemption is intentionally NOT triggered here (Slice 3,
	// DESIGN-P1-B-billing-resilience.md §5 Option B). The current checkout
	// flow stamps admin_promo_code_id into Razorpay subscription notes but
	// does NOT attach a Razorpay Offer (offer_id) — so no discount is
	// actually applied. Marking the code used_at here would consume a
	// single-use code while the customer paid full price, which is a
	// financial broken promise.
	//
	// The code is preserved for redemption once Option A (real Razorpay
	// Offers) is wired in a follow-up PR. When that lands, re-enable
	// maybeMarkAdminPromoCodeUsed gated on sub.Notes["offer_applied"]=="true"
	// so codes are only burned when a discount was actually applied.
	//
	// REGRESSION GUARD: do not re-add a maybeMarkAdminPromoCodeUsed call
	// here without first implementing Razorpay Offer wiring (Slice 5).
	return nil
}

// maybeMarkAdminPromoCodeUsed marks an admin-issued promo code as redeemed
// when the subscription notes carry one. Best-effort, no caller cares about
// the outcome — failures log and return. Race-safe via the
// `WHERE used_at IS NULL` predicate on MarkAdminPromoCodeUsed.
func maybeMarkAdminPromoCodeUsed(ctx context.Context, db *sql.DB, sub rzpSubscriptionEntity, teamID uuid.UUID) {
	if db == nil {
		return
	}
	idStr := strings.TrimSpace(sub.Notes[checkoutNoteAdminPromoCodeID])
	if idStr == "" {
		return
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		slog.Warn("billing.subscription.charged.admin_promo_id_invalid",
			"team_id", teamID,
			"subscription_id", sub.ID,
			"notes_id", idStr,
			"error", err,
		)
		return
	}
	if err := models.MarkAdminPromoCodeUsed(ctx, db, id); err != nil {
		if errors.Is(err, models.ErrAdminPromoCodeAlreadyUsed) {
			// Either a redelivery of the same webhook (idempotent) or a
			// concurrent caller won the race. Either way: nothing to do.
			slog.Info("billing.subscription.charged.admin_promo_already_used",
				"team_id", teamID,
				"subscription_id", sub.ID,
				"admin_promo_code_id", id,
			)
			return
		}
		slog.Warn("billing.subscription.charged.admin_promo_mark_used_failed",
			"team_id", teamID,
			"subscription_id", sub.ID,
			"admin_promo_code_id", id,
			"error", err,
		)
		return
	}
	slog.Info("billing.subscription.charged.admin_promo_redeemed",
		"team_id", teamID,
		"subscription_id", sub.ID,
		"admin_promo_code_id", id,
	)
}

// handleSubscriptionCancelled processes subscription.cancelled events (cancel → downgrade to hobby).
func (h *BillingHandler) handleSubscriptionCancelled(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.cancelled.parse_failed")
		return
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		slog.Error("billing.subscription.cancelled.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return
	}

	// Snapshot the prior tier so the audit row can capture from→to. Failure
	// to read it is non-fatal — we just emit with from_tier="".
	fromTier := ""
	if team, lookupErr := models.GetTeamByID(ctx, h.db, teamID); lookupErr == nil && team != nil {
		fromTier = team.PlanTier
	}

	// Downgrade behaviour: a cancellation with zero paid invoices means the
	// user never actually paid, so they fall back to 'free' (claimed-but-
	// unpaid). 'anonymous' would be wrong — they still have a team_id. A
	// cancellation after at least one paid invoice keeps Hobby as a courtesy
	// floor; resources keep their existing tier (UpdatePlanTier only).
	tier := "hobby"
	if sub.PaidCount != nil && *sub.PaidCount == 0 {
		tier = "free"
	}
	if updateErr := models.UpdatePlanTier(ctx, h.db, teamID, tier); updateErr != nil {
		slog.Error("billing.subscription.cancelled.downgrade_failed",
			"error", updateErr, "team_id", teamID)
		return
	}

	slog.Info("billing.subscription.cancelled",
		"team_id", teamID, "subscription_id", sub.ID, "new_tier", tier)

	// Best-effort audit emit for the Loops cancellation email. Fail-open:
	// the downgrade above is already committed and must not be reverted on
	// an audit failure.
	emitSubscriptionCanceledAudit(ctx, h.db, teamID, fromTier, tier, sub.ID)
}

// handlePaymentFailed processes payment.failed events.
// Does NOT downgrade — Razorpay retries before firing subscription.cancelled.
func (h *BillingHandler) handlePaymentFailed(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) {
	if event.Payload.Payment == nil {
		return
	}
	var pay rzpPaymentEntity
	if err := json.Unmarshal(event.Payload.Payment.Entity, &pay); err != nil {
		slog.Warn("billing.payment.failed.parse_failed", "error", err)
		return
	}

	slog.Warn("billing.payment.failed",
		"payment_id", pay.ID,
		"amount", pay.Amount,
		"currency", pay.Currency,
		"error_desc", pay.ErrorDescription,
	)

	if pay.Email == "" {
		slog.Warn("billing.payment.failed.no_email", "payment_id", pay.ID)
		return
	}

	if err := h.email.SendPaymentFailed(ctx, pay.Email, pay.AttemptCount, nil); err != nil {
		slog.Error("billing.payment.failed.email_failed",
			"error", err, "to", pay.Email, "payment_id", pay.ID)
		return
	}

	slog.Info("billing.payment.failed.email_sent",
		"to", pay.Email, "payment_id", pay.ID)
}

// handleSubscriptionChargeFailed processes subscription.charged_failed
// events — the start of the dunning state machine.
//
// Flow:
//   1. Resolve the team from the subscription's notes (or fall back to
//      the DB lookup by subscription_id).
//   2. Attempt to INSERT a new active grace row. The partial-unique
//      index uq_payment_grace_team_active makes the call idempotent:
//      a redelivery of the same charge_failed event hits the constraint
//      and the model returns ErrPaymentGraceAlreadyActive, which we
//      treat as a silent no-op (the grace clock is already running).
//   3. Emit the payment.grace_started audit row so the worker's Brevo
//      forwarder kicks off the first reminder email. Best-effort.
//
// Fail-open everywhere: the webhook always returns 200 to Razorpay even
// when team resolution / INSERT / audit emit fails. Razorpay re-fires
// charge_failed on every retry attempt anyway, so a single missed event
// gets fixed on the next attempt.
func (h *BillingHandler) handleSubscriptionChargeFailed(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.charged_failed.parse_failed")
		return
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		slog.Error("billing.subscription.charged_failed.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return
	}

	// Extract attempted-amount metadata from the optional payment entity
	// (when Razorpay bundles the failed payment under payload.payment as
	// well). Missing is fine — the email template falls back to the
	// subscription's known monthly amount in that case.
	attemptedAmount := int64(0)
	if event.Payload.Payment != nil {
		var pay rzpPaymentEntity
		if err := json.Unmarshal(event.Payload.Payment.Entity, &pay); err == nil {
			attemptedAmount = pay.Amount
		}
	}

	startGracePeriodForTeam(ctx, h.db, teamID, sub.ID, attemptedAmount)
}

// startGracePeriodForTeam centralises the grace-start logic so both
// subscription.charged_failed AND payment.failed (when it carries a
// subscription reference) can fire it. The function is idempotent —
// callers can invoke it multiple times for the same subscription event
// stream and only the first one creates the row.
//
// attemptedAmount is in paise (Razorpay's smallest unit). Zero means
// "unknown / not present in the event payload" — surfaced as `null` in
// the audit metadata.
func startGracePeriodForTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID, subscriptionID string, attemptedAmount int64) {
	if db == nil || teamID == uuid.Nil || strings.TrimSpace(subscriptionID) == "" {
		return
	}

	startedAt := time.Now().UTC()
	expiresAt := startedAt.Add(time.Duration(models.PaymentGracePeriodGraceDays) * 24 * time.Hour)

	grace, err := models.CreatePaymentGracePeriod(ctx, db, models.CreatePaymentGracePeriodParams{
		TeamID:         teamID,
		SubscriptionID: subscriptionID,
		StartedAt:      startedAt,
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		if errors.Is(err, models.ErrPaymentGraceAlreadyActive) {
			// Idempotent redelivery — grace clock already started.
			slog.Info("billing.subscription.charged_failed.grace_already_active",
				"team_id", teamID, "subscription_id", subscriptionID)
			return
		}
		slog.Error("billing.subscription.charged_failed.grace_create_failed",
			"error", err, "team_id", teamID, "subscription_id", subscriptionID)
		return
	}

	slog.Info("billing.subscription.charged_failed.grace_started",
		"team_id", teamID,
		"subscription_id", subscriptionID,
		"grace_id", grace.ID,
		"expires_at", grace.ExpiresAt,
	)

	emitPaymentGraceStartedAudit(ctx, db, teamID, subscriptionID, grace, attemptedAmount)
}

// maybeRecoverPaymentGrace is the dual of startGracePeriodForTeam — it
// runs from handleSubscriptionCharged on every successful charge,
// checks whether the team had an active grace row, and if so flips it
// to 'recovered' + emits the audit row. The recovery path is fail-open:
// failures here do not roll back the tier elevation that already
// committed in handleSubscriptionCharged.
//
// Returns nothing because callers don't need to react — the email is
// sent off the audit row by the Brevo forwarder, not synchronously.
func maybeRecoverPaymentGrace(ctx context.Context, db *sql.DB, teamID uuid.UUID, subscriptionID string) {
	if db == nil || teamID == uuid.Nil {
		return
	}

	// Snapshot the row so the audit metadata can reference its lifecycle
	// timestamps (started_at, etc.). A miss here just means we emit a
	// thinner audit row — the recovery itself still flips.
	active, err := models.GetActivePaymentGracePeriod(ctx, db, teamID)
	if err != nil {
		slog.Warn("billing.subscription.charged.grace_lookup_failed",
			"error", err, "team_id", teamID)
		return
	}
	if active == nil {
		// Normal happy-path renewal — no grace was in flight.
		return
	}

	recoveredAt := time.Now().UTC()
	flipped, err := models.MarkPaymentGraceRecovered(ctx, db, teamID, recoveredAt)
	if err != nil {
		slog.Error("billing.subscription.charged.grace_recover_failed",
			"error", err, "team_id", teamID, "grace_id", active.ID)
		return
	}
	if !flipped {
		// Race: another worker beat us to it. The Brevo email will
		// already have fired off the first flip's audit row, so we
		// don't emit a duplicate.
		slog.Info("billing.subscription.charged.grace_already_recovered",
			"team_id", teamID, "grace_id", active.ID)
		return
	}

	slog.Info("billing.subscription.charged.grace_recovered",
		"team_id", teamID,
		"grace_id", active.ID,
		"subscription_id", subscriptionID,
	)

	emitPaymentGraceRecoveredAudit(ctx, db, teamID, subscriptionID, active, recoveredAt)
}

// parseSubscriptionEntity extracts the subscription entity from a webhook event.
func parseSubscriptionEntity(event rzpWebhookEvent) (rzpSubscriptionEntity, bool) {
	if event.Payload.Subscription == nil {
		return rzpSubscriptionEntity{}, false
	}
	var sub rzpSubscriptionEntity
	if err := json.Unmarshal(event.Payload.Subscription.Entity, &sub); err != nil {
		return rzpSubscriptionEntity{}, false
	}
	return sub, true
}

// resolveTeamFromNotes returns the team UUID from subscription notes.
// Falls back to a DB lookup by subscription ID when notes are absent.
func resolveTeamFromNotes(ctx context.Context, h *BillingHandler, sub rzpSubscriptionEntity) (uuid.UUID, error) {
	if teamIDStr := sub.Notes["team_id"]; teamIDStr != "" {
		id, err := uuid.Parse(teamIDStr)
		if err == nil {
			return id, nil
		}
	}
	// Fallback: look up by Razorpay subscription ID. (The column is still named
	// stripe_customer_id in the schema for legacy reasons — it now stores
	// Razorpay subscription IDs. Rename pending — see TODO in models/team.go.)
	if sub.ID != "" {
		team, err := models.GetTeamByRazorpaySubscriptionID(ctx, h.db, sub.ID)
		if err != nil {
			return uuid.Nil, err
		}
		return team.ID, nil
	}
	return uuid.Nil, errors.New("cannot resolve team: missing notes.team_id and no subscription_id")
}

// Self-serve cancel was removed per policy — see project memory
// project_no_self_serve_cancel_downgrade.md. The POST /api/v1/billing/cancel
// route is no longer registered (see internal/router/router.go), and no
// handler is exposed here. Cancellation flows through Razorpay's own
// dashboard, executed by support staff, which fires the subscription.cancelled
// webhook → handleSubscriptionCancelled in RazorpayWebhook (unchanged).
//
// The dashboard surfaces cancellation as a mailto:support@instanode.dev link,
// not as a button that calls this API.
//
// If a future internal flow (RTBF / team deletion) needs to cancel a
// subscription programmatically, call razorpaybilling.Portal.CancelAtCycleEnd
// directly — do NOT re-expose this as an HTTP route.

// monthlyAmountINRForTier returns the monthly subscription price in INR rupees
// for a given plan tier. Used as a fallback when Razorpay has not reported a
// paid invoice yet (e.g. brand-new subscription awaiting first charge). The
// values mirror plans.yaml `price_monthly_cents` but in INR — Razorpay charges
// in INR, the USD cents in plans.yaml are display-only.
//
// Returning 0 means "no charge" (anonymous / unrecognised tier) and callers
// should serialise as JSON null.
func monthlyAmountINRForTier(tier string) int64 {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "hobby":
		return 750
	case "hobby_plus":
		// $19/mo ≈ ₹1583 at typical USD→INR. Sits between hobby (₹750)
		// and pro (₹4100). Mirrors the price_monthly_cents ladder.
		return 1583
	case "pro":
		return 4100
	case "team":
		return 16500
	case "growth":
		return 8250
	default:
		return 0
	}
}

// GetBillingState handles GET /api/v1/billing (session JWT).
//
// Aggregates the dashboard's billing view into one response: current tier,
// Razorpay subscription status, next renewal timestamp, monthly amount, and
// the payment method on file. The dashboard previously hard-coded these fields
// from a fixture because no aggregator endpoint existed.
//
// For teams without a Razorpay subscription yet (anonymous-tier / freshly
// claimed Hobby teams that haven't paid), the response still returns 200 with
// sensibly-defaulted nulls — the caller can render the "no subscription" UI
// without branching on error.
func (h *BillingHandler) GetBillingState(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	team, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "Team not found")
		}
		slog.Error("billing.state.team_lookup_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusInternalServerError, "db_error", "Failed to load team")
	}

	// billing_email: owner's email (best-effort — never fail the request if absent).
	billingEmail := ""
	if owner, err := models.GetUserByTeamID(c.Context(), h.db, teamID); err == nil && owner != nil {
		billingEmail = owner.Email
	}

	// Default response: no subscription yet.
	resp := fiber.Map{
		"ok":                       true,
		"tier":                     team.PlanTier,
		"subscription_status":      "none",
		"next_renewal_at":          nil,
		"amount_inr":               nil,
		"payment_method":           nil,
		"billing_email":            billingEmail,
		"razorpay_subscription_id": nil,
		"razorpay_customer_id":     nil,
	}

	// Trial state used to short-circuit here. The platform no longer has a
	// trial period (see policy memory project_no_trial_pay_day_one.md);
	// hobby/pro/team are paid from day one. Anonymous (24h TTL) is the only
	// free tier and is never billed at this endpoint.

	subID := ""
	if team.RazorpaySubscriptionID.Valid {
		subID = strings.TrimSpace(team.RazorpaySubscriptionID.String)
	}
	if subID == "" {
		return c.JSON(resp)
	}
	resp["razorpay_subscription_id"] = subID

	// Razorpay not configured in this environment — return what we know from
	// the DB and skip the live fetch rather than erroring out. The dashboard
	// can still show the current tier and "subscription id on file".
	if h.cfg.RazorpayKeyID == "" || h.cfg.RazorpayKeySecret == "" {
		resp["subscription_status"] = "active"
		// Fall back to the tier-based monthly amount so the UI has a number to
		// render instead of "—" when Razorpay is off.
		if amt := monthlyAmountINRForTier(team.PlanTier); amt > 0 {
			resp["amount_inr"] = amt
		}
		return c.JSON(resp)
	}

	details, err := h.FetchSubscriptionDetails(subID)
	if err != nil {
		slog.Warn("billing.state.razorpay_fetch_failed",
			"error", err, "team_id", teamID, "subscription_id", subID)
		// Fail open: the DB tier is authoritative. Better to show stale data
		// than to break the billing page when Razorpay has a hiccup.
		resp["subscription_status"] = "active"
		if amt := monthlyAmountINRForTier(team.PlanTier); amt > 0 {
			resp["amount_inr"] = amt
		}
		return c.JSON(resp)
	}

	if details != nil {
		// Map Razorpay's subscription.status onto our four-value enum.
		switch strings.ToLower(strings.TrimSpace(details.Status)) {
		case "cancelled", "completed", "expired":
			resp["subscription_status"] = "cancelled"
		case "":
			// no status from Razorpay → trust the DB tier
			resp["subscription_status"] = "active"
		default:
			resp["subscription_status"] = "active"
		}
		if details.CancelAtPeriodEnd {
			resp["subscription_status"] = "cancelled"
		}
		if !details.CurrentPeriodEnd.IsZero() {
			resp["next_renewal_at"] = details.CurrentPeriodEnd.UTC().Format(time.RFC3339Nano)
		}
		// amount_inr — prefer the most recent paid invoice (converts paise→rupees).
		// Fall back to the tier-derived price for brand-new subs that haven't been
		// charged yet.
		if details.LatestPaidAmount > 0 && (details.LatestPaidCurrency == "" || strings.EqualFold(details.LatestPaidCurrency, "INR")) {
			resp["amount_inr"] = details.LatestPaidAmount / 100
		} else if amt := monthlyAmountINRForTier(team.PlanTier); amt > 0 {
			resp["amount_inr"] = amt
		}
		// payment_method — build a typed object from what Razorpay returned.
		if pm := buildPaymentMethod(details); pm != nil {
			resp["payment_method"] = pm
		}
	} else {
		// Subscription stored on the team but Razorpay returned no details —
		// behave as if the sub is active per the DB tier.
		resp["subscription_status"] = "active"
		if amt := monthlyAmountINRForTier(team.PlanTier); amt > 0 {
			resp["amount_inr"] = amt
		}
	}

	return c.JSON(resp)
}

// buildPaymentMethod converts portal SubscriptionDetails into the public
// payment_method shape served by GET /api/v1/billing. Returns nil when no
// payment method is on file yet (subscription created but never charged).
func buildPaymentMethod(d *razorpaybilling.SubscriptionDetails) fiber.Map {
	if d == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(d.PaymentMethod)) {
	case "card":
		pm := fiber.Map{"type": "card", "vpa": nil}
		if d.PaymentNetwork != "" {
			pm["brand"] = d.PaymentNetwork
		}
		if d.PaymentLast4 != "" {
			pm["last4"] = d.PaymentLast4
		}
		return pm
	case "upi":
		pm := fiber.Map{"type": "upi", "brand": nil, "last4": nil}
		if d.PaymentVPA != "" {
			pm["vpa"] = d.PaymentVPA
		} else {
			pm["vpa"] = nil
		}
		return pm
	case "netbanking":
		return fiber.Map{"type": "netbanking", "brand": nil, "last4": nil, "vpa": nil}
	case "wallet":
		return fiber.Map{"type": "wallet", "brand": nil, "last4": nil, "vpa": nil}
	}
	// Fallback: card data present but `method` not reported — assume card.
	if d.PaymentLast4 != "" {
		pm := fiber.Map{"type": "card", "vpa": nil}
		if d.PaymentNetwork != "" {
			pm["brand"] = d.PaymentNetwork
		}
		pm["last4"] = d.PaymentLast4
		return pm
	}
	return nil
}

// ListInvoicesAPI handles GET /api/v1/billing/invoices (session JWT).
func (h *BillingHandler) ListInvoicesAPI(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}
	if h.cfg.RazorpayKeyID == "" || h.cfg.RazorpayKeySecret == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "billing_not_configured", "Billing is not configured")
	}
	portal := &razorpaybilling.Portal{DB: h.db, Cfg: h.cfg}
	subID, err := portal.SubscriptionID(c.Context(), teamID)
	if err != nil {
		return c.JSON(fiber.Map{"ok": true, "invoices": []any{}})
	}
	rows, err := portal.ListSubscriptionInvoices(subID)
	if err != nil {
		if errors.Is(err, circuit.ErrOpen) {
			slog.Error("billing.invoices.razorpay_circuit_open", "team_id", teamID)
			return respondError(c, fiber.StatusServiceUnavailable, "billing_provider_unavailable",
				"The billing provider is temporarily unavailable. Retry in 60 seconds — see https://instanode.dev/status.")
		}
		slog.Error("billing.invoices.list_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusBadGateway, "razorpay_error", "Failed to list invoices")
	}
	out := make([]fiber.Map, 0, len(rows))
	for _, r := range rows {
		out = append(out, fiber.Map{
			"id":       r.ID,
			"amount":   r.Amount,
			"currency": r.Currency,
			"status":   r.Status,
			"date":     r.Date.UTC().Format(time.RFC3339Nano),
			"pdf_url":  r.PDFURL,
		})
	}
	return c.JSON(fiber.Map{"ok": true, "invoices": out})
}

// UpdatePaymentMethodAPI handles POST /api/v1/billing/update-payment (session JWT).
func (h *BillingHandler) UpdatePaymentMethodAPI(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}
	if h.cfg.RazorpayKeyID == "" || h.cfg.RazorpayKeySecret == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "billing_not_configured", "Billing is not configured")
	}
	portal := &razorpaybilling.Portal{DB: h.db, Cfg: h.cfg}
	subID, err := portal.SubscriptionID(c.Context(), teamID)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "no_subscription", err.Error())
	}
	shortURL, err := portal.PaymentUpdateURL(subID)
	if err != nil {
		if errors.Is(err, circuit.ErrOpen) {
			slog.Error("billing.payment_update.razorpay_circuit_open", "team_id", teamID)
			return respondError(c, fiber.StatusServiceUnavailable, "billing_provider_unavailable",
				"The billing provider is temporarily unavailable. Retry in 60 seconds — see https://instanode.dev/status.")
		}
		return respondError(c, fiber.StatusUnprocessableEntity, "no_update_url", err.Error())
	}
	return c.JSON(fiber.Map{"ok": true, "short_url": shortURL})
}

type changePlanBody struct {
	TargetPlan string `json:"target_plan"`
}

// ChangePlanAPI handles POST /api/v1/billing/change-plan (session JWT).
func (h *BillingHandler) ChangePlanAPI(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}
	if h.cfg.RazorpayKeyID == "" || h.cfg.RazorpayKeySecret == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "billing_not_configured", "Billing is not configured")
	}
	var body changePlanBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}
	target := strings.ToLower(strings.TrimSpace(body.TargetPlan))
	if target == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_target_plan", "target_plan is required")
	}
	var planTier string
	if err := h.db.QueryRowContext(c.Context(), `SELECT plan_tier FROM teams WHERE id = $1`, teamID).Scan(&planTier); err != nil {
		if err == sql.ErrNoRows {
			return respondError(c, fiber.StatusNotFound, "not_found", "Team not found")
		}
		return respondError(c, fiber.StatusInternalServerError, "db_error", "Failed to load team")
	}
	if strings.EqualFold(strings.TrimSpace(planTier), target) {
		return respondError(c, fiber.StatusBadRequest, "same_plan", "Already on requested plan")
	}
	planIDs := h.razorpayPlanIDs()
	if _, ok := planIDs[target]; !ok {
		return respondError(c, fiber.StatusBadRequest, "invalid_plan", "target_plan must be hobby, hobby_plus, pro, or team")
	}
	// No self-serve downgrade — see project memory
	// project_no_self_serve_cancel_downgrade.md. A target whose plan rank is
	// at or below the current tier's rank is a downgrade (or lateral move);
	// those are support-only. Reject with a mailto agent_action so the
	// dashboard/agent routes the user to support instead of silently
	// dropping them to a cheaper tier.
	currentRank := plans.Rank(strings.ToLower(strings.TrimSpace(planTier)))
	targetRank := plans.Rank(target)
	if currentRank >= 0 && targetRank >= 0 && targetRank <= currentRank {
		return respondErrorWithAgentAction(c, fiber.StatusBadRequest, "downgrade_not_self_serve",
			"Plan downgrades are handled by support, not self-serve. Email support@instanode.dev to change to a lower tier.",
			"Tell the user that downgrading to a lower plan is support-assisted. Have them email support@instanode.dev with their team and the target plan.",
			"mailto:support@instanode.dev")
	}
	// Team tier is under development — block customer-initiated upgrades to
	// team via the public API. The internal /internal/set-tier endpoint
	// still works for ops use. Drop this guard when team launches.
	if strings.EqualFold(target, "team") {
		return respondError(c, fiber.StatusBadRequest, "tier_unavailable",
			"Team tier is under active development. Email support@instanode.dev to join the early access list.")
	}
	portal := &razorpaybilling.Portal{DB: h.db, Cfg: h.cfg}
	if _, err := portal.SubscriptionID(c.Context(), teamID); err != nil {
		return respondError(c, fiber.StatusBadRequest, "no_subscription", "no active subscription to change")
	}
	res, err := portal.ChangePlan(c.Context(), teamID, target, planIDs)
	if err != nil {
		if errors.Is(err, circuit.ErrOpen) {
			slog.Error("billing.change_plan.razorpay_circuit_open", "team_id", teamID)
			return respondError(c, fiber.StatusServiceUnavailable, "billing_provider_unavailable",
				"The billing provider is temporarily unavailable. Retry in 60 seconds — see https://instanode.dev/status.")
		}
		slog.Error("billing.change_plan.failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusBadGateway, "razorpay_error", err.Error())
	}
	return c.JSON(fiber.Map{
		"ok":             true,
		"new_plan":       res.NewPlan,
		"effective_date": res.EffectiveDate.UTC().Format(time.RFC3339Nano),
		"short_url":      res.CheckoutShort,
	})
}

// emitSubscriptionChangeAudit writes a subscription.upgraded or
// subscription.downgraded row for the Loops forwarder when a charged-webhook
// transition strictly changes the team's tier. Same-tier renewals (the
// monthly Pro→Pro re-charge case) emit nothing — Loops shouldn't send an
// upgrade email on every renewal.
//
// Best-effort: a write failure logs but never surfaces. Called synchronously
// from the webhook handler because the handler already runs in a request
// goroutine that completes before Razorpay sees a 200.
func emitSubscriptionChangeAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, fromTier, toTier, subID string) {
	fromR := plans.Rank(fromTier)
	toR := plans.Rank(toTier)
	// Unknown tiers (-1) or no-change cases produce no audit row.
	if fromR < 0 || toR < 0 || fromR == toR {
		return
	}

	kind := models.AuditKindSubscriptionUpgraded
	summary := "team upgraded from " + fromTier + " to " + toTier
	if fromR > toR {
		kind = models.AuditKindSubscriptionDowngraded
		summary = "team downgraded from " + fromTier + " to " + toTier
	}

	meta := map[string]string{
		"from_tier":       fromTier,
		"to_tier":         toTier,
		"subscription_id": subID,
	}
	metaBlob, _ := json.Marshal(meta)

	if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     kind,
		Summary:  summary,
		Metadata: metaBlob,
	}); err != nil {
		slog.Warn("audit.emit.failed",
			"kind", kind,
			"team_id", teamID,
			"from_tier", fromTier,
			"to_tier", toTier,
			"error", err,
		)
	}
}

// emitSubscriptionCanceledAudit writes the subscription.canceled audit row.
// Always emits on cancellation (regardless of the courtesy fall-back tier)
// because the Loops cancellation email is about the cancellation event
// itself, not the resulting tier delta. Best-effort: failures log only.
func emitSubscriptionCanceledAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, fromTier, toTier, subID string) {
	meta := map[string]string{
		"from_tier":       fromTier,
		"to_tier":         toTier,
		"subscription_id": subID,
	}
	metaBlob, _ := json.Marshal(meta)

	if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     models.AuditKindSubscriptionCanceled,
		Summary:  "subscription canceled",
		Metadata: metaBlob,
	}); err != nil {
		slog.Warn("audit.emit.failed",
			"kind", models.AuditKindSubscriptionCanceled,
			"team_id", teamID,
			"error", err,
		)
	}
}

// emitPaymentGraceStartedAudit writes the payment.grace_started audit
// row consumed by the Brevo forwarder. Metadata carries the recovery
// deadline + attempted-amount so the
// `instanode-payment-grace-started-v1` template can render "your card
// failed for ₹X, you have until $expires_at to update payment."
//
// Fail-open: an audit miss does NOT roll back the grace-row INSERT we
// already committed. The Brevo follow-up will be missed (no first
// reminder email until the worker's 6h reminder kicks in) but the state
// machine is intact and the customer's account still terminates on the
// 7-day clock.
func emitPaymentGraceStartedAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, subscriptionID string, grace *models.PaymentGracePeriod, attemptedAmountPaise int64) {
	meta := map[string]any{
		"subscription_id":  subscriptionID,
		"grace_id":         grace.ID.String(),
		"started_at":       grace.StartedAt.UTC().Format(time.RFC3339),
		"expires_at":       grace.ExpiresAt.UTC().Format(time.RFC3339),
		"attempted_amount": nil,
	}
	if attemptedAmountPaise > 0 {
		meta["attempted_amount"] = attemptedAmountPaise
	}
	metaBlob, _ := json.Marshal(meta)

	if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     models.AuditKindPaymentGraceStarted,
		Summary:  "payment failed — 7-day grace period started",
		Metadata: metaBlob,
	}); err != nil {
		slog.Warn("audit.emit.failed",
			"kind", models.AuditKindPaymentGraceStarted,
			"team_id", teamID,
			"error", err,
		)
	}
}

// emitPaymentGraceRecoveredAudit writes the payment.grace_recovered
// audit row consumed by the Brevo forwarder for the "you're back in
// good standing" recovery email
// (template: instanode-payment-grace-recovered-v1). Metadata carries
// the grace lifecycle timestamps so the email can render "your account
// was at risk for N days" copy.
//
// Same fail-open invariant as the started audit: a miss here does not
// roll back the MarkPaymentGraceRecovered flip — the state machine is
// the source of truth, the audit row is the trigger for the email.
func emitPaymentGraceRecoveredAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, subscriptionID string, grace *models.PaymentGracePeriod, recoveredAt time.Time) {
	meta := map[string]any{
		"subscription_id": subscriptionID,
		"grace_id":        grace.ID.String(),
		"started_at":      grace.StartedAt.UTC().Format(time.RFC3339),
		"recovered_at":    recoveredAt.UTC().Format(time.RFC3339),
	}
	metaBlob, _ := json.Marshal(meta)

	if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     models.AuditKindPaymentGraceRecovered,
		Summary:  "payment recovered — back in good standing",
		Metadata: metaBlob,
	}); err != nil {
		slog.Warn("audit.emit.failed",
			"kind", models.AuditKindPaymentGraceRecovered,
			"team_id", teamID,
			"error", err,
		)
	}
}
