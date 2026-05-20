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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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

// monthlyOngoingTotalCount / yearlyOngoingTotalCount are the Razorpay
// subscription `total_count` values for an ONGOING (effectively indefinite)
// plan. Razorpay's create-subscription API requires a finite total_count, so
// "indefinite" is expressed as a count large enough that the subscription
// never auto-completes in any realistic customer lifetime:
//
//   - monthly: 1200 cycles = 100 years of monthly charges.
//   - yearly:  100 cycles  = 100 years of annual charges.
//
// Audit finding F12: the previous values (12 monthly / 1 yearly) made a
// healthy paying customer's subscription auto-`completed` after the agreed
// term, which the webhook treated as a cancellation and downgraded — silently
// punishing a loyal customer. With these values the subscription stays active
// for the customer's entire realistic lifetime; a genuine cancellation still
// flows through subscription.cancelled, untouched.
const (
	monthlyOngoingTotalCount = 1200
	yearlyOngoingTotalCount  = 100
)

// reusableSubscriptionStatuses is the set of Razorpay subscription `status`
// values that mean "the customer can still complete this checkout" — the
// hosted short_url is live and a card mandate has not yet been
// authorized+charged into an active subscription. Audit finding F7:
// CreateCheckoutAPI reuses an existing subscription in one of these states
// instead of minting a SECOND subscription that could double-charge the card.
//
//   - created       — subscription minted, no payment authorized yet.
//   - authenticated — mandate authorized, first charge not yet captured.
//   - pending       — Razorpay retrying a failed initial charge; still payable.
//
// Any other status (active/halted/cancelled/completed/expired) is NOT
// reusable: active/halted already bill the card (a new checkout is a genuine
// separate intent or a no-op the already-on-tier guard catches), and
// cancelled/completed/expired are terminal — the short_url is dead.
var reusableSubscriptionStatuses = map[string]struct{}{
	"created":       {},
	"authenticated": {},
	"pending":       {},
}

// errCheckoutAlreadyOnTier is the error code returned when a team requests a
// checkout for a tier it already holds (or a lower one). Returning a 4xx with
// this code — rather than minting a subscription — stops a confused customer
// from buying a plan they already pay for.
const errCheckoutAlreadyOnTier = "already_on_plan"

// BillingHandler handles billing and Razorpay webhook endpoints.
type BillingHandler struct {
	db    *sql.DB
	cfg   *config.Config
	// email is the Mailer used for all webhook-triggered sends (payment
	// receipts, payment-failed dunning, etc.). The interface lets main.go
	// wrap the underlying *email.Client in a *email.BreakingClient — a
	// process-wide consecutive-failure circuit breaker — so a Brevo
	// brownout fast-fails after N consecutive errors instead of freezing
	// every webhook handler on the SDK timeout (P0-1
	// CIRCUIT-RETRY-AUDIT-2026-05-20). Tests pass either the bare
	// *email.Client (via NewBillingHandler) or a fake that satisfies
	// the interface.
	email email.Mailer

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

	// CreateSubscription mints a new Razorpay subscription. Factored into an
	// overridable field (not an inline razorpay client call) so the F7
	// idempotency guard in CreateCheckoutAPI is unit-testable: a test can
	// assert the function is invoked EXACTLY ONCE across two checkout calls
	// for a team that already has a live pending subscription. The production
	// default goes through razorpay.NewClient + the package circuit breaker and
	// is wired ONCE in NewBillingHandler — never mutated per-request — so the
	// shared handler is safe for concurrent CreateCheckoutAPI goroutines.
	CreateSubscription func(subBody map[string]any) (map[string]any, error)

	// FetchCheckoutSubscription GETs a Razorpay subscription's raw fields
	// (status + short_url) for the F7 reuse probe. Overridable for the same
	// testability reason as CreateSubscription. A returned error means "could
	// not determine" — the caller fails OPEN (logs + creates a fresh
	// subscription) so a Razorpay GET hiccup never blocks a legitimate
	// checkout. The production default goes through razorpay.NewClient +
	// Subscription.Fetch under the circuit breaker and is wired ONCE in
	// NewBillingHandler — never mutated per-request — so the shared handler is
	// safe for concurrent CreateCheckoutAPI goroutines.
	FetchCheckoutSubscription func(subscriptionID string) (status, shortURL string, err error)
}

// NewBillingHandler constructs a BillingHandler.
//
// All overridable function fields (FetchSubscriptionDetails, CreateSubscription,
// FetchCheckoutSubscription) are wired to their production defaults HERE, at
// construction time, and never mutated again. This is load-bearing for
// concurrency correctness: CreateCheckoutAPI is invoked by many goroutines at
// once (Fiber serves each request on its own goroutine, and a single
// BillingHandler instance is shared by the router). The previous design
// lazily initialised CreateSubscription / FetchCheckoutSubscription on the
// first request via ensureRazorpayFns(), an unsynchronised check-then-write on
// shared struct fields — a genuine data race (caught by `go test -race`,
// TestCheckoutDedup_ConcurrentGoroutines_AtMostOneReachesRazorpay). Setting the
// defaults once here, before the handler is ever registered on a route,
// eliminates the per-request mutation entirely — no lock needed.
//
// Tests that want to fake Razorpay still construct via NewBillingHandler and
// then assign the field directly (e.g. `bh.CreateSubscription = ...`) BEFORE
// the handler is exercised; that single-goroutine setup overwrites the default
// with no race.
func NewBillingHandler(db *sql.DB, cfg *config.Config, emailClient email.Mailer) *BillingHandler {
	h := &BillingHandler{db: db, cfg: cfg, email: emailClient}
	// Default to the real Razorpay portal; tests override this field directly.
	h.FetchSubscriptionDetails = func(subID string) (*razorpaybilling.SubscriptionDetails, error) {
		portal := &razorpaybilling.Portal{DB: h.db, Cfg: h.cfg}
		return portal.FetchSubscriptionDetails(subID)
	}
	// CreateSubscription mints a new Razorpay subscription. Wired once here so
	// CreateCheckoutAPI never mutates the field per-request (see the doc above).
	h.CreateSubscription = func(subBody map[string]any) (map[string]any, error) {
		// P0-2 (CIRCUIT-RETRY-AUDIT-2026-05-20): NewTimeoutClient applies the
		// audit-mandated 30s HTTP timeout. Never razorpay.NewClient directly —
		// the SDK default is 10s, below Razorpay's documented p99 for
		// subscription create, so a brownout would 10s-fail every checkout
		// without ever flipping the breaker.
		client := razorpaybilling.NewTimeoutClient(h.cfg.RazorpayKeyID, h.cfg.RazorpayKeySecret)
		return razorpaybilling.CallWithBreaker(func() (map[string]any, error) {
			return client.Subscription.Create(subBody, nil)
		})
	}
	// FetchCheckoutSubscription GETs a subscription's status + short_url for the
	// F7 reuse probe. Wired once here for the same reason as CreateSubscription.
	h.FetchCheckoutSubscription = func(subscriptionID string) (string, string, error) {
		// P0-2: 30s HTTP timeout via NewTimeoutClient (see CreateSubscription).
		client := razorpaybilling.NewTimeoutClient(h.cfg.RazorpayKeyID, h.cfg.RazorpayKeySecret)
		sub, err := razorpaybilling.CallWithBreaker(func() (map[string]any, error) {
			return client.Subscription.Fetch(subscriptionID, nil, nil)
		})
		if err != nil {
			return "", "", err
		}
		status, _ := sub["status"].(string)
		shortURL, _ := sub["short_url"].(string)
		return status, shortURL, nil
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

// reusablePendingCheckout scans the team's unresolved pending_checkouts rows
// (newest first) and returns the subscription_id + short_url of the first one
// Razorpay still reports as payable (status in reusableSubscriptionStatuses).
//
// Audit finding F7: this is the load-bearing idempotency guard. A confused
// customer whose first checkout silently failed and who clicks "Upgrade" again
// minutes later must NOT get a second Razorpay subscription that can
// double-charge their card. Returning a live subscription here makes the
// second click reuse the first checkout's short_url instead.
//
// Fail-open by contract: a DB error or a Razorpay GET error on any candidate
// is logged and skipped — a probe failure must never block a legitimate new
// checkout. ok=false means "no reusable subscription found, mint a new one".
//
// failure_notified_at being set (the worker already emailed "your checkout
// didn't complete") does NOT by itself disqualify a row — the customer may
// still complete it — so the Razorpay status is the sole authority.
func (h *BillingHandler) reusablePendingCheckout(ctx context.Context, teamID uuid.UUID, requestID string) (subID, shortURL string, ok bool) {
	if h.db == nil {
		return "", "", false
	}
	pending, err := models.FindUnresolvedPendingCheckouts(ctx, h.db, teamID)
	if err != nil {
		// Fail open — a DB hiccup on the reuse probe must not block checkout.
		slog.Warn("billing.checkout.pending_lookup_failed_open",
			"error", err,
			"team_id", teamID,
			"request_id", requestID,
		)
		return "", "", false
	}
	for _, pc := range pending {
		if pc.SubscriptionID == "" {
			continue
		}
		status, url, fetchErr := h.FetchCheckoutSubscription(pc.SubscriptionID)
		if fetchErr != nil {
			// Fail open per-candidate: log and try the next row. If every
			// probe fails the caller mints a fresh subscription — the rare
			// duplicate during a Razorpay brownout is below the cost of
			// blocking a paying customer.
			slog.Warn("billing.checkout.pending_subscription_fetch_failed_open",
				"error", fetchErr,
				"team_id", teamID,
				"subscription_id", pc.SubscriptionID,
				"request_id", requestID,
			)
			continue
		}
		if _, reusable := reusableSubscriptionStatuses[strings.ToLower(strings.TrimSpace(status))]; reusable && url != "" {
			slog.Info("billing.checkout.reusing_pending_subscription",
				"team_id", teamID,
				"subscription_id", pc.SubscriptionID,
				"razorpay_status", status,
				"failure_notified", pc.FailureNotifiedAt.Valid,
				"request_id", requestID,
			)
			return pc.SubscriptionID, url, true
		}
	}
	return "", "", false
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

// planIDRecognised reports whether planID matches a configured RAZORPAY_PLAN_ID_*
// value — i.e. whether planIDToTier returned a genuine mapping rather than the
// fail-safe fallback. handleSubscriptionCharged uses this for F3: an
// unrecognised plan_id means the platform does not actually know what tier the
// customer paid for, so the charge must be flagged for operator make-good
// (billing.charge_undeliverable) even though the safe fallback tier is still
// granted to cap blast radius. An empty planID is treated as unrecognised.
func (h *BillingHandler) planIDRecognised(planID string) bool {
	if planID == "" {
		return false
	}
	for _, configured := range []string{
		h.cfg.RazorpayPlanIDTeam, h.cfg.RazorpayPlanIDTeamYearly,
		h.cfg.RazorpayPlanIDPro, h.cfg.RazorpayPlanIDProYearly,
		h.cfg.RazorpayPlanIDHobbyPlus, h.cfg.RazorpayPlanIDHobbyPlusYearly,
		h.cfg.RazorpayPlanIDHobby, h.cfg.RazorpayPlanIDHobbyYearly,
	} {
		if configured != "" && planID == configured {
			return true
		}
	}
	return false
}

// requireVerifiedEmail gates billing/upgrade actions on the acting user's
// email_verified flag (migration 052). It returns (true, nil) when the caller
// may proceed, and (false, errResponse) when they may not — the caller must
// `return errResponse` immediately in the latter case.
//
// Gate semantics:
//   - Unverified user → 403 email_not_verified + AgentActionEmailNotVerified.
//     A /claim-created account can reach the dashboard but has not proven it
//     controls the email on file; a magic-link sign-in flips the flag.
//   - Verified user → proceed.
//   - DEGRADED PATHS fail OPEN, by design: a user-row lookup error must not
//     block a paying customer over an infra hiccup — the same fail-open
//     principle as the Redis checkout dedup. The miss is logged at WARN so an
//     operator can see it. The pre-052 grandfather backfill means existing
//     users are verified=true regardless.
//   - P2 (BugBash 2026-05-18): an empty user_id is NOT a real degraded path.
//     Both /billing/checkout registrations sit behind RequireAuth (the legacy
//     alias at router.go and the /api/v1 group route), so a missing user_id
//     can only happen via a middleware misconfiguration, not a legitimate
//     unauthenticated call. The earlier comment claimed the legacy alias had
//     "no RequireAuth user context" — that was factually wrong. The branch is
//     kept fail-open (an unreachable case staying permissive is harmless) but
//     the false justification is corrected here.
func (h *BillingHandler) requireVerifiedEmail(c *fiber.Ctx, action string) (bool, error) {
	userIDStr := middleware.GetUserID(c)
	if userIDStr == "" {
		slog.Warn("billing.email_verify_gate.no_user_id_failopen",
			"action", action, "request_id", middleware.GetRequestID(c))
		return true, nil
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		slog.Warn("billing.email_verify_gate.bad_user_id_failopen",
			"action", action, "user_id", userIDStr, "error", err)
		return true, nil
	}
	user, err := models.GetUserByID(c.Context(), h.db, userID)
	if err != nil {
		slog.Warn("billing.email_verify_gate.user_lookup_failopen",
			"action", action, "user_id", userID, "error", err)
		return true, nil
	}
	if user.EmailVerified {
		return true, nil
	}
	slog.Info("billing.email_verify_gate.blocked",
		"action", action, "user_id", userID, "team_id", user.TeamID.UUID)
	return false, respondErrorWithAgentAction(c, fiber.StatusForbidden, "email_not_verified",
		"Verify your email before changing plans. Sign in via the magic link sent to your email to verify it, then retry.",
		AgentActionEmailNotVerified, "")
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
// Idempotency (audit finding F7): before minting a new Razorpay subscription
// the handler (a) short-circuits when the team is already on the requested
// tier or higher, and (b) reuses an existing live, payable subscription from
// pending_checkouts instead of creating a second one that could double-charge
// the customer's card. The 60s Redis SETNX is kept only as a cheap fast-path
// against concurrent double-taps; the pending-subscription reuse is the real
// guarantee against a delayed re-click.
//
// Status codes:
//   - 400  invalid plan / invalid body / already on the requested tier
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

	// Email-verified gate (migration 052): a /claim-created account must
	// verify its email before it can start a paid checkout. Checked before
	// the Redis dedup so an unverified caller never consumes a dedup slot.
	if ok, errResp := h.requireVerifiedEmail(c, "checkout"); !ok {
		return errResp
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

	// ── F7 idempotency guard ────────────────────────────────────────────────
	// Two real-money failure modes the 60s Redis SETNX above does NOT cover:
	//
	//  1. The team already pays for this tier (or a higher one). A confused
	//     re-click must not mint a subscription for a plan they already have.
	//  2. The team has a checkout still in flight from minutes/hours ago
	//     (silent first attempt, F1/F2). Minting a SECOND subscription here is
	//     the F7 double-charge bug: once both authorize, both bill the card.
	//
	// Both are checked before client construction so a reused/rejected
	// checkout never even constructs a Razorpay create body. Fail-open: a DB
	// brownout on the team lookup falls through to create (never block a
	// paying customer); the Razorpay GET inside reusablePendingCheckout is
	// already fail-open per-candidate.
	if h.db != nil {
		if team, teamErr := models.GetTeamByID(c.Context(), h.db, teamID); teamErr != nil {
			slog.Warn("billing.checkout.team_lookup_failed_open",
				"error", teamErr,
				"team_id", teamID,
				"request_id", requestID,
			)
		} else if team != nil {
			currentTier := strings.ToLower(strings.TrimSpace(team.PlanTier))
			// Already on the requested tier or higher → no checkout needed.
			// plans.Rank gives a stable tier ordering; an equal-or-greater
			// rank means the customer already paid for at least this plan.
			if plans.Rank(currentTier) >= plans.Rank(plan) && plans.Rank(plan) > 0 {
				slog.Info("billing.checkout.already_on_tier",
					"team_id", teamID,
					"current_tier", currentTier,
					"requested_plan", plan,
					"request_id", requestID,
				)
				return respondError(c, fiber.StatusBadRequest, errCheckoutAlreadyOnTier,
					"This team is already on the '"+currentTier+"' plan. No checkout is needed — visit /dashboard to manage the existing subscription.")
			}
		}
	}
	// Reuse a live, still-payable subscription from a prior checkout instead
	// of creating a second one. When found, return the SAME short_url +
	// subscription_id the first checkout produced — same response shape as a
	// fresh create below.
	if reuseSubID, reuseURL, reuse := h.reusablePendingCheckout(c.Context(), teamID, requestID); reuse {
		return c.JSON(fiber.Map{
			"ok":              true,
			"short_url":       reuseURL,
			"subscription_id": reuseSubID,
			"reused":          true,
		})
	}
	// ────────────────────────────────────────────────────────────────────────

	// total_count is the number of billing cycles Razorpay charges before the
	// subscription auto-completes (fires subscription.completed → historically
	// a downgrade). For an ONGOING monthly plan we never want that
	// auto-completion: a customer who pays every month must not be silently
	// downgraded at month 13 (audit finding F12). Razorpay's API requires a
	// finite total_count, so we use monthlyOngoingTotalCount — a count so
	// large (100 years of monthly cycles) the subscription is ongoing for
	// every practical purpose. A yearly plan uses yearlyOngoingTotalCount for
	// the same reason. Genuine cancel-at-cycle-end still exits early via the
	// cancelled webhook; the count is only the auto-complete ceiling.
	totalCount := monthlyOngoingTotalCount
	if frequency == "yearly" {
		totalCount = yearlyOngoingTotalCount
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

	// h.CreateSubscription wraps the outbound Subscription.Create with the
	// package-level Razorpay circuit breaker (wired once in NewBillingHandler).
	// When Razorpay is hosed, the breaker returns
	// circuit.ErrOpen → 503 billing_provider_unavailable instead of waiting on
	// the HTTP timeout — agents see a clear "retry in 60s" signal. This is the
	// ONLY subscription-minting call site in CreateCheckoutAPI; the F7 guard
	// above guarantees it is reached at most once per live checkout intent.
	sub, err := h.CreateSubscription(subBody)
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

	// T9 P0-1 (BugHunt 2026-05-20): persist BOTH the subscription_id on
	// the team row AND the pending_checkouts row before returning the
	// short_url to the caller. Previously both writes were best-effort
	// (logged + swallowed). On a DB brownout at checkout time the live
	// Razorpay subscription existed but the platform had no record →
	// F7's reuse guard could not find anything to reuse, so a re-click
	// minted a SECOND live subscription and both billed the card.
	//
	// Making these fatal returns 503 to the caller; the customer
	// retries; the second attempt either hits the live-subscription
	// reuse (now possible because the first attempt no longer leaked
	// a sub) OR fast-fails consistently. Razorpay's idempotency on
	// /subscriptions does NOT cover our case (no Idempotency-Key sent,
	// and our retry would carry a fresh body anyway).
	//
	// Downside accepted: one DB hiccup at checkout → user sees 503 +
	// must retry. The cost of leaving them with an unrecorded live
	// subscription (silent double-charge, no email) is much higher.
	customerEmail := ""
	if owner, ownerErr := models.GetUserByTeamID(c.Context(), h.db, teamID); ownerErr == nil && owner != nil {
		customerEmail = owner.Email
	}
	if updateErr := models.UpdateRazorpaySubscriptionID(c.Context(), h.db, teamID, subID); updateErr != nil {
		slog.Error("billing.checkout.update_subscription_id_failed",
			"error", updateErr,
			"team_id", teamID,
			"subscription_id", subID,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "billing_persistence_failed",
			"Could not persist your subscription. Razorpay created it but our DB write failed — retry to reuse the same subscription. Contact support if this persists.")
	}
	if insertErr := models.InsertPendingCheckout(c.Context(), h.db, subID, teamID, customerEmail, plan); insertErr != nil {
		slog.Error("billing.checkout.pending_checkout_insert_failed",
			"error", insertErr,
			"team_id", teamID,
			"subscription_id", subID,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "billing_persistence_failed",
			"Could not persist your subscription. Razorpay created it but our DB write failed — retry to reuse the same subscription. Contact support if this persists.")
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
	ID               string            `json:"id"`
	Amount           int64             `json:"amount"`
	Currency         string            `json:"currency"`
	Email            string            `json:"email"`
	AttemptCount     int               `json:"attempt_count"`
	ErrorDescription string            `json:"error_description"`
	// SubscriptionID + OrderID + Notes (B11-P1, 2026-05-20): used to
	// resolve the team server-side instead of trusting payload.email
	// verbatim. A payment.failed entity carries `subscription_id` for
	// subscription-tied payments, `order_id` for one-shot orders, and
	// `notes` for any caller-supplied metadata (Razorpay copies notes
	// from the parent subscription onto the payment). resolveTeamFromPayment
	// reads these in priority order.
	SubscriptionID string            `json:"subscription_id"`
	OrderID        string            `json:"order_id"`
	Notes          map[string]string `json:"notes"`
}

// RazorpayWebhook handles POST /razorpay/webhook.
// Always returns 200 on success — Razorpay retries on non-2xx.
func (h *BillingHandler) RazorpayWebhook(c *fiber.Ctx) error {
	payload := c.Body()
	sig := c.Get("X-Razorpay-Signature")

	if !verifyRazorpaySignature(payload, sig, h.cfg.RazorpayWebhookSecret) {
		slog.Error("billing.webhook.signature_failed")
		// B10 P2-3 (BugBash 2026-05-20): hydrate canonical ErrorResponse
		// envelope on signature rejection. Razorpay support always asks for
		// the request_id when a webhook fails; pre-fix the body was bare
		// `{ok:false,error:"invalid_signature"}` with no correlator,
		// message, or operator guidance.
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":                  false,
			"error":               "invalid_signature",
			"message":             "X-Razorpay-Signature did not match HMAC-SHA256 of the raw request body.",
			"request_id":          middleware.GetRequestID(c),
			"retry_after_seconds": nil,
			"agent_action":        "The Razorpay webhook signature did not verify. Confirm RAZORPAY_WEBHOOK_SECRET matches the value in the Razorpay dashboard and that the raw request body is being HMAC'd (not the parsed JSON). Razorpay will retry automatically.",
		})
	}

	var event rzpWebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		slog.Error("billing.webhook.parse_failed", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":                  false,
			"error":               "invalid_payload",
			"message":             "Razorpay webhook body is not valid JSON.",
			"request_id":          middleware.GetRequestID(c),
			"retry_after_seconds": nil,
			"agent_action":        "Razorpay sent a body that is not valid JSON. Check the Razorpay dashboard webhook configuration and recent delivery attempts.",
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
			// B11-P1 (2026-05-20): map ErrTeamNotFound to 404. Razorpay
			// treats 4xx as non-retryable (won't replay the event with
			// the same payload) — exactly what we want for a synthetic
			// or stale notes.team_id. Releasing the dedup claim above
			// still allows a corrected payload to land later.
			return webhookErrorStatus(c, upgradeErr, "upgrade_failed")
		}
	case "subscription.charged":
		if upgradeErr := h.handleSubscriptionCharged(ctx, c, event); upgradeErr != nil {
			slog.Error("billing.webhook.subscription_charged.upgrade_failed",
				"error", upgradeErr, "event_id", eventID)
			// P4: release the claim on failure — see the activated branch.
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return webhookErrorStatus(c, upgradeErr, "upgrade_failed")
		}
	case "subscription.cancelled":
		// P1-W3-09: a swallowed downgrade failure used to leave the team on
		// a paid tier forever (the up-front dedup claim blocked Razorpay's
		// replay). Release the claim and 500 on failure so the event retries.
		if hErr := h.handleSubscriptionCancelled(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_cancelled.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_cancelled_failed",
			})
		}
	case "subscription.halted":
		// P1-F: Razorpay halts a subscription once all charge retries are
		// exhausted. It is terminal — there will be no further charge —
		// so the team is downgraded immediately, identical to a cancel.
		// Without this case a halted subscription kept paid-tier limits
		// until the 15-minute reconciler caught up.
		if hErr := h.handleSubscriptionCancelled(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_halted.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_halted_failed",
			})
		}
	case "subscription.completed":
		// F12: subscription.completed fires when a subscription consumes its
		// agreed total_count of billing cycles. Routing this straight to
		// handleSubscriptionCancelled (the pre-fix behaviour) DOWNGRADED a
		// customer who had paid every single cycle and never asked to leave —
		// punishing a loyal paying customer and emailing them a "canceled"
		// notice. handleSubscriptionCompleted instead keeps a healthy paying
		// customer on their plan; only a genuinely non-paying completion
		// (paid_count == 0) downgrades. New subscriptions also no longer cap
		// at 12 cycles (see monthlyOngoingTotalCount) so this event becomes
		// rare — but legacy 12-count subscriptions still reach it.
		if hErr := h.handleSubscriptionCompleted(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_completed.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_completed_failed",
			})
		}
	case "subscription.paused":
		// P1-F: a paused subscription is not billing. Treat it like a
		// failed charge — open a grace period so the team keeps its tier
		// for the grace window, and the dunning emails / reconciler take
		// over. subscription.resumed reverses this.
		if hErr := h.handleSubscriptionPaused(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_paused.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_paused_failed",
			})
		}
	case "subscription.resumed":
		// P1-F: a previously paused subscription resumed billing. Recover
		// any active grace row so the dunning state machine stops, mirroring
		// the grace recovery handleSubscriptionCharged does on a good charge.
		if hErr := h.handleSubscriptionResumed(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_resumed.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_resumed_failed",
			})
		}
	case "subscription.charged_failed":
		// Razorpay's documented event name for a failed subscription
		// charge. Triggers the dunning state machine — see
		// handleSubscriptionChargeFailed for the 7-day grace contract.
		// F10: on a retryable failure release the claim and 500 so
		// Razorpay redelivers — identical to the pending / payment.failed
		// branches. Without this a transient failure suppressed the
		// redelivery and the first dunning email was ~15 min late.
		if hErr := h.handleSubscriptionChargeFailed(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_charged_failed.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_charged_failed_handler_failed",
			})
		}
	case "subscription.pending":
		// Razorpay fires subscription.pending when a charge fails and the
		// subscription is awaiting retry. Unlike payment.failed there may be
		// NO payment object behind it (a pre-authorization / mandate failure
		// on the hosted checkout page) — so this is the only soft-failure
		// signal that path emits. Treat it like handlePaymentFailed: resolve
		// the team and send the existing payment-failure notification.
		// Release the claim + 500 on a retryable failure so Razorpay
		// redelivers, identical to the payment.failed branch.
		if hErr := h.handleSubscriptionPending(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_pending.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_pending_handler_failed",
			})
		}
	case "payment.failed":
		// Legacy single-payment failure email path. When the failed
		// payment belongs to an active subscription we ALSO open a
		// grace period (idempotent — partial-unique index swallows
		// duplicate calls). See handlePaymentFailed below.
		if hErr := h.handlePaymentFailed(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.payment_failed.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "payment_failed_handler_failed",
			})
		}
	case "subscription.deauthenticated":
		// B11-F1 (BugBash 2026-05-20): subscription.deauthenticated fires
		// when the customer's mandate is revoked (UPI/NACH/eMandate
		// withdrawn). The subscription cannot charge again until the user
		// re-authenticates — for our purposes this is functionally
		// identical to a cancel: the team must move off the paid tier so
		// the next provision-time check sees the correct quota. Without
		// this branch the event silently fell to `default` 200 and the
		// team kept paid-tier limits forever despite Razorpay being unable
		// to bill them.
		if hErr := h.handleSubscriptionCancelled(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_deauthenticated.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "subscription_deauthenticated_failed",
			})
		}
	case "subscription.updated":
		// B11-F1 (BugBash 2026-05-20): subscription.updated fires when a
		// plan change is committed (typically initiated by us via the
		// Razorpay API, or by a support-side dashboard edit). The right
		// next action is "re-resolve the team's tier from the subscription
		// state" — exactly what handleSubscriptionCharged does
		// (idempotent, naming-pinned). Without this branch a mid-cycle
		// plan upgrade left the team on the old tier until the next
		// charge fired (potentially a month later).
		if hErr := h.handleSubscriptionCharged(ctx, c, event); hErr != nil {
			slog.Error("billing.webhook.subscription_updated.failed",
				"error", hErr, "event_id", eventID)
			h.deleteRazorpayWebhookClaim(ctx, eventID, claimedHere)
			return webhookErrorStatus(c, hErr, "subscription_updated_failed")
		}
	case "refund.processed":
		// B11-F1 (BugBash 2026-05-20): refund.processed is a record-keeping
		// event from a successful refund. No tier change is implied — the
		// refund handler in the dunning pipeline already updated the
		// subscription state; this event is the after-the-fact confirmation
		// Razorpay sends once their payment processor settles. Acknowledge
		// at INFO level so it shows up in operator log search but doesn't
		// fire the WARN-tier "unhandled_event" alert. Audit-row emit so
		// finance can correlate against `audit_log` rows for the refund.
		slog.Info("billing.webhook.refund_processed",
			"event_id", eventID, "event_type", event.Event)
		span.SetAttributes(attribute.Bool("rzp.refund_processed", true))
	default:
		// Log unhandled events at WARN so they surface in New Relic — a span
		// attribute alone is invisible to log-based alerting. A new Razorpay
		// event type we should handle (a coverage gap) shows up here.
		span.SetAttributes(attribute.String("rzp.event.unhandled", "true"))
		slog.Warn("billing.webhook.unhandled_event",
			"event_type", event.Event, "event_id", eventID)
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
// webhookErrorStatus maps a webhook-handler error to the right HTTP status +
// JSON envelope so the Razorpay redelivery contract works correctly:
//
//   - ErrTeamNotFound (B11-P1, 2026-05-20)  → 404 with error="team_not_found".
//     The webhook carried a notes.team_id pointing at a non-existent team
//     (typo, deleted-team race, forged synthetic event). Razorpay treats
//     4xx as non-retryable (won't replay) so the dead event doesn't loop
//     forever, and our deleteRazorpayWebhookClaim caller releases the
//     dedup claim so a future event with the corrected team_id can land.
//   - any other error                       → 500 with the caller-supplied
//     error code. Razorpay retries 5xx — appropriate for transient DB or
//     gRPC failures where redelivery may succeed.
//
// The `errorCode` argument is the per-callsite slug used in the response
// envelope (e.g. "upgrade_failed", "subscription_cancelled_failed"). It is
// echoed verbatim in the 500 envelope; on a 404 it is overridden to the
// stable "team_not_found" code so consumers can identify the case.
func webhookErrorStatus(c *fiber.Ctx, err error, errorCode string) error {
	var notFound *models.ErrTeamNotFound
	if errors.As(err, &notFound) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"ok":    false,
			"error": "team_not_found",
		})
	}
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"ok":    false,
		"error": errorCode,
	})
}

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
//
// T7 P3-F (BugHunt 2026-05-20): a probe with `signature = " <hex> "`
// (leading/trailing whitespace) was accepted because some upstream
// header-reader stripped the surrounding whitespace before the
// constant-time compare ran. Razorpay's real signatures are exactly
// 64 hex characters with no padding; tighten the contract by trimming
// surrounding whitespace ONCE at the top and then rejecting any
// signature whose length is not 64 hex chars before the
// constant-time compare. Both the trim and the length check run in
// data-independent time (no early-exit on content) so they do not
// re-introduce a side-channel.
func verifyRazorpaySignature(body []byte, signature, secret string) bool {
	if secret == "" || signature == "" {
		return false
	}
	// Trim once at top — strict compare below.
	sig := strings.TrimSpace(signature)
	// Razorpay HMAC-SHA256 hex = exactly 64 chars. Anything else is
	// rejected before the constant-time compare; the length check is
	// content-independent.
	if len(sig) != 64 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1
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
		// F2: discriminate a transient DB error from a genuinely
		// unresolvable payload — mirror handleSubscriptionCancelled's
		// teamResolveUnretryable contract. Previously this returned nil for
		// EVERY error, so a transient DB blip during team lookup → 200 →
		// Razorpay never retries → a real charge is permanently lost.
		if !teamResolveUnretryable(err) {
			// Transient/DB error — retryable. Return it so RazorpayWebhook
			// releases the dedup claim and 500s; Razorpay redelivers.
			slog.Error("billing.subscription.charged.team_resolve_failed",
				"error", err, "sub_id", sub.ID)
			return fmt.Errorf("subscription.charged team resolve: %w", err)
		}
		// F8: genuinely unresolvable team (bad/missing notes) — the card was
		// charged but the upgrade can NEVER be delivered by retrying.
		// Record it loudly as a make-good worklist item; do NOT 500 (a retry
		// would just re-burn the claim for a payload that will never resolve).
		slog.Error("billing.subscription.charged.team_unresolvable",
			"error", err, "sub_id", sub.ID,
			"action", "Charge confirmed but team is unresolvable — operator must reconcile/refund this charge in the Razorpay dashboard")
		emitChargeUndeliverableAudit(ctx, h.db, uuid.Nil, sub, event,
			chargeUndeliverableReasonTeamUnresolvable, "")
		return nil
	}

	tier := h.planIDToTier(sub.PlanID)

	// F3 — unknown / unrecognised plan_id is no longer SILENTLY swallowed.
	// Two distinct miss conditions are make-good cases (the card was charged,
	// likely at a higher price, but the platform cannot be sure it is granting
	// the tier the customer paid for):
	//
	//   1. planIDRecognised(sub.PlanID) == false — the plan_id matches no
	//      configured RAZORPAY_PLAN_ID_* value (an env-var typo, or a plan
	//      created in the Razorpay dashboard but never wired). planIDToTier
	//      returns the SAFE fallback tier here to cap blast radius, but the
	//      charge MUST still be flagged: we are guessing.
	//   2. The resolved tier is not in plans.yaml — a tier rename / removed
	//      tier would otherwise write an unknown string into teams.plan_tier
	//      and break limits resolution everywhere.
	//
	// Either condition: loud slog.Error + a billing.charge_undeliverable
	// audit row (F8) so an operator reconciles the charge. We do NOT 500
	// (Razorpay retrying cannot help — the fix is an operator env-var /
	// plans.yaml change). For condition 2 we also stop before writing the
	// bad tier; for condition 1 the safe fallback tier is still applied below
	// so the customer is not left on free after paying.
	_, tierKnown := plans.Default().All()[tier]
	planRecognised := h.planIDRecognised(sub.PlanID)
	if !tierKnown {
		slog.Error("billing.subscription.charged.unknown_tier",
			"plan_id", sub.PlanID,
			"resolved_tier", tier,
			"team_id", teamID,
			"action", "Charge confirmed but resolved tier is not in plans.yaml — check RAZORPAY_PLAN_ID_* env vars and plans.yaml, then reconcile/refund this charge",
		)
		emitChargeUndeliverableAudit(ctx, h.db, teamID, sub, event,
			chargeUndeliverableReasonUnknownTier, tier)
		return nil
	}
	if !planRecognised {
		// The plan_id is not one we configured — we are granting the safe
		// fallback tier as a guess. Flag the charge for operator make-good but
		// still proceed with the fallback upgrade so the customer is not
		// stranded on free after paying.
		slog.Error("billing.subscription.charged.unrecognised_plan_id",
			"plan_id", sub.PlanID,
			"fallback_tier", tier,
			"team_id", teamID,
			"action", "Charge confirmed for an unrecognised plan_id — granted the fallback tier as a guess; operator must verify the customer's intended tier and reconcile/refund if wrong",
		)
		emitChargeUndeliverableAudit(ctx, h.db, teamID, sub, event,
			chargeUndeliverableReasonUnknownTier, tier)
		// fall through — apply the fallback tier upgrade.
	}

	// Snapshot the prior tier BEFORE the update so we can classify the
	// transition as upgrade / downgrade / same. A miss here just means we
	// emit no audit row and the Loops lifecycle email is skipped — the
	// upgrade itself proceeds.
	fromTier := ""
	if team, lookupErr := models.GetTeamByID(ctx, h.db, teamID); lookupErr == nil && team != nil {
		fromTier = team.PlanTier
	}

	// MR-P0-6 (BugBash 2026-05-20): a subscription.charged event must NEVER
	// LOWER a team's tier. Razorpay re-fires / late-delivers `charged` events
	// for ANY subscription a team has ever held — a customer who upgraded
	// hobby→pro still has the stale hobby subscription object in Razorpay, and
	// a renewal/retry/late `charged` for it would otherwise demote the paying
	// customer to hobby and emit a spurious subscription.downgraded email.
	//
	// Genuine downgrades flow through subscription.cancelled / explicit
	// plan-change paths, NOT through `charged`. So: if the charged plan's tier
	// ranks BELOW the team's current tier, skip the tier update entirely, log
	// a loud WARN + a billing.charge_undeliverable audit row for operator
	// reconciliation, and keep the higher tier. Same-tier renewals and genuine
	// upgrades (rank >= current) still flow through unchanged.
	if fromTier != "" && plans.Rank(tier) < plans.Rank(fromTier) {
		slog.Warn("billing.subscription.charged.lower_tier_charge",
			"team_id", teamID,
			"current_tier", fromTier,
			"charged_tier", tier,
			"plan_id", sub.PlanID,
			"subscription_id", sub.ID,
			"action", "subscription.charged carried a lower-tier plan_id than the team currently holds — "+
				"NOT downgrading (charged is never a downgrade signal). Operator: verify whether this is a "+
				"stale/re-fired event for an old subscription or a genuine plan change that should go through "+
				"the cancellation/change path, then reconcile/refund if needed",
		)
		emitChargeUndeliverableAudit(ctx, h.db, teamID, sub, event,
			chargeUndeliverableReasonLowerTierCharge, tier)
		// Still resolve any pending checkout / store the subscription id so the
		// checkout reconciler does not later flag this as a failure, but do
		// NOT touch the team tier.
		if sub.ID != "" {
			if updateErr := models.UpdateRazorpaySubscriptionID(ctx, h.db, teamID, sub.ID); updateErr != nil {
				slog.Error("billing.subscription.charged.update_sub_id_failed_lower_tier",
					"error", updateErr, "team_id", teamID)
			}
			if resolveErr := models.ResolvePendingCheckout(ctx, h.db, sub.ID); resolveErr != nil {
				slog.Warn("billing.subscription.charged.pending_checkout_resolve_failed_lower_tier",
					"error", resolveErr, "team_id", teamID, "subscription_id", sub.ID)
			}
		}
		return nil
	}

	// T4 P2-4 (BugHunt 2026-05-20): fold the subscription_id write into
	// UpgradeTeamAllTiers' transaction so a crash between the tier flip
	// and the sub_id write can't leave a paid team with NULL sub_id
	// (which would render any later subscription.cancelled un-matchable
	// and the team paid forever).
	//
	// Atomically upgrade the team tier + all resources, deployments,
	// stacks, AND set stripe_customer_id (== razorpay_subscription_id).
	// Returns an error on failure — caller will return HTTP 500 so
	// Razorpay retries.
	if upgradeErr := models.UpgradeTeamAllTiersWithSubscription(ctx, h.db, teamID, tier, sub.ID); upgradeErr != nil {
		slog.Error("billing.subscription.charged.upgrade_all_tiers_failed",
			"error", upgradeErr, "team_id", teamID, "tier", tier)
		return upgradeErr
	}

	// Enqueue an explicit propagation row for the worker's propagation_runner.
	// This is the durable "user upgraded, infra not yet regraded" signal —
	// the entitlement_reconciler is still the eventually-consistent backstop,
	// but the runner reacts within ~30s + tracks per-team retries with
	// exponential backoff and a dead-letter audit row after maxAttempts. See
	// migration 058 and worker/internal/jobs/propagation_runner.go.
	//
	// FAIL-OPEN: this runs AFTER the atomic upgrade tx has committed. An
	// INSERT failure here MUST NOT 500 the webhook (Razorpay redelivery
	// cannot help, the tier flip already landed, and the entitlement
	// reconciler will eventually correct any infra drift on its 5-min sweep).
	// A loud slog.Error is the operator-visible signal that the eager retry
	// path is not running for this charge — NR can alert on it.
	if _, enqErr := models.EnqueuePendingPropagation(
		ctx, h.db, models.PropagationKindTierElevation, teamID, tier, nil,
	); enqErr != nil {
		slog.Error("billing.subscription.charged.propagation_enqueue_failed",
			"error", enqErr,
			"team_id", teamID,
			"tier", tier,
			"subscription_id", sub.ID,
			"note", "fail-open — tier upgrade committed; entitlement_reconciler 5m sweep is the backstop",
		)
	}

	// Checkout completed — clear the pending_checkouts row so the worker's
	// checkout reconciler does not later notify this subscription as a
	// payment failure. Reached from BOTH subscription.activated and
	// subscription.charged (this handler serves both); ResolvePendingCheckout
	// is idempotent (`WHERE resolved_at IS NULL`) so the second event is a
	// harmless no-op. Best-effort: a miss only leaves a stale unresolved row
	// the reconciler's own grace window will eventually reconcile against the
	// live subscription state.
	if sub.ID != "" {
		if resolveErr := models.ResolvePendingCheckout(ctx, h.db, sub.ID); resolveErr != nil {
			slog.Warn("billing.subscription.charged.pending_checkout_resolve_failed",
				"error", resolveErr, "team_id", teamID, "subscription_id", sub.ID)
		}
	}

	slog.Info("billing.subscription.charged",
		"team_id", teamID, "plan_tier", tier, "subscription_id", sub.ID)
	metrics.ConversionFunnel.WithLabelValues("paid").Inc()

	// Best-effort audit emit for the Loops forwarder. Fail-open: an audit
	// error must not undo the tier update we already committed.
	emitSubscriptionChangeAudit(ctx, h.db, teamID, fromTier, tier, sub.ID)

	// F4: send the customer their payment receipt. Fires on EVERY successful
	// charge — the first paid upgrade AND every monthly/yearly renewal — so a
	// paying customer always has an artifact confirming money left their
	// account (renewals were previously completely silent). isRenewal is
	// derived from the tier transition: a strict tier change is the upgrade
	// receipt, a same-tier charge is the renewal receipt. Fail-open: a receipt
	// send failure must NOT undo the committed upgrade or 500 the webhook —
	// the customer is upgraded regardless of email delivery.
	h.sendPaymentReceipt(ctx, teamID, tier, fromTier, event)

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
//
// P1-W3-09 (bug-hunt 2026-05-18): this handler returns an error on every
// failure path so RazorpayWebhook can release the dedup claim and return 500
// — Razorpay then redelivers and the downgrade is retried. A swallowed DB
// failure here previously left the team on a paid tier forever (the claim row
// blocked the replay). A parse failure is NOT retryable, so it returns nil:
// retrying a malformed payload is pointless and would just re-burn the claim.
func (h *BillingHandler) handleSubscriptionCancelled(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.cancelled.parse_failed")
		return nil
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		// A missing/unknown-team payload will never resolve — non-retryable,
		// keep the claim and 200. A real DB error IS retryable: return it so
		// dispatch releases the claim and 500s for redelivery.
		if teamResolveUnretryable(err) {
			slog.Warn("billing.subscription.cancelled.team_unresolvable",
				"error", err, "sub_id", sub.ID)
			return nil
		}
		slog.Error("billing.subscription.cancelled.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return fmt.Errorf("subscription.cancelled team resolve: %w", err)
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
	//
	// DELIBERATE downgrade-cap asymmetry — DO NOT "fix" this by adding teardown.
	// On cancel / halt / complete this handler calls ONLY models.UpdatePlanTier.
	// Existing resources, deployments, and stacks are KEPT at their current tier
	// as a customer courtesy — over-cap deployments and stacks are NOT torn down
	// here. Only NEW provisions are gated at the lower cap: those hit a 402 from
	// the per-service tier check (/db/new, /deploy/new, /stacks/new, ...). This
	// mirrors the resources-keep-their-tier behaviour documented for
	// ElevateResourceTiersByTeam. Do not add teardown of over-cap deployments or
	// stacks in this handler.
	tier := "hobby"
	if sub.PaidCount != nil && *sub.PaidCount == 0 {
		tier = "free"
	}
	if updateErr := models.UpdatePlanTier(ctx, h.db, teamID, tier); updateErr != nil {
		slog.Error("billing.subscription.cancelled.downgrade_failed",
			"error", updateErr, "team_id", teamID)
		return fmt.Errorf("subscription.cancelled downgrade: %w", updateErr)
	}

	slog.Info("billing.subscription.cancelled",
		"team_id", teamID, "subscription_id", sub.ID, "new_tier", tier)

	// EMAIL-BUGBASH F2: when an operator demotes a paying customer, the
	// admin path (a) emits a subscription.canceled_by_admin audit row whose
	// own forwarder sends a cancellation email AND (b) calls the Razorpay
	// cancel API, which fires this very subscription.cancelled webhook. If we
	// also emit subscription.canceled here the customer gets TWO near-
	// identical cancellation emails for one event. So: if a fresh
	// subscription.canceled_by_admin row exists for this team, the admin
	// path already covered the customer — skip the webhook-path emit.
	// Fail-open: a lookup error falls through to the historical always-emit
	// behaviour (a rare duplicate beats a missed cancellation notice).
	if recent, lookupErr := models.RecentAuditEventExists(
		ctx, h.db, teamID, models.AuditKindSubscriptionCanceledByAdmin, adminCancelDedupWindow,
	); lookupErr != nil {
		slog.Warn("billing.subscription.cancelled.admin_dedup_lookup_failed",
			"error", lookupErr, "team_id", teamID)
	} else if recent {
		slog.Info("billing.subscription.cancelled.admin_initiated_skip_email",
			"team_id", teamID, "subscription_id", sub.ID,
			"note", "subscription.canceled_by_admin already emitted — webhook path skips its cancellation email to avoid a duplicate")
		return nil
	}

	// Best-effort audit emit for the Loops cancellation email. Fail-open:
	// the downgrade above is already committed and must not be reverted on
	// an audit failure.
	emitSubscriptionCanceledAudit(ctx, h.db, teamID, fromTier, tier, sub.ID)
	return nil
}

// adminCancelDedupWindow is how recent a subscription.canceled_by_admin
// audit row must be for handleSubscriptionCancelled to treat the incoming
// subscription.cancelled webhook as the admin-cancel echo (EMAIL-BUGBASH
// F2). Razorpay fires the webhook within seconds-to-minutes of the cancel
// API call; 1 hour is a generous margin that still cannot collide with an
// unrelated customer-initiated cancellation a month later.
const adminCancelDedupWindow = time.Hour

// handleSubscriptionCompleted processes subscription.completed events (F12).
//
// subscription.completed fires when a Razorpay subscription consumes its
// agreed total_count of billing cycles. The pre-fix code routed this straight
// to handleSubscriptionCancelled, which DOWNGRADED the team — so a customer
// who paid every single cycle of a (legacy) 12-count monthly subscription was
// silently dropped to hobby at month 13 and emailed a "canceled" notice they
// never asked for.
//
// The corrected policy: a completion on a HEALTHY paying subscription
// (paid_count > 0) is NOT a cancellation. The customer kept paying; keep them
// on their plan. We deliberately do NOT downgrade and do NOT emit the
// cancellation audit/email. (New subscriptions no longer cap at 12 cycles —
// see monthlyOngoingTotalCount — so a completion on a healthy subscription
// becomes vanishingly rare; this branch protects the legacy 12-count
// subscriptions still in flight.)
//
// A completion with paid_count == 0 means the subscription ended without a
// single successful payment — there is nothing to protect, so it downgrades
// exactly like a zero-paid cancellation (handleSubscriptionCancelled already
// maps paid_count == 0 → the 'free' floor).
//
// Error contract mirrors handleSubscriptionCancelled: a parse failure is
// non-retryable (nil); a real DB error is retryable (returned → 500 → retry).
func (h *BillingHandler) handleSubscriptionCompleted(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.completed.parse_failed")
		return nil
	}

	// A healthy paying subscription that simply reached its term ceiling must
	// keep its plan — downgrading a loyal paying customer is the F12 bug.
	// paid_count == 0 (or absent) is the only completion we treat as a
	// genuine end-of-relationship and route to the downgrade path.
	if sub.PaidCount == nil || *sub.PaidCount > 0 {
		teamID, err := resolveTeamFromNotes(ctx, h, sub)
		if err != nil {
			if teamResolveUnretryable(err) {
				slog.Warn("billing.subscription.completed.team_unresolvable",
					"error", err, "sub_id", sub.ID)
				return nil
			}
			slog.Error("billing.subscription.completed.team_resolve_failed",
				"error", err, "sub_id", sub.ID)
			return fmt.Errorf("subscription.completed team resolve: %w", err)
		}
		// Loud, intentional no-op: the customer paid every cycle; their plan
		// is untouched. An operator may want to re-create an ongoing
		// subscription, but the platform must NEVER auto-downgrade them here.
		slog.Info("billing.subscription.completed.healthy_kept_on_plan",
			"team_id", teamID, "subscription_id", sub.ID,
			"paid_count_known", sub.PaidCount != nil,
			"action", "subscription reached its term ceiling while paying — team kept on plan, not downgraded (F12)")
		return nil
	}

	// paid_count == 0 — the subscription ended without ever charging the
	// card. Downgrade exactly as a never-paid cancellation would.
	slog.Info("billing.subscription.completed.unpaid_downgrading",
		"subscription_id", sub.ID)
	return h.handleSubscriptionCancelled(ctx, c, event)
}

// handlePaymentFailed processes payment.failed events.
// Does NOT downgrade — Razorpay retries before firing subscription.cancelled.
//
// P1-W3-09: returns an error on a retryable failure (the dunning email send
// failed) so RazorpayWebhook releases the dedup claim and 500s — Razorpay
// then redelivers and the customer still gets their payment-failed notice.
// Non-retryable conditions (no payment entity, malformed payload, no email
// address on the payment) return nil: a retry would re-burn the claim for
// nothing.
func (h *BillingHandler) handlePaymentFailed(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	if event.Payload.Payment == nil {
		return nil
	}
	var pay rzpPaymentEntity
	if err := json.Unmarshal(event.Payload.Payment.Entity, &pay); err != nil {
		slog.Warn("billing.payment.failed.parse_failed", "error", err)
		return nil
	}

	slog.Warn("billing.payment.failed",
		"payment_id", pay.ID,
		"amount", pay.Amount,
		"currency", pay.Currency,
		"error_desc", pay.ErrorDescription,
	)

	// B11-P1 (2026-05-20): resolve the dunning recipient server-side from
	// the team_id (via notes/subscription_id), NOT from pay.Email.
	//
	// Previous behaviour trusted `payload.payment.entity.email` verbatim
	// — meaning anyone with the Razorpay webhook secret (a leaked CI
	// var, a malicious vendor, an over-shared HMAC key) could synthesize
	// a payment.failed event with `email: <victim>` and fanout dunning
	// notifications to arbitrary recipients. The Brevo provider treats
	// a payment-failed email as transactional and bypasses unsubscribe
	// preferences, so the impact was "spam any address you can
	// enumerate, with our SendGrid reputation behind it."
	//
	// Fix: derive the team from `notes.team_id` / `subscription_id` /
	// `order_id`, look up its primary user, and send to THAT address.
	// If we can't resolve a team or its primary user, drop the email
	// (loud WARN log so ops can see it; no email is strictly better
	// than the wrong email).
	teamID, resolvedVia := resolveTeamFromPayment(ctx, h, pay, event)
	if teamID == uuid.Nil {
		slog.Warn("billing.payment.failed.team_unresolvable",
			"payment_id", pay.ID,
			"subscription_id", pay.SubscriptionID,
			"order_id", pay.OrderID,
			"note", "no team resolvable from payload — dunning email DROPPED (B11-P1 takes precedence over delivery)")
		return nil
	}
	primary, lookupErr := models.GetPrimaryUserByTeamID(ctx, h.db, teamID)
	if lookupErr != nil {
		slog.Warn("billing.payment.failed.primary_user_lookup_failed",
			"error", lookupErr,
			"payment_id", pay.ID,
			"team_id", teamID,
			"resolved_via", resolvedVia,
			"note", "team resolved but no primary user — dunning email DROPPED")
		return nil
	}
	recipient := models.NormalizeEmail(primary.Email)
	if recipient == "" {
		slog.Warn("billing.payment.failed.primary_email_empty",
			"payment_id", pay.ID, "team_id", teamID)
		return nil
	}

	// Defensive log: surface the case where the payload-supplied email
	// differed from the resolved one. This is the per-event signal that
	// the previous-trust path WOULD have sent to the wrong recipient,
	// useful for both alerting and forensic incident review.
	if payloadEmail := strings.ToLower(strings.TrimSpace(pay.Email)); payloadEmail != "" && payloadEmail != recipient {
		slog.Warn("billing.payment.failed.payload_email_mismatch",
			"payment_id", pay.ID,
			"team_id", teamID,
			"resolved_via", resolvedVia,
			"payload_email_masked", models.MaskEmail(pay.Email),
			"resolved_email_masked", models.MaskEmail(recipient),
			"note", "payload email differs from team primary — using resolved (B11-P1)")
	}

	// C5 per-cycle dedup. payment.failed and subscription.pending are two
	// distinct Razorpay events for the same failed billing cycle, and both
	// call SendPaymentFailed — without a shared key the customer gets two
	// dunning emails. dunningDedupKey collapses one recipient's failed cycle
	// to a single send. A (false, nil) claim means the sibling event already
	// sent the dunning notice. Fail-open: a dedup DB error sends anyway.
	if key := dunningDedupKey(recipient); key != "" {
		claimed, claimErr := models.ClaimEmailSend(ctx, h.db, key, models.EmailSendKindDunning)
		if claimErr != nil {
			slog.Warn("billing.payment.failed.dunning_dedup_failed",
				"error", claimErr, "dedup_key", key)
		} else if !claimed {
			slog.Info("billing.payment.failed.dunning_deduped",
				"payment_id", pay.ID, "dedup_key", key,
				"note", "subscription.pending sibling already sent the dunning email")
			return nil
		}
	}

	// P0-1: thread the per-cycle dedup key through to the email-layer
	// ledger + provider Idempotency-Key header so a network-glitch retry
	// (caller perceives the send failed, retries with the same key)
	// collapses at both layers.
	if err := h.email.SendPaymentFailedWithKey(ctx, recipient, dunningDedupKey(recipient), pay.AttemptCount, nil); err != nil {
		slog.Error("billing.payment.failed.email_failed",
			"error", err, "to", models.MaskEmail(recipient), "payment_id", pay.ID)
		return fmt.Errorf("payment.failed email send: %w", err)
	}

	slog.Info("billing.payment.failed.email_sent",
		"to", models.MaskEmail(recipient),
		"payment_id", pay.ID,
		"team_id", teamID,
		"resolved_via", resolvedVia)
	return nil
}

// resolveTeamFromPayment derives the team UUID for a payment.failed /
// subscription-tied payment event by inspecting the Razorpay payload server-
// side. Priority order (most-specific → least-specific):
//
//  1. payment.notes.team_id        — caller-supplied (we set this on the
//     subscription, which Razorpay copies onto the payment)
//  2. payment.subscription_id      — DB lookup against teams.stripe_customer_id
//     (column name is legacy; stores Razorpay subscription IDs now)
//  3. event.Payload.Subscription   — webhook may include the sibling entity;
//     parse it and recurse via subscription notes / id
//  4. payment.order_id             — not yet wired; future hook for one-shot
//     orders if we add them
//
// Returns (uuid.Nil, "") when no path resolves, signalling "drop the email"
// to the caller. The string is a slug naming the resolution path, used for
// observability logging.
//
// NEVER consults payment.Email — the whole point of this helper (B11-P1) is
// to remove the payload-email trust path from the dunning flow.
func resolveTeamFromPayment(ctx context.Context, h *BillingHandler, pay rzpPaymentEntity, event rzpWebhookEvent) (uuid.UUID, string) {
	// 1. payment.notes.team_id
	if pay.Notes != nil {
		if raw := strings.TrimSpace(pay.Notes["team_id"]); raw != "" {
			if id, err := uuid.Parse(raw); err == nil {
				return id, "payment.notes.team_id"
			}
		}
	}
	// 2. payment.subscription_id → DB lookup
	if sid := strings.TrimSpace(pay.SubscriptionID); sid != "" {
		if team, err := models.GetTeamByRazorpaySubscriptionID(ctx, h.db, sid); err == nil && team != nil {
			return team.ID, "payment.subscription_id"
		}
	}
	// 3. event.Payload.Subscription sibling — same entity unmarshal +
	//    notes/id read as resolveTeamFromNotes
	if event.Payload.Subscription != nil && len(event.Payload.Subscription.Entity) > 0 {
		var sub rzpSubscriptionEntity
		if err := json.Unmarshal(event.Payload.Subscription.Entity, &sub); err == nil {
			if raw := strings.TrimSpace(sub.Notes["team_id"]); raw != "" {
				if id, err := uuid.Parse(raw); err == nil {
					return id, "subscription.notes.team_id"
				}
			}
			if sub.ID != "" {
				if team, err := models.GetTeamByRazorpaySubscriptionID(ctx, h.db, sub.ID); err == nil && team != nil {
					return team.ID, "subscription.id"
				}
			}
		}
	}
	return uuid.Nil, ""
}

// dunningDedupKey builds the per-billing-cycle dedup key for the payment-
// failed dunning email (EMAIL-BUGBASH C5). payment.failed and
// subscription.pending fire for the same failed cycle within the same span
// of hours, and the payment entity carries no subscription id — so the only
// anchor common to both events is the recipient address. The key buckets on
// the recipient + the UTC date: one dunning email per recipient per day.
// A monthly/yearly subscription has at most one failed cycle per day, so the
// bucket never collapses two genuinely-distinct failed cycles.
func dunningDedupKey(recipient string) string {
	recipient = strings.ToLower(strings.TrimSpace(recipient))
	if recipient == "" {
		return ""
	}
	return fmt.Sprintf("dunning:%s:%s", recipient, time.Now().UTC().Format("2006-01-02"))
}

// subscriptionPendingAttemptCount is the attempt_count passed to
// SendPaymentFailed for a subscription.pending event. Unlike payment.failed
// (which carries a real payment.attempt_count), a subscription.pending event
// has NO payment object — there is no attempt count to read. 1 renders the
// non-urgent "your payment didn't go through, please retry" copy, which is the
// correct tone for a first soft-failure / pre-authorization failure.
const subscriptionPendingAttemptCount = 1

// handleSubscriptionPending processes subscription.pending events.
//
// Razorpay fires subscription.pending when a subscription charge fails and the
// subscription is awaiting a retry. Crucially, this is the ONLY failure signal
// emitted when a pre-authorization / mandate fails on Razorpay's hosted
// checkout page ("seller does not support recurring payments", a declined
// mandate): that path creates NO payment object, so payment.failed never
// fires. Without this case the customer got no email at all — the exact
// coverage gap a live Pro upgrade test exposed.
//
// Treated as a soft failure: resolve the team, look up the owner's email, and
// send the existing payment-failure notification (the same SendPaymentFailed
// call handlePaymentFailed uses). Does NOT downgrade — Razorpay retries the
// charge and fires subscription.halted only once all retries are exhausted.
//
// Error contract mirrors handlePaymentFailed: a retryable failure (the email
// send errored) returns an error so RazorpayWebhook releases the dedup claim
// and 500s, and Razorpay redelivers. Non-retryable conditions (malformed
// payload, unresolvable team, no email on file) return nil — a retry would
// re-burn the claim for nothing.
func (h *BillingHandler) handleSubscriptionPending(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.pending.parse_failed")
		return nil // malformed payload — retrying won't help; swallow
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		// A missing/unknown-team payload will never resolve — non-retryable.
		// A real DB error IS retryable: return it so dispatch releases the
		// claim and 500s for redelivery.
		if teamResolveUnretryable(err) {
			slog.Warn("billing.subscription.pending.team_unresolvable",
				"error", err, "sub_id", sub.ID)
			return nil
		}
		slog.Error("billing.subscription.pending.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return fmt.Errorf("subscription.pending team resolve: %w", err)
	}

	// The subscription entity carries no email — look up the team owner.
	owner, ownerErr := models.GetUserByTeamID(ctx, h.db, teamID)
	if ownerErr != nil || owner == nil || owner.Email == "" {
		slog.Warn("billing.subscription.pending.no_email",
			"error", ownerErr, "team_id", teamID, "sub_id", sub.ID)
		return nil // no address to notify — non-retryable
	}

	slog.Warn("billing.subscription.pending",
		"team_id", teamID, "subscription_id", sub.ID, "to", models.MaskEmail(owner.Email))

	// C5 per-cycle dedup — same key space as handlePaymentFailed. If the
	// sibling payment.failed event already sent the dunning email for this
	// recipient today, skip. Fail-open: a dedup DB error sends anyway.
	if key := dunningDedupKey(owner.Email); key != "" {
		claimed, claimErr := models.ClaimEmailSend(ctx, h.db, key, models.EmailSendKindDunning)
		if claimErr != nil {
			slog.Warn("billing.subscription.pending.dunning_dedup_failed",
				"error", claimErr, "dedup_key", key)
		} else if !claimed {
			slog.Info("billing.subscription.pending.dunning_deduped",
				"team_id", teamID, "sub_id", sub.ID, "dedup_key", key,
				"note", "payment.failed sibling already sent the dunning email")
			return nil
		}
	}

	// P0-1: keyed variant so a network-glitch retry collapses at the
	// email-layer ledger + the upstream provider's Idempotency-Key.
	if err := h.email.SendPaymentFailedWithKey(ctx, owner.Email, dunningDedupKey(owner.Email), subscriptionPendingAttemptCount, nil); err != nil {
		slog.Error("billing.subscription.pending.email_failed",
			"error", err, "to", models.MaskEmail(owner.Email), "team_id", teamID, "sub_id", sub.ID)
		return fmt.Errorf("subscription.pending email send: %w", err)
	}

	slog.Info("billing.subscription.pending.email_sent",
		"to", models.MaskEmail(owner.Email), "team_id", teamID, "subscription_id", sub.ID)
	return nil
}

// handleSubscriptionChargeFailed processes subscription.charged_failed
// events — the start of the dunning state machine.
//
// Flow:
//  1. Resolve the team from the subscription's notes (or fall back to
//     the DB lookup by subscription_id).
//  2. Attempt to INSERT a new active grace row. The partial-unique
//     index uq_payment_grace_team_active makes the call idempotent:
//     a redelivery of the same charge_failed event hits the constraint
//     and the model returns ErrPaymentGraceAlreadyActive, which we
//     treat as a silent no-op (the grace clock is already running).
//  3. Emit the payment.grace_started audit row so the worker's Brevo
//     forwarder kicks off the first reminder email. Best-effort.
//
// F10 (billing-trust audit 2026-05-19): error contract now mirrors
// handleSubscriptionPending / handlePaymentFailed. A RETRYABLE failure (a
// real DB error during team resolve, or a grace-row INSERT that errored)
// returns an error so RazorpayWebhook releases the dedup claim and 500s,
// and Razorpay redelivers — without this the up-front dedup claim would
// suppress redelivery and the customer's first dunning email could be
// delayed by ~15 min until the reconciler independently opened a grace
// period. NON-RETRYABLE conditions (malformed payload, unresolvable team)
// return nil — a retry would just re-burn the claim for nothing.
func (h *BillingHandler) handleSubscriptionChargeFailed(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.charged_failed.parse_failed")
		return nil // malformed payload — retrying won't help; swallow
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		// Missing/unknown-team payload → non-retryable. Real DB error →
		// retryable: return it so dispatch releases the claim and 500s.
		if teamResolveUnretryable(err) {
			slog.Warn("billing.subscription.charged_failed.team_unresolvable",
				"error", err, "sub_id", sub.ID)
			return nil
		}
		slog.Error("billing.subscription.charged_failed.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return fmt.Errorf("subscription.charged_failed team resolve: %w", err)
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

	// startGracePeriodForTeam returns a non-nil error only on a retryable
	// grace-row INSERT failure; an idempotent redelivery or a successful
	// start returns nil. Propagate it so the webhook 500s and Razorpay
	// redelivers — the grace period still gets opened on the retry.
	if graceErr := startGracePeriodForTeam(ctx, h.db, teamID, sub.ID, attemptedAmount); graceErr != nil {
		return fmt.Errorf("subscription.charged_failed grace start: %w", graceErr)
	}
	return nil
}

// handleSubscriptionPaused processes subscription.paused events (P1-F).
//
// A paused Razorpay subscription is not actively billing. Rather than
// downgrade immediately we open a grace period — identical to a failed
// charge — so the team keeps its current tier for the grace window and the
// dunning state machine drives the reminder emails. subscription.resumed
// reverses this. Fully idempotent: startGracePeriodForTeam swallows a
// redelivery via the partial-unique index on the active grace row.
//
// P1-W3-09: returns an error on a retryable team-resolve failure so
// RazorpayWebhook releases the dedup claim and 500s — Razorpay redelivers
// and the grace period still gets opened. A parse failure is non-retryable
// and returns nil.
func (h *BillingHandler) handleSubscriptionPaused(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.paused.parse_failed")
		return nil
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		// Missing/unknown-team payload → non-retryable. Real DB error → retryable.
		if teamResolveUnretryable(err) {
			slog.Warn("billing.subscription.paused.team_unresolvable",
				"error", err, "sub_id", sub.ID)
			return nil
		}
		slog.Error("billing.subscription.paused.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return fmt.Errorf("subscription.paused team resolve: %w", err)
	}

	slog.Info("billing.subscription.paused", "team_id", teamID, "subscription_id", sub.ID)
	// attemptedAmount is unknown for a pause (no failed charge) — pass 0.
	// A retryable grace-INSERT failure here is propagated so the paused
	// event 500s and Razorpay redelivers, mirroring the charged_failed
	// contract (F10) — the grace period still gets opened on the retry.
	if graceErr := startGracePeriodForTeam(ctx, h.db, teamID, sub.ID, 0); graceErr != nil {
		return fmt.Errorf("subscription.paused grace start: %w", graceErr)
	}
	return nil
}

// handleSubscriptionResumed processes subscription.resumed events (P1-F).
//
// A resumed subscription is billing again, so any grace period opened by
// the matching subscription.paused must be closed. maybeRecoverPaymentGrace
// flips the active grace row to 'recovered' and emits the recovery audit
// row — identical to the recovery handleSubscriptionCharged performs on a
// good charge. Fully idempotent: a redelivery finds no active grace row
// and is a silent no-op. The tier itself is not re-elevated here — the
// next subscription.charged does that; resume only stops the dunning clock.
//
// P1-W3-09: returns an error on a retryable team-resolve failure so
// RazorpayWebhook releases the dedup claim and 500s — Razorpay redelivers
// and the grace clock still gets stopped. A parse failure is non-retryable
// and returns nil.
func (h *BillingHandler) handleSubscriptionResumed(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) error {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.resumed.parse_failed")
		return nil
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		// Missing/unknown-team payload → non-retryable. Real DB error → retryable.
		if teamResolveUnretryable(err) {
			slog.Warn("billing.subscription.resumed.team_unresolvable",
				"error", err, "sub_id", sub.ID)
			return nil
		}
		slog.Error("billing.subscription.resumed.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return fmt.Errorf("subscription.resumed team resolve: %w", err)
	}

	slog.Info("billing.subscription.resumed", "team_id", teamID, "subscription_id", sub.ID)
	maybeRecoverPaymentGrace(ctx, h.db, teamID, sub.ID)
	return nil
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
//
// F10 (billing-trust audit 2026-05-19): returns a non-nil error ONLY on a
// retryable grace-row INSERT failure (a real DB error). An idempotent
// redelivery (ErrPaymentGraceAlreadyActive), a successful start, or a
// no-op guard return all return nil. Callers that participate in the
// webhook retry contract (handleSubscriptionChargeFailed) propagate this
// so a transient DB failure 500s the webhook and Razorpay redelivers; the
// audit emit remains best-effort and never affects the return value.
func startGracePeriodForTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID, subscriptionID string, attemptedAmount int64) error {
	if db == nil || teamID == uuid.Nil || strings.TrimSpace(subscriptionID) == "" {
		return nil
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
			// Idempotent redelivery — grace clock already started. Not an
			// error: the grace period the caller wanted already exists.
			slog.Info("billing.subscription.charged_failed.grace_already_active",
				"team_id", teamID, "subscription_id", subscriptionID)
			return nil
		}
		// A real DB failure — retryable. Return it so the caller can 500
		// the webhook and let Razorpay redeliver charged_failed.
		slog.Error("billing.subscription.charged_failed.grace_create_failed",
			"error", err, "team_id", teamID, "subscription_id", subscriptionID)
		return fmt.Errorf("create payment grace period: %w", err)
	}

	slog.Info("billing.subscription.charged_failed.grace_started",
		"team_id", teamID,
		"subscription_id", subscriptionID,
		"grace_id", grace.ID,
		"expires_at", grace.ExpiresAt,
	)

	emitPaymentGraceStartedAudit(ctx, db, teamID, subscriptionID, grace, attemptedAmount)
	return nil
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

// ErrTeamUnresolvable is the sentinel returned by resolveTeamFromNotes when
// the subscription event simply does not carry enough information to find a
// team (no valid notes.team_id and no subscription_id). P1-W3-09: webhook
// dispatch treats this as a NON-retryable failure — a payload that will never
// resolve must not 500-and-retry forever, so the claim is kept and 200 is
// returned. A genuine DB error (returned as-is, NOT wrapped in this sentinel)
// is the retryable case that releases the claim and 500s.
var ErrTeamUnresolvable = errors.New("cannot resolve team: missing notes.team_id and no subscription_id")

// teamResolveUnretryable reports whether a resolveTeamFromNotes error is a
// permanent failure that will never succeed on retry — a malformed/missing
// payload (ErrTeamUnresolvable) or a team that genuinely does not exist
// (models.ErrTeamNotFound). P1-W3-09: these keep the dedup claim and return
// 200; everything else (real DB/connection errors) is retryable, releasing
// the claim and returning 500 so Razorpay redelivers.
func teamResolveUnretryable(err error) bool {
	var notFound *models.ErrTeamNotFound
	return errors.Is(err, ErrTeamUnresolvable) || errors.As(err, &notFound)
}

// resolveTeamFromNotes returns the team UUID from subscription notes.
// Falls back to a DB lookup by subscription ID when notes are absent.
//
// Error contract (P1-W3-09): a missing-data failure returns ErrTeamUnresolvable
// (non-retryable); a real DB error from GetTeamByRazorpaySubscriptionID is
// returned unwrapped (retryable). Callers use errors.Is to tell them apart.
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
	return uuid.Nil, ErrTeamUnresolvable
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
	// PlanFrequency mirrors the checkout body field. The ChangePlanModal
	// presents an Annual radio so it sends "yearly" on this field; the
	// backend's Portal.ChangePlan path uses razorpayPlanIDs() which only
	// resolves to monthly plan IDs. Until yearly-via-change-plan is wired,
	// surface a clear 400 instead of silently routing to monthly. T9 P1-1
	// (BugHunt 2026-05-20).
	PlanFrequency string `json:"plan_frequency"`
}

// ChangePlanAPI handles POST /api/v1/billing/change-plan (session JWT).
func (h *BillingHandler) ChangePlanAPI(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}
	// Email-verified gate (migration 052) — same gate as checkout: a
	// /claim-created account must verify its email before changing plans.
	if ok, errResp := h.requireVerifiedEmail(c, "change_plan"); !ok {
		return errResp
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
	// T9 P1-1 (BugHunt 2026-05-20): the ChangePlanModal's Annual radio
	// posts plan_frequency:"yearly" but this endpoint's Razorpay-side
	// resolver only knows monthly plan IDs. Returning 400 here is a
	// clear contract: yearly-via-change-plan is not yet supported.
	// Empty / "monthly" both proceed as before.
	freq := strings.ToLower(strings.TrimSpace(body.PlanFrequency))
	switch freq {
	case "", "monthly":
		// OK — fall through.
	case "yearly":
		return respondError(c, fiber.StatusBadRequest, "yearly_change_plan_unsupported",
			"Changing to a yearly plan via /change-plan is not yet supported. Cancel and use POST /api/v1/billing/checkout with plan_frequency='yearly', or contact support@instanode.dev.")
	default:
		return respondError(c, fiber.StatusBadRequest, "invalid_frequency",
			"plan_frequency must be 'monthly' or 'yearly'")
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

// chargeUndeliverableReason* are the canonical `reason` values stamped into a
// billing.charge_undeliverable audit row's metadata. Named constants (project
// convention) so the emit site and any operator dashboard/alert filter cannot
// drift.
const (
	// chargeUndeliverableReasonTeamUnresolvable — F2/F8: the charged
	// subscription's notes carry no resolvable team and no subscription_id
	// maps to one. The charge cannot be matched to an account.
	chargeUndeliverableReasonTeamUnresolvable = "team_unresolvable"
	// chargeUndeliverableReasonUnknownTier — F3/F8: the team resolved but the
	// plan_id maps to a tier that is not in plans.yaml, so no entitlement can
	// be granted.
	chargeUndeliverableReasonUnknownTier = "unknown_tier"
	// chargeUndeliverableReasonLowerTierCharge — MR-P0-6 (BugBash 2026-05-20):
	// a subscription.charged event carried a plan_id that ranks BELOW the
	// team's current tier. `charged` is never a downgrade signal (genuine
	// downgrades flow through cancellation/plan-change), so the tier was kept
	// and the charge flagged for operator reconciliation.
	chargeUndeliverableReasonLowerTierCharge = "lower_tier_charge"
)

// F11 (billing-trust audit 2026-05-19) — cancellation copy.
//
// The pre-fix subscription.canceled audit row carried a bare
// Summary = "subscription canceled". That string is rendered verbatim by
// the dashboard's Recent Activity feed and is the api-side source of truth
// the worker's cancellation email derives its wording from. It was
// misleading by omission: it gave the customer NO indication that (a) the
// account is NOT cut off — it falls back to a courtesy tier and existing
// resources keep their limits — and (b) a final billing-cycle charge
// already in flight is expected, not an error. A customer reading "canceled"
// could reasonably dispute the next charge as fraudulent.
//
// These constants spell out the accurate outcome. subscriptionCanceledSummary*
// are chosen by the resulting fall-back tier so the copy never claims
// "courtesy access" for a never-paid cancellation that genuinely drops to
// the free floor.
const (
	// subscriptionCanceledSummaryCourtesy — used when the cancellation kept
	// the customer on the 'hobby' courtesy floor (they paid at least one
	// invoice). States the access reality so a still-pending cycle charge
	// is not mistaken for an error.
	subscriptionCanceledSummaryCourtesy = "Subscription cancelled — your account stays active on the hobby plan and existing resources keep their current limits. Any charge already in progress for the current billing cycle will still complete."
	// subscriptionCanceledSummaryFree — used when the cancellation dropped
	// the customer to the 'free' floor (no paid invoice ever posted). No
	// in-flight charge claim is made here because none was ever taken.
	subscriptionCanceledSummaryFree = "Subscription cancelled — your account moved to the free plan. Existing resources keep their current limits; resubscribe any time to restore full access."
	// subscriptionCanceledMetaEffectiveNote is stamped into the audit
	// metadata so the worker's cancellation email can render an accurate
	// effective-state line instead of implying access ended immediately.
	subscriptionCanceledMetaEffectiveNote = "effective_note"
)

// subscriptionCanceledSummary returns the accurate, non-misleading
// cancellation summary copy (F11) for the resulting fall-back tier.
func subscriptionCanceledSummary(toTier string) string {
	if strings.EqualFold(strings.TrimSpace(toTier), "free") {
		return subscriptionCanceledSummaryFree
	}
	return subscriptionCanceledSummaryCourtesy
}

// chargedPaymentMeta extracts the payment id, amount (in the currency's minor
// unit — paise/cents), and currency from a subscription.charged event's
// optional payload.payment entity. Razorpay bundles the successful payment
// alongside the subscription on a charged event; when it is absent every
// field is the zero value and callers fall back accordingly.
func chargedPaymentMeta(event rzpWebhookEvent) (paymentID string, amountMinor int64, currency string) {
	if event.Payload.Payment == nil {
		return "", 0, ""
	}
	var pay rzpPaymentEntity
	if err := json.Unmarshal(event.Payload.Payment.Entity, &pay); err != nil {
		return "", 0, ""
	}
	return pay.ID, pay.Amount, pay.Currency
}

// formatChargedAmount turns a Razorpay minor-unit amount + currency code into
// a display string for the receipt email. Razorpay amounts are always in the
// currency's smallest unit (paise for INR, cents for USD), so we divide by 100
// for the major unit. An unknown/empty currency still renders the numeric
// amount so the receipt is never blank. A zero amount (payment entity absent
// on the event) renders the honest "see your billing dashboard" fallback
// rather than a misleading "0.00".
func formatChargedAmount(amountMinor int64, currency string) string {
	currency = strings.ToUpper(strings.TrimSpace(currency))
	if amountMinor <= 0 {
		return "see your billing dashboard"
	}
	major := float64(amountMinor) / 100.0
	switch currency {
	case "INR":
		return fmt.Sprintf("₹%.2f", major)
	case "USD":
		return fmt.Sprintf("$%.2f", major)
	case "":
		return fmt.Sprintf("%.2f", major)
	default:
		return fmt.Sprintf("%s %.2f", currency, major)
	}
}

// receiptDedupKey builds the per-billing-cycle dedup key for the payment
// receipt (EMAIL-BUGBASH C4). subscription.activated and subscription.charged
// are DISTINCT Razorpay events for the same cycle — both route into
// sendPaymentReceipt — so without a shared key the customer gets two
// receipts. The key is keyed on (subscription_id, paid_count): both events of
// one cycle carry the same subscription and the same count of paid invoices.
// When paid_count is unavailable it falls back to the payment id; if neither
// is present it returns "" and ClaimEmailSend degrades to always-send.
func receiptDedupKey(sub rzpSubscriptionEntity, event rzpWebhookEvent) string {
	if sub.ID == "" {
		return ""
	}
	if sub.PaidCount != nil {
		return fmt.Sprintf("receipt:%s:paid:%d", sub.ID, *sub.PaidCount)
	}
	if paymentID, _, _ := chargedPaymentMeta(event); paymentID != "" {
		return fmt.Sprintf("receipt:%s:pay:%s", sub.ID, paymentID)
	}
	return ""
}

// sendPaymentReceipt sends the F4 payment-success receipt email to the team
// owner after a successful subscription.charged. It is fully fail-open: every
// failure (no owner row, no email on file, email-send error) is logged at WARN
// and swallowed — a receipt-delivery problem must never undo the committed
// upgrade or turn the webhook into a 500.
//
// isRenewal is derived from the tier transition: fromTier == toTier means the
// customer was already on this tier (a renewal charge); a strict change means
// this charge upgraded them. Either way a receipt is sent — renewals are no
// longer silent.
//
// EMAIL-BUGBASH C4: before sending, the cycle is claimed in email_send_dedup
// so subscription.activated + subscription.charged (two distinct events, same
// cycle) yield exactly one receipt. The claim is fail-open: a dedup DB error
// sends anyway (a rare duplicate beats a missed receipt).
func (h *BillingHandler) sendPaymentReceipt(ctx context.Context, teamID uuid.UUID, toTier, fromTier string, event rzpWebhookEvent) {
	if h.email == nil {
		return
	}
	owner, ownerErr := models.GetUserByTeamID(ctx, h.db, teamID)
	if ownerErr != nil || owner == nil || owner.Email == "" {
		slog.Warn("billing.subscription.charged.receipt_no_email",
			"error", ownerErr, "team_id", teamID)
		return
	}

	// C4 per-cycle dedup. A (false, nil) claim means another event of this
	// same billing cycle already sent the receipt — skip silently.
	//
	// receiptKey is also threaded down to SendPaymentSucceededWithKey
	// (P0-1) so the email-layer ledger + upstream provider header collapse
	// a network-glitch retry independently of this pre-send claim.
	var receiptKey string
	if sub, ok := parseSubscriptionEntity(event); ok {
		if key := receiptDedupKey(sub, event); key != "" {
			receiptKey = key
			claimed, claimErr := models.ClaimEmailSend(ctx, h.db, key, models.EmailSendKindReceipt)
			if claimErr != nil {
				slog.Warn("billing.subscription.charged.receipt_dedup_failed",
					"error", claimErr, "team_id", teamID, "dedup_key", key)
				// fail open: fall through and send.
			} else if !claimed {
				slog.Info("billing.subscription.charged.receipt_deduped",
					"team_id", teamID, "dedup_key", key,
					"note", "another event of this billing cycle already sent the receipt")
				return
			}
		}
	}

	paymentID, amountMinor, currency := chargedPaymentMeta(event)

	reg := plans.Default()
	planLabel := reg.DisplayName(toTier)
	if strings.TrimSpace(planLabel) == "" {
		planLabel = toTier
	}
	period := reg.BillingPeriod(toTier)
	if strings.TrimSpace(period) == "" {
		period = "monthly"
	}

	receipt := email.PaymentReceipt{
		Plan:          planLabel,
		AmountDisplay: formatChargedAmount(amountMinor, currency),
		Period:        period,
		IsRenewal:     strings.EqualFold(strings.TrimSpace(fromTier), strings.TrimSpace(toTier)),
		// C8: AmountKnown is true only when a real payment entity carried a
		// positive amount; otherwise the receipt renders the parenthetical
		// "(see your billing dashboard ...)" pointer instead of a fabricated
		// definite figure.
		AmountKnown: paymentID != "" && amountMinor > 0,
	}
	if err := h.email.SendPaymentSucceededWithKey(ctx, owner.Email, receiptKey, receipt); err != nil {
		slog.Warn("billing.subscription.charged.receipt_send_failed",
			"error", err, "team_id", teamID, "to", models.MaskEmail(owner.Email))
		return
	}
	slog.Info("billing.subscription.charged.receipt_sent",
		"team_id", teamID, "to", models.MaskEmail(owner.Email), "plan", toTier, "is_renewal", receipt.IsRenewal)
}

// emitChargeUndeliverableAudit writes a high-severity
// billing.charge_undeliverable audit row (F8) — the make-good worklist signal
// for a charge that was confirmed by Razorpay but that the platform cannot
// turn into a delivered upgrade (an unresolvable team, F2/F8; or an unknown
// plan tier, F3). It carries the subscription_id, payment_id, and reason so an
// operator can locate the charge in the Razorpay dashboard and reconcile it
// (refund or hand-grant). It does NOT issue an automatic refund — that stays a
// deliberate operator action; the deliverable here is that the event is loudly
// and durably recorded, never silent.
//
// teamID may be uuid.Nil when the team itself could not be resolved —
// InsertAuditEvent stores uuid.Nil as SQL NULL, so the row still lands as an
// admin-only (no team) audit entry. Best-effort: an audit-write failure logs
// at Error (the slog line is the second, independent alert surface) but never
// surfaces to the webhook caller.
func emitChargeUndeliverableAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, sub rzpSubscriptionEntity, event rzpWebhookEvent, reason, resolvedTier string) {
	if db == nil {
		return
	}
	paymentID, amountMinor, currency := chargedPaymentMeta(event)
	meta := map[string]any{
		"reason":          reason,
		"subscription_id": sub.ID,
		"payment_id":      paymentID,
		"plan_id":         sub.PlanID,
	}
	if resolvedTier != "" {
		meta["resolved_tier"] = resolvedTier
	}
	if amountMinor > 0 {
		meta["amount_minor"] = amountMinor
		meta["currency"] = currency
	}
	metaBlob, _ := json.Marshal(meta)

	if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     models.AuditKindBillingChargeUndeliverable,
		Summary:  "charge confirmed but undeliverable (" + reason + ") — operator must reconcile/refund",
		Metadata: metaBlob,
	}); err != nil {
		slog.Error("billing.charge_undeliverable.audit_emit_failed",
			"kind", models.AuditKindBillingChargeUndeliverable,
			"team_id", teamID,
			"subscription_id", sub.ID,
			"reason", reason,
			"error", err,
		)
	}
}

// emitSubscriptionChangeAudit writes a subscription.upgraded or
// subscription.downgraded row for the Loops forwarder when a charged-webhook
// transition strictly changes the team's tier. Same-tier renewals (the
// monthly Pro→Pro re-charge case) emit nothing — Loops shouldn't send an
// upgrade email on every renewal.
//
// F9 (billing-trust audit 2026-05-19): the emit is idempotent on
// (team_id, kind, subscription_id). If an identical subscription-change
// audit row already exists, this returns early WITHOUT inserting a second
// one — so the rare fail-open dedup-claim edge (claim INSERT errors during
// a DB brownout → two concurrent deliveries of the same charged event both
// dispatch) can no longer produce a duplicate upgrade-confirmation email.
// The pre-flight check is skipped when subID is empty (no stable dedup key)
// and on a lookup error (fail-open — better a possible duplicate email than
// a swallowed audit row), preserving the prior always-emit behaviour there.
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

	// F9 idempotency guard: skip the insert when a row for this exact
	// (team_id, kind, subscription_id) is already present. A lookup error
	// is fail-open — fall through and insert, the prior behaviour.
	if db != nil {
		if exists, lookupErr := models.SubscriptionChangeAuditExists(ctx, db, teamID, kind, subID); lookupErr != nil {
			slog.Warn("audit.emit.dedup_lookup_failed",
				"kind", kind, "team_id", teamID, "subscription_id", subID, "error", lookupErr)
		} else if exists {
			slog.Info("audit.emit.deduped",
				"kind", kind, "team_id", teamID, "subscription_id", subID)
			return
		}
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
// because the cancellation email is about the cancellation event itself,
// not the resulting tier delta. Best-effort: failures log only.
//
// F11 (billing-trust audit 2026-05-19): the Summary is no longer the bare,
// misleading "subscription canceled". It now states the accurate outcome —
// the account stays active on a courtesy floor (or moves to free if never
// paid), existing resources keep their limits, and an in-flight cycle
// charge will still complete — so the customer does not mistake a pending
// charge for fraud. The same accurate text is duplicated into the audit
// metadata under effective_note so the worker's cancellation email can
// render it verbatim. summary is selected by the resulting toTier.
func emitSubscriptionCanceledAudit(ctx context.Context, db *sql.DB, teamID uuid.UUID, fromTier, toTier, subID string) {
	summary := subscriptionCanceledSummary(toTier)
	meta := map[string]string{
		"from_tier":                           fromTier,
		"to_tier":                             toTier,
		"subscription_id":                     subID,
		subscriptionCanceledMetaEffectiveNote: summary,
	}
	metaBlob, _ := json.Marshal(meta)

	if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     models.AuditKindSubscriptionCanceled,
		Summary:  summary,
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
