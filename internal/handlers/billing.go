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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/email"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/migratorclient"
	"instant.dev/internal/models"
	"instant.dev/internal/razorpaybilling"
)

// BillingHandler handles billing and Razorpay webhook endpoints.
type BillingHandler struct {
	db        *sql.DB
	cfg       *config.Config
	email     *email.Client
	migClient *migratorclient.Client
}

// NewBillingHandler constructs a BillingHandler.
func NewBillingHandler(db *sql.DB, cfg *config.Config, emailClient *email.Client, migClient *migratorclient.Client) *BillingHandler {
	return &BillingHandler{db: db, cfg: cfg, email: emailClient, migClient: migClient}
}

// checkoutRequest is the request body for POST /api/v1/billing/checkout.
type checkoutRequest struct {
	Plan string `json:"plan"`
}

// razorpayPlanIDs returns the configured Razorpay plan_id for each tier.
func (h *BillingHandler) razorpayPlanIDs() map[string]string {
	m := make(map[string]string)
	if h.cfg.RazorpayPlanIDHobby != "" {
		m["hobby"] = h.cfg.RazorpayPlanIDHobby
	}
	if h.cfg.RazorpayPlanIDPro != "" {
		m["pro"] = h.cfg.RazorpayPlanIDPro
	}
	if h.cfg.RazorpayPlanIDTeam != "" {
		m["team"] = h.cfg.RazorpayPlanIDTeam
	}
	return m
}

// planIDToTier maps a Razorpay plan_id back to an instant.dev tier name.
// Defaults to "pro" when the plan_id is unrecognised.
func (h *BillingHandler) planIDToTier(planID string) string {
	switch planID {
	case h.cfg.RazorpayPlanIDTeam:
		return "team"
	case h.cfg.RazorpayPlanIDPro:
		return "pro"
	case h.cfg.RazorpayPlanIDHobby:
		return "hobby"
	}
	return "pro"
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

	var body checkoutRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}

	plan := strings.ToLower(strings.TrimSpace(body.Plan))
	var planID string
	switch plan {
	case "hobby":
		planID = h.cfg.RazorpayPlanIDHobby
	case "pro":
		planID = h.cfg.RazorpayPlanIDPro
	case "team":
		// Team tier is under development — block customer-initiated
		// subscribe via the public API. The internal /internal/set-tier
		// endpoint still works for ops use. Drop this guard when team
		// launches (and revert the public pricing UI).
		return respondError(c, fiber.StatusBadRequest, "tier_unavailable",
			"Team tier is under active development. Email support@instanode.dev to join the early access list.")
	default:
		return respondError(c, fiber.StatusBadRequest, "invalid_plan", "plan must be 'hobby' or 'pro'")
	}

	if h.cfg.RazorpayKeyID == "" || h.cfg.RazorpayKeySecret == "" || planID == "" {
		slog.Warn("billing.checkout.not_configured",
			"team_id", teamID,
			"plan", plan,
			"key_set", h.cfg.RazorpayKeyID != "",
			"secret_set", h.cfg.RazorpayKeySecret != "",
			"plan_id_set", planID != "",
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "billing_not_configured", "Razorpay credentials/plans not configured for this environment")
	}

	client := razorpay.NewClient(h.cfg.RazorpayKeyID, h.cfg.RazorpayKeySecret)

	subBody := map[string]interface{}{
		"plan_id":         planID,
		"total_count":     12, // 12 billing cycles; cancel-at-cycle-end exits early via webhook
		"quantity":        1,
		"customer_notify": 1,
		"notes": map[string]interface{}{
			"team_id": teamID.String(),
			"plan":    plan,
		},
	}

	sub, err := client.Subscription.Create(subBody, nil)
	if err != nil {
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

	switch event.Event {
	case "subscription.charged":
		h.handleSubscriptionCharged(ctx, c, event)
	case "subscription.cancelled":
		h.handleSubscriptionCancelled(ctx, c, event)
	case "payment.failed":
		h.handlePaymentFailed(ctx, c, event)
	default:
		span.SetAttributes(attribute.String("rzp.event.unhandled", "true"))
	}

	// Always return 200 to Razorpay.
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
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
func (h *BillingHandler) handleSubscriptionCharged(ctx context.Context, c *fiber.Ctx, event rzpWebhookEvent) {
	sub, ok := parseSubscriptionEntity(event)
	if !ok {
		slog.Error("billing.subscription.charged.parse_failed")
		return
	}

	teamID, err := resolveTeamFromNotes(ctx, h, sub)
	if err != nil {
		slog.Error("billing.subscription.charged.team_resolve_failed",
			"error", err, "sub_id", sub.ID)
		return
	}

	tier := h.planIDToTier(sub.PlanID)

	if updateErr := models.UpdatePlanTier(ctx, h.db, teamID, tier); updateErr != nil {
		slog.Error("billing.subscription.charged.update_plan_failed",
			"error", updateErr, "team_id", teamID)
		return
	}

	if elevErr := models.ElevateResourceTiersByTeam(ctx, h.db, teamID, tier); elevErr != nil {
		slog.Error("billing.subscription.charged.elevate_tiers_failed",
			"error", elevErr, "team_id", teamID, "tier", tier)
		// Non-fatal: team tier updated; resource elevation is best-effort.
	}

	// Store subscription ID for future lookups.
	if sub.ID != "" {
		if updateErr := models.UpdateRazorpaySubscriptionID(ctx, h.db, teamID, sub.ID); updateErr != nil {
			slog.Error("billing.subscription.charged.update_sub_id_failed",
				"error", updateErr, "team_id", teamID)
		}
	}

	h.triggerMigrationsForTeam(ctx, teamID, teamID.String(), tier, "subscription.charged/"+sub.ID)

	slog.Info("billing.subscription.charged",
		"team_id", teamID, "plan_tier", tier, "subscription_id", sub.ID)
	metrics.ConversionFunnel.WithLabelValues("paid").Inc()
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

	tier := "hobby"
	if sub.PaidCount != nil && *sub.PaidCount == 0 {
		tier = "anonymous"
	}
	if updateErr := models.UpdatePlanTier(ctx, h.db, teamID, tier); updateErr != nil {
		slog.Error("billing.subscription.cancelled.downgrade_failed",
			"error", updateErr, "team_id", teamID)
		return
	}

	slog.Info("billing.subscription.cancelled",
		"team_id", teamID, "subscription_id", sub.ID, "new_tier", tier)
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

// triggerMigrationsForTeam iterates active postgres/redis/mongodb resources for the
// team and calls the migrator for any that still live on shared infrastructure.
// Errors are logged but never propagate — migration failure must not block the webhook response.
func (h *BillingHandler) triggerMigrationsForTeam(ctx context.Context, teamID uuid.UUID, teamIDStr, targetTier, logTag string) {
	if h.migClient == nil || h.cfg.MigratorAddr == "" {
		slog.Info("billing.triggerMigrations.skipped_no_migrator", "team_id", teamIDStr)
		return
	}

	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("billing.triggerMigrations.aes_key_failed", "error", err, "team_id", teamIDStr)
		return
	}

	resources, err := models.ListResourcesByTeam(ctx, h.db, teamID)
	if err != nil {
		slog.Error("billing.triggerMigrations.list_failed", "error", err, "team_id", teamIDStr)
		return
	}

	migratable := map[string]bool{"postgres": true, "redis": true, "mongodb": true}
	triggered := 0

	for _, r := range resources {
		if !migratable[r.ResourceType] {
			continue
		}
		if r.Status != "active" {
			continue
		}
		if r.ExpiresAt.Valid {
			continue // skip ephemeral anonymous resources
		}
		if r.MigrationStatus.Valid {
			switch r.MigrationStatus.String {
			case "complete", "running", "verifying":
				continue
			}
		}
		if !r.ConnectionURL.Valid || r.ConnectionURL.String == "" {
			continue
		}

		plainURL, decErr := crypto.Decrypt(aesKey, r.ConnectionURL.String)
		if decErr != nil {
			plainURL = r.ConnectionURL.String
		}

		if !isSharedInfraURL(plainURL) {
			slog.Info("billing.triggerMigrations.already_isolated",
				"resource_id", r.ID, "resource_type", r.ResourceType, "team_id", teamIDStr)
			continue
		}

		if err := h.migClient.Trigger(ctx, migratorclient.MigrationRequest{
			ResourceID:   r.ID.String(),
			ResourceType: r.ResourceType,
			Token:        r.Token.String(),
			SourceTier:   r.Tier,
			TargetTier:   targetTier,
			SourceURL:    plainURL,
			RequestID:    logTag,
		}); err != nil {
			slog.Warn("billing.triggerMigrations.trigger_failed",
				"error", err,
				"resource_id", r.ID,
				"resource_type", r.ResourceType,
				"team_id", teamIDStr,
			)
			continue
		}

		slog.Info("billing.triggerMigrations.triggered",
			"resource_id", r.ID,
			"resource_type", r.ResourceType,
			"source_tier", r.Tier,
			"target_tier", targetTier,
			"team_id", teamIDStr,
		)
		triggered++
	}

	slog.Info("billing.triggerMigrations.done",
		"triggered", triggered,
		"team_id", teamIDStr,
		"target_tier", targetTier,
	)
}

// isSharedInfraURL returns true when the connection URL points at shared cluster infrastructure.
func isSharedInfraURL(url string) bool {
	return strings.Contains(url, ".svc.cluster.local")
}

// CancelSubscriptionAPI handles POST /api/v1/billing/cancel (session JWT).
func (h *BillingHandler) CancelSubscriptionAPI(c *fiber.Ctx) error {
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
	if err := portal.CancelAtCycleEnd(subID); err != nil {
		slog.Error("billing.cancel.api_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusBadGateway, "razorpay_error", "Failed to cancel subscription")
	}
	return c.JSON(fiber.Map{"ok": true, "cancelled_at_cycle_end": true})
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
		return respondError(c, fiber.StatusBadRequest, "invalid_plan", "target_plan must be hobby, pro, or team")
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
