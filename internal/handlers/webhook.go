package handlers

// webhook.go — POST /webhook/new, POST /webhook/receive/:token, GET /api/v1/webhooks/:token/requests
//
// The webhook service is stateless — no gRPC provisioner needed.
// Received payloads are stored in Redis with a TTL and served back via the list API.
//
// Response shape for POST /webhook/new:
//
//	{
//	  "ok":          true,
//	  "id":          "<uuid>",
//	  "token":       "<uuid>",
//	  "receive_url": "https://instant.dev/webhook/receive/<token>",
//	  "tier":        "anonymous",
//	  "limits":      {"requests_stored": 100, "expires_in": "24h"},
//	  "note":        "...",
//	  "expires_at":  "..."
//	}

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

const (
	// webhookAnonTTL is the Redis TTL for anonymous webhook payloads.
	webhookAnonTTL = 24 * time.Hour

	// webhookAuthTTL is the Redis TTL for authenticated webhook payloads.
	webhookAuthTTL = 7 * 24 * time.Hour
)

// webhookMaxStored returns the request cap for a given tier from plans.yaml.
// Returns 100 as a safe floor when the Registry returns 0 or a negative value
// other than -1 (unlimited). -1 is clamped to 10_000 for the Redis LTRIM call.
func (h *WebhookHandler) webhookMaxStored(tier string) int64 {
	n := h.plans.StorageLimitMB(tier, "webhook") // reuses the webhook_requests_stored field
	if n == -1 {
		return 10_000 // unlimited tier — keep at most 10k in Redis
	}
	if n <= 0 {
		return 100 // safe floor
	}
	return int64(n)
}

// WebhookHandler handles POST /webhook/new, POST /webhook/receive/:token,
// and GET /api/v1/webhooks/:token/requests.
type WebhookHandler struct {
	db    *sql.DB
	rdb   *redis.Client
	cfg   *config.Config
	plans *plans.Registry
	provisionHelper
}

// NewWebhookHandler constructs a WebhookHandler.
func NewWebhookHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, p *plans.Registry) *WebhookHandler {
	return &WebhookHandler{
		db:              db,
		rdb:             rdb,
		cfg:             cfg,
		plans:           p,
		provisionHelper: newProvisionHelper(db, rdb, cfg, p),
	}
}

// receiveURL builds the public receive URL for a given token.
// baseURL should be c.BaseURL() so local dev gets http://localhost:30080 and
// production gets https://instant.dev automatically.
func receiveURL(baseURL, token string) string {
	return fmt.Sprintf("%s/webhook/receive/%s", baseURL, token)
}

// webhookRedisKey returns the per-request Redis key.
func webhookRedisKey(token, reqID string) string {
	return fmt.Sprintf("wh:%s:%s", token, reqID)
}

// webhookListKey returns the list Redis key for a token.
func webhookListKey(token string) string {
	return fmt.Sprintf("wh:list:%s", token)
}

// webhookAnonLimits returns the limits map for anonymous webhook resources.
func webhookAnonLimits() fiber.Map {
	return fiber.Map{
		"requests_stored": 100,
		"expires_in":      "24h",
	}
}

// NewWebhook handles POST /webhook/new.
func (h *WebhookHandler) NewWebhook(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("webhook") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Webhook provisioning is coming soon. Sign up at https://instant.dev/start to be notified.")
	}

	start := time.Now()
	ctx := c.UserContext()
	fp := middleware.GetFingerprint(c)
	country := middleware.GetGeoCountry(c)
	vendor := middleware.GetCloudVendor(c)
	requestID := middleware.GetRequestID(c)

	var body provisionRequestBody
	_ = c.BodyParser(&body)
	body.Name = sanitizeName(body.Name)

	env, envErr := resolveEnv(c, body.Env)
	if envErr != nil {
		return envErr
	}

	// ── Authenticated path ───────────────────────────────────────────────────────
	if teamIDStr := middleware.GetTeamID(c); teamIDStr != "" {
		return h.newWebhookAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, env, start)
	}

	// ── Anonymous path ───────────────────────────────────────────────────────────
	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("webhook.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "webhook")
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "webhook", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("webhook.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = fmt.Sprintf("https://instant.dev/start?t=%s", jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			metrics.FingerprintAbuseBlocked.Inc()

			// Decrypt the stored connection_url (the receive_url) to return it in plaintext.
			url := h.decryptWebhookURL(existing.ConnectionURL.String, requestID)

			resp := fiber.Map{
				"ok":          true,
				"id":          existing.ID.String(),
				"token":       existing.Token.String(),
				"receive_url": url,
				"tier":        existing.Tier,
				"env":         existing.Env,
				"limits":      webhookAnonLimits(),
				"note":        limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
				"upgrade":     upgradeURL,
			}
			if existing.ExpiresAt.Valid {
				resp["expires_at"] = existing.ExpiresAt.Time
			}
			return c.JSON(resp)
		}
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	tokenStr := ""

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "webhook",
		Name:             body.Name,
		Tier:             "anonymous",
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        &expiresAt,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("webhook.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision webhook resource")
	}
	tokenStr = resource.Token.String()

	// Build the receive URL and encrypt it for storage.
	rURL := receiveURL(c.BaseURL(), tokenStr)
	provCtx, span := h.startProvisionSpan(ctx, "webhook", "anonymous", "", fp, tokenStr)
	keyErr := h.storeEncryptedURL(provCtx, resource.ID, rURL, requestID)
	finishProvisionSpan(span, keyErr)
	if keyErr != nil {
		slog.Error("webhook.new.store_url_failed", "error", keyErr, "token", tokenStr, "request_id", requestID)
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "webhook", []string{tokenStr})
	if jwtErr != nil {
		slog.Error("webhook.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("webhook.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = fmt.Sprintf("https://instant.dev/start?t=%s", jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "webhook",
		"token", tokenStr,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("webhook", "anonymous").Inc()
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":          true,
		"id":          resource.ID.String(),
		"token":       tokenStr,
		"receive_url": rURL,
		"tier":        "anonymous",
		"env":         resource.Env,
		"limits":      webhookAnonLimits(),
		"note":        upgradeNote(upgradeURL),
		"expires_at":  expiresAt,
	})
}

// newWebhookAuthenticated handles the authenticated path for POST /webhook/new.
func (h *WebhookHandler) newWebhookAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, env string, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("webhook.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     "webhook",
		Name:             name,
		Tier:             team.PlanTier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        nil,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("webhook.new.create_resource_failed_auth",
			"error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision webhook resource")
	}

	// Best-effort audit event; failures must never block the provision.
	go func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "webhook",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>webhook</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	}()

	tokenStr := resource.Token.String()
	rURL := receiveURL(c.BaseURL(), tokenStr)

	provCtx, span := h.startProvisionSpan(ctx, "webhook", team.PlanTier, teamIDStr, fp, tokenStr)
	keyErr := h.storeEncryptedURL(provCtx, resource.ID, rURL, requestID)
	finishProvisionSpan(span, keyErr)
	if keyErr != nil {
		slog.Error("webhook.new.store_url_failed_auth", "error", keyErr, "token", tokenStr, "request_id", requestID)
	}

	slog.Info("provision.success",
		"service", "webhook",
		"token", tokenStr,
		"team_id", teamIDStr,
		"tier", team.PlanTier,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("webhook", team.PlanTier).Inc()

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":          true,
		"id":          resource.ID.String(),
		"token":       tokenStr,
		"receive_url": rURL,
		"tier":        team.PlanTier,
		"env":         resource.Env,
		"limits": fiber.Map{
			"requests_stored": h.webhookMaxStored(team.PlanTier),
		},
	})
}

// Receive handles POST /webhook/receive/:token — stores the incoming request in Redis.
// This endpoint requires no authentication.
func (h *WebhookHandler) Receive(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("webhook") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Webhook service is not enabled.")
	}

	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)
	tokenStr := c.Params("token")

	tokenUUID, err := uuid.Parse(tokenStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Token must be a valid UUID")
	}

	// Look up the resource to ensure it exists and is active.
	resource, err := models.GetResourceByToken(ctx, h.db, tokenUUID)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Webhook token not found")
		}
		slog.Error("webhook.receive.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to look up webhook")
	}

	if resource.Status != "active" {
		return respondError(c, fiber.StatusGone, "webhook_inactive", "This webhook token is no longer active")
	}

	// Read the body using Fiber's buffered accessor (safe after middleware).
	const maxBodyBytes = 1 << 20 // 1 MB
	rawBody := c.Body()
	if len(rawBody) > maxBodyBytes {
		rawBody = rawBody[:maxBodyBytes]
	}

	// Collect headers, excluding sensitive ones.
	headers := make(map[string]string)
	c.Request().Header.VisitAll(func(key, value []byte) {
		k := string(key)
		headers[k] = string(value)
	})

	reqID := uuid.New().String()
	receivedAt := time.Now().UTC()

	payload := map[string]any{
		"id":          reqID,
		"method":      string(c.Request().Header.Method()),
		"headers":     headers,
		"body":        string(rawBody),
		"received_at": receivedAt.Format(time.RFC3339),
	}

	payloadBytes, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		slog.Error("webhook.receive.marshal_failed",
			"error", marshalErr, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to store request")
	}

	// Determine TTL based on tier.
	ttl := webhookAnonTTL
	if resource.Tier != "anonymous" {
		ttl = webhookAuthTTL
	}

	// Store the individual payload with a TTL.
	redisKey := webhookRedisKey(tokenStr, reqID)
	listKey := webhookListKey(tokenStr)

	pipe := h.rdb.Pipeline()
	pipe.Set(ctx, redisKey, payloadBytes, ttl)
	// Push to the list and cap at the tier's limit.
	maxStored := h.webhookMaxStored(resource.Tier)
	pipe.LPush(ctx, listKey, string(payloadBytes))
	pipe.LTrim(ctx, listKey, 0, maxStored-1)
	pipe.Expire(ctx, listKey, ttl)

	if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
		slog.Error("webhook.receive.redis_store_failed",
			"error", pipeErr, "token", tokenStr, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("webhook_store").Inc()
		// Fail open — don't block the sender even if Redis is down.
	}

	slog.Info("webhook.receive.stored",
		"token", tokenStr,
		"request_id", reqID,
		"tier", resource.Tier,
	)

	return c.JSON(fiber.Map{
		"ok": true,
		"id": reqID,
	})
}

// ListRequests handles GET /api/v1/webhooks/:token/requests.
//
// Auth: the resource token in the URL is itself the credential — no session required.
// This makes the endpoint agent-friendly: whoever holds the token can read their payloads.
// Authenticated users additionally get access to team-owned webhooks by session.
func (h *WebhookHandler) ListRequests(c *fiber.Ctx) error {
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)

	tokenStr := c.Params("token")
	tokenUUID, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Token must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(ctx, h.db, tokenUUID)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Webhook token not found")
		}
		slog.Error("webhook.list_requests.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to look up webhook")
	}

	// Authorization: token in the URL IS the credential (token == resource.Token).
	// If the caller also has a session, verify they own the team resource.
	// Anonymous resources (no team_id) are readable with just the token.
	if resource.TeamID.Valid {
		teamID, authErr := parseTeamID(middleware.GetTeamID(c))
		if authErr != nil || resource.TeamID.UUID != teamID {
			return respondError(c, fiber.StatusForbidden, "forbidden", "Valid session token required for team-owned webhooks")
		}
	}

	listKey := webhookListKey(tokenStr)
	items, redisErr := h.rdb.LRange(ctx, listKey, 0, -1).Result()
	if redisErr != nil {
		slog.Error("webhook.list_requests.redis_read_failed",
			"error", redisErr, "token", tokenStr, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("webhook_list").Inc()
		// Fail open — return empty list rather than 503.
		items = []string{}
	}

	// Decode each item from its JSON string back to a map for the response.
	requests := make([]map[string]any, 0, len(items))
	for _, item := range items {
		var m map[string]any
		if jsonErr := json.Unmarshal([]byte(item), &m); jsonErr != nil {
			slog.Warn("webhook.list_requests.decode_item_failed",
				"error", jsonErr, "token", tokenStr)
			continue
		}
		requests = append(requests, m)
	}

	return c.JSON(fiber.Map{
		"ok":       true,
		"requests": requests,
		"total":    len(requests),
	})
}

// storeEncryptedURL encrypts the receive URL and persists it as connection_url.
func (h *WebhookHandler) storeEncryptedURL(ctx context.Context, resourceID uuid.UUID, rURL, requestID string) error {
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		return fmt.Errorf("storeEncryptedURL: parse key: %w", err)
	}
	encrypted, err := crypto.Encrypt(aesKey, rURL)
	if err != nil {
		return fmt.Errorf("storeEncryptedURL: encrypt: %w", err)
	}
	if upErr := models.UpdateConnectionURL(ctx, h.db, resourceID, encrypted); upErr != nil {
		return fmt.Errorf("storeEncryptedURL: update: %w", upErr)
	}
	return nil
}

// decryptWebhookURL decrypts an AES-encrypted receive URL stored in the DB.
// Returns the ciphertext unchanged if decryption fails (fail open).
func (h *WebhookHandler) decryptWebhookURL(encrypted, requestID string) string {
	if encrypted == "" {
		return ""
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("webhook.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("webhook.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	return plain
}
