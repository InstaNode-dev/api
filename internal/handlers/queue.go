package handlers

// queue.go — POST /queue/new — NATS JetStream provisioning (Phase 4).
//
// Uses internal/providers/queue to generate NATS credentials for each
// provisioned token. The local provider generates username/password credentials
// without contacting the NATS server — credentials are stored encrypted and
// returned to the caller who configures their NATS client directly.
//
// Response shape:
//
//	{
//	  "ok":             true,
//	  "id":             "<resource-uuid>",
//	  "token":          "<token-uuid>",
//	  "name":           "my-queue",
//	  "connection_url": "nats://usr_<prefix>:<pass>@nats.instant-data.svc.cluster.local:4222",
//	  "tier":           "anonymous",
//	  "limits":         { "storage_mb": 1024, "expires_in": "24h" },
//	  "note":           "Works now. Free forever with a free account: <url>"
//	}

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	queueprovider "instant.dev/internal/providers/queue"
)

// QueueHandler handles POST /queue/new — NATS JetStream provisioning.
type QueueHandler struct {
	provisionHelper
	queueProvider *queueprovider.Provider // non-nil when PROVISIONER_ADDR is unset
	provClient    *provisioner.Client     // non-nil when PROVISIONER_ADDR is set (future)
}

// NewQueueHandler constructs a QueueHandler.
func NewQueueHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, provClient *provisioner.Client, reg *plans.Registry) *QueueHandler {
	h := &QueueHandler{
		provisionHelper: newProvisionHelper(db, rdb, cfg, reg),
		provClient:      provClient,
	}
	// Queue provisioning is always handled locally for now — the gRPC provisioner
	// does not yet have a ProvisionQueue RPC. When it does, wire it here like
	// CacheHandler.provisionCache does.
	h.queueProvider = queueprovider.New(cfg.NATSHost)
	return h
}

// provisionQueue provisions NATS credentials.
// Growth, pro, and team tiers use the gRPC provisioner (isolated k8s NATS pod).
// All other tiers use the local provider (shared NATS cluster).
func (h *QueueHandler) provisionQueue(ctx context.Context, token, tier string) (*queueprovider.Credentials, error) {
	if (tier == "pro" || tier == "team" || tier == "growth") && h.provClient != nil {
		creds, err := h.provClient.ProvisionQueue(ctx, token, tier)
		if err != nil {
			return nil, err
		}
		return &queueprovider.Credentials{
			URL:                creds.URL,
			SubjectPrefix:      creds.KeyPrefix,
			ProviderResourceID: creds.ProviderResourceID,
		}, nil
	}
	return h.queueProvider.Provision(ctx, token, tier)
}

// NewQueue handles POST /queue/new.
func (h *QueueHandler) NewQueue(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("queue") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"NATS JetStream provisioning is coming in Phase 4. Sign up at https://instant.dev/start to be notified.")
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

	// ── Authenticated path ────────────────────────────────────────────────────
	if teamIDStr := middleware.GetTeamID(c); teamIDStr != "" {
		return h.newQueueAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, body.Dedicated, start)
	}

	// ── Dedicated requires authentication ─────────────────────────────────────
	if body.Dedicated {
		return respondError(c, fiber.StatusPaymentRequired, "auth_required",
			"isolated resources require an authenticated team. Sign up at https://instant.dev/start")
	}

	// ── Anonymous path ─────────────────────────────────────────────────────────
	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("queue.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "queue")
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "queue", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("queue.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = fmt.Sprintf("https://instant.dev/start?t=%s", jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			// Decrypt the stored connection_url to return it in plaintext.
			connectionURL := h.decryptConnectionURL(existing.ConnectionURL.String, requestID)
			if connectionURL != "" {
				metrics.FingerprintAbuseBlocked.Inc()
				return c.JSON(fiber.Map{
					"ok":             true,
					"id":             existing.ID.String(),
					"token":          existing.Token.String(),
					"name":           existing.Name.String,
					"connection_url": connectionURL,
					"tier":           existing.Tier,
					"limits":         queueAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
				})
			}
			// Empty connection_url means provisioning failed mid-flight on the existing
			// resource. Fall through to provision a fresh one rather than returning
			// an unusable response.
			slog.Warn("queue.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "queue",
		Name:             body.Name,
		Tier:             "anonymous",
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        &expiresAt,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("queue.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision NATS resource")
	}

	tokenStr := resource.Token.String()

	// Provision NATS credentials.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "queue", "anonymous", "", fp, tokenStr)
	creds, err := h.provisionQueue(provCtx, tokenStr, "anonymous")
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("queue", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("queue", "grpc_error").Inc()
		slog.Error("queue.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		// Soft-delete the resource record so limits aren't falsely consumed.
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("queue.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision NATS credentials")
	}

	// Encrypt and persist the connection URL.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("queue.new.aes_key_parse_failed", "error", keyErr, "request_id", requestID)
		// Fail open — resource is still usable, URL just won't be stored.
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.URL)
		if encErr != nil {
			slog.Error("queue.new.encrypt_url_failed", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("queue.new.update_connection_url_failed", "error", upErr, "request_id", requestID)
			}
		}
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "queue", []string{tokenStr})
	if jwtErr != nil {
		slog.Error("queue.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("queue.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = fmt.Sprintf("https://instant.dev/start?t=%s", jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "queue",
		"token", tokenStr,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("queue", "anonymous").Inc()
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"subject_prefix": creds.SubjectPrefix,
		"tier":           "anonymous",
		"limits":         queueAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
	})
}

func (h *QueueHandler) newQueueAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, dedicated bool, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("queue.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	tier := team.PlanTier
	if dedicated {
		tier = "growth"
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     "queue",
		Name:             name,
		Tier:             tier,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        nil,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("queue.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision NATS resource")
	}

	tokenStr := resource.Token.String()

	// Provision NATS credentials.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "queue", tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionQueue(provCtx, tokenStr, tier)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("queue", tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("queue", "grpc_error").Inc()
		slog.Error("queue.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("queue.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision NATS credentials")
	}

	// Encrypt and persist the connection URL.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("queue.new.aes_key_parse_failed_auth", "error", keyErr, "request_id", requestID)
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.URL)
		if encErr != nil {
			slog.Error("queue.new.encrypt_url_failed_auth", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("queue.new.update_connection_url_failed_auth", "error", upErr, "request_id", requestID)
			}
		}
	}

	// Persist provider_resource_id (k8s namespace for dedicated NATS pods).
	if creds.ProviderResourceID != "" {
		if upErr := models.UpdateProviderResourceID(ctx, h.db, resource.ID, creds.ProviderResourceID); upErr != nil {
			slog.Error("queue.new.update_provider_resource_id_failed", "error", upErr, "request_id", requestID)
		}
	}

	slog.Info("provision.success",
		"service", "queue",
		"token", tokenStr,
		"team_id", teamIDStr,
		"tier", tier,
		"dedicated", dedicated,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("queue", tier).Inc()

	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          resource.Token.String(),
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"subject_prefix": creds.SubjectPrefix,
		"tier":           tier,
		"dedicated":      dedicated,
		"limits": fiber.Map{
			"storage_mb": h.plans.StorageLimitMB(tier, "queue"),
		},
	}
	return c.Status(fiber.StatusCreated).JSON(resp)
}

// decryptConnectionURL decrypts an AES-encrypted connection URL stored in the DB.
// Returns the ciphertext unchanged if decryption fails (fails open — caller must handle).
func (h *QueueHandler) decryptConnectionURL(encrypted, requestID string) string {
	if encrypted == "" {
		return ""
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("queue.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("queue.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	return plain
}

func queueAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb": 1024,
		"expires_in": "24h",
	}
}
