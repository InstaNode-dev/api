package handlers

// cache.go — POST /cache/new — Redis cache provisioning (Phase 3).
//
// Uses internal/providers/cache to create a namespaced Redis "database" for each
// provisioned token. Local backend attempts ACL isolation (Redis 6+) and falls
// back to key-namespace isolation.

import (
	"context"
	"database/sql"
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
	"instant.dev/internal/provisioner"
	cacheprovider "instant.dev/internal/providers/cache"
	"instant.dev/internal/quota"
)

// CacheHandler handles POST /cache/new — Redis provisioning.
type CacheHandler struct {
	provisionHelper
	cacheProvider *cacheprovider.Provider // non-nil when PROVISIONER_ADDR is unset
	provClient    *provisioner.Client     // non-nil when PROVISIONER_ADDR is set
}

// NewCacheHandler constructs a CacheHandler.
func NewCacheHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, provClient *provisioner.Client, reg *plans.Registry) *CacheHandler {
	h := &CacheHandler{
		provisionHelper: newProvisionHelper(db, rdb, cfg, reg),
		provClient:      provClient,
	}
	if provClient == nil {
		// fall back to local provider
		h.cacheProvider = cacheprovider.New(rdb, cfg.RedisProvisionBackend, cfg.RedisProvisionHost)
	}
	return h
}

// provisionCache provisions a Redis cache, using gRPC provisioner if available,
// falling back to local provider otherwise.
func (h *CacheHandler) provisionCache(ctx context.Context, token, tier string) (*cacheprovider.Credentials, error) {
	if h.provClient != nil {
		creds, err := h.provClient.ProvisionCache(ctx, token, tier)
		if err != nil {
			return nil, err
		}
		return &cacheprovider.Credentials{
			URL:                creds.URL,
			KeyPrefix:          creds.KeyPrefix,
			ProviderResourceID: creds.ProviderResourceID,
		}, nil
	}
	return h.cacheProvider.Provision(ctx, token, tier)
}

// NewCache handles POST /cache/new.
func (h *CacheHandler) NewCache(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("redis") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Redis provisioning is coming in Phase 3. Sign up at https://instant.dev/start to be notified.")
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

	// ── Authenticated path ────────────────────────────────────────────────────
	if teamIDStr := middleware.GetTeamID(c); teamIDStr != "" {
		return h.newCacheAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, body.Dedicated, env, start)
	}

	// ── Dedicated requires authentication ─────────────────────────────────────
	if body.Dedicated {
		return respondError(c, fiber.StatusPaymentRequired, "auth_required",
			"isolated resources require an authenticated team. Sign up at https://instant.dev/start")
	}

	// ── Anonymous path ─────────────────────────────────────────────────────────
	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("cache.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "redis")
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "redis", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("cache.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
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
				dedupResp := fiber.Map{
					"ok":             true,
					"id":             existing.ID.String(),
					"token":          existing.Token.String(),
					"name":           existing.Name.String,
					"connection_url": connectionURL,
					"internal_url":   proxiedInternalURL(connectionURL, "redis"),
					"tier":           existing.Tier,
					"env":            existing.Env,
					"limits":         cacheAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
				}
				if existing.KeyPrefix.String != "" {
					dedupResp["key_prefix"] = existing.KeyPrefix.String
				}
				return c.JSON(dedupResp)
			}
			// Empty connection_url means provisioning failed mid-flight on the existing
			// resource. Fall through to provision a fresh one rather than returning
			// an unusable response.
			slog.Warn("cache.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "redis",
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
		slog.Error("cache.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision Redis resource")
	}

	tokenStr := resource.Token.String()

	// Provision the real Redis namespace.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "redis", "anonymous", "", fp, tokenStr)
	creds, err := h.provisionCache(provCtx, tokenStr, "anonymous")
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("redis", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("redis", "grpc_error").Inc()
		slog.Error("cache.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		// Soft-delete the resource record so limits aren't falsely consumed.
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("cache.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision Redis namespace")
	}

	// Persist the key_prefix so the dedup path can return the correct ACL namespace.
	if creds.KeyPrefix != "" {
		if kpErr := models.UpdateKeyPrefix(ctx, h.db, resource.ID, creds.KeyPrefix); kpErr != nil {
			slog.Error("cache.new.update_key_prefix_failed", "error", kpErr, "request_id", requestID)
		}
	}

	// Encrypt and persist the connection URL.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("cache.new.aes_key_parse_failed", "error", keyErr, "request_id", requestID)
		// Fail open — resource is still usable, URL just won't be stored.
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.URL)
		if encErr != nil {
			slog.Error("cache.new.encrypt_url_failed", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("cache.new.update_connection_url_failed", "error", upErr, "request_id", requestID)
			}
		}
	}

	// Persist provider_resource_id (k8s namespace for dedicated Redis pods).
	if creds.ProviderResourceID != "" {
		if upErr := models.UpdateProviderResourceID(ctx, h.db, resource.ID, creds.ProviderResourceID); upErr != nil {
			slog.Error("cache.new.update_provider_resource_id_failed", "error", upErr, "request_id", requestID)
		}
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "redis", []string{tokenStr})
	if jwtErr != nil {
		slog.Error("cache.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("cache.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = fmt.Sprintf("https://instant.dev/start?t=%s", jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "redis",
		"token", tokenStr,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("redis", "anonymous").Inc()
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	cacheStorageLimitMB := h.plans.StorageLimitMB("anonymous", "redis")
	_, cacheStorageExceeded, _ := quota.CheckStorageQuota(ctx, h.db, resource.ID, cacheStorageLimitMB)

	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"internal_url":   proxiedInternalURL(creds.URL, "redis"),
		"tier":           "anonymous",
		"env":            resource.Env,
		"limits":         cacheAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
	}
	if creds.KeyPrefix != "" {
		resp["key_prefix"] = creds.KeyPrefix
	}
	if cacheStorageExceeded {
		resp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *CacheHandler) newCacheAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, dedicated bool, env string, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("cache.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	tier := team.PlanTier
	if dedicated {
		tier = "growth"
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     "redis",
		Name:             name,
		Tier:             tier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        nil,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("cache.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision Redis resource")
	}

	// Best-effort audit event; failures must never block the provision.
	go func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "redis",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>redis</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	}()

	tokenStr := resource.Token.String()

	// Provision the real Redis namespace.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "redis", tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionCache(provCtx, tokenStr, tier)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("redis", tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("redis", "grpc_error").Inc()
		slog.Error("cache.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("cache.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision Redis namespace")
	}

	// Persist the key_prefix so the dedup path can return the correct ACL namespace.
	if creds.KeyPrefix != "" {
		if kpErr := models.UpdateKeyPrefix(ctx, h.db, resource.ID, creds.KeyPrefix); kpErr != nil {
			slog.Error("cache.new.update_key_prefix_failed_auth", "error", kpErr, "request_id", requestID)
		}
	}

	// Encrypt and persist the connection URL.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("cache.new.aes_key_parse_failed_auth", "error", keyErr, "request_id", requestID)
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.URL)
		if encErr != nil {
			slog.Error("cache.new.encrypt_url_failed_auth", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("cache.new.update_connection_url_failed_auth", "error", upErr, "request_id", requestID)
			}
		}
	}

	// Persist provider_resource_id (k8s namespace for dedicated Redis pods).
	if creds.ProviderResourceID != "" {
		if upErr := models.UpdateProviderResourceID(ctx, h.db, resource.ID, creds.ProviderResourceID); upErr != nil {
			slog.Error("cache.new.update_provider_resource_id_failed_auth", "error", upErr, "request_id", requestID)
		}
	}

	slog.Info("provision.success",
		"service", "redis",
		"token", tokenStr,
		"team_id", teamIDStr,
		"tier", tier,
		"dedicated", dedicated,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("redis", tier).Inc()

	cacheAuthStorageLimitMB := h.plans.StorageLimitMB(tier, "redis")
	_, cacheAuthStorageExceeded, _ := quota.CheckStorageQuota(ctx, h.db, resource.ID, cacheAuthStorageLimitMB)

	authResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"internal_url":   proxiedInternalURL(creds.URL, "redis"),
		"tier":           tier,
		"env":            resource.Env,
		"dedicated":      dedicated,
		"limits": fiber.Map{
			"memory_mb": cacheAuthStorageLimitMB,
		},
	}
	if creds.KeyPrefix != "" {
		authResp["key_prefix"] = creds.KeyPrefix
	}
	if cacheAuthStorageExceeded {
		authResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return c.Status(fiber.StatusCreated).JSON(authResp)
}

// decryptConnectionURL decrypts an AES-encrypted connection URL stored in the DB.
// Returns the ciphertext unchanged if decryption fails (fails open — caller must handle).
func (h *CacheHandler) decryptConnectionURL(encrypted, requestID string) string {
	if encrypted == "" {
		return ""
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("cache.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("cache.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	return plain
}

func cacheAnonymousLimits() fiber.Map {
	return fiber.Map{
		"memory_mb":  5,
		"expires_in": "24h",
	}
}
