package handlers

// storage.go — POST /storage/new — Cloudflare R2 (S3-compatible) storage provisioning (Phase 5).
//
// Uses internal/providers/storage to generate S3-compatible credentials scoped to a
// per-token prefix within a shared R2 bucket. The local provider generates credentials
// without contacting R2 at provision time — same pattern as queue (NATS).
//
// Response shape:
//
//	{
//	  "ok":                true,
//	  "id":                "<resource-uuid>",
//	  "token":             "<token-uuid>",
//	  "name":              "my-storage",
//	  "connection_url":    "https://r2.instant.dev/abc12345/",
//	  "access_key_id":     "key_abc12345",
//	  "secret_access_key": "<32-hex-chars>",
//	  "prefix":            "abc12345/",
//	  "tier":              "anonymous",
//	  "limits":            { "storage_mb": 1024, "expires_in": "24h" },
//	  "note":              "Works now. Free forever with a free account: <url>",
//	  "upgrade":           "<upgrade-url>",
//	  "expires_at":        "<RFC3339>"    // anonymous only
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
	storageprovider "instant.dev/internal/providers/storage"
)

// StorageHandler handles POST /storage/new — R2 storage provisioning.
type StorageHandler struct {
	provisionHelper
	storageProvider *storageprovider.Provider
}

// NewStorageHandler constructs a StorageHandler.
// When storageProvider is nil, it is auto-initialized from cfg:
//   - MinioEndpoint set → use MinIO (local dev)
//   - R2APIToken set  → use R2 (production, not yet implemented in local.go)
//   - Neither set     → provider stays nil; handler returns 503
func NewStorageHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, storageProvider *storageprovider.Provider, reg *plans.Registry) *StorageHandler {
	h := &StorageHandler{
		provisionHelper: newProvisionHelper(db, rdb, cfg, reg),
	}
	if storageProvider != nil {
		h.storageProvider = storageProvider
	} else if cfg.MinioEndpoint != "" {
		sp, err := storageprovider.New(cfg.MinioEndpoint, cfg.MinioRootUser, cfg.MinioRootPassword, cfg.MinioBucketName)
		if err != nil {
			slog.Warn("storage: MinIO provider init failed — /storage/new will return 503", "error", err)
		} else {
			h.storageProvider = sp
		}
	}
	return h
}

// provisionStorage provisions R2 credentials using the local provider.
func (h *StorageHandler) provisionStorage(ctx context.Context, token, tier string) (*storageprovider.Credentials, error) {
	return h.storageProvider.Provision(ctx, token, tier)
}

// NewStorage handles POST /storage/new.
func (h *StorageHandler) NewStorage(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("storage") || h.storageProvider == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Object storage is not configured. Set MINIO_ENDPOINT for local dev or R2_API_TOKEN for production.")
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
		return h.newStorageAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, start)
	}

	// ── Anonymous path ─────────────────────────────────────────────────────────
	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("storage.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "storage")
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "storage", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("storage.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = fmt.Sprintf("https://instant.dev/start?t=%s", jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			metrics.FingerprintAbuseBlocked.Inc()

			// Decrypt the stored connection_url to return it in plaintext.
			connectionURL := h.decryptStorageURL(existing.ConnectionURL.String, requestID)

			return c.JSON(fiber.Map{
				"ok":             true,
				"id":             existing.ID.String(),
				"token":          existing.Token.String(),
				"name":           existing.Name.String,
				"connection_url": connectionURL,
				"tier":           existing.Tier,
				"limits":         h.storageAnonymousLimits(),
				"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
				"upgrade":        upgradeURL,
			})
		}
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "storage",
		Name:             body.Name,
		Tier:             "anonymous",
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        &expiresAt,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("storage.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision storage resource")
	}

	tokenStr := resource.Token.String()

	// Provision R2 credentials.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "storage", "anonymous", "", fp, tokenStr)
	creds, err := h.provisionStorage(provCtx, tokenStr, "anonymous")
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("storage", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("storage", "grpc_error").Inc()
		slog.Error("storage.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		// Soft-delete the resource record so limits aren't falsely consumed.
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("storage.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision R2 storage credentials")
	}

	// Encrypt and persist the connection URL (BucketURL).
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("storage.new.aes_key_parse_failed", "error", keyErr, "request_id", requestID)
		// Fail open — resource is still usable, URL just won't be stored.
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.BucketURL)
		if encErr != nil {
			slog.Error("storage.new.encrypt_url_failed", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("storage.new.update_connection_url_failed", "error", upErr, "request_id", requestID)
			}
		}
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "storage", []string{tokenStr})
	if jwtErr != nil {
		slog.Error("storage.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("storage.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = fmt.Sprintf("https://instant.dev/start?t=%s", jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "storage",
		"token", tokenStr,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("storage", "anonymous").Inc()
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":                true,
		"id":                resource.ID.String(),
		"token":             tokenStr,
		"name":              resource.Name.String,
		"connection_url":    creds.BucketURL,
		"endpoint":          creds.Endpoint,
		"access_key_id":     creds.AccessKeyID,
		"secret_access_key": creds.SecretAccessKey,
		"prefix":            creds.Prefix,
		"tier":              "anonymous",
		"limits":            h.storageAnonymousLimits(),
		"note":              upgradeNote(upgradeURL),
		"upgrade":           upgradeURL,
		"expires_at":        expiresAt.Format(time.RFC3339),
	})
}

func (h *StorageHandler) newStorageAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("storage.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	// Check storage quota before provisioning.
	storageLimitMB := h.plans.StorageLimitMB(team.PlanTier, "storage")
	if storageLimitMB > 0 {
		usedBytes, quotaErr := models.SumStorageBytesByTeamAndType(ctx, h.db, teamUUID, "storage")
		if quotaErr != nil {
			slog.Error("storage.new.quota_check_failed", "error", quotaErr, "team_id", teamIDStr)
			// Fail open — quota check error never blocks provisioning
		} else {
			limitBytes := int64(storageLimitMB) * 1024 * 1024
			if usedBytes >= limitBytes {
				return respondError(c, fiber.StatusPaymentRequired, "storage_limit_reached",
					fmt.Sprintf("Storage limit reached (%dMB). Upgrade your plan.", storageLimitMB))
			}
		}
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     "storage",
		Name:             name,
		Tier:             team.PlanTier,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        nil,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("storage.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision storage resource")
	}

	tokenStr := resource.Token.String()

	// Provision R2 credentials.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "storage", team.PlanTier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionStorage(provCtx, tokenStr, team.PlanTier)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("storage", team.PlanTier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("storage", "grpc_error").Inc()
		slog.Error("storage.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("storage.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision R2 storage credentials")
	}

	// Encrypt and persist the connection URL.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("storage.new.aes_key_parse_failed_auth", "error", keyErr, "request_id", requestID)
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.BucketURL)
		if encErr != nil {
			slog.Error("storage.new.encrypt_url_failed_auth", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("storage.new.update_connection_url_failed_auth", "error", upErr, "request_id", requestID)
			}
		}
	}

	slog.Info("provision.success",
		"service", "storage",
		"token", tokenStr,
		"team_id", teamIDStr,
		"tier", team.PlanTier,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("storage", team.PlanTier).Inc()

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":                true,
		"id":                resource.ID.String(),
		"token":             resource.Token.String(),
		"name":              resource.Name.String,
		"connection_url":    creds.BucketURL,
		"endpoint":          creds.Endpoint,
		"access_key_id":     creds.AccessKeyID,
		"secret_access_key": creds.SecretAccessKey,
		"prefix":            creds.Prefix,
		"tier":              team.PlanTier,
		"limits": fiber.Map{
			"storage_mb": h.plans.StorageLimitMB(team.PlanTier, "storage"),
		},
	})
}

// decryptStorageURL decrypts an AES-encrypted connection URL stored in the DB.
// Returns the ciphertext unchanged if decryption fails (fails open — caller must handle).
func (h *StorageHandler) decryptStorageURL(encrypted, requestID string) string {
	if encrypted == "" {
		return ""
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("storage.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("storage.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	return plain
}

func (h *StorageHandler) storageAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb": h.plans.StorageLimitMB("anonymous", "storage"),
		"expires_in": "24h",
	}
}
