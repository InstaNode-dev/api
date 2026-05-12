package handlers

// nosql.go — POST /nosql/new — MongoDB provisioning (Phase 4).
//
// Uses internal/providers/nosql to create an isolated MongoDB database and user
// for each provisioned token. Local backend connects to the cluster MongoDB instance.

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/urls"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	nosqlprovider "instant.dev/internal/providers/nosql"
	"instant.dev/internal/quota"
)

// NoSQLHandler handles POST /nosql/new — MongoDB provisioning.
type NoSQLHandler struct {
	provisionHelper
	nosqlProvider *nosqlprovider.Provider // non-nil when PROVISIONER_ADDR is unset
	provClient    *provisioner.Client     // non-nil when PROVISIONER_ADDR is set
}

// NewNoSQLHandler constructs a NoSQLHandler.
func NewNoSQLHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, provClient *provisioner.Client, reg *plans.Registry) *NoSQLHandler {
	h := &NoSQLHandler{
		provisionHelper: newProvisionHelper(db, rdb, cfg, reg),
		provClient:      provClient,
	}
	if provClient == nil {
		// fall back to local provider
		h.nosqlProvider = nosqlprovider.New(cfg.MongoAdminURI, cfg.MongoHost)
	}
	return h
}

// provisionNoSQL provisions a MongoDB database, using gRPC provisioner if available,
// falling back to local provider otherwise.
func (h *NoSQLHandler) provisionNoSQL(ctx context.Context, token, tier string) (*nosqlprovider.Credentials, error) {
	if h.provClient != nil {
		creds, err := h.provClient.ProvisionNoSQL(ctx, token, tier)
		if err != nil {
			return nil, err
		}
		return &nosqlprovider.Credentials{
			URL:                creds.URL,
			DatabaseName:       creds.DatabaseName,
			ProviderResourceID: creds.ProviderResourceID,
		}, nil
	}
	return h.nosqlProvider.Provision(ctx, token, tier)
}

// NewNoSQL handles POST /nosql/new.
func (h *NoSQLHandler) NewNoSQL(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("mongodb") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"MongoDB provisioning is coming in Phase 4. Sign up at "+urls.StartURLPrefix+" to be notified.")
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
		return h.newNoSQLAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, body.Dedicated, env, body.ParentResourceID, start)
	}

	// Anonymous callers cannot family-link.
	if body.ParentResourceID != "" {
		return respondError(c, fiber.StatusPaymentRequired, "auth_required",
			"parent_resource_id requires an authenticated team. Sign up at "+urls.StartURLPrefix)
	}

	// ── Dedicated requires authentication ─────────────────────────────────────
	if body.Dedicated {
		return respondError(c, fiber.StatusPaymentRequired, "auth_required",
			"isolated resources require an authenticated team. Sign up at "+urls.StartURLPrefix)
	}

	// ── Anonymous path ─────────────────────────────────────────────────────────
	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("nosql.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "mongodb")
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "mongodb", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("nosql.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = urls.UpgradeStartURL(jwtToken)
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
					"internal_url":   proxiedInternalURL(connectionURL, "mongodb"),
					"tier":           existing.Tier,
					"env":            existing.Env,
					"limits":         nosqlAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
					"upgrade_jwt":    jwtToken,
				})
			}
			// Empty connection_url means provisioning failed mid-flight on the existing
			// resource. Fall through to provision a fresh one rather than returning
			// an unusable response.
			slog.Warn("nosql.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	// Free-tier recycle gate (see provision_helper.go for rationale).
	if h.recycleGate(c, fp, "mongodb") {
		return nil
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "mongodb",
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
		slog.Error("nosql.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision MongoDB resource")
	}

	tokenStr := resource.Token.String()

	// Provision the real MongoDB database and user.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "mongodb", "anonymous", "", fp, tokenStr)
	creds, err := h.provisionNoSQL(provCtx, tokenStr, "anonymous")
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("mongodb", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("mongodb", "grpc_error").Inc()
		slog.Error("nosql.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		// Soft-delete the resource record so limits aren't falsely consumed.
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("nosql.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision MongoDB database")
	}

	// Encrypt and persist the connection URL.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("nosql.new.aes_key_parse_failed", "error", keyErr, "request_id", requestID)
		// Fail open — resource is still usable, URL just won't be stored.
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.URL)
		if encErr != nil {
			slog.Error("nosql.new.encrypt_url_failed", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("nosql.new.update_connection_url_failed", "error", upErr, "request_id", requestID)
			}
		}
	}

	// Persist provider_resource_id (k8s namespace for dedicated MongoDB pods).
	if creds.ProviderResourceID != "" {
		if upErr := models.UpdateProviderResourceID(ctx, h.db, resource.ID, creds.ProviderResourceID); upErr != nil {
			slog.Error("nosql.new.update_provider_resource_id_failed", "error", upErr, "request_id", requestID)
		}
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "mongodb", []string{tokenStr})
	if jwtErr != nil {
		slog.Error("nosql.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("nosql.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = urls.UpgradeStartURL(jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "mongodb",
		"token", tokenStr,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("mongodb", "anonymous").Inc()
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("nosql.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	nosqlStorageLimitMB := h.plans.StorageLimitMB("anonymous", "mongodb")
	_, nosqlStorageExceeded, _ := quota.CheckStorageQuota(ctx, h.db, resource.ID, nosqlStorageLimitMB)

	nosqlResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"internal_url":   proxiedInternalURL(creds.URL, "mongodb"),
		"tier":           "anonymous",
		"env":            resource.Env,
		"limits":         nosqlAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
		"upgrade":        upgradeURL,
		"upgrade_jwt":    jwtToken,
	}
	if nosqlStorageExceeded {
		nosqlResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return c.Status(fiber.StatusCreated).JSON(nosqlResp)
}

func (h *NoSQLHandler) newNoSQLAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, dedicated bool, env, parentResourceID string, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("nosql.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	tier := team.PlanTier
	if dedicated {
		tier = "growth"
	}

	parentRootID, perr := resolveFamilyParent(c, h.db, parentResourceID, teamUUID, models.ResourceTypeMongoDB, env)
	if perr != nil {
		return perr
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     models.ResourceTypeMongoDB,
		Name:             name,
		Tier:             tier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        nil,
		CreatedRequestID: requestID,
		ParentResourceID: parentRootID,
	})
	if err != nil {
		slog.Error("nosql.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision MongoDB resource")
	}

	// Best-effort audit event; failures must never block the provision.
	go func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "mongodb",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>mongodb</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	}()

	tokenStr := resource.Token.String()

	// Provision the real MongoDB database and user.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "mongodb", tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionNoSQL(provCtx, tokenStr, tier)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("mongodb", tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("mongodb", "grpc_error").Inc()
		slog.Error("nosql.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("nosql.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision MongoDB database")
	}

	// Encrypt and persist the connection URL.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("nosql.new.aes_key_parse_failed_auth", "error", keyErr, "request_id", requestID)
	} else {
		encryptedURL, encErr := crypto.Encrypt(aesKey, creds.URL)
		if encErr != nil {
			slog.Error("nosql.new.encrypt_url_failed_auth", "error", encErr, "request_id", requestID)
		} else {
			if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
				slog.Error("nosql.new.update_connection_url_failed_auth", "error", upErr, "request_id", requestID)
			}
		}
	}

	// Persist provider_resource_id (k8s namespace for dedicated MongoDB pods).
	if creds.ProviderResourceID != "" {
		if upErr := models.UpdateProviderResourceID(ctx, h.db, resource.ID, creds.ProviderResourceID); upErr != nil {
			slog.Error("nosql.new.update_provider_resource_id_failed_auth", "error", upErr, "request_id", requestID)
		}
	}

	slog.Info("provision.success",
		"service", "mongodb",
		"token", tokenStr,
		"team_id", teamIDStr,
		"tier", tier,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("mongodb", tier).Inc()

	nosqlAuthStorageLimitMB := h.plans.StorageLimitMB(tier, "mongodb")
	_, nosqlAuthStorageExceeded, _ := quota.CheckStorageQuota(ctx, h.db, resource.ID, nosqlAuthStorageLimitMB)

	nosqlAuthResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          resource.Token.String(),
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"internal_url":   proxiedInternalURL(creds.URL, "mongodb"),
		"tier":           tier,
		"env":            resource.Env,
		"limits": fiber.Map{
			"storage_mb":  nosqlAuthStorageLimitMB,
			"connections": h.plans.ConnectionsLimit(tier, "mongodb"),
		},
	}
	if nosqlAuthStorageExceeded {
		nosqlAuthResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return c.Status(fiber.StatusCreated).JSON(nosqlAuthResp)
}

// decryptConnectionURL decrypts an AES-encrypted connection URL stored in the DB.
// Returns the ciphertext unchanged if decryption fails (fails open — caller must handle).
func (h *NoSQLHandler) decryptConnectionURL(encrypted, requestID string) string {
	if encrypted == "" {
		return ""
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("nosql.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("nosql.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	return plain
}

func nosqlAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb":  5,
		"connections": 2,
		"expires_in":  "24h",
	}
}

// ProvisionForTwin runs the same pipeline as newNoSQLAuthenticated for a
// pre-validated twin input. Mirrors DBHandler.ProvisionForTwin — see the
// doc comment there for the orchestration shape. The twin flow always
// inherits source.Tier (never elevates to growth/dedicated).
func (h *NoSQLHandler) ProvisionForTwin(c *fiber.Ctx, in ProvisionForTwinInput) error {
	ctx := c.UserContext()

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &in.TeamID,
		ResourceType:     models.ResourceTypeMongoDB,
		Name:             in.Name,
		Tier:             in.Tier,
		Env:              in.Env,
		Fingerprint:      in.Fingerprint,
		CloudVendor:      in.CloudVendor,
		CountryCode:      in.CountryCode,
		ExpiresAt:        nil,
		CreatedRequestID: in.RequestID,
		ParentResourceID: in.ParentRootID,
	})
	if err != nil {
		slog.Error("twin.nosql.create_resource_failed",
			"error", err, "team_id", in.TeamID, "env", in.Env, "request_id", in.RequestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to record twin resource")
	}

	go func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       in.TeamID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: models.ResourceTypeMongoDB,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary: "agent provisioned <strong>mongodb</strong> twin <code>" +
				resource.Token.String()[:8] + "</code> in env=<code>" + in.Env + "</code>",
		})
	}()

	tokenStr := resource.Token.String()
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, models.ResourceTypeMongoDB, in.Tier, in.TeamID.String(), in.Fingerprint, tokenStr)
	creds, err := h.provisionNoSQL(provCtx, tokenStr, in.Tier)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues(models.ResourceTypeMongoDB, in.Tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues(models.ResourceTypeMongoDB, "grpc_error").Inc()
		slog.Error("twin.nosql.provision_failed",
			"error", err, "token", tokenStr, "team_id", in.TeamID, "request_id", in.RequestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("twin.nosql.soft_delete_failed",
				"error", delErr, "resource_id", resource.ID, "request_id", in.RequestID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision MongoDB twin")
	}

	if aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey); keyErr != nil {
		slog.Error("twin.nosql.aes_key_parse_failed", "error", keyErr, "request_id", in.RequestID)
	} else if encryptedURL, encErr := crypto.Encrypt(aesKey, creds.URL); encErr != nil {
		slog.Error("twin.nosql.encrypt_url_failed", "error", encErr, "request_id", in.RequestID)
	} else if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
		slog.Error("twin.nosql.update_connection_url_failed", "error", upErr, "request_id", in.RequestID)
	}

	if creds.ProviderResourceID != "" {
		if upErr := models.UpdateProviderResourceID(ctx, h.db, resource.ID, creds.ProviderResourceID); upErr != nil {
			slog.Error("twin.nosql.update_provider_resource_id_failed", "error", upErr, "request_id", in.RequestID)
		}
	}

	slog.Info("twin.provision.success",
		"service", models.ResourceTypeMongoDB,
		"token", tokenStr,
		"team_id", in.TeamID,
		"tier", in.Tier,
		"env", in.Env,
		"family_root_id", in.ParentRootID,
		"duration_ms", time.Since(in.Start).Milliseconds(),
		"request_id", in.RequestID,
	)
	metrics.ProvisionsTotal.WithLabelValues(models.ResourceTypeMongoDB, in.Tier).Inc()

	storageLimitMB := h.plans.StorageLimitMB(in.Tier, models.ResourceTypeMongoDB)
	_, storageExceeded, _ := quota.CheckStorageQuota(ctx, h.db, resource.ID, storageLimitMB)

	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"internal_url":   proxiedInternalURL(creds.URL, models.ResourceTypeMongoDB),
		"tier":           in.Tier,
		"env":            resource.Env,
		"family_root_id": derefUUID(in.ParentRootID),
		"limits": fiber.Map{
			"storage_mb":  storageLimitMB,
			"connections": h.plans.ConnectionsLimit(in.Tier, models.ResourceTypeMongoDB),
		},
	}
	if storageExceeded {
		resp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return c.Status(fiber.StatusCreated).JSON(resp)
}
