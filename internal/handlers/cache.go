package handlers

// cache.go — POST /cache/new — Redis cache provisioning (Phase 3).
//
// Uses internal/providers/cache to create a namespaced Redis "database" for each
// provisioned token. Local backend attempts ACL isolation (Redis 6+) and falls
// back to key-namespace isolation.

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
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	cacheprovider "instant.dev/internal/providers/cache"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
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
// teamID scopes the dedicated namespace label — pass empty for anonymous provisions.
func (h *CacheHandler) provisionCache(ctx context.Context, token, tier, teamID string) (*cacheprovider.Credentials, error) {
	if h.provClient != nil {
		creds, err := h.provClient.ProvisionCache(ctx, token, tier, teamID)
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
			"Redis provisioning is coming in Phase 3. Sign up at "+urls.StartURLPrefix+" to be notified.")
	}

	start := time.Now()
	ctx := c.UserContext()
	fp := middleware.GetFingerprint(c)
	country := middleware.GetGeoCountry(c)
	vendor := middleware.GetCloudVendor(c)
	requestID := middleware.GetRequestID(c)

	var body provisionRequestBody
	if err := parseProvisionBody(c, &body); err != nil {
		return err
	}
	cleanName, nameErr := requireName(c, body.Name)
	if nameErr != nil {
		return nameErr
	}
	body.Name = cleanName

	env, envErr := resolveEnv(c, body.Env)
	if envErr != nil {
		return envErr
	}

	// ── Authenticated path ────────────────────────────────────────────────────
	if teamIDStr := middleware.GetTeamID(c); teamIDStr != "" {
		return h.newCacheAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, body.Dedicated, env, body.ParentResourceID, start)
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
	// Recycle gate runs BEFORE the daily-cap check — see db.go API-7 fix.
	if h.recycleGate(c, fp, "redis") {
		return nil
	}

	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("cache.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "redis", env)
		if err != nil {
			// P1-A: cross-service daily-cap fallback — see db.go for rationale.
			if _, anyErr := models.GetActiveResourceByFingerprint(ctx, h.db, fp, env); anyErr == nil {
				metrics.FingerprintAbuseBlocked.Inc()
				return respondError(c, fiber.StatusTooManyRequests, "provision_limit_reached",
					"Daily anonymous provisioning limit reached for this network. Sign up at "+urls.StartURLPrefix)
			}
			// F2 TOCTOU fix (2026-05-19): over-cap caller, both lookups missed
			// (burst winners not yet committed). Hard-deny — never fall through
			// to a fresh provision. See denyProvisionOverCap for the full rationale.
			return h.denyProvisionOverCap(c, fp, "redis")
		}
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "redis", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("cache.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = urls.UpgradeStartURL(jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			// Decrypt the stored connection_url to return it in plaintext.
			// T1 P1-5 (BugHunt 2026-05-20): fail-closed — see db.go.
			connectionURL, ok := h.decryptConnectionURL(existing.ConnectionURL.String, requestID)
			if !ok {
				slog.Warn("cache.new.dedup_decrypt_failed — provisioning fresh",
					"token", existing.Token, "request_id", requestID)
			} else if connectionURL != "" {
				metrics.FingerprintAbuseBlocked.Inc()
				// internal_url omitted via setInternalURL on the anon dedup
				// path — see internal_url.go for the W11 scrub rationale.
				dedupResp := fiber.Map{
					"ok":             true,
					"id":             existing.ID.String(),
					"token":          existing.Token.String(),
					"name":           existing.Name.String,
					"connection_url": connectionURL,
					"tier":           existing.Tier,
					"env":            existing.Env,
					"limits":         h.cacheAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
					"upgrade_jwt":    jwtToken,
					"claim_url":      upgradeURL, // DOG-21: see db.go
				}
				setInternalURL(dedupResp, existing.Tier, connectionURL, "redis")
				if existing.KeyPrefix.String != "" {
					dedupResp["key_prefix"] = existing.KeyPrefix.String
				}
				return respondOK(c, dedupResp)
			}
			// Empty connection_url means provisioning failed mid-flight on the existing
			// resource. Fall through to provision a fresh one rather than returning
			// an unusable response.
			slog.Warn("cache.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	// (Recycle gate moved above — see API-7 / QA 2026-05-29 ordering fix.)

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
	creds, err := h.provisionCache(provCtx, tokenStr, "anonymous", "") // no teamID for anonymous
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("redis", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("redis", "grpc_error").Inc()
		middleware.RecordProvisionFail("redis", middleware.ProvisionFailBackendUnavailable)
		slog.Error("cache.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		// Soft-delete the resource record so limits aren't falsely consumed.
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("cache.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision Redis namespace")
	}

	// MR-P0-2 / MR-P0-3: persist key_prefix + connection URL + PRID and flip
	// the row pending→active. Any persistence failure tears down the backend
	// Redis namespace and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, creds.KeyPrefix, creds.ProviderResourceID, requestID, "cache.new",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "redis", "cache.new") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("redis", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist Redis resource")
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
		upgradeURL = urls.UpgradeStartURL(jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "redis",
		"token", tokenStr,
		"name", resource.Name.String,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("redis", "anonymous").Inc()
	middleware.RecordProvisionSuccess("redis")
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()
	// WS4: per-entity funnel custom event alongside the aggregate counter.
	recordFunnelEvent(ctx, funnelStepProvision, funnelAttrs{Tier: "anonymous", Env: env, Fingerprint: fp})

	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("cache.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	cacheStorageLimitMB := h.plans.StorageLimitMB("anonymous", "redis")
	_, cacheStorageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, cacheStorageLimitMB)

	// internal_url omitted on the anonymous path — see internal_url.go.
	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"tier":           "anonymous",
		"env":            resource.Env,
		"limits":         h.cacheAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
		"upgrade":        upgradeURL,
		"upgrade_jwt":    jwtToken,
		"claim_url":      upgradeURL, // DOG-21: see dedup branch above
	}
	// T19 P0-2 (BugHunt 2026-05-20): emit top-level expires_at for
	// shape parity with storage/webhook responses; see db.go for rationale.
	if resource.ExpiresAt.Valid {
		resp["expires_at"] = resource.ExpiresAt.Time.Format(time.RFC3339)
	}
	if creds.KeyPrefix != "" {
		resp["key_prefix"] = creds.KeyPrefix
	}
	if cacheStorageExceeded {
		resp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, resp)
}

func (h *CacheHandler) newCacheAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, dedicated bool, env, parentResourceID string, start time.Time,
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
		if !h.plans.IsDedicatedTier(team.PlanTier) {
			metrics.DedicatedTierUpgradeBlocked.WithLabelValues("cache", team.PlanTier).Inc()
			return respondError(c, fiber.StatusPaymentRequired, "upgrade_required",
				"Isolated (dedicated) resources require a Growth plan. Upgrade at "+urls.StartURLPrefix)
		}
		tier = "growth"
	}

	// Task #55: per-tier redis count cap (flag-gated, default OFF). Redis is the
	// binding COGS constraint ($6.50/GB) so this is the most-conservative cap.
	if handled, capErr := h.enforceResourceCountCap(c, teamUUID, team.PlanTier, models.ResourceTypeRedis, requestID); handled {
		return capErr
	}

	parentRootID, perr := resolveFamilyParent(c, h.db, parentResourceID, teamUUID, models.ResourceTypeRedis, env)
	if perr != nil {
		return perr
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     models.ResourceTypeRedis,
		Name:             name,
		Tier:             tier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        resourceExpiryForTier(tier), // free→24h TTL, paid→permanent (bug bash #4)
		CreatedRequestID: requestID,
		ParentResourceID: parentRootID,
	})
	if err != nil {
		slog.Error("cache.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision Redis resource")
	}

	// Best-effort audit event; failures must never block the provision.
	safego.Go("cache.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "redis",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>redis</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	})

	tokenStr := resource.Token.String()

	// Provision the real Redis namespace.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "redis", tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionCache(provCtx, tokenStr, tier, teamIDStr)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("redis", tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("redis", "grpc_error").Inc()
		middleware.RecordProvisionFail("redis", middleware.ProvisionFailBackendUnavailable)
		slog.Error("cache.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("cache.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision Redis namespace")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend Redis namespace and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, creds.KeyPrefix, creds.ProviderResourceID, requestID, "cache.new.auth",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "redis", "cache.new.auth") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("redis", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist Redis resource")
	}

	slog.Info("provision.success",
		"service", "redis",
		"token", tokenStr,
		"name", resource.Name.String,
		"team_id", teamIDStr,
		"tier", tier,
		"dedicated", dedicated,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("redis", tier).Inc()
	middleware.RecordProvisionSuccess("redis")

	cacheAuthStorageLimitMB := h.plans.StorageLimitMB(tier, "redis")
	_, cacheAuthStorageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, cacheAuthStorageLimitMB)

	authResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"tier":           tier,
		"env":            resource.Env,
		"dedicated":      dedicated,
		"limits": fiber.Map{
			"memory_mb": cacheAuthStorageLimitMB,
		},
	}
	setInternalURL(authResp, tier, creds.URL, "redis")
	if creds.KeyPrefix != "" {
		authResp["key_prefix"] = creds.KeyPrefix
	}
	if cacheAuthStorageExceeded {
		authResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, authResp)
}

// decryptConnectionURL decrypts an AES-encrypted connection URL stored
// in the DB. T1 P1-5 (BugHunt 2026-05-20): fail-CLOSED — see db.go for
// rationale. Returns (plain, true) on success, ("", true) for empty
// input, ("", false) on decrypt error. Callers MUST NOT treat a
// (_, false) return as a valid URL — fall through to fresh-provision.
func (h *CacheHandler) decryptConnectionURL(encrypted, requestID string) (string, bool) {
	if encrypted == "" {
		return "", true
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("cache.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return "", false
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("cache.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return "", false
	}
	return plain, true
}

// cacheAnonymousLimits returns the limits map for anonymous Redis resources.
// memory_mb is read from plans.Registry (convention #3) so a plans.yaml edit
// to the anonymous tier flows through automatically instead of drifting
// against a hardcoded literal — matches dbAnonymousLimits/queueAnonymousLimits.
func (h *CacheHandler) cacheAnonymousLimits() fiber.Map {
	return fiber.Map{
		"memory_mb":  h.plans.StorageLimitMB(tierAnonymous, models.ResourceTypeRedis),
		"expires_in": "24h",
	}
}

// ProvisionForTwin runs the same pipeline as newCacheAuthenticated for a
// pre-validated twin input. Mirrors DBHandler.ProvisionForTwin — see the
// doc comment there for the orchestration shape. The twin flow always
// inherits source.Tier (never elevates to growth/dedicated).
//
// Delegates to ProvisionForTwinCore (the fiber-free core) so bulk-twin
// can reuse the same pipeline without a fiber.Ctx per row.
func (h *CacheHandler) ProvisionForTwin(c *fiber.Ctx, in ProvisionForTwinInput) error {
	ctx := c.UserContext()
	res, err := h.ProvisionForTwinCore(ctx, in)
	if err != nil {
		// T12 P1-1 (BugBash 2026-05-20): use a static message, never err.Error(),
		// to avoid leaking the admin DSN (which contains the admin password) into
		// the response body. Matches the non-twin path's static phrasing.
		return respondProvisionFailed(c, err, "Failed to provision Redis namespace")
	}

	resp := fiber.Map{
		"ok":             true,
		"id":             res.ID,
		"token":          res.Token,
		"name":           res.Name,
		"connection_url": res.ConnectionURL,
		"tier":           res.Tier,
		"env":            res.Env,
		"family_root_id": res.FamilyRootID,
		"key_prefix":     res.KeyPrefix,
		"limits": fiber.Map{
			"memory_mb": res.Limits.StorageMB,
		},
	}
	// Twin pipeline requires an authenticated team — res.Tier is never
	// anonymous in practice. Defensive guard preserves the W11 invariant.
	if res.Tier != tierAnonymous && res.InternalURL != "" {
		resp[internalURLResponseKey] = res.InternalURL
	}
	if res.StorageExceeded {
		resp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, resp)
}

// ProvisionForTwinCore is the fiber-free implementation of ProvisionForTwin.
// See DBHandler.ProvisionForTwinCore for the contract.
func (h *CacheHandler) ProvisionForTwinCore(ctx context.Context, in ProvisionForTwinInput) (TwinProvisionResult, error) {
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &in.TeamID,
		ResourceType:     models.ResourceTypeRedis,
		Name:             in.Name,
		Tier:             in.Tier,
		Env:              in.Env,
		Fingerprint:      in.Fingerprint,
		CloudVendor:      in.CloudVendor,
		CountryCode:      in.CountryCode,
		ExpiresAt:        resourceExpiryForTier(in.Tier), // free→24h TTL, paid→permanent (bug bash #4)
		CreatedRequestID: in.RequestID,
		ParentResourceID: in.ParentRootID,
	})
	if err != nil {
		slog.Error("twin.cache.create_resource_failed",
			"error", err, "team_id", in.TeamID, "env", in.Env, "request_id", in.RequestID)
		return TwinProvisionResult{}, twinCoreErr("Failed to record twin resource")
	}

	safego.Go("cache.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       in.TeamID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: models.ResourceTypeRedis,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary: "agent provisioned <strong>redis</strong> twin <code>" +
				resource.Token.String()[:8] + "</code> in env=<code>" + in.Env + "</code>",
		})
	})

	tokenStr := resource.Token.String()
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, models.ResourceTypeRedis, in.Tier, in.TeamID.String(), in.Fingerprint, tokenStr)
	creds, err := h.provisionCache(provCtx, tokenStr, in.Tier, in.TeamID.String())
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues(models.ResourceTypeRedis, in.Tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues(models.ResourceTypeRedis, "grpc_error").Inc()
		middleware.RecordProvisionFail(models.ResourceTypeRedis, middleware.ProvisionFailBackendUnavailable)
		slog.Error("twin.cache.provision_failed",
			"error", err, "token", tokenStr, "team_id", in.TeamID, "request_id", in.RequestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("twin.cache.soft_delete_failed",
				"error", delErr, "resource_id", resource.ID, "request_id", in.RequestID)
		}
		return TwinProvisionResult{}, twinCoreErr("Failed to provision Redis twin")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend Redis namespace and surfaces a hard error.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, creds.KeyPrefix, creds.ProviderResourceID, in.RequestID, "twin.cache",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "redis", "twin.cache") },
	); finErr != nil {
		return TwinProvisionResult{}, twinCoreErr("Failed to persist Redis twin")
	}

	slog.Info("twin.provision.success",
		"service", models.ResourceTypeRedis,
		"token", tokenStr,
		"team_id", in.TeamID,
		"tier", in.Tier,
		"env", in.Env,
		"family_root_id", in.ParentRootID,
		"duration_ms", time.Since(in.Start).Milliseconds(),
		"request_id", in.RequestID,
	)
	metrics.ProvisionsTotal.WithLabelValues(models.ResourceTypeRedis, in.Tier).Inc()
	middleware.RecordProvisionSuccess(models.ResourceTypeRedis)

	storageLimitMB := h.plans.StorageLimitMB(in.Tier, models.ResourceTypeRedis)
	_, storageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, storageLimitMB)

	return TwinProvisionResult{
		ID:            resource.ID.String(),
		Token:         tokenStr,
		Name:          resource.Name.String,
		ResourceType:  models.ResourceTypeRedis,
		ConnectionURL: creds.URL,
		InternalURL:   proxiedInternalURL(creds.URL, models.ResourceTypeRedis),
		Tier:          in.Tier,
		Env:           resource.Env,
		FamilyRootID:  derefUUID(in.ParentRootID),
		KeyPrefix:     creds.KeyPrefix,
		Limits: TwinResultLimits{
			StorageMB: storageLimitMB,
		},
		StorageExceeded: storageExceeded,
	}, nil
}
