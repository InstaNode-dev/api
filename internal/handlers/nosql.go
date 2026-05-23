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
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	nosqlprovider "instant.dev/internal/providers/nosql"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
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
// teamID scopes the dedicated namespace label — pass empty for anonymous provisions.
func (h *NoSQLHandler) provisionNoSQL(ctx context.Context, token, tier, teamID string) (*nosqlprovider.Credentials, error) {
	if h.provClient != nil {
		creds, err := h.provClient.ProvisionNoSQL(ctx, token, tier, teamID)
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
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "mongodb", env)
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
			return h.denyProvisionOverCap(c, fp, "mongodb")
		}
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
			// T1 P1-5 (BugHunt 2026-05-20): fail-closed — see db.go.
			connectionURL, ok := h.decryptConnectionURL(existing.ConnectionURL.String, requestID)
			if !ok {
				slog.Warn("nosql.new.dedup_decrypt_failed — provisioning fresh",
					"token", existing.Token, "request_id", requestID)
			} else if connectionURL != "" {
				metrics.FingerprintAbuseBlocked.Inc()
				// internal_url omitted on the anonymous dedup path — see
				// internal_url.go (W11 scrub).
				dedupResp := fiber.Map{
					"ok":             true,
					"id":             existing.ID.String(),
					"token":          existing.Token.String(),
					"name":           existing.Name.String,
					"connection_url": connectionURL,
					"tier":           existing.Tier,
					"env":            existing.Env,
					"limits":         h.nosqlAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
					"upgrade_jwt":    jwtToken,
				}
				setInternalURL(dedupResp, existing.Tier, connectionURL, "mongodb")
				return respondOK(c, dedupResp)
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
	creds, err := h.provisionNoSQL(provCtx, tokenStr, "anonymous", "") // no teamID for anonymous
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("mongodb", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("mongodb", "grpc_error").Inc()
		middleware.RecordProvisionFail("mongodb", middleware.ProvisionFailBackendUnavailable)
		slog.Error("nosql.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		// Soft-delete the resource record so limits aren't falsely consumed.
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("nosql.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision MongoDB database")
	}

	// MR-P0-2 / MR-P0-3: persist connection URL + PRID and flip the row
	// pending→active. Any persistence failure tears down the backend Mongo
	// database and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "nosql.new",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "mongodb", "nosql.new") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("mongodb", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist MongoDB resource")
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
		"name", resource.Name.String,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("mongodb", "anonymous").Inc()
	middleware.RecordProvisionSuccess("mongodb")
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("nosql.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	nosqlStorageLimitMB := h.plans.StorageLimitMB("anonymous", "mongodb")
	_, nosqlStorageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, nosqlStorageLimitMB)

	// internal_url omitted on the anonymous path — see internal_url.go.
	nosqlResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"tier":           "anonymous",
		"env":            resource.Env,
		"limits":         h.nosqlAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
		"upgrade":        upgradeURL,
		"upgrade_jwt":    jwtToken,
	}
	// T19 P0-2 (BugHunt 2026-05-20): emit top-level expires_at for
	// shape parity with storage/webhook responses; see db.go for rationale.
	if resource.ExpiresAt.Valid {
		nosqlResp["expires_at"] = resource.ExpiresAt.Time.Format(time.RFC3339)
	}
	if nosqlStorageExceeded {
		nosqlResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, nosqlResp)
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
		if !h.plans.IsDedicatedTier(team.PlanTier) {
			metrics.DedicatedTierUpgradeBlocked.WithLabelValues("nosql", team.PlanTier).Inc()
			return respondError(c, fiber.StatusPaymentRequired, "upgrade_required",
				"Isolated (dedicated) resources require a Growth plan. Upgrade at "+urls.StartURLPrefix)
		}
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
	safego.Go("nosql.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "mongodb",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>mongodb</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	})

	tokenStr := resource.Token.String()

	// Provision the real MongoDB database and user.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "mongodb", tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionNoSQL(provCtx, tokenStr, tier, teamIDStr)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("mongodb", tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("mongodb", "grpc_error").Inc()
		middleware.RecordProvisionFail("mongodb", middleware.ProvisionFailBackendUnavailable)
		slog.Error("nosql.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("nosql.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision MongoDB database")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend Mongo database and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "nosql.new.auth",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "mongodb", "nosql.new.auth") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("mongodb", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist MongoDB resource")
	}

	slog.Info("provision.success",
		"service", "mongodb",
		"token", tokenStr,
		"name", resource.Name.String,
		"team_id", teamIDStr,
		"tier", tier,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("mongodb", tier).Inc()
	middleware.RecordProvisionSuccess("mongodb")

	nosqlAuthStorageLimitMB := h.plans.StorageLimitMB(tier, "mongodb")
	_, nosqlAuthStorageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, nosqlAuthStorageLimitMB)

	nosqlAuthResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          resource.Token.String(),
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"tier":           tier,
		"env":            resource.Env,
		"limits": fiber.Map{
			"storage_mb": nosqlAuthStorageLimitMB,
			// P1-D (2026-05-17): MongoDB has no per-user connection cap and the
			// platform enforces none — advertising connections as a per-token
			// guarantee was a false promise. Surface it as informational only,
			// mirroring nosqlAnonymousLimits' connections_note: the figure is the
			// nominal tier allowance, but the underlying MongoDB pod is
			// shared-tenant, so the real ceiling is your share of the pod's
			// pool, not an enforced per-token limit.
			"connections_informational": h.plans.ConnectionsLimit(tier, "mongodb"),
			"connections_note":          "informational only — MongoDB connections are a shared pod-wide pool, not an enforced per-token cap",
		},
	}
	setInternalURL(nosqlAuthResp, tier, creds.URL, "mongodb")
	if nosqlAuthStorageExceeded {
		nosqlAuthResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, nosqlAuthResp)
}

// decryptConnectionURL decrypts an AES-encrypted connection URL stored
// in the DB. T1 P1-5 (BugHunt 2026-05-20): fail-CLOSED — see db.go.
// (plain, true) / ("", true on empty) / ("", false on decrypt error).
func (h *NoSQLHandler) decryptConnectionURL(encrypted, requestID string) (string, bool) {
	if encrypted == "" {
		return "", true
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("nosql.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return "", false
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("nosql.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return "", false
	}
	return plain, true
}

// nosqlAnonymousLimits returns the limits map for anonymous MongoDB resources.
// storage_mb and connections are read from plans.Registry (convention #3) so a
// plans.yaml edit to the anonymous tier flows through automatically instead of
// drifting against a hardcoded literal — matches dbAnonymousLimits.
func (h *NoSQLHandler) nosqlAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb":  h.plans.StorageLimitMB(tierAnonymous, models.ResourceTypeMongoDB),
		"connections": h.plans.ConnectionsLimit(tierAnonymous, models.ResourceTypeMongoDB),
		// FIX-G (2026-05-14, #167): per-token cap is 2, but the underlying
		// MongoDB pod is shared-tenant and admits up to 20 simultaneous
		// connections across all anonymous tokens (`--maxConns 20` on the
		// statefulset). Surfacing the shared cap lets an agent reading
		// this response avoid the "I asked for 2 and got refused under
		// burst" footgun — under load, your effective per-token ceiling
		// is your share of 20, not the nominal 2.
		"connections_shared_cap_pod": 20,
		"connections_note":           "shared cap up to 20 across all anonymous tokens",
		"expires_in":                 "24h",
	}
}

// ProvisionForTwin runs the same pipeline as newNoSQLAuthenticated for a
// pre-validated twin input. Mirrors DBHandler.ProvisionForTwin — see the
// doc comment there for the orchestration shape. The twin flow always
// inherits source.Tier (never elevates to growth/dedicated).
//
// Delegates to ProvisionForTwinCore (the fiber-free core) so bulk-twin
// can reuse the same pipeline without a fiber.Ctx per row.
func (h *NoSQLHandler) ProvisionForTwin(c *fiber.Ctx, in ProvisionForTwinInput) error {
	ctx := c.UserContext()
	res, err := h.ProvisionForTwinCore(ctx, in)
	if err != nil {
		// T12 P1-1 (BugBash 2026-05-20): use a static message, never err.Error(),
		// to avoid leaking the admin DSN (which contains the admin password) into
		// the response body. Matches the non-twin path's static phrasing.
		return respondProvisionFailed(c, err, "Failed to provision MongoDB database")
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
		"limits": fiber.Map{
			"storage_mb":  res.Limits.StorageMB,
			"connections": res.Limits.Connections,
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
func (h *NoSQLHandler) ProvisionForTwinCore(ctx context.Context, in ProvisionForTwinInput) (TwinProvisionResult, error) {
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
		return TwinProvisionResult{}, twinCoreErr("Failed to record twin resource")
	}

	safego.Go("nosql.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       in.TeamID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: models.ResourceTypeMongoDB,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary: "agent provisioned <strong>mongodb</strong> twin <code>" +
				resource.Token.String()[:8] + "</code> in env=<code>" + in.Env + "</code>",
		})
	})

	tokenStr := resource.Token.String()
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, models.ResourceTypeMongoDB, in.Tier, in.TeamID.String(), in.Fingerprint, tokenStr)
	creds, err := h.provisionNoSQL(provCtx, tokenStr, in.Tier, in.TeamID.String())
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues(models.ResourceTypeMongoDB, in.Tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues(models.ResourceTypeMongoDB, "grpc_error").Inc()
		middleware.RecordProvisionFail(models.ResourceTypeMongoDB, middleware.ProvisionFailBackendUnavailable)
		slog.Error("twin.nosql.provision_failed",
			"error", err, "token", tokenStr, "team_id", in.TeamID, "request_id", in.RequestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("twin.nosql.soft_delete_failed",
				"error", delErr, "resource_id", resource.ID, "request_id", in.RequestID)
		}
		return TwinProvisionResult{}, twinCoreErr("Failed to provision MongoDB twin")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend Mongo database and surfaces a hard error.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, in.RequestID, "twin.nosql",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "mongodb", "twin.nosql") },
	); finErr != nil {
		return TwinProvisionResult{}, twinCoreErr("Failed to persist MongoDB twin")
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
	middleware.RecordProvisionSuccess(models.ResourceTypeMongoDB)

	storageLimitMB := h.plans.StorageLimitMB(in.Tier, models.ResourceTypeMongoDB)
	_, storageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, storageLimitMB)

	return TwinProvisionResult{
		ID:            resource.ID.String(),
		Token:         tokenStr,
		Name:          resource.Name.String,
		ResourceType:  models.ResourceTypeMongoDB,
		ConnectionURL: creds.URL,
		InternalURL:   proxiedInternalURL(creds.URL, models.ResourceTypeMongoDB),
		Tier:          in.Tier,
		Env:           resource.Env,
		FamilyRootID:  derefUUID(in.ParentRootID),
		Limits: TwinResultLimits{
			StorageMB:   storageLimitMB,
			Connections: h.plans.ConnectionsLimit(in.Tier, models.ResourceTypeMongoDB),
		},
		StorageExceeded: storageExceeded,
	}, nil
}
