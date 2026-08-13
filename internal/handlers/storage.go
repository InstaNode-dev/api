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
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
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
		sp, err := storageprovider.New(cfg.MinioEndpoint, cfg.MinioPublicEndpoint, cfg.MinioRootUser, cfg.MinioRootPassword, cfg.MinioBucketName)
		if err != nil {
			slog.Warn("storage: MinIO provider init failed — /storage/new will return 503", "error", err)
		} else {
			h.storageProvider = sp
		}
	}
	return h
}

// provisionStorage provisions storage credentials via the configured backend.
// The capability-aware mode decision (broker vs credential) is made by
// decideStorageMode below; this just calls the underlying provider.
func (h *StorageHandler) provisionStorage(ctx context.Context, token, tier string) (*storageprovider.Credentials, error) {
	return h.storageProvider.Provision(ctx, token, tier)
}

// decideStorageMode is the capability-aware switch from STORAGE-ABSTRACTION-
// DESIGN. Given the live backend's Capabilities() and the tenant's tier, it
// picks ONE of:
//
//   - "credential"       — issue a long-lived (or temp) tenant credential
//                          (PrefixScopedKeys=true backends: R2, S3, MinIO)
//   - "broker"           — no long-lived credential; tenant calls
//                          /storage/:token/presign for short-lived URLs
//                          (PrefixScopedKeys=false backends: DO Spaces, when
//                          tenant tier doesn't qualify for a dedicated bucket)
//   - "dedicated-bucket" — paid-tier on a backend without prefix-scoping but
//                          with BucketPerTenant=true. Reserved; not yet
//                          auto-provisioned (the API skeleton routes these to
//                          broker mode for now).
//
// The DO Spaces master-key behaviour is still reachable as a fallback so
// existing tenants don't break, but it's not selectable by this switch.
func (h *StorageHandler) decideStorageMode(tier string) storageProvisionStrategy {
	if h.storageProvider == nil {
		return storageProvisionStrategy{kind: "unavailable"}
	}
	caps := h.storageProvider.Capabilities()
	switch {
	case caps.PrefixScopedKeys:
		return storageProvisionStrategy{kind: "credential"}
	case caps.BucketPerTenant && isPaidTier(tier):
		// Reserved for the dedicated-bucket-per-paying-tenant flow. For now,
		// fall through to broker mode rather than mint a bucket we don't yet
		// know how to lifecycle. Tracked as a follow-up in CLAUDE.md.
		return storageProvisionStrategy{kind: "broker", reason: "dedicated-bucket-not-yet-wired"}
	default:
		return storageProvisionStrategy{kind: "broker", reason: "backend-has-no-prefix-scoping"}
	}
}

// storageProvisionStrategy carries the decision made by decideStorageMode.
type storageProvisionStrategy struct {
	kind   string // "credential" | "broker" | "unavailable"
	reason string // human-readable note for logs / response when applicable
}

// isPaidTier reports whether a tier qualifies for the dedicated-bucket path.
// Kept narrow on purpose — anonymous/free never qualify; hobby+ do.
func isPaidTier(tier string) bool {
	switch tier {
	case "hobby", "hobby_plus", "pro", "growth", "team",
		"hobby_yearly", "hobby_plus_yearly", "pro_yearly", "team_yearly":
		return true
	}
	return false
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
		return h.newStorageAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, env, start)
	}

	// ── Anonymous path ─────────────────────────────────────────────────────────
	// Recycle gate runs BEFORE the daily-cap check — see db.go API-7 fix.
	if h.recycleGate(c, fp, "storage") {
		return nil
	}

	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("storage.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "storage", env)
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
			return h.denyProvisionOverCap(c, fp, "storage")
		}
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(c, fp, country, vendor, "storage", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("storage.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = urls.UpgradeStartURL(jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			// Decrypt the stored connection_url to return it in plaintext.
			// T1 P1-5 (BugHunt 2026-05-20): fail-closed — see db.go.
			connectionURL, ok := h.decryptStorageURL(existing.ConnectionURL.String, requestID)
			if !ok {
				slog.Warn("storage.new.dedup_decrypt_failed — provisioning fresh",
					"token", existing.Token, "request_id", requestID)
			}

			// P2-04: mirror the db/cache/nosql/queue dedup guard — only return
			// the existing resource when it has a usable connection_url. An
			// empty URL means provisioning failed mid-flight on the existing
			// row; fall through to a fresh provision rather than handing the
			// caller a 200 with an unusable resource.
			if ok && connectionURL != "" {
				metrics.FingerprintAbuseBlocked.Inc()
				dedupResp := fiber.Map{
					"ok":             true,
					"id":             existing.ID.String(),
					"token":          existing.Token.String(),
					"name":           existing.Name.String,
					"connection_url": connectionURL,
					"tier":           existing.Tier,
					"env":            existing.Env,
					"limits":         h.storageAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
					"upgrade_jwt":    jwtToken,
					"claim_url":      upgradeURL, // DOG-21: see db.go
					"expires_at":     existing.ExpiresAt.Time.Format(time.RFC3339),
				}
				// P2-05: the S3 prefix is recoverable from the persisted
				// provider_resource_id, but the secret_access_key is minted
				// once at provision time and never stored — it cannot be
				// re-derived on a dedup hit. Surface the prefix and an
				// explicit note so the caller knows credentials are not
				// re-issued on the rate-limited dedup path.
				if existing.ProviderResourceID.String != "" {
					dedupResp["prefix"] = existing.ProviderResourceID.String + "/"
				}
				// Surface the storage_mode the dedup-hit row is on so the
				// dashboard / caller knows whether to expect a credential or
				// use the presign endpoint. Mode is derived from the live
				// backend's Capabilities() (legacy DO Spaces rows surface as
				// shared-master-key; an R2-backed deployment shows
				// prefix-scoped).
				if h.storageProvider != nil {
					caps := h.storageProvider.Capabilities()
					dedupResp["mode"] = string(storageprovider.DeriveStorageMode(caps, false))
					if !caps.PrefixScopedKeys {
						dedupResp["presign_url"] = "/storage/" + existing.Token.String() + "/presign"
					}
				}
				dedupResp["credentials_note"] = "access_key_id/secret_access_key are issued once at provision time and not re-emitted on a dedup hit — sign up to provision a fresh bucket with credentials"
				// P2-06: use respondOK so the dedup response carries
				// decorateEnvOverride's env_override_reason like every other
				// provision response.
				return respondOK(c, dedupResp)
			}
			// Empty connection_url — provisioning failed mid-flight on the
			// existing resource. Fall through to provision a fresh one.
			slog.Warn("storage.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	// (Recycle gate moved above — see API-7 / QA 2026-05-29 ordering fix.)

	// P1-B: enforce the anonymous-tier storage byte cap. The authenticated path
	// (newStorageAuthenticated) sums SumStorageBytesByTeamAndType vs the tier
	// limit; the anonymous path previously had NO byte check, so the advertised
	// anonymous cap (e.g. 10MB) was unenforced. Scope the sum to the fingerprint
	// (anonymous rows have no team). storage_bytes is worker-populated, so this
	// cap lags real usage by one scanner tick — acceptable for the abuse-defense
	// goal. Fails open on a sum error (CLAUDE.md #1).
	anonStorageLimitMB := h.plans.StorageLimitMB("anonymous", "storage")
	if anonStorageLimitMB > 0 {
		usedBytes, quotaErr := models.SumStorageBytesByFingerprintAndType(ctx, h.db, fp, "storage")
		if quotaErr != nil {
			slog.Error("storage.new.anon_quota_check_failed", "error", quotaErr, "fingerprint", fp, "request_id", requestID)
			// Fail open — quota check error never blocks provisioning.
		} else if usedBytes >= int64(anonStorageLimitMB)*1024*1024 {
			return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired, "storage_limit_reached",
				fmt.Sprintf("Anonymous storage limit reached (%dMB). Sign up for a paid plan to continue.", anonStorageLimitMB),
				newAgentActionStorageLimitReached("anonymous", anonStorageLimitMB),
				DefaultPricingURL)
		}
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "storage",
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
		slog.Error("storage.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision storage resource")
	}

	tokenStr := resource.Token.String()

	// Capability-aware fallback — see STORAGE-ABSTRACTION-DESIGN-2026-05-20.md.
	// DO Spaces today: anon lands in broker mode (no long-lived credential).
	// R2 / S3 / MinIO: anon gets a real prefix-scoped credential.
	strategy := h.decideStorageMode("anonymous")

	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "storage", "anonymous", "", fp, tokenStr)
	creds, err := h.provisionStorage(provCtx, tokenStr, "anonymous")
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("storage", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("storage", "grpc_error").Inc()
		middleware.RecordProvisionFail("storage", middleware.ProvisionFailBackendUnavailable)
		slog.Error("storage.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		if delErr := models.MarkResourceFailed(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("storage.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision storage credentials")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active.
	if finErr := h.finalizeProvision(ctx, resource, creds.BucketURL, "", creds.ProviderResourceID, requestID, "storage.new",
		func() {
			if h.storageProvider != nil {
				if dErr := h.storageProvider.Deprovision(ctx, tokenStr, creds.ProviderResourceID); dErr != nil {
					slog.Warn("storage.new.cleanup_deprovision_failed", "error", dErr, "token", tokenStr)
				}
			}
		},
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("storage", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist storage resource")
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(c, fp, country, vendor, "storage", []string{tokenStr})
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
		upgradeURL = urls.UpgradeStartURL(jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "storage",
		"token", tokenStr,
		"name", resource.Name.String,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"mode", string(creds.StorageMode),
		"strategy", strategy.kind,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("storage", "anonymous").Inc()
	middleware.RecordProvisionSuccess("storage")
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()
	// WS4: per-entity funnel custom event alongside the aggregate counter.
	recordFunnelEvent(ctx, funnelStepProvision, funnelAttrs{Tier: "anonymous", Env: env, Fingerprint: fp})

	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("storage.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	resp := h.buildStorageResponse(strategy, creds, tokenStr, resource, "anonymous")
	resp["note"] = upgradeNote(upgradeURL)
	resp["upgrade"] = upgradeURL
	resp["upgrade_jwt"] = jwtToken
	resp["claim_url"] = upgradeURL // DOG-21: see dedup branch above
	resp["expires_at"] = expiresAt.Format(time.RFC3339)
	resp["limits"] = h.storageAnonymousLimits()
	return respondCreated(c, resp)
}

// buildStorageResponse composes the /storage/new response body. Centralised
// so the broker vs credential branching is in one place; both the anonymous
// and authenticated paths use it.
//
// In broker mode, access_key_id / secret_access_key are OMITTED — the tenant
// uses POST /storage/:token/presign to mint short-lived presigned URLs. The
// agent_action field tells an automated caller how to fetch them.
func (h *StorageHandler) buildStorageResponse(
	strategy storageProvisionStrategy,
	creds *storageprovider.Credentials,
	tokenStr string,
	resource *models.Resource,
	tier string,
) fiber.Map {
	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.BucketURL,
		"endpoint":       creds.Endpoint,
		"prefix":         creds.Prefix,
		"tier":           tier,
		"env":            resource.Env,
		"mode":           string(creds.StorageMode),
	}
	switch strategy.kind {
	case "broker":
		// Override the mode to broker (overrides any derived mode), and omit
		// long-lived credentials. The agent uses /storage/:token/presign to
		// get short-lived URLs.
		resp["mode"] = string(storageprovider.ModeBroker)
		resp["agent_action"] = "use_presign_endpoint"
		resp["presign_url"] = "/storage/" + tokenStr + "/presign"
		resp["broker_reason"] = strategy.reason
		resp["note_isolation"] = "Backend does not enforce s3:prefix at the IAM layer; long-lived keys would let any tenant read others' objects. Use the presign endpoint for short-lived signed URLs instead."
	case "credential":
		resp["access_key_id"] = creds.AccessKeyID
		resp["secret_access_key"] = creds.SecretAccessKey
		if creds.SessionToken != "" {
			resp["session_token"] = creds.SessionToken
		}
	}
	return resp
}

func (h *StorageHandler) newStorageAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, env string, start time.Time,
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
				return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired, "storage_limit_reached",
					fmt.Sprintf("Storage limit reached (%dMB). Upgrade your plan.", storageLimitMB),
					newAgentActionStorageLimitReached(team.PlanTier, storageLimitMB),
					DefaultPricingURL)
			}
		}
	}

	// Task #55: per-tier storage *count* cap (flag-gated, default OFF). This is
	// distinct from the storage-bytes quota above (total bytes across buckets):
	// it caps the NUMBER of storage resources so a tenant can't open many
	// prefix-scoped buckets each near the byte cap. Mirrors queue.go.
	if handled, capErr := h.enforceResourceCountCap(c, teamUUID, team.PlanTier, models.ResourceTypeStorage, requestID); handled {
		return capErr
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     "storage",
		Name:             name,
		Tier:             team.PlanTier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        resourceExpiryForTier(team.PlanTier), // free→24h TTL, paid→permanent (bug bash #4)
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("storage.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision storage resource")
	}

	// Best-effort audit event; failures must never block the provision.
	safego.Go("storage.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "storage",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>storage</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	})

	tokenStr := resource.Token.String()

	// Capability-aware fallback (see STORAGE-ABSTRACTION-DESIGN-2026-05-20.md).
	strategy := h.decideStorageMode(team.PlanTier)

	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "storage", team.PlanTier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionStorage(provCtx, tokenStr, team.PlanTier)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("storage", team.PlanTier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("storage", "grpc_error").Inc()
		middleware.RecordProvisionFail("storage", middleware.ProvisionFailBackendUnavailable)
		slog.Error("storage.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.MarkResourceFailed(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("storage.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision storage credentials")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the bucket prefix and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.BucketURL, "", creds.ProviderResourceID, requestID, "storage.new.auth",
		func() {
			if h.storageProvider != nil {
				if dErr := h.storageProvider.Deprovision(ctx, tokenStr, creds.ProviderResourceID); dErr != nil {
					slog.Warn("storage.new.auth.cleanup_deprovision_failed", "error", dErr, "token", tokenStr)
				}
			}
		},
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("storage", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist storage resource")
	}

	slog.Info("provision.success",
		"service", "storage",
		"token", tokenStr,
		"name", resource.Name.String,
		"team_id", teamIDStr,
		"tier", team.PlanTier,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("storage", team.PlanTier).Inc()
	middleware.RecordProvisionSuccess("storage")

	// In admin-mode the provider just minted a per-tenant IAM user. Surface
	// that as a discrete audit row so compliance can answer "who held this
	// access key at time T?" — distinct from the generic "provision" event
	// already inserted above. Best-effort; an audit failure never blocks
	// the provision. Only emitted when the provider is actually issuing
	// per-tenant keys; shared-key mode reuses the master across all
	// customers and the kind would be misleading.
	// Emit a per-tenant-key audit row only when a credential was actually
	// minted (prefix-scoped backends), so the audit log doesn't lie in
	// broker / shared-master-key mode where no new identity was created.
	if h.storageProvider != nil && creds.StorageMode == storageprovider.ModePrefixScoped {
		safego.Go("storage.iam_audit", func() {
			(func(rid uuid.UUID, accessKey string) {
				_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
					TeamID:       teamUUID,
					Actor:        "system",
					Kind:         models.AuditKindStorageIAMUserCreated,
					ResourceType: "storage",
					ResourceID:   uuid.NullUUID{UUID: rid, Valid: true},
					Summary: "minted per-tenant storage key <code>" +
						accessKey + "</code> for prefix <code>" + creds.Prefix + "</code>",
				})
			})(resource.ID, creds.AccessKeyID)
		})
	}

	resp := h.buildStorageResponse(strategy, creds, resource.Token.String(), resource, team.PlanTier)
	resp["limits"] = fiber.Map{
		"storage_mb": h.plans.StorageLimitMB(team.PlanTier, "storage"),
	}
	return respondCreated(c, resp)
}

// decryptStorageURL decrypts an AES-encrypted connection URL stored
// in the DB. T1 P1-5 (BugHunt 2026-05-20): fail-CLOSED — see db.go.
// (plain, true) / ("", true on empty) / ("", false on decrypt error).
func (h *StorageHandler) decryptStorageURL(encrypted, requestID string) (string, bool) {
	if encrypted == "" {
		return "", true
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("storage.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return "", false
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("storage.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return "", false
	}
	return plain, true
}

func (h *StorageHandler) storageAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb": h.plans.StorageLimitMB("anonymous", "storage"),
		"expires_in": "24h",
	}
}
