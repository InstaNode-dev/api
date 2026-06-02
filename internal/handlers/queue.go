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
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	commonqp "instant.dev/common/queueprovider"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	queueprovider "instant.dev/internal/providers/queue"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
)

// QueueHandler handles POST /queue/new — NATS JetStream provisioning.
type QueueHandler struct {
	provisionHelper
	queueProvider *queueprovider.Provider // non-nil when PROVISIONER_ADDR is unset
	provClient    *provisioner.Client     // non-nil when PROVISIONER_ADDR is set (future)
	// credProvider issues per-tenant credentials via the common/queueprovider
	// abstraction (MR-P0-5 — NATS per-tenant isolation). Returned creds may
	// be AuthMode=isolated (real per-tenant account JWT) or
	// AuthMode=legacy_open (no auth — staged-cutover fallback).
	credProvider commonqp.QueueCredentialProvider
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
	// Build the credential issuer. Falls back to legacy_open when no operator
	// seed is configured so api can deploy before the operator-key generation.
	if cp, err := buildQueueProvider(cfg); err == nil {
		h.credProvider = cp
	} else {
		slog.Error("queue.cred_provider_init_failed_fallback_legacy_open",
			"error", err,
			"backend", cfg.QueueBackend)
		// Defensive: never leave h.credProvider nil. The legacyopen provider
		// is always registered so this fallback always succeeds.
		fallback, _ := commonqp.Factory(commonqp.Config{
			Backend:    "legacy_open",
			Host:       cfg.NATSHost,
			PublicHost: cfg.NATSPublicHost,
			Port:       4222,
			UseTLS:     cfg.NATSUseTLS,
		})
		h.credProvider = fallback
	}
	return h
}

// SetCredProvider swaps the per-tenant credential issuer. Production code
// never calls this — NewQueueHandler resolves the provider from cfg
// (legacy_open by default, nats once the operator seed is configured).
// Coverage tests inject a double here to exercise the isolated-creds and
// creds-issuance-error arms of the handler without standing up a real NATS
// operator + signing keys. Mirrors DeployHandler.SetComputeProvider.
func (h *QueueHandler) SetCredProvider(p commonqp.QueueCredentialProvider) {
	h.credProvider = p
}

// provisionQueue provisions NATS credentials.
// When the gRPC provisioner is configured, every tier uses it — the provisioner
// chooses local vs k8s-dedicated backend based on QUEUE_PROVISION_BACKEND.
// Falls back to the local provider only when no provisioner client is wired.
// teamID scopes the dedicated namespace label — pass empty for anonymous provisions.
func (h *QueueHandler) provisionQueue(ctx context.Context, token, tier, teamID string) (*queueprovider.Credentials, error) {
	if h.provClient != nil {
		creds, err := h.provClient.ProvisionQueue(ctx, token, tier, teamID)
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

// issueTenantCreds asks the common/queueprovider abstraction for a per-tenant
// credential. Returns (nil, nil) when the resolved credential is legacy_open
// (no creds to embed) so the caller can keep the existing response shape;
// returns a populated TenantCreds when isolation is in effect.
//
// MR-P0-5 (2026-05-20): this is the single point where /queue/new transitions
// from "shared unauthenticated NATS" to "per-tenant accounts + signed user
// JWTs". Other backends (rabbitmq, kafka, future) plug in here without
// touching the handler.
func (h *QueueHandler) issueTenantCreds(ctx context.Context, token, subjectPrefix string) (*commonqp.TenantCreds, error) {
	if h.credProvider == nil {
		return nil, nil
	}
	creds, err := h.credProvider.IssueTenantCredentials(ctx, commonqp.IssueRequest{
		ResourceToken: token,
		Subject:       subjectPrefix,
		TTL:           0, // long-lived; the resource row lifetime controls expiry
	})
	if err != nil {
		// Don't fail the provision over creds-issuance — log + return nil and
		// the handler will fall back to the legacy_open response shape. The
		// row will get auth_mode='legacy_open' and the worker reaper will
		// recycle it next sweep.
		metrics.NatsAuthFailures.Inc()
		slog.Error("queue.cred_issue_failed_fallback_legacy_open",
			"error", err,
			"token", token,
			"backend", h.credProvider.Name())
		return nil, err
	}
	return creds, nil
}

// NewQueue handles POST /queue/new.
func (h *QueueHandler) NewQueue(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("queue") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"NATS JetStream provisioning is coming in Phase 4. Sign up at "+urls.StartURLPrefix+" to be notified.")
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
		return h.newQueueAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, body.Dedicated, env, start)
	}

	// ── Dedicated requires authentication ─────────────────────────────────────
	if body.Dedicated {
		return respondError(c, fiber.StatusPaymentRequired, "auth_required",
			"isolated resources require an authenticated team. Sign up at "+urls.StartURLPrefix)
	}

	// ── Anonymous path ─────────────────────────────────────────────────────────
	// Recycle gate runs BEFORE the daily-cap check — see db.go API-7 fix.
	if h.recycleGate(c, fp, "queue") {
		return nil
	}

	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("queue.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "queue", env)
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
			return h.denyProvisionOverCap(c, fp, "queue")
		}
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "queue", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("queue.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
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
				slog.Warn("queue.new.dedup_decrypt_failed — provisioning fresh",
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
					"limits":         h.queueAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
					"upgrade_jwt":    jwtToken,
					"claim_url":      upgradeURL, // DOG-21: see db.go
				}
				setInternalURL(dedupResp, existing.Tier, connectionURL, "queue")
				return respondOK(c, dedupResp)
			}
			// Empty connection_url means provisioning failed mid-flight on the existing
			// resource. Fall through to provision a fresh one rather than returning
			// an unusable response.
			slog.Warn("queue.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	// (Recycle gate moved above — see API-7 / QA 2026-05-29 ordering fix.)

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "queue",
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
		slog.Error("queue.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision NATS resource")
	}

	tokenStr := resource.Token.String()

	// Provision NATS credentials.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "queue", "anonymous", "", fp, tokenStr)
	creds, err := h.provisionQueue(provCtx, tokenStr, "anonymous", "") // no teamID for anonymous
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("queue", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("queue", "grpc_error").Inc()
		middleware.RecordProvisionFail("queue", middleware.ProvisionFailBackendUnavailable)
		slog.Error("queue.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		// Soft-delete the resource record so limits aren't falsely consumed.
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("queue.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision NATS credentials")
	}

	// MR-P0-5: issue per-tenant credentials via the queueprovider abstraction.
	// May return AuthMode=isolated (real per-tenant account JWT) or
	// AuthMode=legacy_open (no auth — staged-cutover fallback).
	tenantCreds, _ := h.issueTenantCreds(ctx, tokenStr, creds.SubjectPrefix)
	authMode := commonqp.AuthModeLegacyOpen
	if tenantCreds != nil && tenantCreds.AuthMode != "" {
		authMode = tenantCreds.AuthMode
	}

	// MR-P0-2 / MR-P0-3: persist connection URL + PRID and flip the row
	// pending→active. Any persistence failure tears down the backend NATS
	// resource and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "queue.new",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "queue", "queue.new") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("queue", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist queue resource")
	}
	// Persist the auth_mode on the row. Best-effort — a failure here is
	// non-fatal (the row already lives with the column default 'isolated';
	// only legacy_open needs an explicit UPDATE).
	if authMode == commonqp.AuthModeLegacyOpen {
		if err := models.SetResourceAuthMode(ctx, h.db, resource.ID, authMode); err != nil {
			slog.Warn("queue.new.set_auth_mode_failed_non_fatal",
				"error", err, "resource_id", resource.ID, "auth_mode", authMode, "request_id", requestID)
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
		upgradeURL = urls.UpgradeStartURL(jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "queue",
		"token", tokenStr,
		"name", resource.Name.String,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("queue", "anonymous").Inc()
	middleware.RecordProvisionSuccess("queue")
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("queue.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	// internal_url omitted on the anonymous path — see internal_url.go.
	queueResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"subject_prefix": creds.SubjectPrefix,
		"auth_mode":      authMode,
		"tier":           "anonymous",
		"env":            resource.Env,
		"limits":         h.queueAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
		"upgrade":        upgradeURL,
		"upgrade_jwt":    jwtToken,
		"claim_url":      upgradeURL, // DOG-21: see dedup branch above
	}
	// MR-P0-5: when isolated creds are minted, surface them. Tenant clients
	// pass nats_jwt + nats_nkey to nats.UserJWTAndSeed(), or write the
	// creds_file blob to disk and pass it to nats.UserCredentials(path).
	addQueueCredentials(queueResp, tenantCreds)
	// T19 P0-2 (BugHunt 2026-05-20): emit top-level expires_at for
	// shape parity with storage/webhook responses; see db.go for rationale.
	if resource.ExpiresAt.Valid {
		queueResp["expires_at"] = resource.ExpiresAt.Time.Format(time.RFC3339)
	}
	return respondCreated(c, queueResp)
}

// addQueueCredentials embeds the per-tenant credentials into the /queue/new
// response when the queueprovider returned isolated creds. Legacy-open creds
// (no JWT, no NKey) leave the response shape untouched — the caller still
// gets the unauthenticated connection_url for now and the row carries
// auth_mode=legacy_open so the worker reaper can recycle it on schedule.
func addQueueCredentials(resp fiber.Map, creds *commonqp.TenantCreds) {
	if creds == nil || creds.AuthMode != commonqp.AuthModeIsolated {
		return
	}
	credMap := fiber.Map{
		"auth_mode": creds.AuthMode,
	}
	if creds.JWT != "" {
		credMap["nats_jwt"] = creds.JWT
	}
	if creds.NKey != "" {
		credMap["nats_nkey"] = creds.NKey
	}
	if creds.CredsFile != "" {
		credMap["creds_file"] = creds.CredsFile
	}
	if creds.Username != "" {
		credMap["username"] = creds.Username
	}
	if creds.Password != "" {
		credMap["password"] = creds.Password
	}
	if creds.KeyID != "" {
		credMap["key_id"] = creds.KeyID
	}
	if creds.ExpiresAt != nil {
		credMap["expires_at"] = creds.ExpiresAt.Format(time.RFC3339)
	}
	resp["credentials"] = credMap
}

func (h *QueueHandler) newQueueAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, dedicated bool, env string, start time.Time,
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
		if !h.plans.IsDedicatedTier(team.PlanTier) {
			metrics.DedicatedTierUpgradeBlocked.WithLabelValues("queue", team.PlanTier).Inc()
			return respondError(c, fiber.StatusPaymentRequired, "upgrade_required",
				"Isolated (dedicated) resources require a Growth plan. Upgrade at "+urls.StartURLPrefix)
		}
		tier = "growth"
	}

	// A6: per-tier queue count cap from plans.yaml.
	if h.plans != nil {
		queueLimit := h.plans.QueueCountLimit(team.PlanTier)
		if queueLimit >= 0 {
			existing, countErr := models.CountActiveResourcesByTeamAndType(ctx, h.db, teamUUID, "queue")
			if countErr != nil {
				slog.Error("queue.new.count_failed", "error", countErr, "team_id", teamIDStr, "request_id", requestID)
				return respondError(c, fiber.StatusServiceUnavailable, "quota_check_failed",
					"Failed to check queue quota")
			}
			if existing >= queueLimit {
				metrics.QueueProvisionLimitBlocked.WithLabelValues(team.PlanTier).Inc()
				return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
					"queue_limit_reached",
					fmt.Sprintf("Your %s plan allows %d queue(s). Upgrade at %s", team.PlanTier, queueLimit, urls.StartURLPrefix),
					fmt.Sprintf("Tell the user they've hit the %s tier queue cap (%d). Upgrade at https://instanode.dev/pricing for more queues.", team.PlanTier, queueLimit),
					"https://instanode.dev/pricing",
				)
			}
		}
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     "queue",
		Name:             name,
		Tier:             tier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        resourceExpiryForTier(tier), // free→24h TTL, paid→permanent (bug bash #4)
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("queue.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision NATS resource")
	}

	// Best-effort audit event; failures must never block the provision.
	safego.Go("queue.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "queue",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>queue</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	})

	tokenStr := resource.Token.String()

	// Provision NATS credentials.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "queue", tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionQueue(provCtx, tokenStr, tier, teamIDStr)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("queue", tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("queue", "grpc_error").Inc()
		middleware.RecordProvisionFail("queue", middleware.ProvisionFailBackendUnavailable)
		slog.Error("queue.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("queue.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision NATS credentials")
	}

	// MR-P0-5: issue per-tenant credentials via the queueprovider abstraction.
	tenantCreds, _ := h.issueTenantCreds(ctx, tokenStr, creds.SubjectPrefix)
	authMode := commonqp.AuthModeLegacyOpen
	if tenantCreds != nil && tenantCreds.AuthMode != "" {
		authMode = tenantCreds.AuthMode
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend NATS resource and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "queue.new.auth",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "queue", "queue.new.auth") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("queue", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist queue resource")
	}
	if authMode == commonqp.AuthModeLegacyOpen {
		if err := models.SetResourceAuthMode(ctx, h.db, resource.ID, authMode); err != nil {
			slog.Warn("queue.new.set_auth_mode_failed_non_fatal_auth",
				"error", err, "resource_id", resource.ID, "auth_mode", authMode, "request_id", requestID)
		}
	}

	slog.Info("provision.success",
		"service", "queue",
		"token", tokenStr,
		"name", resource.Name.String,
		"team_id", teamIDStr,
		"tier", tier,
		"dedicated", dedicated,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("queue", tier).Inc()
	middleware.RecordProvisionSuccess("queue")

	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          resource.Token.String(),
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"subject_prefix": creds.SubjectPrefix,
		"auth_mode":      authMode,
		"tier":           tier,
		"env":            resource.Env,
		"dedicated":      dedicated,
		"limits": fiber.Map{
			"storage_mb": h.plans.StorageLimitMB(tier, "queue"),
		},
	}
	addQueueCredentials(resp, tenantCreds)
	setInternalURL(resp, tier, creds.URL, "queue")
	return respondCreated(c, resp)
}

// decryptConnectionURL decrypts an AES-encrypted connection URL stored
// in the DB. T1 P1-5 (BugHunt 2026-05-20): fail-CLOSED. See db.go for
// rationale. (plain, true) success / ("", true) empty / ("", false)
// decrypt error — never returns ciphertext as a "connection_url".
func (h *QueueHandler) decryptConnectionURL(encrypted, requestID string) (string, bool) {
	if encrypted == "" {
		return "", true
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("queue.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return "", false
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("queue.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return "", false
	}
	return plain, true
}

// queueAnonymousLimits returns the limits map for anonymous queue resources.
// storage_mb is read from plans.Registry (convention #3) so a plans.yaml edit
// to queue_storage_mb flows through instead of drifting against a literal.
func (h *QueueHandler) queueAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb": h.plans.StorageLimitMB(tierAnonymous, "queue"),
		"expires_in": "24h",
	}
}
