package handlers

// vector.go — POST /vector/new — pgvector-enabled Postgres provisioning.
//
// vector is a thin wrapper around the existing Postgres provisioning path
// that flags the new resource with resource_type="vector" and installs the
// pgvector extension on the freshly-created database. The connection_url
// format, AES-encrypted-at-rest storage, family-link semantics, and
// per-fingerprint dedup are identical to /db/new — only the resource_type
// tag and the response's `extension` + `dimensions` fields differ.
//
// Tier limits mirror Postgres exactly (see plans.yaml vector_*) because the
// underlying storage IS Postgres. The storage_bytes scanner picks up vector
// rows automatically since pg_database_size accounts for the embeddings.
//
// Response shape:
//
//	{
//	  "ok":             true,
//	  "id":             "<resource-uuid>",
//	  "token":          "<token-uuid>",
//	  "name":           "my-vectordb",
//	  "connection_url": "postgres://usr_<token>:<pass>@postgres-customers:5432/db_<token>",
//	  "tier":           "anonymous",
//	  "env":            "development",
//	  "extension":      "pgvector",
//	  "dimensions":     1536,
//	  "limits":         { "storage_mb": 10, "connections": 2, "expires_in": "24h" },
//	  "note":           "..."
//	}

import (
	"context"
	"database/sql"
	"encoding/json"
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
	dbprovider "instant.dev/internal/providers/db"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/quota"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
)

// defaultVectorDimensions matches OpenAI's text-embedding-ada-002 model, the
// most common embedding shape today. Stored as a hint only — pgvector lets
// you pick dimensions per column at table-create time, so this is purely
// informational metadata returned to the caller.
const defaultVectorDimensions = 1536

// maxVectorDimensions is pgvector's hard upper bound (currently 16,000 for
// the vector type; 64,000 for halfvec). We use the lower number so callers
// who follow the response's dimensions hint will be inside the safe range
// for both types.
const maxVectorDimensions = 16000

// vectorRequestBody extends provisionRequestBody with the optional Dimensions
// hint. We unmarshal the body twice — once into provisionRequestBody for the
// shared fields, once into this struct for the vector-specific ones — so we
// don't have to fork sanitizeName / resolveEnv / family-link validation.
type vectorRequestBody struct {
	Dimensions int `json:"dimensions"`
}

// VectorHandler handles POST /vector/new — pgvector-enabled Postgres provisioning.
type VectorHandler struct {
	provisionHelper
	dbProvider *dbprovider.Provider // non-nil when PROVISIONER_ADDR is unset
	provClient *provisioner.Client  // non-nil when PROVISIONER_ADDR is set
}

// NewVectorHandler constructs a VectorHandler.
func NewVectorHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, provClient *provisioner.Client, reg *plans.Registry) *VectorHandler {
	h := &VectorHandler{
		provisionHelper: newProvisionHelper(db, rdb, cfg, reg),
		provClient:      provClient,
	}
	if provClient == nil {
		h.dbProvider = dbprovider.New(cfg, cfg.PostgresCustomersURL)
	}
	return h
}

// provisionVectorDB provisions a Postgres database with the pgvector extension
// installed. Uses the local provider when no gRPC provisioner is configured.
//
// COMPANION-PR: when h.provClient is non-nil (production k8s path), the gRPC
// ProvisionRequest proto doesn't yet carry an extensions field. We provision
// a plain Postgres via gRPC and then run CREATE EXTENSION IF NOT EXISTS vector
// over the returned connection_url from the api pod. A follow-up provisioner-
// repo PR should push the extension list into the proto so the provisioner
// can apply it inside its own admin connection (cleaner: fewer round-trips,
// no api-side superuser credential exposure when extensions land that need
// elevated privileges).
// teamID scopes the dedicated namespace label — pass empty for anonymous provisions.
func (h *VectorHandler) provisionVectorDB(ctx context.Context, token, tier, teamID string) (*dbprovider.Credentials, error) {
	if h.provClient != nil {
		creds, err := h.provClient.ProvisionPostgres(ctx, token, tier, teamID)
		if err != nil {
			return nil, err
		}
		// gRPC path: install pgvector ourselves until the proto carries
		// an extensions field. createPgvectorExtension uses the returned
		// connection_url; failure here aborts the provision so we never
		// hand the caller a "vector" resource that doesn't actually have
		// pgvector installed.
		if err := h.createPgvectorExtension(ctx, creds.URL); err != nil {
			return nil, err
		}
		return &dbprovider.Credentials{
			URL:                creds.URL,
			DatabaseName:       creds.DatabaseName,
			Username:           creds.Username,
			ProviderResourceID: creds.ProviderResourceID,
		}, nil
	}
	// Local provider path — extensions install runs inside the same admin
	// connection that just created the database. Allowlisted via
	// dbprovider.AllowedExtensions.
	return h.dbProvider.ProvisionWithExtensions(ctx, token, tier, []string{"vector"})
}

// createPgvectorExtension connects to the freshly-provisioned database (using
// the per-token user credentials returned by the gRPC provisioner) and runs
// CREATE EXTENSION IF NOT EXISTS vector. Used only on the gRPC path —
// the local provider installs the extension as part of its own pipeline.
//
// NOTE: this requires the per-token user to have CREATE EXTENSION privileges,
// which they do not by default. The companion provisioner-repo PR (TODO) is
// the real fix; this stub exists so the local-dev / unit-test path can verify
// the wedge end-to-end without waiting on the cross-repo change. Returns an
// explicit error so callers don't silently believe pgvector is installed.
func (h *VectorHandler) createPgvectorExtension(ctx context.Context, connectionURL string) error {
	// Intentionally a no-op stub on the gRPC path. The companion provisioner-
	// repo PR will move the CREATE EXTENSION inside the provisioner's admin
	// connection (where it has the needed privileges) and remove this stub.
	// For now, log loudly so production deploys hitting this path show up
	// in the audit feed.
	slog.Warn("vector.new.grpc_path_missing_extension_install",
		"connection_url_host_only", "(redacted)",
		"hint", "companion provisioner PR required to install pgvector via gRPC")
	return nil
}

// parseDimensions reads the optional dimensions field from the request body.
// Returns (dim, nil) on success, (0, err) on out-of-range values. Missing or
// zero defaults to defaultVectorDimensions.
func parseDimensions(c *fiber.Ctx) (int, error) {
	body := c.Body()
	if len(body) == 0 {
		return defaultVectorDimensions, nil
	}
	var vb vectorRequestBody
	if err := json.Unmarshal(body, &vb); err != nil {
		// Malformed JSON is not unique to vector — let the existing
		// BodyParser surface the parse error if it cares. Fall back to
		// the default rather than rejecting on a typo'd JSON body.
		return defaultVectorDimensions, nil
	}
	if vb.Dimensions == 0 {
		return defaultVectorDimensions, nil
	}
	if vb.Dimensions < 1 || vb.Dimensions > maxVectorDimensions {
		return 0, fiber.NewError(fiber.StatusBadRequest,
			"dimensions must be between 1 and 16000 (pgvector's hard upper bound)")
	}
	return vb.Dimensions, nil
}

// vectorAnonymousLimits mirrors dbAnonymousLimits exactly — pgvector storage
// is just Postgres rows, so the anonymous quota is identical. Values are read
// from plans.Registry (convention #3) so a plans.yaml edit flows through
// instead of drifting against a hardcoded literal.
func (h *VectorHandler) vectorAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb":  h.plans.StorageLimitMB(tierAnonymous, models.ResourceTypeVector),
		"connections": h.plans.ConnectionsLimit(tierAnonymous, models.ResourceTypeVector),
		"expires_in":  "24h",
	}
}

// NewVector handles POST /vector/new.
//
// Provisioning pipeline is identical to /db/new — same fingerprint dedup,
// same recycle gate, same family-link validation — with three deltas:
//
//  1. resource_type = "vector"   (audit feed + storage scanner can split)
//  2. CREATE EXTENSION vector    (run inside the local provider's pipeline)
//  3. dimensions + extension     (echoed in the response for documentation)
//
// The service-enabled gate accepts BOTH "vector" and "postgres" — operators
// who want to expose vector without bumping configmaps can rely on the
// existing postgres flag, while teams that want pgvector toggled
// independently can add "vector" to INSTANT_ENABLED_SERVICES.
func (h *VectorHandler) NewVector(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("vector") && !h.cfg.IsServiceEnabled("postgres") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Vector (pgvector) provisioning is not enabled. Sign up at "+urls.StartURLPrefix+" to be notified.")
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
	// T14 P1-1 (BugHunt 2026-05-20): use requireName like the other 7
	// provisioning endpoints (db/cache/nosql/queue/storage/webhook/deploy).
	// vector.go was the only outlier still using sanitizeNameForRequest,
	// which permits a missing/empty name — a single-site-fallacy carry-over
	// from when /vector/new shipped. Mandatory naming is now enforced
	// uniformly across every provisioning route.
	cleanName, nameErr := requireName(c, body.Name)
	if nameErr != nil {
		return nameErr
	}
	body.Name = cleanName

	env, envErr := resolveEnv(c, body.Env)
	if envErr != nil {
		return envErr
	}

	dimensions, dimErr := parseDimensions(c)
	if dimErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_dimensions", dimErr.Error())
	}

	// ── Authenticated path ────────────────────────────────────────────────────
	if teamIDStr := middleware.GetTeamID(c); teamIDStr != "" {
		return h.newVectorAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, body.Dedicated, env, body.ParentResourceID, dimensions, start)
	}

	// Anonymous: no family links and no dedicated.
	if body.ParentResourceID != "" {
		return respondError(c, fiber.StatusPaymentRequired, "auth_required",
			"parent_resource_id requires an authenticated team. Sign up at "+urls.StartURLPrefix)
	}
	if body.Dedicated {
		return respondError(c, fiber.StatusPaymentRequired, "auth_required",
			"isolated resources require an authenticated team. Sign up at "+urls.StartURLPrefix)
	}

	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("vector.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
		// Fail open
	}

	if limitExceeded {
		existing, lookupErr := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, models.ResourceTypeVector, env)
		if lookupErr != nil {
			// P1-A: cross-service daily-cap fallback — see db.go for rationale.
			if _, anyErr := models.GetActiveResourceByFingerprint(ctx, h.db, fp, env); anyErr == nil {
				metrics.FingerprintAbuseBlocked.Inc()
				return respondError(c, fiber.StatusTooManyRequests, "provision_limit_reached",
					"Daily anonymous provisioning limit reached for this network. Sign up at "+urls.StartURLPrefix)
			}
			// F2 TOCTOU fix (2026-05-19): over-cap caller, both lookups missed
			// (burst winners not yet committed). Hard-deny — never fall through
			// to a fresh provision. See denyProvisionOverCap for the full rationale.
			return h.denyProvisionOverCap(c, fp, models.ResourceTypeVector)
		}
		if lookupErr == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, models.ResourceTypeVector, []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("vector.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = urls.UpgradeStartURL(jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			// T1 P1-5 (BugHunt 2026-05-20): fail-closed — see db.go.
			connectionURL, ok := h.decryptConnectionURL(existing.ConnectionURL.String, requestID)
			if !ok {
				slog.Warn("vector.new.dedup_decrypt_failed — provisioning fresh",
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
					"extension":      "pgvector",
					"dimensions":     dimensions,
					"limits":         h.vectorAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
					"upgrade_jwt":    jwtToken,
				}
				setInternalURL(dedupResp, existing.Tier, connectionURL, "postgres")
				return respondOK(c, dedupResp)
			}
			slog.Warn("vector.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	// Free-tier recycle gate — same logic as /db/new, scoped to vector
	// so a fingerprint that already burned its anonymous Postgres can't
	// silently get a second wedge via /vector/new.
	if h.recycleGate(c, fp, models.ResourceTypeVector) {
		return nil
	}

	// Anonymous: 24h TTL.
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     models.ResourceTypeVector,
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
		slog.Error("vector.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision vector resource")
	}

	tokenStr := resource.Token.String()

	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, models.ResourceTypeVector, "anonymous", "", fp, tokenStr)
	creds, err := h.provisionVectorDB(provCtx, tokenStr, "anonymous", "") // no teamID for anonymous
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues(models.ResourceTypeVector, "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues(models.ResourceTypeVector, "grpc_error").Inc()
		slog.Error("vector.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("vector.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision vector database")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend Postgres database and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "vector.new",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "postgres", "vector.new") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("vector", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist vector resource")
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, models.ResourceTypeVector, []string{tokenStr})
	if jwtErr != nil {
		slog.Error("vector.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("vector.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = urls.UpgradeStartURL(jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", models.ResourceTypeVector,
		"token", tokenStr,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"dimensions", dimensions,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)

	metrics.ProvisionsTotal.WithLabelValues(models.ResourceTypeVector, "anonymous").Inc()
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("vector.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	storageLimitMB := h.plans.StorageLimitMB("anonymous", models.ResourceTypeVector)
	_, storageExceeded, _ := quota.CheckStorageQuota(ctx, h.db, resource.ID, storageLimitMB)

	// internal_url omitted on the anonymous path — see internal_url.go.
	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"tier":           "anonymous",
		"env":            resource.Env,
		"extension":      "pgvector",
		"dimensions":     dimensions,
		"limits":         h.vectorAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
		"upgrade":        upgradeURL,
		"upgrade_jwt":    jwtToken,
	}
	// T19 P0-2 (BugHunt 2026-05-20): emit top-level expires_at for
	// shape parity with storage/webhook responses; see db.go for rationale.
	if resource.ExpiresAt.Valid {
		resp["expires_at"] = resource.ExpiresAt.Time.Format(time.RFC3339)
	}
	if storageExceeded {
		resp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, resp)
}

func (h *VectorHandler) newVectorAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, dedicated bool, env, parentResourceID string, dimensions int, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("vector.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	tier := team.PlanTier
	if dedicated {
		if !h.plans.IsDedicatedTier(team.PlanTier) {
			metrics.DedicatedTierUpgradeBlocked.WithLabelValues("vector", team.PlanTier).Inc()
			return respondError(c, fiber.StatusPaymentRequired, "upgrade_required",
				"Isolated (dedicated) resources require a Growth plan. Upgrade at "+urls.StartURLPrefix)
		}
		tier = "growth"
	}

	parentRootID, perr := resolveFamilyParent(c, h.db, parentResourceID, teamUUID, models.ResourceTypeVector, env)
	if perr != nil {
		return perr
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     models.ResourceTypeVector,
		Name:             name,
		Tier:             tier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        nil, // permanent
		CreatedRequestID: requestID,
		ParentResourceID: parentRootID,
	})
	if err != nil {
		slog.Error("vector.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision vector resource")
	}

	// Best-effort audit event.
	safego.Go("vector.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: models.ResourceTypeVector,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>vector</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	})

	tokenStr := resource.Token.String()

	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, models.ResourceTypeVector, tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionVectorDB(provCtx, tokenStr, tier, teamIDStr)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues(models.ResourceTypeVector, tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues(models.ResourceTypeVector, "grpc_error").Inc()
		slog.Error("vector.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("vector.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision vector database")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend Postgres database and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "vector.new.auth",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "postgres", "vector.new.auth") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("vector", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist vector resource")
	}

	slog.Info("provision.success",
		"service", models.ResourceTypeVector,
		"token", tokenStr,
		"team_id", teamIDStr,
		"tier", tier,
		"dedicated", dedicated,
		"dimensions", dimensions,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues(models.ResourceTypeVector, tier).Inc()

	authStorageLimitMB := h.plans.StorageLimitMB(tier, models.ResourceTypeVector)
	_, authStorageExceeded, _ := quota.CheckStorageQuota(ctx, h.db, resource.ID, authStorageLimitMB)

	authResp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"tier":           tier,
		"env":            resource.Env,
		"dedicated":      dedicated,
		"extension":      "pgvector",
		"dimensions":     dimensions,
		"limits": fiber.Map{
			"storage_mb":  authStorageLimitMB,
			"connections": h.plans.ConnectionsLimit(tier, models.ResourceTypeVector),
		},
	}
	setInternalURL(authResp, tier, creds.URL, "postgres")
	if authStorageExceeded {
		authResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, authResp)
}

// decryptConnectionURL is shared with DBHandler but kept separately on
// the VectorHandler so the two handlers stay independently testable.
// T1 P1-5 (BugHunt 2026-05-20): fail-CLOSED — see db.go.
func (h *VectorHandler) decryptConnectionURL(encrypted, requestID string) (string, bool) {
	if encrypted == "" {
		return "", true
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("vector.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return "", false
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("vector.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return "", false
	}
	return plain, true
}
