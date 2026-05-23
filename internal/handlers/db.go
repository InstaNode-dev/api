package handlers

// db.go — POST /db/new — Postgres + pgvector provisioning (Phase 2).
//
// Response shape:
//
//	{
//	  "ok":             true,
//	  "id":             "<resource-uuid>",
//	  "token":          "<token-uuid>",
//	  "name":           "my-db",
//	  "connection_url": "postgres://usr_<token>:<pass>@postgres-customers:5432/db_<token>",
//	  "tier":           "anonymous",
//	  "env":            "development",
//	  "limits":         { "storage_mb": 10, "connections": 3, "expires_in": "24h" },
//	  "note":           "Works now. Free forever with a free account: <url>"
//	}

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
	dbprovider "instant.dev/internal/providers/db"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
)

// DBHandler handles POST /db/new — Postgres provisioning.
type DBHandler struct {
	provisionHelper
	dbProvider *dbprovider.Provider // non-nil when PROVISIONER_ADDR is unset
	provClient *provisioner.Client  // non-nil when PROVISIONER_ADDR is set
}

// NewDBHandler constructs a DBHandler.
func NewDBHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, provClient *provisioner.Client, reg *plans.Registry) *DBHandler {
	h := &DBHandler{
		provisionHelper: newProvisionHelper(db, rdb, cfg, reg),
		provClient:      provClient,
	}
	if provClient == nil {
		// fall back to local provider
		h.dbProvider = dbprovider.New(cfg, cfg.PostgresCustomersURL)
	}
	return h
}

// provisionDB provisions a Postgres database, using gRPC provisioner if available,
// falling back to local provider otherwise.
// teamID is the owning team UUID string passed to the provisioner so it can
// label the dedicated namespace with instant.dev/owner-team for NetworkPolicy
// scoping. Pass empty string for anonymous provisions.
func (h *DBHandler) provisionDB(ctx context.Context, token, tier, teamID string) (*dbprovider.Credentials, error) {
	if h.provClient != nil {
		creds, err := h.provClient.ProvisionPostgres(ctx, token, tier, teamID)
		if err != nil {
			return nil, err
		}
		return &dbprovider.Credentials{
			URL:                creds.URL,
			DatabaseName:       creds.DatabaseName,
			Username:           creds.Username,
			ProviderResourceID: creds.ProviderResourceID,
		}, nil
	}
	return h.dbProvider.Provision(ctx, token, tier)
}

// NewDB handles POST /db/new.
func (h *DBHandler) NewDB(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("postgres") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Postgres provisioning is coming in Phase 2. Sign up at "+urls.StartURLPrefix+" to be notified.")
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
		return h.newDBAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, body.Dedicated, env, body.ParentResourceID, start)
	}

	// Anonymous callers cannot family-link — there's no team to scope the
	// link to. Reject early so we don't silently drop the field.
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
		slog.Error("db.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
		// Fail open
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "postgres", env)
		if err != nil {
			// P1-A: no same-type resource for this fingerprint+env. Before
			// provisioning fresh — which would let an abuser mint 5/day per
			// service type and bypass the daily cap (CLAUDE.md #6) — fall
			// back to a cross-service check. If ANY anonymous resource exists
			// for this fingerprint+env, the cap is genuinely spent: reject 429.
			if _, anyErr := models.GetActiveResourceByFingerprint(ctx, h.db, fp, env); anyErr == nil {
				metrics.FingerprintAbuseBlocked.Inc()
				return respondError(c, fiber.StatusTooManyRequests, "provision_limit_reached",
					"Daily anonymous provisioning limit reached for this network. Sign up at "+urls.StartURLPrefix)
			}
			// F2 TOCTOU fix (2026-05-19): both lookups missed. checkProvisionLimit's
			// atomic INCR already proved this caller is over the cap; the absent
			// row only means the ≤5 winning provisions in this burst have claimed
			// their slots but not yet committed. An over-cap caller must NEVER
			// fall through to CreateResource — that is exactly the race that let
			// a 30-way burst mint 22–29 tokens. Hard-deny with 429.
			return h.denyProvisionOverCap(c, fp, "postgres")
		}
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "postgres", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("db.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = urls.UpgradeStartURL(jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			// Decrypt the stored connection_url to return it in plaintext.
			// T1 P1-5 (BugHunt 2026-05-20): decryptConnectionURL is now
			// fail-closed — ok=false on decrypt error returns
			// (""=, false) so we fall through to fresh-provision rather
			// than emitting ciphertext-as-connection_url to the agent.
			connectionURL, ok := h.decryptConnectionURL(existing.ConnectionURL.String, requestID)
			if !ok {
				// Decrypt error on a non-empty stored URL — log was
				// already emitted at ERROR. Treat as "no usable URL"
				// and fall through to fresh provision; better than
				// returning unusable ciphertext to the caller.
				slog.Warn("db.new.dedup_decrypt_failed — provisioning fresh",
					"token", existing.Token, "request_id", requestID)
			} else if connectionURL != "" {
				metrics.FingerprintAbuseBlocked.Inc()
				// internal_url omitted via setInternalURL: existing.Tier is
				// "anonymous" on the fingerprint-dedup path (never crosses into
				// authenticated territory — that's a separate code branch).
				dedupResp := fiber.Map{
					"ok":             true,
					"id":             existing.ID.String(),
					"token":          existing.Token.String(),
					"name":           existing.Name.String,
					"connection_url": connectionURL,
					"tier":           existing.Tier,
					"env":            existing.Env,
					"limits":         h.dbAnonymousLimits(),
					"note":           limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
					"upgrade":        upgradeURL,
					"upgrade_jwt":    jwtToken,
				}
				setInternalURL(dedupResp, existing.Tier, connectionURL, "postgres")
				return respondOK(c, dedupResp)
			}
			// Empty connection_url means provisioning failed mid-flight on the existing
			// resource. Fall through to provision a fresh one rather than returning
			// an unusable response.
			slog.Warn("db.new.dedup_empty_url — provisioning fresh",
				"token", existing.Token, "request_id", requestID)
		}
	}

	// Free-tier recycle gate (Option B / FREE-TIER-RECYCLE-2026-05-12). If
	// this fingerprint has provisioned anonymously before AND no active row
	// exists today, require a one-time email claim instead of silently
	// handing out another 24h free resource. Anonymous-only — the
	// authenticated path returned above. Fails open on Redis/DB errors so
	// the magic-first-touch wedge is never collateral damage.
	if h.recycleGate(c, fp, "postgres") {
		return nil
	}

	// Provision new anonymous Postgres resource (expires in 24h).
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "postgres",
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
		slog.Error("db.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision Postgres resource")
	}

	tokenStr := resource.Token.String()

	// Provision the real Postgres database.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "postgres", "anonymous", "", fp, tokenStr)
	creds, err := h.provisionDB(provCtx, tokenStr, "anonymous", "") // no teamID for anonymous
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("postgres", "anonymous").Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("postgres", "grpc_error").Inc()
		middleware.RecordProvisionFail("postgres", middleware.ProvisionFailBackendUnavailable)
		slog.Error("db.new.provision_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("db.new.soft_delete_failed", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision Postgres database")
	}

	// MR-P0-2 / MR-P0-3: persist the connection URL + provider_resource_id and
	// flip the row pending→active atomically. Any persistence failure tears
	// down the backend DB and returns 503 — never a 201 for a resource the
	// platform can't address.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "db.new",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "postgres", "db.new") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("postgres", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist Postgres resource")
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "postgres", []string{tokenStr})
	if jwtErr != nil {
		slog.Error("db.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("db.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = urls.UpgradeStartURL(jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "postgres",
		"token", tokenStr,
		"name", resource.Name.String,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)

	metrics.ProvisionsTotal.WithLabelValues("postgres", "anonymous").Inc()
	middleware.RecordProvisionSuccess("postgres")
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	// Record this fingerprint as having had at least one anonymous touch.
	// The next anonymous POST after this resource expires will hit the
	// recycle gate above and require an email claim. Best-effort: log on
	// failure but never block the response.
	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("db.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	storageLimitMB := h.plans.StorageLimitMB("anonymous", "postgres")
	_, storageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, storageLimitMB)

	// internal_url intentionally omitted on the anonymous path — see
	// setInternalURL doc comment in internal_url.go. Anon callers can't run
	// in-cluster workloads (POST /deploy/new requires a claimed team), so
	// internal_url has zero utility for them and leaks infra topology.
	resp := fiber.Map{
		"ok":             true,
		"id":             resource.ID.String(),
		"token":          tokenStr,
		"name":           resource.Name.String,
		"connection_url": creds.URL,
		"tier":           "anonymous",
		"env":            resource.Env,
		"limits":         h.dbAnonymousLimits(),
		"note":           upgradeNote(upgradeURL),
		"upgrade":        upgradeURL,
		"upgrade_jwt":    jwtToken,
	}
	// T19 P0-2 (BugHunt 2026-05-20): unify the TTL contract across all
	// provisioning endpoints — storage/webhook already emit a top-level
	// RFC3339 expires_at; db/cache/nosql/queue/vector did not. Anonymous
	// resources always carry an expires_at (24h TTL); skipping the field
	// when the column is NULL keeps authenticated/permanent responses
	// shape-compatible.
	if resource.ExpiresAt.Valid {
		resp["expires_at"] = resource.ExpiresAt.Time.Format(time.RFC3339)
	}
	if storageExceeded {
		resp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, resp)
}

func (h *DBHandler) newDBAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, dedicated bool, env, parentResourceID string, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("db.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	tier := team.PlanTier
	if dedicated {
		if !h.plans.IsDedicatedTier(team.PlanTier) {
			metrics.DedicatedTierUpgradeBlocked.WithLabelValues("db", team.PlanTier).Inc()
			return respondError(c, fiber.StatusPaymentRequired, "upgrade_required",
				"Isolated (dedicated) resources require a Growth plan. Upgrade at "+urls.StartURLPrefix)
		}
		tier = "growth"
	}

	// Family-link validation runs BEFORE provisioning so a cross-team /
	// cross-type / duplicate-twin parent_resource_id never causes us to
	// create-then-fail (which would leak a database we can't link).
	parentRootID, perr := resolveFamilyParent(c, h.db, parentResourceID, teamUUID, models.ResourceTypePostgres, env)
	if perr != nil {
		return perr
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     models.ResourceTypePostgres,
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
		slog.Error("db.new.create_resource_failed_auth", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision Postgres resource")
	}

	// Best-effort audit event; failures must never block the provision.
	safego.Go("db.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "postgres",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>postgres</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	})

	tokenStr := resource.Token.String()

	// Provision the real Postgres database.
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, "postgres", tier, teamIDStr, fp, tokenStr)
	creds, err := h.provisionDB(provCtx, tokenStr, tier, teamIDStr)
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues("postgres", tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues("postgres", "grpc_error").Inc()
		middleware.RecordProvisionFail("postgres", middleware.ProvisionFailBackendUnavailable)
		slog.Error("db.new.provision_failed_auth",
			"error", err, "token", tokenStr, "team_id", teamIDStr, "request_id", requestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("db.new.soft_delete_failed_auth", "error", delErr, "resource_id", resource.ID)
		}
		return respondProvisionFailed(c, err, "Failed to provision Postgres database")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend DB and returns 503, never a 201.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, requestID, "db.new.auth",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "postgres", "db.new.auth") },
	); finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("postgres", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist Postgres resource")
	}

	slog.Info("provision.success",
		"service", "postgres",
		"token", tokenStr,
		"name", resource.Name.String,
		"team_id", teamIDStr,
		"tier", tier,
		"dedicated", dedicated,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("postgres", tier).Inc()
	middleware.RecordProvisionSuccess("postgres")

	authStorageLimitMB := h.plans.StorageLimitMB(tier, "postgres")
	_, authStorageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, authStorageLimitMB)

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
			"storage_mb":  authStorageLimitMB,
			"connections": h.plans.ConnectionsLimit(tier, "postgres"),
		},
	}
	setInternalURL(authResp, tier, creds.URL, "postgres")
	if authStorageExceeded {
		authResp["warning"] = "Storage limit reached. Upgrade to continue."
		c.Set("X-Instant-Notice", "storage_limit_reached")
	}
	return respondCreated(c, authResp)
}

// decryptConnectionURL decrypts an AES-encrypted connection URL stored
// in the DB.
//
// T1 P1-5 (BugHunt 2026-05-20): previously this fail-OPEN'd on a
// decrypt error and returned the ciphertext to the caller — non-empty,
// so the rate-limit dedup branch in newDB / newCache / etc. wrote it
// straight into the 201/200 response's `connection_url` field. The
// customer's agent then dialed garbage. Fail-CLOSED instead: a
// non-empty `encrypted` that fails decrypt returns ("", false) so the
// caller skips the dedup branch and either returns 500 or falls
// through to a fresh provision.
//
// Semantics:
//   - ("", true)         → input was empty; nothing to decrypt.
//   - (plain, true)      → successful decrypt.
//   - ("", false)        → decrypt error; caller MUST treat as
//                          "no usable URL" (NOT as ciphertext).
//
// Logging stays as ERROR — a decrypt failure on a non-empty stored
// value is always alarming (key rotation gone wrong, DB tamper, etc.).
func (h *DBHandler) decryptConnectionURL(encrypted, requestID string) (string, bool) {
	if encrypted == "" {
		return "", true
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("db.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return "", false
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("db.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return "", false
	}
	return plain, true
}

// dbAnonymousLimits returns the limits map for anonymous Postgres resources.
// Values are read from plans.Registry (convention #3) so a plans.yaml edit to
// the anonymous tier flows through automatically instead of drifting against
// a hardcoded literal.
func (h *DBHandler) dbAnonymousLimits() fiber.Map {
	return fiber.Map{
		"storage_mb":  h.plans.StorageLimitMB(tierAnonymous, models.ResourceTypePostgres),
		"connections": h.plans.ConnectionsLimit(tierAnonymous, models.ResourceTypePostgres),
		"expires_in":  "24h",
	}
}

// ProvisionForTwin runs the same pipeline as newDBAuthenticated for a single
// resource row, but skips the body-parsing / tier-derivation / family-link
// validation that already happened upstream in TwinHandler.ProvisionTwin.
//
// The caller (TwinHandler) supplies a pre-validated input — TeamID is the
// caller's team, ParentRootID is the family root id, Tier is mirrored from
// the source resource, Fingerprint/CloudVendor/CountryCode are inherited
// so quota+geo dashboards group siblings together.
//
// Response shape on 201 mirrors newDBAuthenticated so the dashboard +
// MCP can consume twin responses with zero branching against /db/new.
//
// This method delegates to ProvisionForTwinCore (the fiber-free core) and
// renders the result as JSON — bulk-twin reuses the Core path directly so
// it can aggregate many results into one Multi-Status response without
// fiber writes-per-row.
func (h *DBHandler) ProvisionForTwin(c *fiber.Ctx, in ProvisionForTwinInput) error {
	ctx := c.UserContext()
	res, err := h.ProvisionForTwinCore(ctx, in)
	if err != nil {
		// T12 P1-1 (BugBash 2026-05-20): use a static message, never err.Error(),
		// to avoid leaking the admin DSN (which contains the admin password) into
		// the response body. Matches the non-twin path's static phrasing.
		return respondProvisionFailed(c, err, "Failed to provision Postgres database")
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
	// Twin requires an authenticated team (see TwinHandler.ProvisionTwin)
	// so res.Tier is never "anonymous" in practice. Defensive guard
	// preserves the W11 anon-internal_url-scrub invariant if a future
	// callpath ever invokes the twin pipeline against an anon resource.
	// res.InternalURL is already pre-computed (proxiedInternalURL ran
	// upstream in ProvisionForTwinCore), so don't re-transform.
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
// Returns a TwinProvisionResult on success, or an error string suitable for
// surfacing to the caller. Used by both the single-twin handler (which renders
// the result as JSON) and the bulk-twin handler (which aggregates results).
//
// Errors are returned with a human-friendly message — the bulk handler
// records them verbatim in the failures array. Side-effects (audit row,
// soft-delete on provision failure) are identical to the original path.
func (h *DBHandler) ProvisionForTwinCore(ctx context.Context, in ProvisionForTwinInput) (TwinProvisionResult, error) {
	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &in.TeamID,
		ResourceType:     models.ResourceTypePostgres,
		Name:             in.Name,
		Tier:             in.Tier,
		Env:              in.Env,
		Fingerprint:      in.Fingerprint,
		CloudVendor:      in.CloudVendor,
		CountryCode:      in.CountryCode,
		ExpiresAt:        nil, // permanent — twin inherits source's no-TTL status
		CreatedRequestID: in.RequestID,
		ParentResourceID: in.ParentRootID,
	})
	if err != nil {
		slog.Error("twin.db.create_resource_failed",
			"error", err, "team_id", in.TeamID, "env", in.Env, "request_id", in.RequestID)
		return TwinProvisionResult{}, twinCoreErr("Failed to record twin resource")
	}

	safego.Go("db.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       in.TeamID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: models.ResourceTypePostgres,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary: "agent provisioned <strong>postgres</strong> twin <code>" +
				resource.Token.String()[:8] + "</code> in env=<code>" + in.Env + "</code>",
		})
	})

	tokenStr := resource.Token.String()
	provStart := time.Now()
	provCtx, span := h.startProvisionSpan(ctx, models.ResourceTypePostgres, in.Tier, in.TeamID.String(), in.Fingerprint, tokenStr)
	creds, err := h.provisionDB(provCtx, tokenStr, in.Tier, in.TeamID.String())
	finishProvisionSpan(span, err)
	metrics.ProvisionDuration.WithLabelValues(models.ResourceTypePostgres, in.Tier).Observe(time.Since(provStart).Seconds())
	if err != nil {
		metrics.ProvisionFailures.WithLabelValues(models.ResourceTypePostgres, "grpc_error").Inc()
		middleware.RecordProvisionFail(models.ResourceTypePostgres, middleware.ProvisionFailBackendUnavailable)
		slog.Error("twin.db.provision_failed",
			"error", err, "token", tokenStr, "team_id", in.TeamID, "request_id", in.RequestID)
		if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
			slog.Error("twin.db.soft_delete_failed",
				"error", delErr, "resource_id", resource.ID, "request_id", in.RequestID)
		}
		return TwinProvisionResult{}, twinCoreErr("Failed to provision Postgres twin")
	}

	// MR-P0-2 / MR-P0-3: persist + flip pending→active; a persistence failure
	// tears down the backend DB and surfaces a hard error, never a success.
	if finErr := h.finalizeProvision(ctx, resource, creds.URL, "", creds.ProviderResourceID, in.RequestID, "twin.db",
		func() { deprovisionBestEffort(ctx, h.provClient, tokenStr, creds.ProviderResourceID, "postgres", "twin.db") },
	); finErr != nil {
		return TwinProvisionResult{}, twinCoreErr("Failed to persist Postgres twin")
	}

	slog.Info("twin.provision.success",
		"service", models.ResourceTypePostgres,
		"token", tokenStr,
		"team_id", in.TeamID,
		"tier", in.Tier,
		"env", in.Env,
		"family_root_id", in.ParentRootID,
		"duration_ms", time.Since(in.Start).Milliseconds(),
		"request_id", in.RequestID,
	)
	metrics.ProvisionsTotal.WithLabelValues(models.ResourceTypePostgres, in.Tier).Inc()
	middleware.RecordProvisionSuccess(models.ResourceTypePostgres)

	storageLimitMB := h.plans.StorageLimitMB(in.Tier, models.ResourceTypePostgres)
	_, storageExceeded, _ := checkStorageQuota(ctx, h.db, resource.ID, storageLimitMB)

	return TwinProvisionResult{
		ID:            resource.ID.String(),
		Token:         tokenStr,
		Name:          resource.Name.String,
		ResourceType:  models.ResourceTypePostgres,
		ConnectionURL: creds.URL,
		InternalURL:   proxiedInternalURL(creds.URL, models.ResourceTypePostgres),
		Tier:          in.Tier,
		Env:           resource.Env,
		FamilyRootID:  derefUUID(in.ParentRootID),
		Limits: TwinResultLimits{
			StorageMB:   storageLimitMB,
			Connections: h.plans.ConnectionsLimit(in.Tier, models.ResourceTypePostgres),
		},
		StorageExceeded: storageExceeded,
	}, nil
}
