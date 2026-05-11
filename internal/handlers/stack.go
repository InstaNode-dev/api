package handlers

// stack.go — Multi-service stack endpoints (Phase 6).
//
// POST /stacks/new, GET /stacks/:slug, GET /stacks/:slug/logs/:svc, and
// DELETE /stacks/:slug use OptionalAuth — anonymous users can deploy stacks
// exactly as they provision databases (same tier system, 24h TTL, fingerprint dedup).
//
// PATCH /stacks/:slug/env and POST /stacks/:slug/redeploy require auth (mutations
// on owned stacks only). GET /api/v1/stacks requires auth (team-scoped listing).
//
// Routes (router.go registers middleware):
//   POST   /stacks/new              (OptionalAuth) — upload manifest + tarballs
//   GET    /stacks/:slug            (OptionalAuth) — fetch stack status + services
//   GET    /stacks/:slug/logs/:svc  (OptionalAuth) — SSE streaming service logs
//   DELETE /stacks/:slug            (OptionalAuth) — teardown stack
//   PATCH  /stacks/:slug/env        (RequireAuth)  — note env overrides for next redeploy
//   POST   /stacks/:slug/redeploy   (RequireAuth)  — rebuild + rolling update
//   GET    /api/v1/stacks           (RequireAuth)  — list stacks for team
//
// Compute work is delegated to compute.StackProvider so the handler is
// not tied to any specific backend (k8s, noop, etc.).

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/manifest"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	compute "instant.dev/internal/providers/compute"
	"instant.dev/internal/providers/compute/k8s"
	"instant.dev/internal/providers/compute/noop"
)

// StackHandler handles all /stacks endpoints.
type StackHandler struct {
	db        *sql.DB
	rdb       *redis.Client
	cfg       *config.Config
	stackProv compute.StackProvider
	plans     *plans.Registry
}

// NewStackHandler initialises the handler and selects the stack compute backend
// based on cfg.ComputeProvider. Falls back to noop if k8s init fails.
// planRegistry must be non-nil (use plans.Load at startup or plans.Default() in tests).
func NewStackHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, planRegistry *plans.Registry) *StackHandler {
	var sp compute.StackProvider
	if cfg.ComputeProvider == "k8s" {
		ksp, err := k8s.NewStackProvider(cfg.KubeNamespaceApps, buildContextConfigFromCfg(cfg))
		if err != nil {
			slog.Warn("stack.k8s_provider_unavailable — using noop", "error", err)
			sp = noop.NewStack()
		} else {
			sp = ksp
		}
	} else {
		sp = noop.NewStack()
	}
	return &StackHandler{db: db, rdb: rdb, cfg: cfg, stackProv: sp, plans: planRegistry}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// requireStackTeam extracts and validates the team from the request context.
// Returns (team, nil) on success; calls respondError and returns the error on failure.
// Used by auth-required endpoints (UpdateEnv, Redeploy, List).
func (h *StackHandler) requireStackTeam(c *fiber.Ctx) (*models.Team, error) {
	teamIDStr := middleware.GetTeamID(c)
	if teamIDStr == "" {
		return nil, respondError(c, fiber.StatusUnauthorized, "unauthorized",
			"A session token is required for this action. Sign in at https://instant.dev/start")
	}
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_team",
			"Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(c.Context(), h.db, teamUUID)
	if err != nil {
		slog.Error("stack.team_lookup_failed",
			"error", err, "team_id", teamIDStr,
			"request_id", middleware.GetRequestID(c))
		return nil, respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed",
			"Failed to look up team")
	}
	return team, nil
}

// optionalStackTeam returns the authenticated team if a valid token is present,
// or nil for unauthenticated (anonymous) requests.
// Returns an error (and writes the response) only on a malformed or invalid token.
// Used by OptionalAuth endpoints (New, Get, Logs, Delete).
func (h *StackHandler) optionalStackTeam(c *fiber.Ctx) (*models.Team, error) {
	teamIDStr := middleware.GetTeamID(c)
	if teamIDStr == "" {
		return nil, nil // anonymous caller — nil team is valid
	}
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_team",
			"Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(c.Context(), h.db, teamUUID)
	if err != nil {
		slog.Error("stack.team_lookup_failed",
			"error", err, "team_id", teamIDStr,
			"request_id", middleware.GetRequestID(c))
		return nil, respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed",
			"Failed to look up team")
	}
	return team, nil
}

// checkStackDeployLimit checks the per-fingerprint daily anonymous stack deploy limit.
// Uses the same shared Redis key as other provisioning endpoints so all service types
// count against a single daily cap per fingerprint.
//
// Returns (true, nil)  when limit is exceeded.
// Returns (false, nil) when the deploy is allowed (or Redis is unavailable — fail open).
func (h *StackHandler) checkStackDeployLimit(ctx context.Context, fp string) (bool, error) {
	if h.rdb == nil {
		return false, nil // fail open in tests / when Redis is not configured
	}
	date := time.Now().UTC().Format("2006-01-02")
	key := fmt.Sprintf("prov:%s:%s", fp, date)

	pipe := h.rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 25*time.Hour) // 25h avoids midnight thundering-herd

	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("checkStackDeployLimit redis pipeline: %w", err)
	}
	count, err := incrCmd.Result()
	if err != nil {
		return false, fmt.Errorf("checkStackDeployLimit incr result: %w", err)
	}
	return count > int64(h.plans.ProvisionLimit("anonymous")), nil
}

// stackOwnerCheck verifies the requesting user can access the given stack.
//   - Authenticated (team != nil): stack must belong to that team.
//   - Anonymous (team == nil): stack must itself be anonymous (team-less); the slug acts as the secret.
func stackOwnerCheck(c *fiber.Ctx, stack *models.Stack, team *models.Team) error {
	if team != nil {
		if stack.TeamID == nil || *stack.TeamID != team.ID {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
	} else {
		if stack.TeamID != nil {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
	}
	return nil
}

// rewriteToInternalURL replaces the host:port of a customer-facing connection
// URL with the cluster-internal FQDN of the dedicated pod, so stack workloads
// can reach their `needs:` resources without going through the LoadBalancer.
//
// Why this is needed: customer URLs use K8S_EXTERNAL_HOST (e.g. pg.instanode.dev)
// + a per-resource port. From outside the cluster they work. From INSIDE the
// cluster, the LoadBalancer doesn't hairpin reliably on DOKS, so a stack pod
// trying to reach pg.instanode.dev:5432 just times out.
//
// Resource → internal FQDN mapping:
//
//	postgres  → instant-pg-proxy.instant.svc.cluster.local:5432
//	            (the proxy routes by db name in the startup packet)
//	redis     → redis.<provider_resource_id>.svc.cluster.local:6379
//	mongodb   → mongo.<provider_resource_id>.svc.cluster.local:27017
//	queue     → nats.<provider_resource_id>.svc.cluster.local:4222
//
// If providerResourceID is empty (legacy / non-dedicated resource), the URL is
// returned unchanged. Callers should still log a warning in that case.
func rewriteToInternalURL(publicURL, resourceType, providerResourceID string) string {
	if publicURL == "" {
		return publicURL
	}
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Host == "" {
		return publicURL
	}

	var newHost string
	switch resourceType {
	case "postgres":
		// Always route via the cluster-internal pg-proxy. The proxy reads the
		// database name from the Postgres startup packet and forwards to the
		// dedicated pod — works for every customer DB without per-resource state.
		newHost = "instant-pg-proxy.instant.svc.cluster.local:5432"
	case "redis":
		if providerResourceID == "" {
			return publicURL
		}
		newHost = "redis." + providerResourceID + ".svc.cluster.local:6379"
	case "mongodb":
		if providerResourceID == "" {
			return publicURL
		}
		newHost = "mongo." + providerResourceID + ".svc.cluster.local:27017"
	case "queue":
		if providerResourceID == "" {
			return publicURL
		}
		newHost = "nats." + providerResourceID + ".svc.cluster.local:4222"
	default:
		return publicURL
	}

	parsed.Host = newHost
	return parsed.String()
}

// resourceEnvKey returns the canonical env var name for a resource type.
// index > 0 appends a numeric suffix (DATABASE_URL_2, etc.).
func resourceEnvKey(resourceType string, index int) string {
	var key string
	switch resourceType {
	case "postgres":
		key = "DATABASE_URL"
	case "redis":
		key = "REDIS_URL"
	case "mongodb":
		key = "MONGO_URL"
	case "queue":
		key = "NATS_URL"
	case "storage":
		key = "STORAGE_URL"
	default:
		key = strings.ToUpper(resourceType) + "_URL"
	}
	if index > 0 {
		key = fmt.Sprintf("%s_%d", key, index+1)
	}
	return key
}

// serializeServices converts a slice of StackService to a JSON-friendly slice.
func serializeServices(services []*models.StackService) []fiber.Map {
	result := make([]fiber.Map, 0, len(services))
	for _, ss := range services {
		result = append(result, fiber.Map{
			"name":   ss.Name,
			"status": ss.Status,
			"expose": ss.Expose,
			"port":   ss.Port,
			"url":    ss.AppURL,
		})
	}
	return result
}

// ── runStackDeploy ────────────────────────────────────────────────────────────

// runStackDeploy is run in a goroutine after POST /stacks/new returns 202.
// It calls the stack provider and updates DB rows on each status transition.
func (h *StackHandler) runStackDeploy(
	ctx context.Context,
	stack *models.Stack,
	serviceRows map[string]*models.StackService,
	opts compute.StackDeployOptions,
) {
	onUpdate := func(svcName, status, appURL, errMsg string) {
		ss, ok := serviceRows[svcName]
		if !ok {
			slog.Warn("stack.runDeploy.unknown_service", "name", svcName)
			return
		}
		if dbErr := models.UpdateStackServiceStatus(context.Background(), h.db, ss.ID, status, appURL, errMsg); dbErr != nil {
			slog.Error("stack.runDeploy.update_service", "error", dbErr)
		}
	}

	if err := h.stackProv.DeployStack(ctx, opts, onUpdate); err != nil {
		slog.Error("stack.runDeploy.failed", "slug", stack.Slug, "error", err)
		_ = models.UpdateStackStatus(context.Background(), h.db, stack.ID, "failed", err.Error())
		return
	}
	_ = models.UpdateStackStatus(context.Background(), h.db, stack.ID, "healthy", "")
	slog.Info("stack.runDeploy.healthy", "slug", stack.Slug)
}

// runStackRedeploy is run in a goroutine after POST /stacks/:slug/redeploy returns 202.
func (h *StackHandler) runStackRedeploy(
	ctx context.Context,
	stack *models.Stack,
	serviceRows map[string]*models.StackService,
	stackNamespace string,
	services []compute.StackServiceDef,
) {
	onUpdate := func(svcName, status, appURL, errMsg string) {
		ss, ok := serviceRows[svcName]
		if !ok {
			slog.Warn("stack.runRedeploy.unknown_service", "name", svcName)
			return
		}
		if dbErr := models.UpdateStackServiceStatus(context.Background(), h.db, ss.ID, status, appURL, errMsg); dbErr != nil {
			slog.Error("stack.runRedeploy.update_service", "error", dbErr)
		}
	}

	if err := h.stackProv.RedeployStack(ctx, stackNamespace, services, onUpdate); err != nil {
		slog.Error("stack.runRedeploy.failed", "slug", stack.Slug, "error", err)
		_ = models.UpdateStackStatus(context.Background(), h.db, stack.ID, "failed", err.Error())
		return
	}
	_ = models.UpdateStackStatus(context.Background(), h.db, stack.ID, "healthy", "")
	slog.Info("stack.runRedeploy.healthy", "slug", stack.Slug)
}

// ── POST /stacks/new ─────────────────────────────────────────────────────────

// New handles POST /stacks/new.
// Accepts a multipart form with:
//   - manifest: instant.yaml contents as text
//   - {serviceName}: gzipped tarball for each service declared in the manifest
//   - name: optional human label for the stack
//
// Anonymous deploys are supported (no auth required). Anonymous stacks expire in 24h,
// matching the same model used by /db/new, /cache/new, etc.
func (h *StackHandler) New(c *fiber.Ctx) error {
	// OptionalAuth: team is nil for anonymous deployments (router uses OptionalAuth).
	team, authErr := h.optionalStackTeam(c)
	if authErr != nil {
		return authErr
	}
	// anon is true when no valid session token was presented.
	anon := team == nil

	// Rate limit anonymous deployments before parsing the (potentially large) multipart body.
	if anon {
		fp := middleware.GetFingerprint(c)
		exceeded, limitErr := h.checkStackDeployLimit(c.Context(), fp)
		if limitErr != nil {
			slog.Warn("stack.new.rate_limit_check_failed", "error", limitErr)
			// fail open — Redis errors must not block legitimate deploys
		} else if exceeded {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"ok":      false,
				"error":   "rate_limit_exceeded",
				"message": "Anonymous deploy limit reached. Upgrade at https://instant.dev/start",
			})
		}
	}

	// Step 1: Parse multipart form (max 200 MB — stacks have multiple tarballs).
	form, err := c.MultipartForm()
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_form",
			"Request must be multipart/form-data (max 200 MB)")
	}

	// Step 2: Parse + validate + resolve manifest.
	manifestValues := form.Value["manifest"]
	if len(manifestValues) == 0 || manifestValues[0] == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_manifest",
			"Multipart field 'manifest' is required (instant.yaml contents)")
	}

	m, err := manifest.Parse([]byte(manifestValues[0]))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_manifest", err.Error())
	}

	warnings, err := m.Validate()
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_manifest", err.Error())
	}

	if err := m.Resolve(); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_manifest", err.Error())
	}

	// Step 3: Check all service tarballs are present.
	tarballs := make(map[string][]byte, len(m.Services))
	for name := range m.Services {
		fileHeaders, ok := form.File[name]
		if !ok || len(fileHeaders) == 0 {
			return respondError(c, fiber.StatusBadRequest, "missing_tarball",
				"missing tarball for service: "+name)
		}
		f, openErr := fileHeaders[0].Open()
		if openErr != nil {
			return respondError(c, fiber.StatusBadRequest, "tarball_open_failed",
				"failed to open tarball for service: "+name)
		}
		data, readErr := io.ReadAll(f)
		f.Close()
		if readErr != nil {
			return respondError(c, fiber.StatusBadRequest, "tarball_read_failed",
				"failed to read tarball for service: "+name)
		}
		tarballs[name] = data
	}

	// Step 4: Validate needs: token ownership.
	// Parse the AES key once for decryption in step 5.
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("stack.new.aes_key_parse_failed", "error", err)
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Server configuration error")
	}

	// needsResources maps service name → list of *models.Resource in Needs order.
	needsResources := make(map[string][]*models.Resource, len(m.Services))
	for svcName, svc := range m.Services {
		for _, tokenStr := range svc.Needs {
			tokenUUID, parseErr := parseResourceToken(tokenStr)
			if parseErr != nil {
				return respondError(c, fiber.StatusBadRequest, "invalid_token",
					"invalid resource token: "+tokenStr)
			}
			resource, lookupErr := models.GetResourceByToken(c.Context(), h.db, tokenUUID)
			if lookupErr != nil {
				var notFound *models.ErrResourceNotFound
				if errors.As(lookupErr, &notFound) {
					return respondError(c, fiber.StatusBadRequest, "resource_not_found",
						"resource not found: "+tokenStr)
				}
				slog.Error("stack.new.resource_lookup_failed",
					"error", lookupErr, "token", tokenStr)
				return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed",
					"Failed to look up resource: "+tokenStr)
			}
			if resource.Status == "deleted" {
				return respondError(c, fiber.StatusBadRequest, "resource_not_found",
					"resource not found: "+tokenStr)
			}

			// Cross-team resource ownership check.
			if anon {
				// Anonymous stacks may only reference anonymous (team-less) resources.
				if resource.TeamID.Valid {
					return respondError(c, fiber.StatusForbidden, "forbidden",
						"resource "+tokenStr+" belongs to a team; authentication required")
				}
			} else {
				// Authenticated stacks may only reference resources owned by this team.
				if resource.TeamID.Valid && resource.TeamID.UUID != team.ID {
					return respondError(c, fiber.StatusForbidden, "forbidden",
						"resource "+tokenStr+" belongs to another team")
				}
			}
			needsResources[svcName] = append(needsResources[svcName], resource)
		}
	}

	// Step 5: Build env vars per service from needs:.
	needsEnvByService := make(map[string]map[string]string, len(m.Services))
	for svcName, resources := range needsResources {
		env := make(map[string]string)
		typeIndex := make(map[string]int)
		for _, res := range resources {
			idx := typeIndex[res.ResourceType]
			typeIndex[res.ResourceType]++
			if !res.ConnectionURL.Valid || res.ConnectionURL.String == "" {
				continue
			}
			plainURL, decErr := crypto.Decrypt(aesKey, res.ConnectionURL.String)
			if decErr != nil {
				// Fail open: use ciphertext as-is if decryption fails (key rotation safety).
				slog.Warn("stack.new.decrypt_failed",
					"token", res.Token, "error", decErr)
				plainURL = res.ConnectionURL.String
			}
			// Rewrite the customer-facing URL (LB external host + NodePort or proxy
			// port) to the in-cluster FQDN. Stack pods must connect via cluster DNS
			// because DOKS LoadBalancers don't reliably hairpin and the public IP
			// route adds latency + crosses the namespace egress firewall.
			//
			// Customer's dashboard / `connection_url` field still shows the public URL
			// — only the env injected into in-cluster stack pods is rewritten.
			// Fallback: redis/mongo/queue handlers don't all persist provider_resource_id
			// today (cache.go and nosql.go are missing the UpdateProviderResourceID call).
			// Derive the namespace from the token using the same convention the k8s
			// backends use ("instant-customer-<token>") so the rewrite still works.
			prid := res.ProviderResourceID.String
			if prid == "" || prid == "local:0" {
				prid = "instant-customer-" + res.Token.String()
			}
			plainURL = rewriteToInternalURL(plainURL, res.ResourceType, prid)
			key := resourceEnvKey(res.ResourceType, idx)
			env[key] = plainURL
		}
		needsEnvByService[svcName] = env
	}

	// Step 6: Create stack + service DB rows.
	slug, err := models.GenerateStackSlug()
	if err != nil {
		slog.Error("stack.new.slug_generate_failed", "error", err)
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to generate stack ID")
	}

	// Optional human-readable name.
	name := ""
	if names := form.Value["name"]; len(names) > 0 {
		name = sanitizeName(names[0])
	}

	// Anonymous stacks: nil TeamID + 24h TTL + fingerprint (same model as /db/new).
	// Authenticated stacks: real TeamID + plan tier from the team record.
	var (
		stackTeamID      *uuid.UUID
		stackExpiresAt   *time.Time
		stackFingerprint string
		stackTier        = "anonymous"
	)
	if anon {
		exp := time.Now().Add(24 * time.Hour)
		stackExpiresAt = &exp
		stackFingerprint = middleware.GetFingerprint(c)
	} else {
		stackTeamID = &team.ID
		stackTier = team.PlanTier
	}

	stack, err := models.CreateStack(c.Context(), h.db, models.CreateStackParams{
		TeamID:      stackTeamID,
		Name:        name,
		Slug:        slug,
		Tier:        stackTier,
		ExpiresAt:   stackExpiresAt,
		Fingerprint: stackFingerprint,
	})
	if err != nil {
		logAttrs := []any{"error", err, "request_id", middleware.GetRequestID(c)}
		if anon {
			logAttrs = append(logAttrs, "fingerprint", stackFingerprint)
		} else {
			logAttrs = append(logAttrs, "team_id", team.ID)
		}
		slog.Error("stack.new.db_create_failed", logAttrs...)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed",
			"Failed to create stack record")
	}

	serviceRows := make(map[string]*models.StackService, len(m.Services))
	for svcName, svc := range m.Services {
		ss, svcErr := models.CreateStackService(c.Context(), h.db, models.CreateStackServiceParams{
			StackID: stack.ID,
			Name:    svcName,
			Expose:  svc.Expose,
			Port:    svc.Port,
		})
		if svcErr != nil {
			slog.Error("stack.new.service_create_failed",
				"error", svcErr, "service", svcName,
				"request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusServiceUnavailable, "provision_failed",
				"Failed to create service record for: "+svcName)
		}
		serviceRows[svcName] = ss
	}

	// Step 7: Build StackDeployOptions.
	//
	// Per-service env vars may include "vault://KEY" references. We resolve
	// them here against the team's vault for the production env (stack
	// deploys do not yet expose multi-env scoping; this matches the
	// per-deployment behaviour). Anonymous stacks cannot use vault refs
	// because there is no team to look up.
	services := make([]compute.StackServiceDef, 0, len(m.Services))
	for svcName, svc := range m.Services {
		// Merge: needs env first (low priority), then service-defined env (high priority).
		envVars := make(map[string]string)
		for k, v := range needsEnvByService[svcName] {
			envVars[k] = v
		}
		for k, v := range svc.Env {
			envVars[k] = v
		}

		// Resolve vault:// refs (authenticated only).
		if !anon {
			resolved, vaultErr := ResolveVaultRefs(c.Context(), h.db, h.cfg.AESKey, team.ID, "production", envVars)
			if vaultErr != nil {
				slog.Error("stack.new.vault_resolve_failed",
					"error", vaultErr, "slug", slug, "service", svcName,
					"team_id", team.ID, "request_id", middleware.GetRequestID(c))
				return respondError(c, fiber.StatusBadRequest, "vault_ref_failed",
					"Failed to resolve vault reference for "+svcName+": "+vaultErr.Error())
			}
			envVars = resolved
		} else {
			// Reject vault refs from anonymous callers — fail loud, not silent.
			for k, v := range envVars {
				if strings.HasPrefix(v, vaultRefPrefix) {
					return respondError(c, fiber.StatusForbidden, "vault_requires_auth",
						"vault:// references require authentication: "+svcName+"."+k)
				}
			}
		}

		services = append(services, compute.StackServiceDef{
			Name:    svcName,
			Tarball: tarballs[svcName],
			Port:    svc.Port,
			Expose:  svc.Expose,
			EnvVars: envVars,
		})
	}

	opts := compute.StackDeployOptions{
		StackID:  stack.Slug,
		Tier:     stackTier,
		Services: services,
	}

	// Step 8: Launch async deploy goroutine.
	go h.runStackDeploy(context.Background(), stack, serviceRows, opts)

	logAttrs := []any{
		"slug", slug,
		"services", len(m.Services),
		"request_id", middleware.GetRequestID(c),
	}
	if anon {
		if len(stackFingerprint) >= 8 {
			logAttrs = append(logAttrs, "fingerprint_prefix", stackFingerprint[:8])
		}
	} else {
		logAttrs = append(logAttrs, "team_id", team.ID)
	}
	slog.Info("stack.new.accepted", logAttrs...)

	// Step 9: Return 202.
	noteMsg := "Stack is building. Poll GET /stacks/" + slug + " for status."
	if anon {
		noteMsg += " Anonymous stacks expire in 24h. Upgrade at https://instant.dev/start"
	}
	if len(warnings) > 0 {
		noteMsg = fmt.Sprintf("%d warning(s) from manifest parsing. %s", len(warnings), noteMsg)
	}

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"ok":         true,
		"stack_id":   stack.Slug,
		"status":     "building",
		"tier":       stackTier,
		"expires_in": func() string {
			if anon {
				return "24h"
			}
			return ""
		}(),
		"note": noteMsg,
	})
}

// ── GET /stacks/:slug ─────────────────────────────────────────────────────────

// Get handles GET /stacks/:slug.
// Anonymous requests may fetch anonymous stacks by slug. Authenticated requests
// may only fetch stacks belonging to their team.
func (h *StackHandler) Get(c *fiber.Ctx) error {
	team, authErr := h.optionalStackTeam(c)
	if authErr != nil {
		return authErr
	}

	slug := c.Params("slug")
	stack, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}

	if ownerErr := stackOwnerCheck(c, stack, team); ownerErr != nil {
		return ownerErr
	}

	svcs, err := models.GetStackServicesByStack(c.Context(), h.db, stack.ID)
	if err != nil {
		slog.Error("stack.get.services_failed",
			"error", err, "stack_id", stack.ID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack services")
	}

	resp := fiber.Map{
		"ok":       true,
		"stack_id": stack.Slug,
		"status":   stack.Status,
		"tier":     stack.Tier,
		"name":     stack.Name,
		"services": serializeServices(svcs),
	}
	if stack.ExpiresAt != nil {
		resp["expires_at"] = stack.ExpiresAt
	}
	return c.JSON(resp)
}

// ── GET /stacks/:slug/logs/:svc ───────────────────────────────────────────────

// Logs handles GET /stacks/:slug/logs/:svc — SSE streaming.
// Follows the same OptionalAuth ownership rules as Get.
func (h *StackHandler) Logs(c *fiber.Ctx) error {
	team, authErr := h.optionalStackTeam(c)
	if authErr != nil {
		return authErr
	}

	slug := c.Params("slug")
	stack, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}

	if ownerErr := stackOwnerCheck(c, stack, team); ownerErr != nil {
		return ownerErr
	}

	svcName := c.Params("svc")

	// Tail logs for alive stacks; read-only for stopped/failed.
	follow := stack.Status != "stopped" && stack.Status != "failed"

	logStream, err := h.stackProv.ServiceLogs(c.Context(), stack.Namespace, svcName, follow)
	if err != nil {
		slog.Error("stack.logs.stream_failed",
			"slug", slug, "service", svcName, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "logs_failed",
			"Failed to stream logs: "+err.Error())
	}
	// SSE headers.
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	// logStream.Close() deferred inside callback — defers in the outer handler run
	// before SetBodyStreamWriter's callback executes, which would close the stream early.
	c.Context().Response.SetBodyStreamWriter(func(w *bufio.Writer) {
		defer logStream.Close()
		scanner := bufio.NewScanner(logStream)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintf(w, "data: %s\n\n", line)
			_ = w.Flush()
		}
		fmt.Fprint(w, "data: [end]\n\n")
		_ = w.Flush()
	})

	return nil
}

// ── DELETE /stacks/:slug ──────────────────────────────────────────────────────

// Delete handles DELETE /stacks/:slug.
// Calls TeardownStack on the provider (best-effort), then deletes the DB row.
// Follows the same OptionalAuth ownership rules as Get.
func (h *StackHandler) Delete(c *fiber.Ctx) error {
	team, authErr := h.optionalStackTeam(c)
	if authErr != nil {
		return authErr
	}

	slug := c.Params("slug")
	stack, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}

	if ownerErr := stackOwnerCheck(c, stack, team); ownerErr != nil {
		return ownerErr
	}

	// Teardown compute resources (best-effort — don't block delete on provider errors).
	if teardownErr := h.stackProv.TeardownStack(c.Context(), stack.Namespace); teardownErr != nil {
		slog.Warn("stack.delete.teardown_failed",
			"slug", slug, "namespace", stack.Namespace, "error", teardownErr)
		// Continue to delete the DB row regardless.
	}

	if err := models.DeleteStack(c.Context(), h.db, stack.ID); err != nil {
		slog.Error("stack.delete.db_failed",
			"slug", slug, "error", err,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "delete_failed",
			"Failed to delete stack record")
	}

	if team != nil {
		slog.Info("stack.deleted", "slug", slug, "team_id", team.ID,
			"request_id", middleware.GetRequestID(c))
	} else {
		slog.Info("stack.deleted", "slug", slug, "anonymous", true,
			"request_id", middleware.GetRequestID(c))
	}

	return c.JSON(fiber.Map{
		"ok":      true,
		"message": "Stack deleted",
	})
}

// ── PATCH /stacks/:slug/env ───────────────────────────────────────────────────

// updateStackEnvBody is the JSON body for PATCH /stacks/:slug/env.
type updateStackEnvBody struct {
	Env map[string]string `json:"env"`
}

// UpdateEnv handles PATCH /stacks/:slug/env.
// For MVP: accepts env var overrides and returns a note that they take effect on the
// next redeploy. Env vars are NOT persisted to the DB (no env_vars column on stacks).
// Auth required — anonymous stacks cannot be mutated after creation.
func (h *StackHandler) UpdateEnv(c *fiber.Ctx) error {
	team, err := h.requireStackTeam(c)
	if err != nil {
		return err
	}

	slug := c.Params("slug")
	stack, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}

	// RequireAuth means team is guaranteed non-nil here.
	if stack.TeamID == nil || *stack.TeamID != team.ID {
		return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
	}

	var body updateStackEnvBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Request body must be valid JSON: {\"env\": {\"KEY\": \"VALUE\"}}")
	}
	if len(body.Env) == 0 {
		return respondError(c, fiber.StatusBadRequest, "missing_env",
			"Field 'env' must be a non-empty object")
	}

	slog.Info("stack.env.noted",
		"slug", slug, "team_id", team.ID, "keys_noted", len(body.Env))

	return c.JSON(fiber.Map{
		"ok":      true,
		"message": "Env vars noted. Call POST /stacks/" + slug + "/redeploy with updated tarballs to apply.",
	})
}

// ── POST /stacks/:slug/redeploy ───────────────────────────────────────────────

// Redeploy handles POST /stacks/:slug/redeploy.
// Accepts same multipart form as /stacks/new (updated manifest + tarballs).
// Auth required — anonymous stacks cannot be redeployed.
func (h *StackHandler) Redeploy(c *fiber.Ctx) error {
	team, err := h.requireStackTeam(c)
	if err != nil {
		return err
	}

	slug := c.Params("slug")
	stack, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}

	// RequireAuth means team is guaranteed non-nil here.
	if stack.TeamID == nil || *stack.TeamID != team.ID {
		return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
	}

	// Parse multipart form.
	form, err := c.MultipartForm()
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_form",
			"Request must be multipart/form-data with a 'manifest' field")
	}

	manifestValues := form.Value["manifest"]
	if len(manifestValues) == 0 || manifestValues[0] == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_manifest",
			"Multipart field 'manifest' is required")
	}

	m, err := manifest.Parse([]byte(manifestValues[0]))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_manifest", err.Error())
	}
	if _, err := m.Validate(); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_manifest", err.Error())
	}
	if err := m.Resolve(); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_manifest", err.Error())
	}

	// Read tarballs.
	tarballs := make(map[string][]byte, len(m.Services))
	for name := range m.Services {
		fileHeaders, ok := form.File[name]
		if !ok || len(fileHeaders) == 0 {
			return respondError(c, fiber.StatusBadRequest, "missing_tarball",
				"missing tarball for service: "+name)
		}
		f, openErr := fileHeaders[0].Open()
		if openErr != nil {
			return respondError(c, fiber.StatusBadRequest, "tarball_open_failed",
				"failed to open tarball for service: "+name)
		}
		data, readErr := io.ReadAll(f)
		f.Close()
		if readErr != nil {
			return respondError(c, fiber.StatusBadRequest, "tarball_read_failed",
				"failed to read tarball for service: "+name)
		}
		tarballs[name] = data
	}

	// Build service defs. Resolve "vault://KEY" references in env vars
	// before passing to the compute provider — same semantics as the
	// initial /stacks/new path. Redeploy is always authenticated, so
	// no anonymous-rejection branch is needed here.
	services := make([]compute.StackServiceDef, 0, len(m.Services))
	for svcName, svc := range m.Services {
		envVars := svc.Env
		resolved, vaultErr := ResolveVaultRefs(c.Context(), h.db, h.cfg.AESKey, team.ID, "production", envVars)
		if vaultErr != nil {
			slog.Error("stack.redeploy.vault_resolve_failed",
				"error", vaultErr, "slug", slug, "service", svcName,
				"team_id", team.ID, "request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusBadRequest, "vault_ref_failed",
				"Failed to resolve vault reference for "+svcName+": "+vaultErr.Error())
		}
		services = append(services, compute.StackServiceDef{
			Name:    svcName,
			Tarball: tarballs[svcName],
			Port:    svc.Port,
			Expose:  svc.Expose,
			EnvVars: resolved,
		})
	}

	// Fetch current service rows for DB updates in the goroutine.
	existingSvcs, err := models.GetStackServicesByStack(c.Context(), h.db, stack.ID)
	if err != nil {
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Failed to fetch stack services")
	}
	serviceRows := make(map[string]*models.StackService, len(existingSvcs))
	for _, ss := range existingSvcs {
		serviceRows[ss.Name] = ss
	}

	// Update stack status to "building".
	if updErr := models.UpdateStackStatus(c.Context(), h.db, stack.ID, "building", ""); updErr != nil {
		slog.Warn("stack.redeploy.status_update_failed", "slug", slug, "error", updErr)
	}

	go h.runStackRedeploy(context.Background(), stack, serviceRows, stack.Namespace, services)

	slog.Info("stack.redeploy.accepted",
		"slug", slug, "team_id", team.ID,
		"request_id", middleware.GetRequestID(c))

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"ok":       true,
		"stack_id": stack.Slug,
		"status":   "building",
		"note":     "Redeploy in progress. Poll GET /stacks/" + slug + " for status.",
	})
}

// ── GET /api/v1/stacks ────────────────────────────────────────────────────────

// List handles GET /api/v1/stacks — list all stacks for the team.
// Auth required — anonymous users have no persistent identity to list by.
func (h *StackHandler) List(c *fiber.Ctx) error {
	team, err := h.requireStackTeam(c)
	if err != nil {
		return err
	}

	stacks, err := models.GetStacksByTeam(c.Context(), h.db, team.ID)
	if err != nil {
		slog.Error("stack.list.failed",
			"error", err, "team_id", team.ID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to list stacks")
	}

	items := make([]fiber.Map, 0, len(stacks))
	for _, s := range stacks {
		items = append(items, fiber.Map{
			"stack_id":   s.Slug,
			"name":       s.Name,
			"status":     s.Status,
			"tier":       s.Tier,
			"namespace":  s.Namespace,
			"created_at": s.CreatedAt,
		})
	}

	return c.JSON(fiber.Map{
		"ok":    true,
		"items": items,
		"total": len(items),
	})
}

// ── private helpers ───────────────────────────────────────────────────────────

// parseResourceToken parses a UUID string into a uuid.UUID.
// Returns an error if the string is not a valid UUID.
func parseResourceToken(tokenStr string) ([16]byte, error) {
	return parseTeamID(tokenStr) // same logic: uuid.Parse
}
