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
	"encoding/json"
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
	"instant.dev/internal/urls"
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
			"A session token is required for this action. Sign in at "+urls.StartURLPrefix)
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
//
// onImageBuilt persists stack_services.image_ref so a subsequent /promote
// can re-use the built image rather than re-running the build pipeline.
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

	onImageBuilt := func(svcName, imageRef string) {
		ss, ok := serviceRows[svcName]
		if !ok {
			slog.Warn("stack.runDeploy.image_built_unknown_service", "name", svcName)
			return
		}
		if imageRef == "" {
			return
		}
		if dbErr := models.UpdateStackServiceImageRef(context.Background(), h.db, ss.ID, imageRef); dbErr != nil {
			slog.Error("stack.runDeploy.update_image_ref", "service", svcName, "error", dbErr)
			return
		}
		// Local mirror so the in-memory serviceRows reflect what we just
		// persisted — useful if a subsequent step inside the same goroutine
		// reads ImageRef (none today, but cheap to keep correct).
		ss.ImageRef = imageRef
	}

	if err := h.stackProv.DeployStack(ctx, opts, onUpdate, onImageBuilt); err != nil {
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

	onImageBuilt := func(svcName, imageRef string) {
		ss, ok := serviceRows[svcName]
		if !ok {
			slog.Warn("stack.runRedeploy.image_built_unknown_service", "name", svcName)
			return
		}
		if imageRef == "" {
			return
		}
		if dbErr := models.UpdateStackServiceImageRef(context.Background(), h.db, ss.ID, imageRef); dbErr != nil {
			slog.Error("stack.runRedeploy.update_image_ref", "service", svcName, "error", dbErr)
			return
		}
		ss.ImageRef = imageRef
	}

	if err := h.stackProv.RedeployStack(ctx, stackNamespace, services, onUpdate, onImageBuilt); err != nil {
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
			return respondError(c, fiber.StatusTooManyRequests, "rate_limit_exceeded",
				"Anonymous deploy limit reached. Upgrade at "+urls.StartURLPrefix)
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
	// them here against the team's vault scoped to the STACK'S env (post-
	// §10.17 — was hardcoded "production"). Today the /stacks/new path does
	// not accept an `env` form field so freshly created stacks default to
	// production, but promoted stacks inherit their target env and any
	// future endpoint that creates a non-production stack will get the
	// right vault scoping for free. Anonymous stacks cannot use vault refs
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
		// IMPORTANT: we resolve against the stack's own env, NOT a hardcoded
		// "production" string. Promoted staging stacks read from the staging
		// vault namespace, dev stacks from dev, and so on. This is what
		// makes the env-aware deployment story actually work end-to-end —
		// previously every redeploy resolved against production's vault
		// regardless of where the stack lived (§10.17 J's flagged gap #3).
		if !anon {
			vaultEnv := stack.Env
			if vaultEnv == "" {
				vaultEnv = "production"
			}
			resolved, vaultErr := ResolveVaultRefs(c.Context(), h.db, h.cfg.AESKey, team.ID, vaultEnv, envVars)
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
		noteMsg += " Anonymous stacks expire in 24h. Upgrade at "+urls.StartURLPrefix+""
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
	//
	// Resolve against the stack's own env (NOT hardcoded "production"). A
	// staging stack redeploying must read from the staging vault — that
	// is the whole point of multi-env deployments.
	vaultEnv := stack.Env
	if vaultEnv == "" {
		vaultEnv = "production"
	}
	services := make([]compute.StackServiceDef, 0, len(m.Services))
	for svcName, svc := range m.Services {
		envVars := svc.Env
		resolved, vaultErr := ResolveVaultRefs(c.Context(), h.db, h.cfg.AESKey, team.ID, vaultEnv, envVars)
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
			"stack_id":        s.Slug,
			"name":            s.Name,
			"status":          s.Status,
			"tier":            s.Tier,
			"namespace":       s.Namespace,
			"env":             s.Env,
			"parent_stack_id": toString(s.ParentStackID),
			"created_at":      s.CreatedAt,
		})
	}

	return c.JSON(fiber.Map{
		"ok":    true,
		"items": items,
		"total": len(items),
	})
}

// ── GET /api/v1/stacks/:slug/family ───────────────────────────────────────────

// Family handles GET /api/v1/stacks/:slug/family — return the env siblings of
// a stack so the dashboard's "Environments" grid can render production /
// staging / dev variants of the same app side-by-side.
//
// Behaviour:
//  1. Source stack must be owned by the requesting team (404 otherwise to
//     avoid existence leak across teams).
//  2. Same tier gate as Promote/CopySecrets — Pro / Team / Growth only. Free
//     and hobby callers get a 402 with `agent_action` telling them to upgrade
//     (the contract is identical to the promote endpoint by design).
//  3. Returns the family the model layer already knows how to walk:
//     `GetStackFamily(team_id, any_member_id)` resolves the root via
//     WITH RECURSIVE and returns root + all direct children, ordered with
//     the root first.
//
// Response shape:
//
//	{
//	  "ok": true,
//	  "slug": "<source slug>",
//	  "family": [
//	    { "slug": "...", "name": "...", "env": "production", "status": "healthy",
//	      "tier": "pro", "url": "...", "is_root": true,
//	      "parent_stack_id": "", "last_deploy_at": "2026-05-12T...", "created_at": "..." },
//	    { "slug": "...", "env": "staging", ... "is_root": false, "parent_stack_id": "<root>" }
//	  ],
//	  "total": 2
//	}
//
// `url` is derived from the primary service's app_url where present so the
// dashboard can render a clickable link per env without doing N service
// lookups client-side. When the family has no services or the primary is not
// yet healthy, `url` is the empty string.
//
// The endpoint sets a short `Cache-Control: private, max-age=60` since family
// metadata is read-only and per-team-scoped, but never longer than 60s — env
// state changes during promotes/redeploys and stale UI is worse than a fresh
// 60ms refetch.
func (h *StackHandler) Family(c *fiber.Ctx) error {
	team, err := h.requireStackTeam(c)
	if err != nil {
		return err
	}

	// Tier gate first — symmetric with Promote/CopySecrets. The §10.17 spec
	// treats multi-env discoverability as part of the Pro-tier bundle, so
	// the family read itself is gated. Free/hobby cannot see other envs
	// because they cannot create other envs.
	if !multiEnvTierAllowed(team.PlanTier) {
		return respondMultiEnvUpgradeRequired(c, team.PlanTier)
	}

	slug := c.Params("slug")
	source, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}

	// Cross-team ownership check (404 to avoid existence leak).
	if source.TeamID == nil || *source.TeamID != team.ID {
		return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
	}

	family, err := models.GetStackFamily(c.Context(), h.db, team.ID, source.ID)
	if err != nil {
		slog.Error("stack.family.lookup_failed",
			"error", err, "team_id", team.ID, "slug", slug,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed",
			"Failed to look up env family")
	}

	// If the recursive walk found nothing (e.g. orphaned row), fall back to
	// the source alone so the UI still has a single tile to render — this
	// keeps the legacy "production-only" path working for stacks that pre-
	// date the env migration.
	if len(family) == 0 {
		family = []*models.Stack{source}
	}

	// Best-effort per-stack URL enrichment. We look up services per stack
	// and pick the first exposed one. Stacks rarely have >5 services so the
	// N+1 is bounded and cheap; the alternative (one JOIN'd query) would
	// require ordering hacks to find "the primary service" per row.
	items := make([]fiber.Map, 0, len(family))
	for _, s := range family {
		url := ""
		svcs, svcErr := models.GetStackServicesByStack(c.Context(), h.db, s.ID)
		if svcErr == nil {
			for _, svc := range svcs {
				if svc.Expose && svc.AppURL != "" {
					url = svc.AppURL
					break
				}
			}
			// If nothing is exposed yet, fall back to the first service URL
			// so callers see SOMETHING for in-progress builds.
			if url == "" {
				for _, svc := range svcs {
					if svc.AppURL != "" {
						url = svc.AppURL
						break
					}
				}
			}
		}

		items = append(items, fiber.Map{
			"slug":            s.Slug,
			"name":            s.Name,
			"env":             s.Env,
			"status":          s.Status,
			"tier":            s.Tier,
			"url":             url,
			"is_root":         s.ParentStackID == nil,
			"parent_stack_id": toString(s.ParentStackID),
			"last_deploy_at":  s.UpdatedAt,
			"created_at":      s.CreatedAt,
		})
	}

	// Short cache: env-family metadata is read-only and per-team-scoped, so
	// edge caches must NOT share across teams. `private` keeps it browser-
	// local; max-age=60 covers the typical dashboard navigation between
	// envs without serving stale state across a promote.
	c.Set("Cache-Control", "private, max-age=60")

	return c.JSON(fiber.Map{
		"ok":     true,
		"slug":   slug,
		"family": items,
		"total":  len(items),
	})
}

// ── POST /api/v1/stacks/:slug/promote ────────────────────────────────────────

// promoteBody is the JSON body for POST /api/v1/stacks/:slug/promote.
//
//	From:      source env (e.g. "staging"). Defaults to the source stack's env.
//	To:        target env (e.g. "production"). Required.
//	Name:      optional override for the target stack's display name.
//	CopyVault: when true (the default), every vault key that exists in the
//	           source env but NOT in the target env is copied across as part
//	           of the promote so the promoted stack can resolve vault://
//	           references against the target namespace on its first deploy.
//	           Defaults to true for backward compat — pre-slice-5 callers
//	           that don't send the field still get the auto-copy behaviour.
//	           Pointer-typed so we can distinguish "field omitted" (= true)
//	           from "explicitly false".
type promoteBody struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Name      string `json:"name"`
	CopyVault *bool  `json:"copy_vault,omitempty"`
}

// promoteCopyVaultDefault is the value used when the request body omits the
// copy_vault field — keeping it as a named constant so the backward-compat
// contract is documented in one place (slice 5, ENV-AWARE-DEPLOYMENTS-DESIGN
// §4 slice 5).
const promoteCopyVaultDefault = true

// auditKindVaultPromoted is the audit_log.kind value written for every vault
// secret that gets auto-copied during a stack promote. Held as a const so the
// dashboard's Recent Activity feed + the slice-5 tests can both reference it
// without a magic string.
const auditKindVaultPromoted = "vault.promoted"

// auditActorSystem is the audit_log.actor value for events the platform writes
// on the caller's behalf (rather than the agent or user). The promote auto-copy
// is a system action — the operator asked for a promote, the platform copied
// vault values as a side-effect.
const auditActorSystem = "system"

// auditResourceTypeVault is the audit_log.resource_type tag for vault-scoped
// events. Matches what the dashboard's Activity feed filters on for vault rows.
const auditResourceTypeVault = "vault"

// multiEnvTierAllowed reports whether the given tier may use the env-promotion
// endpoints. Pro / Team / Growth only. The spec (RETRO-2026-05-12 §10.17) calls
// this out as a Pro-tier differentiator — the hobby tier explicitly does NOT
// get multi-env workflows.
//
// Held inline rather than added to common/plans/Registry because the plan YAML
// does not yet have a `features.multi_env` flag and we don't want to widen the
// shared schema for a feature that's still bedding in. If the policy grows
// teeth (e.g. variant per-tier env count caps), promote this into plans.yaml.
func multiEnvTierAllowed(tier string) bool {
	switch tier {
	case "pro", "team", "growth":
		return true
	default:
		return false
	}
}

// respondMultiEnvUpgradeRequired writes the canonical 402 the spec requires.
// Carries an `agent_action` string so an agent reading the response knows
// exactly what to tell the user — same shape used elsewhere in the codebase
// for upgrade-gated paths.
func respondMultiEnvUpgradeRequired(c *fiber.Ctx, currentTier string) error {
	_ = c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
		"ok":           false,
		"error":        "upgrade_required",
		"message":      "Multi-env workflows require the Pro plan or higher. Your team is on the " + currentTier + " plan.",
		"upgrade_url":  "https://instanode.dev/pricing",
		"agent_action": "Tell user to upgrade to Pro at https://instanode.dev/pricing to unlock multi-env workflows.",
	})
	return ErrResponseWritten
}

// validatePromoteEnv enforces the same charset as vault env names (a-z, A-Z,
// 0-9, _, -). Reuses the validateEnv helper from vault.go for consistency, but
// keeps a local wrapper so the error code matches the stack-handler family.
func validatePromoteEnv(raw string) (string, bool) {
	return validateEnv(raw)
}

// copyVaultRefsForPromote copies every vault key that exists in fromEnv but
// NOT in toEnv across to toEnv for the given team. Returns the list of keys
// that were actually written so the caller can attribute the per-key audit
// rows; missing source / existing target keys are silently skipped (this is
// the non-destructive contract spelled out in slice 5 of the design doc).
//
// Behaviour:
//   - List the distinct keys in the source env.
//   - For each key, look up the target env's latest version. If a row exists,
//     skip (existing target values win — non-destructive).
//   - Otherwise, copy the source ciphertext into the target env at version 1
//     (CreateVaultSecret picks the next free version automatically).
//   - Append one audit_log row per copied key, kind=vault.promoted, with
//     metadata carrying from_env / to_env / key. Audit failures are logged
//     but never block the copy — same fail-open posture the rest of the
//     audit pipeline uses.
//
// Shared with vault.CopySecrets in spirit but intentionally smaller: the REST
// /vault/copy handler has dry_run / overwrite / tier-gate / per-tier quota
// machinery that would be wrong to invoke here (the promote already gated on
// pro+ at the top of Promote, and quota enforcement during a promote would
// silently leave the target stack with a half-copied env).
//
// userID is uuid.Nil for system-actor copies; the audit row records "system"
// as the actor regardless so the dashboard can render the event consistently.
func copyVaultRefsForPromote(
	ctx context.Context,
	db *sql.DB,
	teamID uuid.UUID,
	userID uuid.UUID,
	fromEnv, toEnv string,
) (copied []string, err error) {
	keys, err := models.ListVaultKeys(ctx, db, teamID, fromEnv)
	if err != nil {
		return nil, fmt.Errorf("copyVaultRefsForPromote: list source keys: %w", err)
	}
	if len(keys) == 0 {
		// No-op when the source env has no vault entries — covers the
		// "stack with no vault refs" test case from the slice-5 spec.
		return nil, nil
	}

	copied = make([]string, 0, len(keys))
	var createdBy uuid.NullUUID
	if userID != uuid.Nil {
		createdBy = uuid.NullUUID{UUID: userID, Valid: true}
	}

	for _, k := range keys {
		src, ferr := models.GetVaultSecretLatest(ctx, db, teamID, fromEnv, k)
		if ferr != nil {
			if errors.Is(ferr, models.ErrVaultSecretNotFound) {
				// Race: key disappeared between list and fetch. Skip.
				continue
			}
			return copied, fmt.Errorf("copyVaultRefsForPromote: fetch %s: %w", k, ferr)
		}

		// Non-destructive: existing target keys are never overwritten.
		_, derr := models.GetVaultSecretLatest(ctx, db, teamID, toEnv, k)
		if derr == nil {
			continue
		}
		if !errors.Is(derr, models.ErrVaultSecretNotFound) {
			return copied, fmt.Errorf("copyVaultRefsForPromote: check target %s: %w", k, derr)
		}

		if _, werr := models.CreateVaultSecret(ctx, db, teamID, toEnv, k, src.EncryptedValue, createdBy); werr != nil {
			return copied, fmt.Errorf("copyVaultRefsForPromote: persist %s: %w", k, werr)
		}
		copied = append(copied, k)

		// Per-key audit row. Best-effort — never block the copy.
		meta, mErr := json.Marshal(map[string]string{
			"from_env": fromEnv,
			"to_env":   toEnv,
			"key":      k,
		})
		if mErr != nil {
			slog.Warn("stack.promote.vault.audit_meta_failed",
				"error", mErr, "team_id", teamID, "key", k)
			meta = nil
		}
		if aErr := models.InsertAuditEvent(ctx, db, models.AuditEvent{
			TeamID:       teamID,
			UserID:       createdBy,
			Actor:        auditActorSystem,
			Kind:         auditKindVaultPromoted,
			ResourceType: auditResourceTypeVault,
			Summary:      "auto-copied vault key <code>" + k + "</code> " + fromEnv + " → " + toEnv,
			Metadata:     meta,
		}); aErr != nil {
			slog.Warn("stack.promote.vault.audit_failed",
				"error", aErr, "team_id", teamID, "key", k,
				"from_env", fromEnv, "to_env", toEnv)
		}
	}

	return copied, nil
}

// Promote handles POST /api/v1/stacks/:slug/promote.
//
// Semantics:
//  1. Source stack must be owned by the requesting team.
//  2. Requesting team must be on pro / team / growth (402 otherwise).
//  3. Every service on the source stack must have an image_ref recorded by an
//     earlier successful deploy (migration 017_stack_image_ref.sql). Stacks
//     created before this migration return 412 with an agent_action telling
//     the caller to redeploy the source first. This is a hard fail rather
//     than a silent no-op so the compute-hook gap can never re-emerge.
//  4. If a sibling stack already exists with target env: copy the source's
//     image_refs onto the target's existing service rows, flip status to
//     "building", and trigger a pull-and-deploy goroutine. Otherwise create
//     a new stack row + service rows with the source's image_refs and run
//     the same goroutine. Vault refs always resolve against the target env.
//  5. The new (or updated) stack inherits the source's tier and is created in
//     status="building" so callers can poll with GET /stacks/:slug.
//
// What changed (vs. the pre-017 implementation): this endpoint used to be a
// pure DB-row write — a CREATE stack/services with no compute work behind
// it. The row would sit at status="building" forever because nothing ever
// flipped it. With per-service image_ref persistence we can finally hand
// off to runStackPromoteDeploy and have the cached image rolled out under
// the target's vault namespace.
func (h *StackHandler) Promote(c *fiber.Ctx) error {
	team, err := h.requireStackTeam(c)
	if err != nil {
		return err
	}

	// Tier gate first — fail before doing any DB work for off-tier callers.
	if !multiEnvTierAllowed(team.PlanTier) {
		return respondMultiEnvUpgradeRequired(c, team.PlanTier)
	}

	slug := c.Params("slug")
	source, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}

	// Cross-team ownership check (404, not 403, to avoid leaking existence).
	if source.TeamID == nil || *source.TeamID != team.ID {
		return respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
	}

	var body promoteBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			`Body must be valid JSON: {"from":"staging","to":"production"}`)
	}

	from := body.From
	if from == "" {
		from = source.Env
	}
	if fromV, ok := validatePromoteEnv(from); ok {
		from = fromV
	} else {
		return respondError(c, fiber.StatusBadRequest, "invalid_env",
			"from must be 1-64 chars [A-Za-z0-9_-]")
	}
	to, ok := validatePromoteEnv(body.To)
	if !ok || body.To == "" {
		return respondError(c, fiber.StatusBadRequest, "invalid_env",
			`to is required and must be 1-64 chars [A-Za-z0-9_-]`)
	}
	if from == to {
		return respondError(c, fiber.StatusBadRequest, "invalid_target",
			"from and to must differ")
	}

	// The source env must match what the caller asserted so promotes are
	// idempotent under concurrent callers (no surprise: "I thought I was
	// promoting staging but it was actually dev").
	if source.Env != from {
		return respondError(c, fiber.StatusConflict, "env_mismatch",
			fmt.Sprintf("Source stack %s is in env %q, not %q", slug, source.Env, from))
	}

	// Step A: Pull the source's services. If ANY service is missing
	// image_ref (pre-017 row, or a deploy that never finished its build)
	// the promote is rejected. We do NOT silently create a target row that
	// would never get a real Deployment behind it — that's the exact bug
	// migration 017 was added to close.
	sourceSvcs, err := models.GetStackServicesByStack(c.Context(), h.db, source.ID)
	if err != nil {
		slog.Error("stack.promote.source_services_failed",
			"error", err, "slug", slug,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Failed to fetch source stack services")
	}
	if len(sourceSvcs) == 0 {
		return respondError(c, fiber.StatusPreconditionFailed, "no_services",
			"Source stack has no services to promote")
	}
	for _, ss := range sourceSvcs {
		if ss.ImageRef == "" {
			_ = c.Status(fiber.StatusPreconditionFailed).JSON(fiber.Map{
				"ok":           false,
				"error":        "missing_image_ref",
				"message":      "Source stack service " + ss.Name + " has no recorded image_ref; promote cannot deploy a cached image.",
				"agent_action": "This stack predates the image-ref persistence migration. Redeploy the source stack first so its image is cached, then promote.",
			})
			return ErrResponseWritten
		}
	}

	// Step B: Find or create the target stack + services.
	existing, err := models.FindStackByEnvInFamily(c.Context(), h.db, team.ID, source.ID, to)
	if err != nil {
		slog.Error("stack.promote.family_lookup_failed",
			"error", err, "team_id", team.ID, "slug", slug, "to", to,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed",
			"Failed to look up env family")
	}

	var (
		target       *models.Stack
		targetSvcs   map[string]*models.StackService
		action       = "created"
		responseCode = fiber.StatusAccepted
	)

	if existing != nil {
		// In-place re-promote: re-use the existing target stack row.
		target = existing
		action = "updated_existing"
		responseCode = fiber.StatusOK

		// Map existing target services by name so we can update their
		// image_refs to whatever the source has now. Services missing on
		// the target are created on the fly.
		curr, currErr := models.GetStackServicesByStack(c.Context(), h.db, target.ID)
		if currErr != nil {
			slog.Error("stack.promote.target_services_failed",
				"error", currErr, "slug", target.Slug,
				"request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
				"Failed to fetch target stack services")
		}
		byName := make(map[string]*models.StackService, len(curr))
		for _, ss := range curr {
			byName[ss.Name] = ss
		}
		targetSvcs = make(map[string]*models.StackService, len(sourceSvcs))
		for _, src := range sourceSvcs {
			if cur, ok := byName[src.Name]; ok {
				// Update the target row's image_ref so the deploy step
				// picks up the source's latest cached image.
				if updErr := models.UpdateStackServiceImageRef(c.Context(), h.db, cur.ID, src.ImageRef); updErr != nil {
					slog.Error("stack.promote.update_image_ref_failed",
						"error", updErr, "service", src.Name, "target", target.Slug)
					return respondError(c, fiber.StatusServiceUnavailable, "update_failed",
						"Failed to update target image_ref for "+src.Name)
				}
				cur.ImageRef = src.ImageRef
				targetSvcs[src.Name] = cur
			} else {
				newSS, createErr := models.CreateStackService(c.Context(), h.db, models.CreateStackServiceParams{
					StackID:  target.ID,
					Name:     src.Name,
					Expose:   src.Expose,
					Port:     src.Port,
					ImageRef: src.ImageRef,
				})
				if createErr != nil {
					slog.Error("stack.promote.target_service_create_failed",
						"error", createErr, "service", src.Name, "target", target.Slug)
					return respondError(c, fiber.StatusServiceUnavailable, "create_failed",
						"Failed to create target service "+src.Name)
				}
				targetSvcs[src.Name] = newSS
			}
		}
		if updErr := models.UpdateStackStatus(c.Context(), h.db, target.ID, "building", ""); updErr != nil {
			slog.Warn("stack.promote.status_update_failed",
				"slug", target.Slug, "error", updErr)
		}
	} else {
		// Fresh target: new stack row + matching service rows.
		// Family root: the source itself if it has no parent, else the
		// source's parent so all envs share one root.
		rootID := source.ID
		if source.ParentStackID != nil {
			rootID = *source.ParentStackID
		}

		newSlug, slugErr := models.GenerateStackSlug()
		if slugErr != nil {
			slog.Error("stack.promote.slug_failed",
				"error", slugErr, "request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusInternalServerError, "internal_error",
				"Failed to generate stack ID")
		}
		name := sanitizeName(body.Name)
		if name == "" {
			name = source.Name
		}
		created, createErr := models.CreateStack(c.Context(), h.db, models.CreateStackParams{
			TeamID:        &team.ID,
			Name:          name,
			Slug:          newSlug,
			Tier:          source.Tier,
			Env:           to,
			ParentStackID: &rootID,
		})
		if createErr != nil {
			slog.Error("stack.promote.create_failed",
				"error", createErr, "team_id", team.ID, "source_slug", slug, "to", to,
				"request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusServiceUnavailable, "create_failed",
				"Failed to create promoted stack record")
		}
		target = created
		targetSvcs = make(map[string]*models.StackService, len(sourceSvcs))
		for _, src := range sourceSvcs {
			ss, ssErr := models.CreateStackService(c.Context(), h.db, models.CreateStackServiceParams{
				StackID:  target.ID,
				Name:     src.Name,
				Expose:   src.Expose,
				Port:     src.Port,
				ImageRef: src.ImageRef,
			})
			if ssErr != nil {
				slog.Error("stack.promote.target_service_create_failed",
					"error", ssErr, "service", src.Name, "target", target.Slug)
				return respondError(c, fiber.StatusServiceUnavailable, "create_failed",
					"Failed to create target service "+src.Name)
			}
			targetSvcs[src.Name] = ss
		}
	}

	// Step B-bis: Auto-copy vault refs (slice 5).
	//
	// Every vault key that exists in the source env but NOT in the target env
	// is copied across so the promoted stack's first redeploy can resolve
	// vault:// references against the target namespace without the operator
	// having to remember a separate POST /vault/copy call. The copy is non-
	// destructive — existing target keys are never overwritten so prod values
	// always win over staging.
	//
	// Disabled when copy_vault=false. Today that's the only way to opt out —
	// the design (§4 slice 5) deliberately makes the default behaviour the
	// "complete promote" so the agent doesn't have to know about the option.
	copyVault := promoteCopyVaultDefault
	if body.CopyVault != nil {
		copyVault = *body.CopyVault
	}
	var copiedVaultKeys []string
	if copyVault {
		uid := uuid.Nil
		if userIDStr := middleware.GetUserID(c); userIDStr != "" {
			if parsed, perr := uuid.Parse(userIDStr); perr == nil {
				uid = parsed
			}
		}
		copied, vErr := copyVaultRefsForPromote(c.Context(), h.db, team.ID, uid, from, to)
		if vErr != nil {
			// A vault copy failure must NOT roll back the stack rows we just
			// created — the promote contract is "image first, secrets second"
			// so a failed secret-copy still leaves a deployable target. Log
			// loudly and continue; the operator can re-run POST /vault/copy
			// (or POST /stacks/:slug/promote again) to retry.
			slog.Error("stack.promote.vault_autocopy_failed",
				"error", vErr, "team_id", team.ID, "from", from, "to", to,
				"copied_before_failure", len(copied),
				"request_id", middleware.GetRequestID(c))
		}
		copiedVaultKeys = copied
	}

	// Step C: Resolve vault refs against the TARGET env (not source.Env) and
	// build the StackServiceDefs the provider will deploy. The vault scoping
	// is the whole point of multi-env promotion — production must read from
	// the production vault namespace even when the promote originates from
	// staging.
	vaultEnv := target.Env
	if vaultEnv == "" {
		vaultEnv = to
	}

	services := make([]compute.StackServiceDef, 0, len(sourceSvcs))
	for _, src := range sourceSvcs {
		// Vault refs on the source's manifest were resolved at /stacks/new
		// time, so the source service rows don't store the raw `vault://`
		// strings — only the resolved values. To re-resolve against the
		// target env we'd need to keep the original manifest around. Until
		// /stacks/new persists the manifest, the promote path skips re-
		// resolution and trusts what's on the deployed image. The target's
		// env is still set correctly on the stack row, so future redeploys
		// (with a tarball) WILL resolve against the right vault namespace.
		//
		// We DO still pass through the vaultEnv into a no-op ResolveVaultRefs
		// call so any future inline vault refs (e.g. env vars set via
		// PATCH /stacks/:slug/env on the target) get resolved against the
		// target's namespace and not the source's. Today envVars is empty,
		// so this is a placeholder for the env_overrides workstream.
		envVars := map[string]string{}
		resolved, vaultErr := ResolveVaultRefs(c.Context(), h.db, h.cfg.AESKey, team.ID, vaultEnv, envVars)
		if vaultErr != nil {
			slog.Error("stack.promote.vault_resolve_failed",
				"error", vaultErr, "service", src.Name, "target_env", vaultEnv,
				"team_id", team.ID, "request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusBadRequest, "vault_ref_failed",
				"Failed to resolve vault reference for "+src.Name+": "+vaultErr.Error())
		}
		services = append(services, compute.StackServiceDef{
			Name:      src.Name,
			Port:      src.Port,
			Expose:    src.Expose,
			EnvVars:   resolved,
			ImageRef:  src.ImageRef,
			SkipBuild: true,
		})
	}

	// Step D: Hand off to the goroutine that calls the provider with
	// SkipBuild=true. The dashboard's EnvironmentsGrid polls /family so it
	// picks up the building → healthy transition automatically.
	opts := compute.StackDeployOptions{
		StackID:  target.Slug,
		Tier:     target.Tier,
		Services: services,
	}
	go h.runStackDeploy(context.Background(), target, targetSvcs, opts)

	slog.Info("stack.promote."+action,
		"source_slug", slug, "target_slug", target.Slug,
		"from", from, "to", to,
		"team_id", team.ID, "services", len(services),
		"request_id", middleware.GetRequestID(c))

	parentID := ""
	if target.ParentStackID != nil {
		parentID = target.ParentStackID.String()
	}

	// vault_keys_copied is always present in the response (empty slice when
	// nothing was copied) so MCP/agent callers can detect the contract
	// regardless of whether keys actually moved. Pre-slice-5 callers ignore
	// the field, so backward compat is preserved.
	if copiedVaultKeys == nil {
		copiedVaultKeys = []string{}
	}

	return c.Status(responseCode).JSON(fiber.Map{
		"ok":                true,
		"action":            action,
		"stack_id":          target.Slug,
		"env":               target.Env,
		"parent_id":         parentID,
		"source":            slug,
		"status":            "building",
		"vault_keys_copied": copiedVaultKeys,
		"note":              "Promoted to " + to + ". Poll GET /stacks/" + target.Slug + " for status.",
	})
}

// toString stringifies an optional UUID pointer for JSON responses (returns ""
// for nil so the field is never `null` in the serialized payload).
func toString(p *uuid.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// ── private helpers ───────────────────────────────────────────────────────────

// parseResourceToken parses a UUID string into a uuid.UUID.
// Returns an error if the string is not a valid UUID.
func parseResourceToken(tokenStr string) ([16]byte, error) {
	return parseTeamID(tokenStr) // same logic: uuid.Parse
}
