package handlers

// deploy.go — Container deployment endpoints (Phase 6).
//
// All endpoints require authentication — anonymous deploy is not supported.
//
// Routes:
//   POST   /deploy/new         — upload tarball, get back deployment ID + URL
//   GET    /deploy/:id         — fetch deployment status
//   GET    /deploy/:id/logs    — SSE streaming logs
//   PATCH  /deploy/:id/env     — update env vars (redeploy required to apply)
//   DELETE /deploy/:id         — teardown + delete
//   POST   /deploy/:id/redeploy — rebuild + rolling update
//
// The actual compute work is delegated to a compute.Provider so the handler
// is not tied to any specific backend (k8s, noop, future Fly.io, etc.).

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/urls"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute"
	"instant.dev/internal/providers/compute/k8s"
	"instant.dev/internal/providers/compute/noop"
)

// maxAllowedIPs caps the size of the allowed_ips list on a private deploy.
// Anything bigger belongs in a real VPN / CF Access policy — the goal here is
// "agent locks the staging app to the office IP", not corporate networking.
const maxAllowedIPs = 32

// privateDeployAllowedTiers is the set of tiers permitted to use private=true.
// Hobby / anonymous / free fall through to the 402 wall.
var privateDeployAllowedTiers = map[string]bool{
	"pro":         true,
	"pro_yearly":  true,
	"team":        true,
	"team_yearly": true,
	"growth":      true,
}

// DeployHandler handles all /deploy endpoints.
type DeployHandler struct {
	db           *sql.DB
	rdb          *redis.Client
	cfg          *config.Config
	compute      compute.Provider
	planRegistry *plans.Registry
}

// NewDeployHandler initialises the handler and selects the compute backend based on
// cfg.ComputeProvider. Falls back to noop if k8s init fails.
//
// planRegistry supplies tier-specific limits (deployments_apps from plans.yaml).
// It is required — pass plans.Default() in tests if you don't have a loaded registry.
func NewDeployHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, planRegistry *plans.Registry) *DeployHandler {
	var cp compute.Provider
	switch cfg.ComputeProvider {
	case "k8s":
		k8sProv, err := k8s.New(cfg.KubeNamespaceApps, buildContextConfigFromCfg(cfg))
		if err != nil {
			slog.Error("deploy: k8s provider init failed — falling back to noop", "error", err)
			cp = noop.New()
		} else {
			cp = k8sProv
		}
	default:
		cp = noop.New()
	}
	return &DeployHandler{db: db, rdb: rdb, cfg: cfg, compute: cp, planRegistry: planRegistry}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// truncateForAudit caps an error summary so a multi-paragraph build log
// doesn't blow up audit_log.metadata. The full error stays in
// deployments.error_message; audit_log carries the headline only.
func truncateForAudit(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// emitDeployAudit writes one row to audit_log best-effort. Runs in a
// goroutine so a slow audit insert never blocks the deploy goroutine that
// just updated the row's terminal status. kind is one of
// AuditKindDeployCreated / AuditKindDeployHealthy / AuditKindDeployFailed.
func emitDeployAudit(db *sql.DB, kind string, d *models.Deployment, extra map[string]any) {
	go func() {
		meta := map[string]any{
			"deploy_id": d.ID.String(),
			"team_id":   d.TeamID.String(),
		}
		for k, v := range extra {
			meta[k] = v
		}
		metaBlob, _ := json.Marshal(meta)

		summary := "deploy " + d.AppID + " " + strings.TrimPrefix(kind, "deploy.")
		ev := models.AuditEvent{
			TeamID:       d.TeamID,
			Actor:        "system",
			Kind:         kind,
			ResourceType: "deploy",
			Summary:      summary,
			Metadata:     metaBlob,
		}
		if err := models.InsertAuditEvent(context.Background(), db, ev); err != nil {
			slog.Warn("audit.emit.failed",
				"kind", kind,
				"team_id", d.TeamID,
				"deploy_id", d.ID,
				"error", err,
			)
		}
	}()
}

// generateAppID produces an 8-char lowercase hex string via crypto/rand.
func generateAppID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// deploymentToMap converts a Deployment to a JSON-friendly fiber.Map.
//
// Naming collision note: prior to multi-environment support the response field
// "env" was already in use to expose the deployment's env_vars map. We keep
// that meaning for backwards compatibility and add a separate "environment"
// field for the new env scope (production / staging / dev / ...). Callers can
// continue to read .env as a map of vars; .environment is the scope name.
func deploymentToMap(d *models.Deployment) fiber.Map {
	// allowed_ips is always emitted (as [] when empty) so a Pro-tier dashboard
	// can branch on "is this deployment private?" without having to special-case
	// the missing-key path. private mirrors the column verbatim.
	allowedIPs := d.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = []string{}
	}
	m := fiber.Map{
		"id":          d.ID,
		"token":       d.AppID, // public-facing alias
		"app_id":      d.AppID,
		"provider_id": d.ProviderID,
		"url":         d.AppURL,
		"port":        d.Port,
		"tier":        d.Tier,
		"status":      d.Status,
		"env":         d.EnvVars,
		"environment": d.Env,
		"private":     d.Private,
		"allowed_ips": allowedIPs,
		"created_at":  d.CreatedAt,
		"updated_at":  d.UpdatedAt,
		"team_id":     d.TeamID,
		// notify_webhook surface (migration 026): URL is echoed back (the
		// caller supplied it, so no secret is leaked); secret + state +
		// attempts are emitted only when a webhook is configured so we
		// don't pollute the shape for legacy callers. The plaintext
		// secret is NEVER returned — only its lifecycle metadata.
		"notify_webhook": d.NotifyWebhook,
		"notify_state":   d.NotifyState,
	}
	if d.NotifyWebhook != "" {
		m["notify_attempts"] = d.NotifyAttempts
		m["notify_secret_set"] = d.NotifyWebhookSecret != ""
	}
	if d.ErrorMessage != "" {
		m["error"] = d.ErrorMessage
	}
	if d.ResourceID.Valid {
		m["resource_id"] = d.ResourceID.UUID
	}
	return m
}

// requireTeam extracts and validates the team from the request context.
// Returns (team, teamUUID, nil) on success; calls respondError and returns on failure.
func (h *DeployHandler) requireTeam(c *fiber.Ctx) (*models.Team, error) {
	teamIDStr := middleware.GetTeamID(c)
	if teamIDStr == "" {
		return nil, respondError(c, fiber.StatusUnauthorized, "unauthorized",
			"A session token is required to deploy. Sign in at "+urls.StartURLPrefix)
	}
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_team",
			"Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(c.Context(), h.db, teamUUID)
	if err != nil {
		slog.Error("deploy.team_lookup_failed",
			"error", err, "team_id", teamIDStr,
			"request_id", middleware.GetRequestID(c))
		return nil, respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed",
			"Failed to look up team")
	}
	return team, nil
}

// ── runDeploy — async provisioning goroutine ─────────────────────────────────

// runDeploy is run in a goroutine after POST /deploy/new returns 202.
// It calls the compute provider, then updates the deployment record in DB.
//
// Before the compute call, every "vault://KEY" entry in d.EnvVars is replaced
// with the decrypted plaintext from the team's vault for d.Env. The plaintext
// is passed to the compute provider but never written back to the deployments
// row, so vault rotations take effect on the next redeploy.
func (h *DeployHandler) runDeploy(d *models.Deployment, tarball []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	startedAt := time.Now()

	resolvedEnv, err := ResolveVaultRefs(ctx, h.db, h.cfg.AESKey, d.TeamID, d.Env, d.EnvVars)
	if err != nil {
		slog.Error("deploy.run_deploy.vault_resolve_failed",
			"app_id", d.AppID, "team_id", d.TeamID, "env", d.Env, "error", err)
		_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, "failed", err.Error())
		// vault resolution happens before the build step — classify as build-stage.
		emitDeployAudit(h.db, models.AuditKindDeployFailed, d, map[string]any{
			"failure_stage": "build",
			"error_summary": truncateForAudit(err.Error(), 256),
		})
		return
	}

	opts := compute.DeployOptions{
		AppID:      d.AppID,
		Token:      d.ID.String(),
		Tarball:    tarball,
		Port:       d.Port,
		Tier:       d.Tier,
		EnvVars:    resolvedEnv,
		Private:    d.Private,
		AllowedIPs: d.AllowedIPs,
	}
	result, err := h.compute.Deploy(ctx, opts)
	if err != nil {
		slog.Error("deploy.run_deploy.failed",
			"app_id", d.AppID, "error", err)
		_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, "failed", err.Error())
		// compute.Deploy bundles both the image build and the apply/rollout
		// step. Without a structured error type from the provider we can't
		// distinguish in this layer; default to "build" as the most common
		// failure mode (kaniko build > kube apply).
		emitDeployAudit(h.db, models.AuditKindDeployFailed, d, map[string]any{
			"failure_stage": "build",
			"error_summary": truncateForAudit(err.Error(), 256),
		})
		return
	}
	_ = models.UpdateDeploymentProviderID(ctx, h.db, d.ID, result.ProviderID, result.AppURL)
	_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, result.Status, "")

	// audit_log emit: deploy.healthy fires once compute.Deploy returns
	// without error and the deployment row has been stamped with the
	// provider id + status. time_to_healthy is measured from runDeploy
	// entry; for k8s this includes the kaniko build + apply pipeline.
	emitDeployAudit(h.db, models.AuditKindDeployHealthy, d, map[string]any{
		"time_to_healthy_seconds": int(time.Since(startedAt).Round(time.Second).Seconds()),
	})
}

// ── POST /deploy/new ─────────────────────────────────────────────────────────

// New handles POST /deploy/new.
// Accepts a multipart form with:
//   - tarball: gzipped tar archive containing the Dockerfile + source (max 50 MB)
//   - name:    optional human label
//   - port:    optional container port (default 8080)
func (h *DeployHandler) New(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("deploy") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Container deployment is coming in Phase 6. Sign up at "+urls.StartURLPrefix+" to be notified.")
	}

	team, err := h.requireTeam(c)
	if err != nil {
		return err // respondError already called
	}

	// Parse multipart form (max 50 MB).
	form, err := c.MultipartForm()
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_form",
			"Request must be multipart/form-data (max 50 MB)")
	}

	// tarball field.
	tarballs := form.File["tarball"]
	if len(tarballs) == 0 {
		return respondError(c, fiber.StatusBadRequest, "missing_tarball",
			"Multipart field 'tarball' is required")
	}
	fh := tarballs[0]
	if fh.Size > 50<<20 {
		return respondError(c, fiber.StatusBadRequest, "tarball_too_large",
			"Tarball must be at most 50 MB")
	}
	f, err := fh.Open()
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "tarball_open_failed",
			"Failed to read tarball")
	}
	defer f.Close()

	tarball := make([]byte, fh.Size)
	if _, err := f.Read(tarball); err != nil {
		return respondError(c, fiber.StatusBadRequest, "tarball_read_failed",
			"Failed to read tarball bytes")
	}

	// Optional name field.
	name := ""
	if names := form.Value["name"]; len(names) > 0 {
		name = sanitizeName(names[0])
	}

	// Optional port field (default 8080).
	port := 8080
	if ports := form.Value["port"]; len(ports) > 0 {
		if p, err := strconv.Atoi(ports[0]); err == nil {
			port = p
		}
	}
	if port < 1 || port > 65535 {
		return respondError(c, fiber.StatusBadRequest, "invalid_port",
			"Field 'port' must be between 1 and 65535")
	}

	// Optional environment scope: ?env=staging or multipart "env" field.
	// Empty defaults to "development" (post-migration 026 — see
	// models.EnvDefault). Validation is centralised in models.NormalizeEnv
	// via resolveEnv.
	envBody := ""
	if vals := form.Value["env"]; len(vals) > 0 {
		envBody = vals[0]
	}
	environment, envErr := resolveEnv(c, envBody)
	if envErr != nil {
		return envErr
	}

	// Generate app ID.
	appID, err := generateAppID()
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to generate app ID")
	}

	// Persist the deployment record immediately (status = "building").
	initEnv := make(map[string]string)
	if name != "" {
		initEnv["_name"] = name
	}

	// Optional env_vars multipart field: a JSON object {KEY:"value", ...} that
	// gets injected into the deployed pod on the FIRST build. Avoids the
	// previous round-trip pattern of (POST /deploy/new) → wait → (PATCH /env) →
	// (POST /redeploy) — agents can now ship a working app in one call.
	// vault://KEY refs are resolved at deploy time (same as PATCH /env).
	if vals := form.Value["env_vars"]; len(vals) > 0 {
		var parsed map[string]string
		if err := json.Unmarshal([]byte(vals[0]), &parsed); err != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_env_vars",
				"Field 'env_vars' must be a JSON object {KEY:\"value\", ...}")
		}
		for k, v := range parsed {
			// Reserved underscore-prefixed keys are internal-only.
			if strings.HasPrefix(k, "_") {
				continue
			}
			initEnv[k] = v
		}
	}

	// Optional resource_bindings multipart field (slice 4 of env-aware
	// deployments): JSON map of env-var-name → "family:<root_id>" or raw
	// resource-token UUID. Resolved server-side BEFORE the deployments row
	// is persisted so 4xx surfaces sit in front of the user (vs failing
	// silently in the async runDeploy goroutine).
	//
	// Family bindings let one manifest work across all envs — the resolver
	// walks the family for each root id, picks the member matching the
	// deploy's env, and substitutes its decrypted connection URL into the
	// deployment's env vars. Raw token UUIDs are also accepted (backward
	// compat).
	if vals := form.Value["resource_bindings"]; len(vals) > 0 {
		var bindings map[string]string
		if err := json.Unmarshal([]byte(vals[0]), &bindings); err != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_resource_bindings",
				"Field 'resource_bindings' must be a JSON object {KEY:\"family:<uuid>\" | \"<token-uuid>\", ...}")
		}
		resolved, bErr := resolveResourceBindings(
			c.Context(), h.db, h.cfg.AESKey, team.ID, environment, bindings,
			h.cfg.FamilyBindingsEnabled,
		)
		if bErr != nil {
			status, code, msg, action := mapBindingError(bErr)
			slog.Info("deploy.new.resource_binding_rejected",
				"env_var", bErr.EnvVarKey,
				"raw_value", bErr.RawValue,
				"kind", string(bErr.Kind),
				"team_id", team.ID,
				"deploy_env", environment,
				"request_id", middleware.GetRequestID(c))
			return respondErrorWithAgentAction(c, status, code, msg, action, "")
		}
		// Merge resolved bindings — explicit env_vars from the caller win
		// over family-resolved values, so an agent can still pin a literal
		// override per env if needed.
		for k, v := range resolved {
			if _, present := initEnv[k]; present {
				continue
			}
			initEnv[k] = v
		}
	}

	// ── Private deploy fields (Track A — migration 020) ─────────────────────
	//
	// Two new multipart fields gate ingress access for the deployed app:
	//   private:     "true" / "1" / "yes" → set the nginx
	//                whitelist-source-range annotation on the Ingress
	//   allowed_ips: comma-separated list of IPs or CIDRs
	//                (e.g. "1.2.3.4,10.0.0.0/8"); required when private=true.
	//
	// Validation order matters:
	//   1. Tier gate FIRST so hobby/anonymous never sees a 400 for "missing
	//      allowed_ips" when the real failure is "your plan can't do this".
	//      Hides ladder-rung knowledge from low-tier callers.
	//   2. Then non-empty allowed_ips.
	//   3. Then per-entry parsing.
	//   4. Then the 32-entry cap.
	private, allowedIPs, privErr := parsePrivateDeployFields(c, form, team.PlanTier)
	if privErr != nil {
		return privErr // respondError already called inside parsePrivateDeployFields
	}

	// ── Notify webhook fields (migration 026) ────────────────────────────────
	//
	// Optional async notification: when the deploy reaches a terminal state
	// (healthy / failed) the worker POSTs to this URL. SSRF + scheme gate
	// fires here, before any DB write, so the row never carries an unsafe
	// URL. Secret is AES-256-GCM encrypted before persistence.
	//
	// Worker-side dispatcher is a separate PR — this PR only persists the
	// fields. notify_state defaults to 'pending' when a URL is supplied
	// (see CreateDeployment) so the future worker scan picks it up
	// immediately on terminal-state arrival.
	notifyURL, notifySecret, notifyErr := parseNotifyWebhookFields(c, form, h.cfg.AESKey)
	if notifyErr != nil {
		return notifyErr // respondError already called inside parseNotifyWebhookFields
	}

	// ── Tier-limit enforcement (plans.yaml: deployments_apps) ────────────────
	//
	// Count the team's currently-active deployments and reject when over the
	// per-tier cap. A limit of -1 means unlimited (team tier). A limit of 0
	// means the tier cannot deploy at all (anonymous / free) — natural
	// fall-through because existing (≥ 0) is always ≥ 0.
	if h.planRegistry != nil {
		existing, err := models.CountActiveDeploymentsByTeam(c.Context(), h.db, team.ID)
		if err != nil {
			slog.Error("deploy.new.count_failed",
				"error", err, "team_id", team.ID,
				"request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusServiceUnavailable, "count_failed",
				"Failed to check deployment quota")
		}
		limit := h.planRegistry.DeploymentsAppsLimit(team.PlanTier)
		if limit >= 0 && existing >= limit {
			return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
				"deployment_limit_reached",
				fmt.Sprintf("Your %s tier allows %d deployment(s).", team.PlanTier, limit),
				newAgentActionDeploymentLimitReached(team.PlanTier, limit),
				"https://instanode.dev/pricing")
		}
	}

	saved, err := models.CreateDeployment(c.Context(), h.db, models.CreateDeploymentParams{
		TeamID:              team.ID,
		AppID:               appID,
		Port:                port,
		Tier:                team.PlanTier,
		Env:                 environment,
		EnvVars:             initEnv,
		Private:             private,
		AllowedIPs:          allowedIPs,
		NotifyWebhook:       notifyURL,
		NotifyWebhookSecret: notifySecret,
	})
	if err != nil {
		slog.Error("deploy.new.db_create_failed",
			"error", err, "team_id", team.ID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed",
			"Failed to create deployment record")
	}

	// audit_log emit: deploy.created fires immediately after the row is
	// inserted — BEFORE the async build runs. Reaching healthy or failed is
	// reported separately via deploy.healthy / deploy.failed from runDeploy.
	emitDeployAudit(h.db, models.AuditKindDeployCreated, saved, map[string]any{
		"env":      saved.Env,
		"app_name": saved.AppID,
	})

	// Launch async provisioning; return 202 immediately.
	go h.runDeploy(saved, tarball)

	slog.Info("deploy.new.accepted",
		"app_id", appID, "team_id", team.ID,
		"port", port, "tier", team.PlanTier,
		"request_id", middleware.GetRequestID(c))

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"ok":   true,
		"item": deploymentToMap(saved),
		"note": "Deployment is building. Poll GET /deploy/" + appID + " for status.",
	})
}

// ── GET /deploy/:id ───────────────────────────────────────────────────────────

// Get handles GET /deploy/:id.
func (h *DeployHandler) Get(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}

	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	return c.JSON(fiber.Map{
		"ok":   true,
		"item": deploymentToMap(d),
	})
}

// ── GET /deploy/:id/logs ──────────────────────────────────────────────────────

// Logs handles GET /deploy/:id/logs — SSE streaming.
func (h *DeployHandler) Logs(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}

	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	if d.ProviderID == "" {
		return respondError(c, fiber.StatusConflict, "not_ready",
			"Deployment is still building — no provider ID yet")
	}

	// Tail logs only if deployment is alive; use follow=false for stopped/failed.
	follow := d.Status != "stopped" && d.Status != "failed"

	logStream, err := h.compute.Logs(c.Context(), d.ProviderID, follow)
	if err != nil {
		slog.Error("deploy.logs.stream_failed",
			"app_id", appID, "provider_id", d.ProviderID, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "logs_failed",
			"Failed to stream logs: "+err.Error())
	}
	// SSE headers.
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	// Stream lines. Fiber writes the response via fasthttp which buffers internally,
	// but we flush per-line for a real-time feel via c.Context().Response.SetBodyStreamWriter.
	// logStream.Close() must be deferred inside the callback — defers in the outer
	// handler run when ResourceLogs returns nil (before the callback executes).
	c.Context().Response.SetBodyStreamWriter(func(w *bufio.Writer) {
		defer logStream.Close()
		scanner := bufio.NewScanner(logStream)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintf(w, "data: %s\n\n", line)
			_ = w.Flush()
		}
		// Signal end of stream.
		fmt.Fprint(w, "data: [end]\n\n")
		_ = w.Flush()
	})

	return nil
}

// ── PATCH /deploy/:id/env ─────────────────────────────────────────────────────

// updateEnvBody is the JSON body for PATCH /deploy/:id/env.
type updateEnvBody struct {
	Env map[string]string `json:"env"`
}

// UpdateEnv handles PATCH /deploy/:id/env.
// Merges the supplied env vars with the existing ones and persists them.
// Returns a note that a redeploy is required to apply the changes.
func (h *DeployHandler) UpdateEnv(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}

	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	var body updateEnvBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Request body must be valid JSON: {\"env\": {\"KEY\": \"VALUE\"}}")
	}
	if len(body.Env) == 0 {
		return respondError(c, fiber.StatusBadRequest, "missing_env",
			"Field 'env' must be a non-empty object")
	}

	// Merge: existing vars take lower priority than incoming.
	merged := make(map[string]string, len(d.EnvVars)+len(body.Env))
	for k, v := range d.EnvVars {
		merged[k] = v
	}
	for k, v := range body.Env {
		merged[k] = v
	}

	if err := models.UpdateDeploymentEnvVars(c.Context(), h.db, d.ID, merged); err != nil {
		slog.Error("deploy.env.update_failed",
			"app_id", appID, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "update_failed",
			"Failed to update env vars")
	}

	slog.Info("deploy.env.updated",
		"app_id", appID, "team_id", team.ID,
		"keys_added", len(body.Env))

	return c.JSON(fiber.Map{
		"ok":   true,
		"note": "Env vars updated. Run POST /deploy/" + appID + "/redeploy to apply changes.",
		"env":  merged,
	})
}

// ── DELETE /deploy/:id ────────────────────────────────────────────────────────

// Delete handles DELETE /deploy/:id.
// Calls Teardown on the compute provider (best-effort), then hard-deletes the DB row.
func (h *DeployHandler) Delete(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}

	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	// Teardown compute resources (best-effort — don't block delete on provider errors).
	if d.ProviderID != "" {
		if teardownErr := h.compute.Teardown(c.Context(), d.ProviderID); teardownErr != nil {
			slog.Warn("deploy.delete.teardown_failed",
				"app_id", appID, "provider_id", d.ProviderID, "error", teardownErr)
			// Continue to delete the DB row regardless.
		}
	}

	if err := models.DeleteDeployment(c.Context(), h.db, d.ID); err != nil {
		slog.Error("deploy.delete.db_failed",
			"app_id", appID, "error", err,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "delete_failed",
			"Failed to delete deployment record")
	}

	slog.Info("deploy.deleted",
		"app_id", appID, "team_id", team.ID,
		"request_id", middleware.GetRequestID(c))

	return c.JSON(fiber.Map{
		"ok":      true,
		"message": "Deployment deleted",
	})
}

// ── POST /deploy/:id/redeploy ─────────────────────────────────────────────────

// Redeploy handles POST /deploy/:id/redeploy.
// Accepts a multipart form with a new tarball. Rebuilds the image and triggers
// a rolling update on the existing deployment.
func (h *DeployHandler) Redeploy(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}

	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	if d.ProviderID == "" {
		return respondError(c, fiber.StatusConflict, "not_ready",
			"Deployment has no provider ID yet — initial deploy may still be building")
	}

	// Parse multipart form (max 50 MB).
	form, err := c.MultipartForm()
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_form",
			"Request must be multipart/form-data with a 'tarball' field")
	}

	tarballs := form.File["tarball"]
	if len(tarballs) == 0 {
		return respondError(c, fiber.StatusBadRequest, "missing_tarball",
			"Multipart field 'tarball' is required")
	}
	fh := tarballs[0]
	if fh.Size > 50<<20 {
		return respondError(c, fiber.StatusBadRequest, "tarball_too_large",
			"Tarball must be at most 50 MB")
	}
	f, err := fh.Open()
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "tarball_open_failed",
			"Failed to read tarball")
	}
	defer f.Close()

	tarball := make([]byte, fh.Size)
	if _, err := f.Read(tarball); err != nil {
		return respondError(c, fiber.StatusBadRequest, "tarball_read_failed",
			"Failed to read tarball bytes")
	}

	// Update status to "building" while the redeploy runs.
	if err := models.UpdateDeploymentStatus(c.Context(), h.db, d.ID, "building", ""); err != nil {
		slog.Warn("deploy.redeploy.status_update_failed", "app_id", appID, "error", err)
	}

	// Kick off async redeploy.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		startedAt := time.Now()
		result, reErr := h.compute.Redeploy(ctx, d.ProviderID, tarball, d.EnvVars)
		if reErr != nil {
			slog.Error("deploy.redeploy.failed", "app_id", appID, "error", reErr)
			_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, "failed", reErr.Error())
			// Redeploy implies the row already exists; failure here is a
			// rollout (not first-build) issue.
			emitDeployAudit(h.db, models.AuditKindDeployFailed, d, map[string]any{
				"failure_stage": "rollout",
				"error_summary": truncateForAudit(reErr.Error(), 256),
			})
			return
		}
		_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, result.Status, "")
		emitDeployAudit(h.db, models.AuditKindDeployHealthy, d, map[string]any{
			"time_to_healthy_seconds": int(time.Since(startedAt).Round(time.Second).Seconds()),
		})
	}()

	slog.Info("deploy.redeploy.accepted",
		"app_id", appID, "provider_id", d.ProviderID, "team_id", team.ID)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"ok":   true,
		"note": "Redeploy in progress. Poll GET /deploy/" + appID + " for status.",
		"item": deploymentToMap(d),
	})
}

// ── GET /api/v1/deployments ───────────────────────────────────────────────────

// List handles GET /api/v1/deployments — list deployments for the team.
// Accepts an optional ?env=<name> query parameter to filter by environment.
// When omitted, returns all envs.
func (h *DeployHandler) List(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	envFilter := c.Query("env")
	var deploys []*models.Deployment
	if envFilter != "" {
		normalized, ok := models.NormalizeEnv(envFilter)
		if !ok {
			return c.JSON(fiber.Map{"ok": true, "items": []fiber.Map{}, "total": 0})
		}
		deploys, err = models.GetDeploymentsByTeamAndEnv(c.Context(), h.db, team.ID, normalized)
	} else {
		deploys, err = models.GetDeploymentsByTeam(c.Context(), h.db, team.ID)
	}
	if err != nil {
		slog.Error("deploy.list.failed",
			"error", err, "team_id", team.ID,
			"env_filter", envFilter,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to list deployments")
	}

	items := make([]fiber.Map, 0, len(deploys))
	for _, d := range deploys {
		items = append(items, deploymentToMap(d))
	}

	return c.JSON(fiber.Map{
		"ok":    true,
		"items": items,
		"total": len(items),
	})
}
