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
	"instant.dev/internal/providers/compute"
	"instant.dev/internal/providers/compute/k8s"
	"instant.dev/internal/providers/compute/noop"
)

// DeployHandler handles all /deploy endpoints.
type DeployHandler struct {
	db      *sql.DB
	rdb     *redis.Client
	cfg     *config.Config
	compute compute.Provider
}

// NewDeployHandler initialises the handler and selects the compute backend based on
// cfg.ComputeProvider. Falls back to noop if k8s init fails.
func NewDeployHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config) *DeployHandler {
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
	return &DeployHandler{db: db, rdb: rdb, cfg: cfg, compute: cp}
}

// ── helpers ───────────────────────────────────────────────────────────────────

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
		"created_at":  d.CreatedAt,
		"updated_at":  d.UpdatedAt,
		"team_id":     d.TeamID,
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

	resolvedEnv, err := ResolveVaultRefs(ctx, h.db, h.cfg.AESKey, d.TeamID, d.Env, d.EnvVars)
	if err != nil {
		slog.Error("deploy.run_deploy.vault_resolve_failed",
			"app_id", d.AppID, "team_id", d.TeamID, "env", d.Env, "error", err)
		_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, "failed", err.Error())
		return
	}

	opts := compute.DeployOptions{
		AppID:   d.AppID,
		Token:   d.ID.String(),
		Tarball: tarball,
		Port:    d.Port,
		Tier:    d.Tier,
		EnvVars: resolvedEnv,
	}
	result, err := h.compute.Deploy(ctx, opts)
	if err != nil {
		slog.Error("deploy.run_deploy.failed",
			"app_id", d.AppID, "error", err)
		_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, "failed", err.Error())
		return
	}
	_ = models.UpdateDeploymentProviderID(ctx, h.db, d.ID, result.ProviderID, result.AppURL)
	_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, result.Status, "")
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
	// Empty defaults to "production". Validation is centralised in
	// models.NormalizeEnv via resolveEnv.
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

	saved, err := models.CreateDeployment(c.Context(), h.db, models.CreateDeploymentParams{
		TeamID:  team.ID,
		AppID:   appID,
		Port:    port,
		Tier:    team.PlanTier,
		Env:     environment,
		EnvVars: initEnv,
	})
	if err != nil {
		slog.Error("deploy.new.db_create_failed",
			"error", err, "team_id", team.ID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed",
			"Failed to create deployment record")
	}

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
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this deployment")
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
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this deployment")
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
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this deployment")
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
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this deployment")
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
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this deployment")
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

		result, reErr := h.compute.Redeploy(ctx, d.ProviderID, tarball, d.EnvVars)
		if reErr != nil {
			slog.Error("deploy.redeploy.failed", "app_id", appID, "error", reErr)
			_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, "failed", reErr.Error())
			return
		}
		_ = models.UpdateDeploymentStatus(ctx, h.db, d.ID, result.Status, "")
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

// List handles GET /api/v1/deployments — list all deployments for the team.
func (h *DeployHandler) List(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	deploys, err := models.GetDeploymentsByTeam(c.Context(), h.db, team.ID)
	if err != nil {
		slog.Error("deploy.list.failed",
			"error", err, "team_id", team.ID,
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
