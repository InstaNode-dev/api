package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/quota"
	storageprovider "instant.dev/internal/providers/storage"
	commonv1 "instant.dev/proto/common/v1"
)

// ResourceHandler handles /api/v1/resources/* endpoints.
type ResourceHandler struct {
	db              *sql.DB
	rdb             *redis.Client
	cfg             *config.Config
	plans           *plans.Registry
	provisioner     *provisioner.Client
	storageProvider *storageprovider.Provider
}

// NewResourceHandler constructs a ResourceHandler.
func NewResourceHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, reg *plans.Registry, prov *provisioner.Client, storageProv *storageprovider.Provider) *ResourceHandler {
	return &ResourceHandler{db: db, rdb: rdb, cfg: cfg, plans: reg, provisioner: prov, storageProvider: storageProv}
}

// List handles GET /api/v1/resources — lists resources for the authenticated team.
// Accepts an optional ?env=<name> query parameter to filter by environment.
// Omitting it returns all envs (backward compat with pre-slice-1 callers).
func (h *ResourceHandler) List(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	envFilter := c.Query("env")
	var resources []*models.Resource
	if envFilter != "" {
		// Bogus envs (uppercase, spaces, unicode) fail NormalizeEnv and
		// return 200 + empty so the dashboard stays stable on stale state.
		normalized, ok := models.NormalizeEnv(envFilter)
		if !ok {
			return c.JSON(fiber.Map{"ok": true, "items": []fiber.Map{}, "total": 0})
		}
		resources, err = models.ListResourcesByTeamAndEnv(c.Context(), h.db, teamID, normalized)
	} else {
		resources, err = models.ListResourcesByTeam(c.Context(), h.db, teamID)
	}
	if err != nil {
		slog.Error("resource.list.failed",
			"error", err,
			"team_id", teamID,
			"env_filter", envFilter,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to list resources")
	}

	items := make([]fiber.Map, 0, len(resources))
	for _, r := range resources {
		items = append(items, resourceToMap(r))
	}

	return c.JSON(fiber.Map{
		"ok":    true,
		"items": items,
		"total": len(items),
	})
}

// Get handles GET /api/v1/resources/:id — returns a single resource.
func (h *ResourceHandler) Get(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(c.Context(), h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("resource.get.failed",
			"error", err,
			"token", tokenStr,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}

	if resource.TeamID.UUID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this resource")
	}

	storageLimitMB := h.plans.StorageLimitMB(resource.Tier, resource.ResourceType)
	_, storageExceeded, _ := quota.CheckStorageQuota(c.Context(), h.db, resource.ID, storageLimitMB)

	item := resourceToMap(resource)
	item["storage_exceeded"] = storageExceeded

	return c.JSON(fiber.Map{
		"ok":   true,
		"item": item,
	})
}

// Delete handles DELETE /api/v1/resources/:id — soft-deletes a resource.
func (h *ResourceHandler) Delete(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(c.Context(), h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("resource.delete.lookup_failed",
			"error", err,
			"token", tokenStr,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}

	if resource.TeamID.UUID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this resource")
	}

	if err := models.SoftDeleteResource(c.Context(), h.db, resource.ID); err != nil {
		slog.Error("resource.delete.failed",
			"error", err,
			"resource_id", resource.ID,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "delete_failed", "Failed to delete resource")
	}

	// Deprovision the physical resource.
	// Fail open: a provisioner error is logged but does not affect the 200 response.
	// The expiry worker will clean up orphaned physical resources as a fallback.
	switch resource.ResourceType {
	case "storage":
		if h.storageProvider != nil {
			deprovErr := h.storageProvider.Deprovision(c.Context(), token.String())
			if deprovErr != nil {
				slog.Warn("resource.delete.storage_deprovision_failed",
					"error", deprovErr,
					"resource_id", resource.ID,
					"token", token.String(),
					"request_id", requestID,
				)
			}
			// Audit-emit the per-tenant IAM user removal so the create/delete
			// pair brackets exactly how long the key existed. Only meaningful
			// in admin mode — shared-key mode has no per-tenant key to remove.
			if deprovErr == nil && h.storageProvider.Backend() == storageprovider.BackendMinIOAdmin {
				go func(rid uuid.UUID, tid uuid.UUID, tok string) {
					_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
						TeamID:       tid,
						Actor:        "system",
						Kind:         models.AuditKindStorageIAMUserDeleted,
						ResourceType: "storage",
						ResourceID:   uuid.NullUUID{UUID: rid, Valid: true},
						Summary:      "removed per-tenant storage key <code>key_" + tok[:8] + "</code>",
					})
				}(resource.ID, teamID, token.String())
			}
		}
	default:
		if h.provisioner != nil {
			resType := resourceTypeToProto(resource.ResourceType)
			if resType != commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED {
				providerID := resource.ProviderResourceID.String
				if deprovErr := h.provisioner.DeprovisionResource(c.Context(), token.String(), providerID, resType); deprovErr != nil {
					slog.Warn("resource.delete.deprovision_failed",
						"error", deprovErr,
						"resource_id", resource.ID,
						"resource_type", resource.ResourceType,
						"token", token.String(),
						"request_id", requestID,
					)
				}
			}
		}
	}

	// Invalidate the cached resource entry so any in-flight requests
	// see the deletion immediately rather than waiting for TTL expiry.
	// Use token.String() (normalized lowercase UUID) to match the key written by
	// getResourceCached — tokenStr is the raw URL param and may be mixed-case.
	h.rdb.Del(c.Context(), fmt.Sprintf("res:%s", token.String()))

	slog.Info("resource.deleted",
		"resource_id", resource.ID,
		"token", tokenStr,
		"team_id", teamID,
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{
		"ok":      true,
		"message": "Resource deleted",
	})
}

// GetCredentials handles GET /api/v1/resources/:id/credentials.
// Returns the plaintext connection URL for the team's own resource — same
// auth boundary as RotateCredentials, but does NOT change the password.
// Used by `instant up` to re-emit URLs into .env on subsequent runs.
func (h *ResourceHandler) GetCredentials(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(c.Context(), h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("resource.credentials.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}

	if !resource.TeamID.Valid || resource.TeamID.UUID != teamID {
		// Mirror "404 not 403" pattern used elsewhere — never confirm the
		// existence of resources owned by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
	}

	if !resource.ConnectionURL.Valid || resource.ConnectionURL.String == "" {
		return respondError(c, fiber.StatusBadRequest, "no_connection_url",
			"This resource does not have a connection URL")
	}

	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("resource.credentials.aes_key_invalid",
			"error", err, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Encryption configuration error")
	}
	plain, err := crypto.Decrypt(aesKey, resource.ConnectionURL.String)
	if err != nil {
		slog.Error("resource.credentials.decrypt_failed",
			"error", err, "resource_id", resource.ID, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to decrypt connection URL")
	}

	return c.JSON(fiber.Map{
		"ok":             true,
		"id":             resource.ID,
		"token":          resource.Token,
		"resource_type":  resource.ResourceType,
		"env":            resource.Env,
		"connection_url": plain,
	})
}

// RotateCredentials handles POST /api/v1/resources/:id/rotate-credentials.
// Generates a new password, re-encrypts the connection URL, persists it, and
// returns the new plaintext URL — this is the only endpoint that exposes connection_url.
func (h *ResourceHandler) RotateCredentials(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(c.Context(), h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("resource.rotate.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}

	if resource.TeamID.UUID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this resource")
	}

	if !resource.ConnectionURL.Valid || resource.ConnectionURL.String == "" {
		return respondError(c, fiber.StatusBadRequest, "no_connection_url",
			"This resource does not have a connection URL to rotate")
	}

	// Parse the AES key from config.
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("resource.rotate.aes_key_invalid",
			"error", err, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Encryption configuration error")
	}

	// Decrypt the stored connection URL so we can reconstruct it with a new password.
	plainURL, err := crypto.Decrypt(aesKey, resource.ConnectionURL.String)
	if err != nil {
		slog.Error("resource.rotate.decrypt_failed",
			"error", err, "resource_id", resource.ID, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to decrypt connection URL")
	}

	// Generate a new 16-byte (32 hex char) random password.
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		slog.Error("resource.rotate.rand_failed",
			"error", err, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to generate new password")
	}
	newPassword := hex.EncodeToString(pwBytes)

	// Substitute the password in the connection URL.
	parsed, err := url.Parse(plainURL)
	if err != nil {
		slog.Error("resource.rotate.url_parse_failed",
			"error", err, "resource_id", resource.ID, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to parse connection URL")
	}
	parsed.User = url.UserPassword(parsed.User.Username(), newPassword)
	newPlainURL := parsed.String()

	// For Postgres resources: apply the new password in the actual database.
	if resource.ResourceType == "postgres" && h.cfg.CustomerDatabaseURL != "" {
		if rotErr := rotatePostgresPassword(c.Context(), h.cfg.CustomerDatabaseURL,
			parsed.User.Username(), newPassword); rotErr != nil {
			slog.Warn("resource.rotate.postgres_alter_role_failed",
				"resource_id", resource.ID,
				"request_id", requestID,
				"error", rotErr,
			)
			// Non-fatal: the new URL is still persisted. The backend password change
			// failed (e.g. postgres-customers unreachable), but we proceed so the
			// stored URL stays in sync. A retry via re-rotation will fix both.
		}
	}

	// For Redis resources: update the ACL user password on the running instance.
	if resource.ResourceType == "redis" {
		username := parsed.User.Username()
		if rotErr := rotateRedisPassword(c.Context(), plainURL, username, newPassword); rotErr != nil {
			slog.Warn("resource.rotate.redis_acl_setuser_failed",
				"resource_id", resource.ID,
				"request_id", requestID,
				"error", rotErr,
			)
			// Non-fatal: stored URL is updated regardless; re-rotation will resync.
		}
	}

	// For MongoDB resources: update the user password via updateUser command.
	if resource.ResourceType == "mongodb" && h.cfg.MongoAdminURI != "" {
		username := parsed.User.Username()
		if rotErr := rotateMongoPassword(c.Context(), h.cfg.MongoAdminURI, username, newPassword); rotErr != nil {
			slog.Warn("resource.rotate.mongo_update_user_failed",
				"resource_id", resource.ID,
				"request_id", requestID,
				"error", rotErr,
			)
			// Non-fatal: stored URL is updated regardless; re-rotation will resync.
		}
	}

	// Encrypt and persist the new URL.
	newEncryptedURL, err := crypto.Encrypt(aesKey, newPlainURL)
	if err != nil {
		slog.Error("resource.rotate.encrypt_failed",
			"error", err, "resource_id", resource.ID, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to encrypt new connection URL")
	}

	if err := models.UpdateConnectionURL(c.Context(), h.db, resource.ID, newEncryptedURL); err != nil {
		slog.Error("resource.rotate.update_failed",
			"error", err, "resource_id", resource.ID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "update_failed", "Failed to persist rotated credentials")
	}

	slog.Info("resource.rotate.success",
		"resource_id", resource.ID,
		"team_id", teamID,
		"request_id", requestID,
	)

	// Rotation response is the ONE place we expose connection_url in plaintext.
	return c.JSON(fiber.Map{
		"ok":             true,
		"connection_url": newPlainURL,
	})
}

// Pause handles POST /api/v1/resources/:id/pause — suspends a resource without
// deleting it. Tier-gated to Pro+ (multi-env workflow). Sets resources.status =
// 'paused' and stamps paused_at; the provider-side action revokes the
// connection so paused resources don't accept new connections while paused.
//
// Atomicity rule: the provider-side revoke runs BEFORE the DB flip. If the
// revoke fails, the DB row is left in 'active' and the caller gets a 503 —
// the iron rule is "provider failures during pause should NOT change the DB
// row state." If the DB flip fails after a successful revoke, we attempt to
// roll the revoke back (best-effort grant on the way out).
//
// Errors:
//
//	400 invalid_id
//	401 unauthorized
//	402 upgrade_required (hobby/free) — carries agent_action + upgrade_url
//	403 forbidden       (caller doesn't own resource)
//	404 not_found
//	409 already_paused  (idempotent error — row is already paused)
//	503 provider_failed / pause_failed (transient infra)
func (h *ResourceHandler) Pause(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)
	ctx := c.UserContext()

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(ctx, h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("resource.pause.lookup_failed", "error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}

	if !resource.TeamID.Valid || resource.TeamID.UUID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this resource")
	}

	// Cheap idempotency-error check up front: if the row is already paused
	// we return 409 without touching the provider. Saves a wasteful REVOKE
	// round-trip on a no-op call.
	if resource.Status == "paused" {
		return respondErrorWithAgentAction(c, fiber.StatusConflict, "already_paused",
			"Resource is already paused.",
			AgentActionResourceAlreadyPaused, "")
	}
	if resource.Status != "active" {
		return respondError(c, fiber.StatusConflict, "invalid_state",
			"Resource is "+resource.Status+" and cannot be paused")
	}

	// Tier gate: pause/resume is a Pro+ feature. Looked up after authz so an
	// unauthenticated / wrong-team caller never learns the tier policy.
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		slog.Error("resource.pause.team_lookup_failed", "error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}
	if !multiEnvTierAllowed(team.PlanTier) {
		return respondPauseUpgradeRequired(c, team.PlanTier)
	}

	// Provider-side revoke FIRST. If this fails, the DB row stays 'active'
	// and the caller gets a 503 — the iron-rule atomicity guarantee.
	if provErr := h.pauseProvider(ctx, resource); provErr != nil {
		slog.Error("resource.pause.provider_failed",
			"error", provErr,
			"resource_id", resource.ID,
			"resource_type", resource.ResourceType,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "provider_failed",
			"Failed to suspend the underlying resource. The pause was not applied; retry in a few seconds.")
	}

	// DB flip. Wrapped in a defensive rollback: if the UPDATE fails after a
	// successful provider revoke, undo the revoke so the resource stays
	// reachable. Best-effort — a rollback failure is logged but the user
	// still sees the original error.
	if pauseErr := models.PauseResource(ctx, h.db, resource.ID); pauseErr != nil {
		if errors.Is(pauseErr, models.ErrResourceNotActive) {
			// Race: another caller flipped it between our SELECT and UPDATE.
			// Roll back the revoke so the row's effective state matches the
			// DB (which a parallel caller may have left as paused already —
			// in which case the rollback is a no-op).
			if rbErr := h.resumeProvider(context.Background(), resource); rbErr != nil {
				slog.Warn("resource.pause.race_rollback_failed",
					"error", rbErr, "resource_id", resource.ID, "request_id", requestID)
			}
			return respondErrorWithAgentAction(c, fiber.StatusConflict, "already_paused",
				"Resource is already paused.",
				AgentActionResourceAlreadyPaused, "")
		}
		slog.Error("resource.pause.db_update_failed",
			"error", pauseErr, "resource_id", resource.ID, "request_id", requestID)
		if rbErr := h.resumeProvider(context.Background(), resource); rbErr != nil {
			slog.Warn("resource.pause.rollback_failed",
				"error", rbErr, "resource_id", resource.ID, "request_id", requestID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "pause_failed",
			"Failed to record pause; the resource was reverted to active.")
	}

	// Invalidate cached resource entry so subsequent GETs reflect the new state.
	h.rdb.Del(ctx, fmt.Sprintf("res:%s", token.String()))

	// Best-effort audit event. Failure must not block the response.
	go func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamID,
			Actor:        "agent",
			Kind:         "resource.paused",
			ResourceType: resource.ResourceType,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "paused <strong>" + resource.ResourceType + "</strong> <code>" + token.String()[:8] + "</code>",
		})
	}()

	slog.Info("resource.paused",
		"resource_id", resource.ID,
		"resource_type", resource.ResourceType,
		"team_id", teamID,
		"request_id", requestID,
	)

	// W10 fix #81: dashboards (W8 + W9 PauseResumeButton) expect a structured
	// `resource` field so the click-handler can swap local React state in
	// place rather than re-fetch. Keep the legacy top-level fields for any
	// agent/CLI client that consumed the flat shape (additive change).
	resource.Status = "paused"
	return c.JSON(fiber.Map{
		"ok":       true,
		"id":       resource.ID,
		"token":    resource.Token,
		"status":   "paused",
		"message":  "Resource paused. Storage is preserved and the connection URL is unchanged; new connections are refused until resume.",
		"item":     resourceToMap(resource),
	})
}

// Resume handles POST /api/v1/resources/:id/resume — flips a paused resource
// back to 'active'. The connection URL is preserved unchanged (same password,
// same host, same database name) so the customer's existing config still works.
// Tier-gated to Pro+ in symmetry with Pause.
//
// Errors mirror Pause; 409 is `not_paused` when the row isn't in paused state.
func (h *ResourceHandler) Resume(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)
	ctx := c.UserContext()

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(ctx, h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("resource.resume.lookup_failed", "error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}

	if !resource.TeamID.Valid || resource.TeamID.UUID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this resource")
	}

	if resource.Status != "paused" {
		return respondErrorWithAgentAction(c, fiber.StatusConflict, "not_paused",
			"Resource is not paused (current status: "+resource.Status+").",
			AgentActionResourceNotPaused, "")
	}

	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		slog.Error("resource.resume.team_lookup_failed", "error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}
	if !multiEnvTierAllowed(team.PlanTier) {
		return respondPauseUpgradeRequired(c, team.PlanTier)
	}

	// Provider-side grant FIRST. Iron-rule mirror of Pause: if the grant
	// fails, the DB row stays 'paused' and the caller gets a 503.
	if provErr := h.resumeProvider(ctx, resource); provErr != nil {
		slog.Error("resource.resume.provider_failed",
			"error", provErr,
			"resource_id", resource.ID,
			"resource_type", resource.ResourceType,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "provider_failed",
			"Failed to re-enable the underlying resource. The resume was not applied; retry in a few seconds.")
	}

	if resumeErr := models.ResumeResource(ctx, h.db, resource.ID); resumeErr != nil {
		if errors.Is(resumeErr, models.ErrResourceNotPaused) {
			// Race: someone flipped it back to active between SELECT and UPDATE.
			// The provider is already granted; no rollback needed (it's an idempotent
			// "re-grant" of an already-active row).
			return respondErrorWithAgentAction(c, fiber.StatusConflict, "not_paused",
				"Resource is not paused.",
				AgentActionResourceNotPaused, "")
		}
		slog.Error("resource.resume.db_update_failed",
			"error", resumeErr, "resource_id", resource.ID, "request_id", requestID)
		if rbErr := h.pauseProvider(context.Background(), resource); rbErr != nil {
			slog.Warn("resource.resume.rollback_failed",
				"error", rbErr, "resource_id", resource.ID, "request_id", requestID)
		}
		return respondError(c, fiber.StatusServiceUnavailable, "resume_failed",
			"Failed to record resume; the resource was re-suspended.")
	}

	h.rdb.Del(ctx, fmt.Sprintf("res:%s", token.String()))

	go func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamID,
			Actor:        "agent",
			Kind:         "resource.resumed",
			ResourceType: resource.ResourceType,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "resumed <strong>" + resource.ResourceType + "</strong> <code>" + token.String()[:8] + "</code>",
		})
	}()

	slog.Info("resource.resumed",
		"resource_id", resource.ID,
		"resource_type", resource.ResourceType,
		"team_id", teamID,
		"request_id", requestID,
	)

	// W10 fix #81: parallel to Pause — surface the full Resource so the
	// dashboard adapter can swap state without refetching.
	resource.Status = "active"
	return c.JSON(fiber.Map{
		"ok":       true,
		"id":       resource.ID,
		"token":    resource.Token,
		"status":   "active",
		"message":  "Resource resumed. The connection URL is unchanged — your existing config still works.",
		"item":     resourceToMap(resource),
	})
}

// respondPauseUpgradeRequired is the canonical 402 for pause/resume tier walls.
// Mirrors respondMultiEnvUpgradeRequired but carries a pause-specific
// agent_action so the LLM tells the user about the right feature.
func respondPauseUpgradeRequired(c *fiber.Ctx, currentTier string) error {
	_ = c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
		"ok":           false,
		"error":        "upgrade_required",
		"message":      "Pausing resources requires the Pro plan or higher. Your team is on the " + currentTier + " plan.",
		"upgrade_url":  "https://instanode.dev/pricing",
		"agent_action": AgentActionPauseRequiresPro,
	})
	return ErrResponseWritten
}

// pauseProvider runs the provider-side "stop accepting new connections" action
// for the given resource. The DB row is NOT touched here — the caller is
// responsible for the status flip. Returns nil for resource types that don't
// have a provider-side pause (webhook/queue/storage are pure-status flips).
func (h *ResourceHandler) pauseProvider(ctx context.Context, r *models.Resource) error {
	switch r.ResourceType {
	case models.ResourceTypePostgres:
		if h.cfg.CustomerDatabaseURL == "" {
			// No customer DB configured (test path) — no-op so the handler
			// still exercises the full DB-update / status-flip codepath.
			return nil
		}
		username := extractURLUsername(r.ConnectionURL.String, h.cfg.AESKey)
		dbName := "db_" + r.Token.String()
		return revokePostgresConnect(ctx, h.cfg.CustomerDatabaseURL, dbName, username)
	case models.ResourceTypeRedis:
		// Decrypt the URL only to extract the username; ACL SETUSER ... off
		// disables the user reversibly without losing the password. This is
		// the key reason we don't use ACL DELUSER — DELUSER would require us
		// to store the password hash and recreate the user on resume, which
		// is a one-way trip if the encrypted blob is lost.
		plainURL := decryptOrEmpty(r.ConnectionURL.String, h.cfg.AESKey)
		if plainURL == "" {
			return nil // no URL stored — nothing to revoke
		}
		username := urlUsername(plainURL)
		if username == "" {
			return nil
		}
		return setRedisACLEnabled(ctx, plainURL, username, false)
	case models.ResourceTypeMongoDB:
		if h.cfg.MongoAdminURI == "" {
			return nil
		}
		username := "usr_" + r.Token.String()
		return revokeMongoRoles(ctx, h.cfg.MongoAdminURI, username, "db_"+r.Token.String())
	default:
		// queue / storage / webhook: status flip is the entire pause.
		return nil
	}
}

// resumeProvider is the inverse of pauseProvider — re-grants connection /
// re-enables ACL / re-grants role.
func (h *ResourceHandler) resumeProvider(ctx context.Context, r *models.Resource) error {
	switch r.ResourceType {
	case models.ResourceTypePostgres:
		if h.cfg.CustomerDatabaseURL == "" {
			return nil
		}
		username := extractURLUsername(r.ConnectionURL.String, h.cfg.AESKey)
		dbName := "db_" + r.Token.String()
		return grantPostgresConnect(ctx, h.cfg.CustomerDatabaseURL, dbName, username)
	case models.ResourceTypeRedis:
		plainURL := decryptOrEmpty(r.ConnectionURL.String, h.cfg.AESKey)
		if plainURL == "" {
			return nil
		}
		username := urlUsername(plainURL)
		if username == "" {
			return nil
		}
		return setRedisACLEnabled(ctx, plainURL, username, true)
	case models.ResourceTypeMongoDB:
		if h.cfg.MongoAdminURI == "" {
			return nil
		}
		username := "usr_" + r.Token.String()
		return grantMongoRoles(ctx, h.cfg.MongoAdminURI, username, "db_"+r.Token.String())
	default:
		return nil
	}
}

// validateSQLIdent rejects identifiers that would let an injection escape the
// quoted form. We only allow [a-z0-9_-] which is the charset our provisioner
// uses for db / user names.
func validateSQLIdent(s string) error {
	if s == "" {
		return fmt.Errorf("empty identifier")
	}
	for _, ch := range s {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return fmt.Errorf("unsafe identifier %q", s)
		}
	}
	return nil
}

// revokePostgresConnect runs REVOKE CONNECT ON DATABASE ... FROM <user> on the
// shared customer DB. Idempotent — Postgres treats revoke-of-not-granted as a
// success (the grant just isn't there anymore).
func revokePostgresConnect(ctx context.Context, dsn, dbName, username string) error {
	if err := validateSQLIdent(dbName); err != nil {
		return fmt.Errorf("revokePostgresConnect: db: %w", err)
	}
	if err := validateSQLIdent(username); err != nil {
		return fmt.Errorf("revokePostgresConnect: user: %w", err)
	}
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("revokePostgresConnect: open: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx,
		fmt.Sprintf(`REVOKE CONNECT ON DATABASE %q FROM %q`, dbName, username)); err != nil {
		return fmt.Errorf("revokePostgresConnect: REVOKE: %w", err)
	}
	// Terminate any open sessions so the pause takes effect immediately.
	if _, err := conn.ExecContext(ctx,
		`SELECT pg_terminate_backend(pid)
		   FROM pg_stat_activity
		  WHERE datname = $1 AND usename = $2 AND pid <> pg_backend_pid()`,
		dbName, username); err != nil {
		// Termination failure is non-fatal — the revoke already prevents
		// new connections; existing ones will time out / be killed on
		// reconnect attempts.
		slog.Warn("revokePostgresConnect: pg_terminate_backend", "error", err, "db", dbName, "user", username)
	}
	return nil
}

// grantPostgresConnect re-grants CONNECT. Safe to call on an already-granted
// role — GRANT is idempotent.
func grantPostgresConnect(ctx context.Context, dsn, dbName, username string) error {
	if err := validateSQLIdent(dbName); err != nil {
		return fmt.Errorf("grantPostgresConnect: db: %w", err)
	}
	if err := validateSQLIdent(username); err != nil {
		return fmt.Errorf("grantPostgresConnect: user: %w", err)
	}
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("grantPostgresConnect: open: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx,
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %q TO %q`, dbName, username)); err != nil {
		return fmt.Errorf("grantPostgresConnect: GRANT: %w", err)
	}
	return nil
}

// setRedisACLEnabled toggles ACL user state to "on" (enable) or "off"
// (disable). The user's password and key-pattern rules are left intact — this
// is the reversible alternative to ACL DELUSER. See the explanatory comment in
// ResourceHandler.pauseProvider for why we don't use DELUSER.
func setRedisACLEnabled(ctx context.Context, originalURL, username string, enable bool) error {
	opts, err := redis.ParseURL(originalURL)
	if err != nil {
		return fmt.Errorf("setRedisACLEnabled: parse url: %w", err)
	}
	client := redis.NewClient(opts)
	defer client.Close()
	state := "off"
	if enable {
		state = "on"
	}
	if err := client.Do(ctx, "ACL", "SETUSER", username, state).Err(); err != nil {
		return fmt.Errorf("setRedisACLEnabled: ACL SETUSER %s: %w", state, err)
	}
	return nil
}

// revokeMongoRoles runs revokeRolesFromUser to remove the readWrite role on
// the customer DB. The user itself stays — only the role is dropped — so a
// resume can re-grant cleanly without recreating the user.
func revokeMongoRoles(ctx context.Context, adminURI, username, dbName string) error {
	client, err := mongo.Connect(ctx, mongooptions.Client().ApplyURI(adminURI).
		SetServerSelectionTimeout(3*time.Second))
	if err != nil {
		return fmt.Errorf("revokeMongoRoles: connect: %w", err)
	}
	defer func() {
		if discErr := client.Disconnect(ctx); discErr != nil {
			slog.Warn("revokeMongoRoles: disconnect", "error", discErr)
		}
	}()
	result := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "revokeRolesFromUser", Value: username},
		{Key: "roles", Value: bson.A{
			bson.D{
				{Key: "role", Value: "readWrite"},
				{Key: "db", Value: dbName},
			},
		}},
	})
	if result.Err() != nil {
		return fmt.Errorf("revokeMongoRoles: revokeRolesFromUser: %w", result.Err())
	}
	return nil
}

// grantMongoRoles is the inverse — re-grants readWrite on the customer DB.
func grantMongoRoles(ctx context.Context, adminURI, username, dbName string) error {
	client, err := mongo.Connect(ctx, mongooptions.Client().ApplyURI(adminURI).
		SetServerSelectionTimeout(3*time.Second))
	if err != nil {
		return fmt.Errorf("grantMongoRoles: connect: %w", err)
	}
	defer func() {
		if discErr := client.Disconnect(ctx); discErr != nil {
			slog.Warn("grantMongoRoles: disconnect", "error", discErr)
		}
	}()
	result := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "grantRolesToUser", Value: username},
		{Key: "roles", Value: bson.A{
			bson.D{
				{Key: "role", Value: "readWrite"},
				{Key: "db", Value: dbName},
			},
		}},
	})
	if result.Err() != nil {
		return fmt.Errorf("grantMongoRoles: grantRolesToUser: %w", result.Err())
	}
	return nil
}

// extractURLUsername decrypts the encrypted connection_url and returns the
// userinfo username. Returns "" on any failure (the caller treats this as
// "no provider action needed").
func extractURLUsername(encryptedURL, aesKeyHex string) string {
	plain := decryptOrEmpty(encryptedURL, aesKeyHex)
	if plain == "" {
		return ""
	}
	return urlUsername(plain)
}

// decryptOrEmpty wraps crypto.Decrypt + key parse. Returns "" if any step
// fails — used by pause/resume helpers that want a "best-effort, fail open
// to no-op" semantics.
func decryptOrEmpty(encryptedURL, aesKeyHex string) string {
	if encryptedURL == "" {
		return ""
	}
	aesKey, err := crypto.ParseAESKey(aesKeyHex)
	if err != nil {
		return ""
	}
	plain, err := crypto.Decrypt(aesKey, encryptedURL)
	if err != nil {
		return ""
	}
	return plain
}

// urlUsername returns the username component of a URL (the userinfo before ":").
// Empty when the URL has no userinfo.
func urlUsername(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if parsed.User == nil {
		return ""
	}
	return parsed.User.Username()
}

// parseTeamID parses a UUID from the string stored in fiber.Locals by RequireAuth.
func parseTeamID(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, errors.New("missing team_id")
	}
	return uuid.Parse(s)
}

// resourceToMap converts a Resource to a JSON-friendly map, omitting sensitive fields.
func resourceToMap(r *models.Resource) fiber.Map {
	m := fiber.Map{
		"id":            r.ID,
		"token":         r.Token,
		"resource_type": r.ResourceType,
		"env":           r.Env,
		"tier":          r.Tier,
		"status":        r.Status,
		"created_at":    r.CreatedAt,
	}
	if r.Name.Valid {
		m["name"] = r.Name.String
	}
	if r.CloudVendor.Valid {
		m["cloud_vendor"] = r.CloudVendor.String
	}
	if r.CountryCode.Valid {
		m["country_code"] = r.CountryCode.String
	}
	if r.ExpiresAt.Valid {
		m["expires_at"] = r.ExpiresAt.Time
	}
	if r.PausedAt.Valid {
		m["paused_at"] = r.PausedAt.Time
	}
	if r.TeamID.Valid {
		m["team_id"] = r.TeamID.UUID
	}
	m["storage_bytes"] = r.StorageBytes
	// Never expose connection_url in API responses
	return m
}

// rotatePostgresPassword runs ALTER ROLE on postgres-customers to apply the
// new password. The username is derived from our own token — no user input —
// so fmt.Sprintf is safe here.
func rotatePostgresPassword(ctx context.Context, dsn, username, newPassword string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("rotatePostgresPassword: open: %w", err)
	}
	defer db.Close()

	// Validate username is safe (must match usr_<uuid> pattern from provisioner).
	for _, ch := range username {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return fmt.Errorf("rotatePostgresPassword: unsafe username %q", username)
		}
	}

	// ALTER ROLE does not support parameterised password — use string formatting.
	// Username is double-quoted as a Postgres identifier (pool tokens contain dashes).
	// Username is validated above; password is hex-encoded random bytes (safe).
	_, err = db.ExecContext(ctx, fmt.Sprintf(`ALTER ROLE "%s" WITH PASSWORD '%s'`, username, newPassword))
	if err != nil {
		return fmt.Errorf("rotatePostgresPassword: ALTER ROLE: %w", err)
	}
	return nil
}

// rotateRedisPassword updates the ACL password for the given Redis user.
// Connects to the shared Redis using the ORIGINAL credentials so the ACL SETUSER
// command is authorised, then resets the password to newPassword.
func rotateRedisPassword(ctx context.Context, originalURL, username, newPassword string) error {
	opts, err := redis.ParseURL(originalURL)
	if err != nil {
		return fmt.Errorf("rotateRedisPassword: parse url: %w", err)
	}
	client := redis.NewClient(opts)
	defer client.Close()

	// ACL SETUSER <username> resetpass ><newPassword> keeps all other ACL rules intact.
	if err := client.Do(ctx, "ACL", "SETUSER", username, "resetpass", ">"+newPassword).Err(); err != nil {
		return fmt.Errorf("rotateRedisPassword: ACL SETUSER: %w", err)
	}
	return nil
}

// rotateMongoPassword updates the password for the given MongoDB user.
// Connects using the admin URI and runs updateUser on the admin database
// (where users are created by the provisioner).
func rotateMongoPassword(ctx context.Context, adminURI, username, newPassword string) error {
	client, err := mongo.Connect(ctx, mongooptions.Client().ApplyURI(adminURI).
		SetServerSelectionTimeout(3*time.Second))
	if err != nil {
		return fmt.Errorf("rotateMongoPassword: connect: %w", err)
	}
	defer func() {
		if discErr := client.Disconnect(ctx); discErr != nil {
			slog.Warn("rotateMongoPassword: disconnect", "error", discErr)
		}
	}()

	// The user was created in the admin database with per-db roles.
	// updateUser must run against the database where the user was created.
	result := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "updateUser", Value: username},
		{Key: "pwd", Value: newPassword},
	})
	if result.Err() != nil {
		return fmt.Errorf("rotateMongoPassword: updateUser: %w", result.Err())
	}
	return nil
}

// resourceTypeToProto maps a resource_type string to the corresponding protobuf enum.
// Returns RESOURCE_TYPE_UNSPECIFIED for unknown/unsupported types (caller skips provisioner call).
// queue/NATS has no provisioner deprovision RPC yet — it returns UNSPECIFIED so the caller skips it.
func resourceTypeToProto(resourceType string) commonv1.ResourceType {
	switch resourceType {
	case "postgres":
		return commonv1.ResourceType_RESOURCE_TYPE_POSTGRES
	case "redis":
		return commonv1.ResourceType_RESOURCE_TYPE_REDIS
	case "mongodb":
		return commonv1.ResourceType_RESOURCE_TYPE_MONGODB
	default:
		return commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED
	}
}

