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

// List handles GET /api/v1/resources — lists all resources for the authenticated team.
func (h *ResourceHandler) List(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	resources, err := models.ListResourcesByTeam(c.Context(), h.db, teamID)
	if err != nil {
		slog.Error("resource.list.failed",
			"error", err,
			"team_id", teamID,
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
			if deprovErr := h.storageProvider.Deprovision(c.Context(), token.String()); deprovErr != nil {
				slog.Warn("resource.delete.storage_deprovision_failed",
					"error", deprovErr,
					"resource_id", resource.ID,
					"token", token.String(),
					"request_id", requestID,
				)
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

