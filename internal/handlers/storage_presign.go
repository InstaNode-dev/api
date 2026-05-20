package handlers

// storage_presign.go — POST /storage/:token/presign — mint a short-lived
// S3 presigned URL on behalf of a tenant. This is the broker-mode access
// path: on backends without per-tenant prefix-scoping (DO Spaces today), no
// long-lived credential is handed out — every read/write is a fresh
// presigned URL.
//
// Request body:
//
//	{ "operation": "GET" | "PUT", "key": "<object-key>", "expires_in": 600 }
//
// Response:
//
//	{
//	  "ok": true,
//	  "url": "https://nyc3.digitaloceanspaces.com/instant-shared/<token>/<key>?...",
//	  "expires_at": "<RFC3339>",
//	  "method": "GET" | "PUT"
//	}
//
// The handler verifies the token matches an active storage resource (so a
// stolen URL can't sign requests for an unowned tenant), bounds expires_in
// to ≤ 1h, and signs the URL using the platform's master key (lifted out of
// the provider's Capabilities()-aware interface — kept in api so secrets
// don't leak across packages).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	storageprovider "instant.dev/internal/providers/storage"
)

// presignRequest is the JSON body the agent sends.
type presignRequest struct {
	Operation string `json:"operation"`           // GET or PUT
	Key       string `json:"key"`                 // object key relative to the resource's prefix
	ExpiresIn int    `json:"expires_in,omitempty"` // seconds (default 600, max 3600)
}

// PresignStorage handles POST /storage/:token/presign.
func (h *StorageHandler) PresignStorage(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("storage") || h.storageProvider == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Object storage is not configured.")
	}

	tokenStr := c.Params("token")
	tokenUUID, err := uuid.Parse(tokenStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "token must be a UUID")
	}

	requestID := middleware.GetRequestID(c)

	var req presignRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "could not parse JSON body")
	}
	op := strings.ToUpper(strings.TrimSpace(req.Operation))
	if op != "GET" && op != "PUT" {
		return respondError(c, fiber.StatusBadRequest, "invalid_operation",
			"operation must be GET or PUT")
	}
	if strings.TrimSpace(req.Key) == "" {
		return respondError(c, fiber.StatusBadRequest, "invalid_key", "key is required")
	}
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 600
	}
	if req.ExpiresIn > 3600 {
		// Hard cap. A 1-hour presigned URL is already a lot of attack surface
		// for a leaked URL; longer would push us toward "they may as well
		// have the long-lived key."
		req.ExpiresIn = 3600
	}

	// Verify the token maps to an active storage resource.
	resource, err := models.GetResourceByToken(c.UserContext(), h.db, tokenUUID)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "resource_not_found", "no resource for that token")
		}
		slog.Error("storage.presign.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "could not look up resource")
	}
	if resource.ResourceType != "storage" {
		return respondError(c, fiber.StatusBadRequest, "not_a_storage_resource",
			"this token does not own a storage resource")
	}
	if resource.Status != "active" {
		return respondError(c, fiber.StatusGone, "resource_inactive",
			"storage resource is not active")
	}

	// Resolve the canonical object prefix from the stored provider_resource_id,
	// then sanitise the user-supplied key. The signed URL MUST land inside
	// <prefix>/, so leading slashes / "../" components are stripped.
	prefix := resource.ProviderResourceID.String
	if prefix == "" {
		// Legacy row — fall back to the token-derived prefix (the same fallback
		// used by the worker scanner).
		prefix = tokenStr
	}
	key := sanitisePresignKey(req.Key)
	objectKey := prefix + "/" + key

	signedURL, expiresAt, err := h.signStorageURL(c.UserContext(), op, objectKey, time.Duration(req.ExpiresIn)*time.Second)
	if err != nil {
		slog.Error("storage.presign.sign_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "sign_failed",
			"could not produce presigned URL")
	}

	slog.Info("storage.presign",
		"token", tokenStr,
		"operation", op,
		"key", key,
		"expires_in", req.ExpiresIn,
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{
		"ok":         true,
		"url":        signedURL,
		"method":     op,
		"key":        key,
		"object_key": objectKey,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
}

// signStorageURL constructs a presigned URL using the platform's master key.
// Lives here (not in providers/storage) because it needs minio-go's S3
// client and we don't want that transitive dep leaking into common.
func (h *StorageHandler) signStorageURL(ctx context.Context, op, objectKey string, ttl time.Duration) (string, time.Time, error) {
	bucket := h.cfg.ObjectStoreBucket
	endpoint := h.cfg.ObjectStoreEndpoint
	if bucket == "" || endpoint == "" {
		return "", time.Time{}, errors.New("storage: ObjectStoreBucket / ObjectStoreEndpoint not configured")
	}
	access := h.cfg.ObjectStoreAccessKey
	secret := h.cfg.ObjectStoreSecretKey
	if access == "" || secret == "" {
		return "", time.Time{}, errors.New("storage: master access key / secret not configured")
	}

	client, err := miniogo.New(endpoint, &miniogo.Options{
		Creds:  credentials.NewStaticV4(access, secret, ""),
		Secure: h.cfg.ObjectStoreSecure,
		Region: h.cfg.ObjectStoreRegion,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("minio client: %w", err)
	}

	expiresAt := time.Now().Add(ttl)

	var signed *url.URL
	switch op {
	case "GET":
		signed, err = client.PresignedGetObject(ctx, bucket, objectKey, ttl, url.Values{})
	case "PUT":
		signed, err = client.PresignedPutObject(ctx, bucket, objectKey, ttl)
	default:
		return "", time.Time{}, fmt.Errorf("unsupported operation %q", op)
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("presign: %w", err)
	}
	return signed.String(), expiresAt, nil
}

// sanitisePresignKey trims leading slashes + collapses "../" path traversal
// so the signed URL cannot escape the tenant's prefix. Conservative but
// strict: any path component equal to "." or ".." is dropped.
func sanitisePresignKey(in string) string {
	in = strings.TrimLeft(in, "/")
	parts := strings.Split(in, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "/")
}

// The storageprovider import is consumed by callers in storage.go in the
// same package; keep it here too so this file compiles standalone in IDE
// contexts that re-evaluate per-file imports.
var _ = storageprovider.ModeBroker
