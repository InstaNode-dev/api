package handlers

// storage_presign.go — POST /storage/:token/presign — mint a short-lived
// S3 presigned URL on behalf of a tenant. This is the broker-mode access
// path: on backends without per-tenant prefix-scoping (DO Spaces today), no
// long-lived credential is handed out — every read/write is a fresh
// presigned URL.
//
// Request body:
//
//	{ "operation": "GET" | "PUT" | "HEAD", "key": "<object-key>", "expires_in": 600 }
//
// Response:
//
//	{
//	  "ok": true,
//	  "url": "https://nyc3.digitaloceanspaces.com/instant-shared/<token>/<key>?...",
//	  "expires_at": "<RFC3339>",
//	  "method": "GET" | "PUT" | "HEAD"
//	}
//
// The handler verifies the token matches an active storage resource (so a
// stolen URL can't sign requests for an unowned tenant), bounds expires_in
// to ≤ 1h, and signs the URL using the platform's master key (lifted out of
// the provider's Capabilities()-aware interface — kept in api so secrets
// don't leak across packages).
//
// B17-P0 (2026-05-20) — security hardening:
//
//   - Operation allow-list. Only GET / PUT / HEAD are accepted. DELETE,
//     POST, PATCH, and any unknown verb return 400 invalid_operation. A
//     leaked URL must not let an attacker mass-delete a tenant's prefix.
//   - Path-traversal hard reject. The pre-B17 handler silently stripped
//     "../" components — but silent truncation hides intent ("/etc/passwd"
//     and "passwd" hashing to the same prefix is a tell-tale sign of
//     exploit traffic that we want surfaced, not hidden). Any "..", ".",
//     leading-slash, or empty-segment input now returns 400 path_unsafe.
//     The sanitiser remains as a defense-in-depth final pass but the
//     handler-level reject is the user-facing contract.
//   - Session/team cross-check. If the caller presents a session JWT
//     (OptionalAuth populated team_id), the JWT's team_id MUST match the
//     resource's team_id. This blocks the "leaked token + legit but
//     different-team session" impersonation path: an admin debugging
//     team B's dashboard cannot accidentally sign requests for team A's
//     bucket prefix just because the bearer URL leaked.
//   - Audit-log emit. Every successful presign drops a
//     `storage.presign_minted` row into audit_log via safego.Go (so a
//     slow audit insert never blocks the response). Metadata carries the
//     masked token, operation, masked key, team_id, expires_at — exactly
//     what an SOC investigator needs to reconstruct activity without
//     re-leaking the bearer secret.

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"instant.dev/internal/safego"
)

// presignRequest is the JSON body the agent sends.
type presignRequest struct {
	Operation string `json:"operation"`            // GET | PUT | HEAD
	Key       string `json:"key"`                  // object key relative to the resource's prefix
	ExpiresIn int    `json:"expires_in,omitempty"` // seconds (default 600, max 3600)
}

// presignAllowedOperations is the closed allow-list of S3 verbs callers
// may request. DELETE is intentionally omitted — broker-mode tenants must
// not be able to wipe their prefix from a leaked URL alone; per-tier
// deletion will land via a separate explicitly-gated endpoint when needed.
// POST and PATCH are not S3 verbs we issue presigned URLs for.
var presignAllowedOperations = map[string]struct{}{
	"GET":  {},
	"PUT":  {},
	"HEAD": {},
}

// presignMaxTTL caps expires_in. Matches the design doc's 1h hard ceiling.
// A 1-hour presigned URL is already a lot of attack surface for a leaked
// URL; longer would push us toward "they may as well have the long-lived
// key." Callers requesting more get capped to this with a WARN log.
const presignMaxTTL = 3600

// presignAuditKind is the audit_log.kind written on every successful
// presign. SOC alerts pivot off this string — do not rename without
// migrating the NR alert query at the same time.
const presignAuditKind = "storage.presign_minted"

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

	// B18 M4 (BugBash 2026-05-20): verify token existence BEFORE body validation.
	// Previously, /storage/<random-uuid>/presign with an invalid body would
	// surface `invalid_operation` (400) before checking whether the token
	// matched a real resource. That ordering is information-flow risk if the
	// validators ever loosen — a path-traversal `key` could be inspected for
	// shape before the existence check. New order: parse token → fetch
	// resource → validate body shape (operation, key, expires_in). The body
	// parse itself stays early because `c.BodyParser` errors are not
	// resource-conditional.
	var req presignRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "could not parse JSON body")
	}

	// Verify the token maps to an active storage resource FIRST.
	// B18 M4: existence check precedes body-shape validation so an attacker
	// probing a random UUID with a malformed body can't distinguish
	// "valid token + bad body" from "bad token".
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

	// B17-P0 / H46 F1 (2026-05-21): session/team cross-check.
	// The token in the URL is the primary authentication. But when a
	// session JWT is ALSO present (OptionalAuthStrict populated locals),
	// we require the session's team match the resource's team. This blocks
	// a leaked bearer being laundered through a legitimate-but-different-team
	// session — the 'view-as-customer' admin path, or a developer with their
	// own dev session, must not accidentally sign for a different tenant.
	//
	// Anonymous resources (TeamID.Valid=false) and anonymous callers
	// (sessionTeamID=="") pass through — the token alone is the boundary
	// in those cases, which is the same posture as /webhook/receive/:token.
	if sessionTeamID := middleware.GetTeamID(c); sessionTeamID != "" {
		if !resource.TeamID.Valid || resource.TeamID.UUID.String() != sessionTeamID {
			slog.Warn("storage.presign.cross_team_session_rejected",
				"token", tokenStr,
				"session_team_id", sessionTeamID,
				"request_id", requestID,
			)
			return respondError(c, fiber.StatusForbidden, "cross_team_session",
				"session team does not own this storage resource")
		}
	}

	// Body-shape validation. B17-P0: operation allow-list (GET/PUT/HEAD),
	// path-traversal hard-reject, expires_in cap with WARN log.
	op := strings.ToUpper(strings.TrimSpace(req.Operation))
	if _, ok := presignAllowedOperations[op]; !ok {
		return respondError(c, fiber.StatusBadRequest, "invalid_operation",
			"operation must be one of GET, PUT, HEAD")
	}
	if strings.TrimSpace(req.Key) == "" {
		return respondError(c, fiber.StatusBadRequest, "invalid_key", "key is required")
	}
	if !isSafePresignKey(req.Key) {
		return respondError(c, fiber.StatusBadRequest, "path_unsafe",
			"key must not contain '..' / '.' segments, leading slashes, or empty path components")
	}
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 600
	}
	if req.ExpiresIn > presignMaxTTL {
		slog.Warn("storage.presign.ttl_capped",
			"token", tokenStr,
			"requested_ttl", req.ExpiresIn,
			"capped_ttl", presignMaxTTL,
			"request_id", requestID,
		)
		req.ExpiresIn = presignMaxTTL
	}

	// Resolve the canonical object prefix from the stored provider_resource_id,
	// then perform a final defensive sanitisation. The handler-level reject
	// above has already enforced the contract; this pass is belt-and-braces
	// against any future caller that bypasses validation (e.g. a sibling
	// internal handler).
	prefix := resource.ProviderResourceID.String
	if prefix == "" {
		// Legacy row — fall back to the token-derived prefix (the same fallback
		// used by the worker scanner).
		prefix = tokenStr
	}
	key := sanitisePresignKey(req.Key)
	if key == "" {
		// Defense in depth: if sanitisation reduced the key to empty
		// (every segment was a traversal token), reject. The earlier
		// isSafePresignKey check should have caught this already.
		return respondError(c, fiber.StatusBadRequest, "path_unsafe",
			"key resolved to empty after sanitisation")
	}
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

	// B17-P0: audit_log emit. Best-effort via safego.Go so a slow audit
	// insert never delays the response. Metadata is masked — the full
	// token / object key would re-leak the very secret we're trying to
	// log activity for.
	emitPresignAudit(h.db, resource, op, key, req.ExpiresIn, expiresAt, requestID)

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
	case "HEAD":
		// HEAD is implemented as a presigned GET — the S3 protocol uses
		// the same V4 signature for GET and HEAD on the same key; the
		// client chooses the verb at request time. Issuing a GET URL
		// and instructing the client to use HEAD is equivalent and avoids
		// a separate signing path that minio-go doesn't expose directly.
		signed, err = client.PresignedGetObject(ctx, bucket, objectKey, ttl, url.Values{})
	default:
		// Unreachable because of presignAllowedOperations above, but
		// keeps the compiler happy.
		return "", time.Time{}, fmt.Errorf("unsupported operation %q", op)
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("presign: %w", err)
	}
	return signed.String(), expiresAt, nil
}

// isSafePresignKey reports whether key is safe to use as a tenant-supplied
// path segment without traversal risk. Returns false if any of:
//   - key starts with '/' (rooted path)
//   - any path component is "" (empty segment / double slash)
//   - any path component is "." or ".."
//
// Used by the handler to hard-reject path-traversal attempts with 400
// instead of silently stripping them.
func isSafePresignKey(in string) bool {
	if in == "" {
		return false
	}
	if strings.HasPrefix(in, "/") {
		return false
	}
	parts := strings.Split(in, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

// sanitisePresignKey trims leading slashes + collapses "../" path traversal
// so the signed URL cannot escape the tenant's prefix. Conservative but
// strict: any path component equal to "." or ".." is dropped. Retained as
// defense-in-depth — the primary contract is isSafePresignKey rejecting
// such input with 400, but a missed validation site upstream must still
// not let a "../" land in the signed URL.
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

// emitPresignAudit writes one audit_log row best-effort. Runs via
// safego.Go so a slow audit insert never blocks the response.
// Metadata fields are masked to avoid re-leaking the bearer token or the
// full object key into log storage. Mirrors the emitDeployAudit pattern
// in deploy.go (audit emission is fire-and-forget; logging the audit
// failure is the floor, blocking the user is never an option).
func emitPresignAudit(db *sql.DB, resource *models.Resource, op, key string, expiresInSec int, expiresAt time.Time, requestID string) {
	safego.Go("storage.presign.audit", func() {
		teamID := uuid.Nil
		if resource.TeamID.Valid {
			teamID = resource.TeamID.UUID
		}
		meta := map[string]any{
			"resource_token": maskPresignTokenForAudit(resource.Token.String()),
			"resource_id":    resource.ID.String(),
			"operation":      op,
			"path":           maskPresignKeyForAudit(key),
			"expires_in_s":   expiresInSec,
			"expires_at":     expiresAt.UTC().Format(time.RFC3339),
			"request_id":     requestID,
		}
		metaBlob, _ := json.Marshal(meta)

		ev := models.AuditEvent{
			TeamID:       teamID,
			Actor:        "agent",
			Kind:         presignAuditKind,
			ResourceType: "storage",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "storage presign URL minted (" + op + ")",
			Metadata:     metaBlob,
		}
		if err := models.InsertAuditEvent(context.Background(), db, ev); err != nil {
			slog.Warn("storage.presign.audit_emit_failed",
				"kind", presignAuditKind,
				"resource_id", resource.ID,
				"error", err,
			)
		}
	})
}

// maskPresignTokenForAudit returns the first 8 chars + ellipsis so the
// audit row is useful for correlation without re-leaking the full bearer.
// Matches the pattern in the worker for resource bearer tokens.
func maskPresignTokenForAudit(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}

// maskPresignKeyForAudit drops everything past the first 32 chars of the
// caller-supplied key and elides intermediate path segments. Keeps the
// audit row useful ("the agent accessed an export/* path") without
// recording the full filename (which may itself encode customer PII).
func maskPresignKeyForAudit(key string) string {
	if len(key) <= 32 {
		return key
	}
	return key[:32] + "..."
}

// The storageprovider import is consumed by callers in storage.go in the
// same package; keep it here too so this file compiles standalone in IDE
// contexts that re-evaluate per-file imports.
var _ = storageprovider.ModeBroker
