package handlers

// deploys_audit.go — GET /api/v1/<admin-prefix>/deploys.
//
// Answers the founder/operator question: "what binary was running at
// $TIME on service $X?" Reads from the deploys_audit table; one row per
// unique (service, commit_id, image_digest) tuple that has ever booted,
// written by the binary itself on startup (see models.InsertSelfReport
// + main.go's emitDeployAuditSelfReport).
//
// Auth: this handler does NOT implement its own gate. The router only
// registers it under the admin group, which already chains:
//
//   middleware.RequireAuth → middleware.RequireAdmin
//
// plus the unguessable-path-prefix obscurity gate (route only registered
// when ADMIN_PATH_PREFIX is set, served under /api/v1/<prefix>/deploys
// not /api/v1/admin/deploys). The OpenAPI spec intentionally omits this
// route — see internal/handlers/openapi.go.
//
// Freshness: every call is a live SQL read. The table is small (one row
// per deploy, not per pod) and the founder hits this endpoint a handful
// of times a day — caching would buy nothing and risk staleness on the
// "which binary is running RIGHT NOW" question this endpoint exists to
// answer.

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/models"
)

// deploysAuditMaxSinceWindow caps the `since` query parameter to one
// year back. A request for `since=1970-01-01T00:00:00Z` would still be
// answered (the table is small), but bounding the input keeps the
// surface predictable and stops a typo from accidentally scanning a
// pathological history.
const deploysAuditMaxSinceWindow = 365 * 24 * time.Hour

// DeploysAuditHandler serves GET /api/v1/<admin-prefix>/deploys.
type DeploysAuditHandler struct {
	db *sql.DB
}

// NewDeploysAuditHandler constructs the handler. The only dependency is
// the platform DB — the table this reads is owned by the api repo, so
// every read is local.
func NewDeploysAuditHandler(db *sql.DB) *DeploysAuditHandler {
	return &DeploysAuditHandler{db: db}
}

// deployAuditItem is the JSON shape of one row in the response. Time
// fields are serialized as RFC-3339 UTC for predictable parsing on the
// caller side. Nullable columns surface as null (not empty string) so
// "I never set a version" is distinguishable from `version=""`.
type deployAuditItem struct {
	ID               string  `json:"id"`
	Service          string  `json:"service"`
	CommitID         string  `json:"commit_id"`
	ImageDigest      string  `json:"image_digest"`
	Version          *string `json:"version"`
	BuildTime        *string `json:"build_time"`
	AppliedAt        string  `json:"applied_at"`
	MigrationVersion *string `json:"migration_version"`
	NoticedBy        string  `json:"noticed_by"`
}

// List handles GET /api/v1/<admin-prefix>/deploys.
//
// Query params:
//
//	service — optional, must be one of {api, worker, provisioner}
//	since   — optional RFC-3339 timestamp; rows with applied_at >= since
//	limit   — optional, 1..models.DeployListMaxLimit (default
//	          models.DeployListDefaultLimit)
//
// Response: { ok: true, deploys: [...] }. Sorted newest-first.
func (h *DeploysAuditHandler) List(c *fiber.Ctx) error {
	service := strings.TrimSpace(c.Query("service"))
	if service != "" && !models.ValidDeployServices[service] {
		return respondError(c, fiber.StatusBadRequest, "invalid_service",
			fmt.Sprintf("service must be one of: %s, %s, %s",
				models.DeployServiceAPI, models.DeployServiceWorker, models.DeployServiceProvisioner))
	}

	var since time.Time
	if raw := strings.TrimSpace(c.Query("since")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_since",
				"since must be an RFC-3339 timestamp (e.g. 2026-05-12T14:00:00Z)")
		}
		if cutoff := time.Now().Add(-deploysAuditMaxSinceWindow); parsed.Before(cutoff) {
			return respondError(c, fiber.StatusBadRequest, "since_too_old",
				"since must be within the last 365 days")
		}
		since = parsed.UTC()
	}

	limit := models.DeployListDefaultLimit
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return respondError(c, fiber.StatusBadRequest, "invalid_limit",
				"limit must be a positive integer")
		}
		limit = n
	}

	rows, err := models.ListDeploys(c.Context(), h.db, models.ListDeploysParams{
		Service: service,
		Since:   since,
		Limit:   limit,
	})
	if err != nil {
		slog.Error("admin.deploys_audit.list.failed", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to list deploys")
	}

	out := make([]deployAuditItem, 0, len(rows))
	for _, r := range rows {
		item := deployAuditItem{
			ID:          r.ID.String(),
			Service:     r.Service,
			CommitID:    r.CommitID,
			ImageDigest: r.ImageDigest,
			AppliedAt:   r.AppliedAt.UTC().Format(time.RFC3339),
			NoticedBy:   r.NoticedBy,
		}
		if r.Version.Valid {
			v := r.Version.String
			item.Version = &v
		}
		if r.BuildTime.Valid {
			bt := r.BuildTime.Time.UTC().Format(time.RFC3339)
			item.BuildTime = &bt
		}
		if r.MigrationVersion.Valid {
			mv := r.MigrationVersion.String
			item.MigrationVersion = &mv
		}
		out = append(out, item)
	}

	return c.JSON(fiber.Map{
		"ok":      true,
		"deploys": out,
	})
}
