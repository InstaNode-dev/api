package handlers

// backup.go — customer-facing Postgres backup + restore API.
//
// Routes (wired in router.go under the authenticated /api/v1 group):
//
//   POST   /api/v1/resources/:id/backup    — ad-hoc backup. Tier-gated.
//   GET    /api/v1/resources/:id/backups   — list backups for a resource.
//   POST   /api/v1/resources/:id/restore   — restore from a specific backup.
//                                            Tier-gated to Pro+.
//   GET    /api/v1/resources/:id/restores  — list restores for a resource.
//
// Contract with the worker (sibling repo, instanode.dev/worker):
//
//   The API ONLY writes status='pending' rows into resource_backups /
//   resource_restores. The worker polls these tables every 30s, flips
//   pending→running, performs pg_dump → S3 (or pg_restore from S3),
//   and writes the terminal status + size_bytes + error_summary +
//   finished_at. The API never reads or writes any state past 'pending'.
//
// Conventions (match the rest of internal/handlers):
//
//   - All limits come from plans.Registry (BackupRestoreEnabled,
//     ManualBackupsPerDay, BackupRetentionDays) — never hardcoded.
//   - Tier-gate responses return 402 + agent_action so an LLM caller
//     can render an upgrade nudge with no extra round-trip.
//   - Best-effort audit emit on every successful POST. Audit failure
//     must NEVER block the response (goroutine, ignored error).
//   - Rate limit uses a Redis key shape consistent with the other
//     per-day caps: manual_backup:<team_id>:<YYYY-MM-DD>. Fails OPEN
//     on Redis errors — a Redis outage must not block a backup any
//     more than it blocks a provision (project convention rule #1).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/safego"
)

// BackupHandler bundles the four endpoints above. Held as a struct (rather
// than free functions) so the test suite can swap in fakes for db / rdb /
// plans / now without touching the router.
type BackupHandler struct {
	db    *sql.DB
	rdb   *redis.Client
	plans *plans.Registry

	// now is injected for tests that want to freeze the manual-backup
	// rate-limit window. Defaults to time.Now in production.
	now func() time.Time
}

// NewBackupHandler constructs a BackupHandler.
func NewBackupHandler(db *sql.DB, rdb *redis.Client, planRegistry *plans.Registry) *BackupHandler {
	return &BackupHandler{
		db:    db,
		rdb:   rdb,
		plans: planRegistry,
		now:   time.Now,
	}
}

// listBackupsDefaultLimit / Max — keep the page size predictable across
// the dashboard and any agent-side pagination loop.
const (
	listBackupsDefaultLimit = 50
	listBackupsMaxLimit     = 200
)

// CreateBackup handles POST /api/v1/resources/:id/backup.
//
// Tier policy:
//
//	anonymous / free  → 402 (backups require a claimed paid account)
//	hobby             → allowed up to manual_backups_per_day (1)
//	pro / growth      → allowed up to 100/day
//	team              → allowed up to 1000/day
//
// Only postgres resources accept backups today. Other resource types return
// 400 unsupported_resource_type — we'll widen this when redis/mongo backups
// ship.
//
// On success: inserts a 'pending' row in resource_backups and returns
// {ok:true, backup_id, status:"pending"}. The worker picks it up within 30s.
func (h *BackupHandler) CreateBackup(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)
	ctx := c.UserContext()

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	userID := parseUserIDFromCtx(c)

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := h.requireOwnedResource(ctx, c, teamID, token, "backup.create")
	if err != nil {
		return err // requireOwnedResource already wrote the response
	}

	// Backups only ship for postgres today. Refusing other types up front
	// keeps the row from being created and the worker from having to
	// classify-and-fail it later.
	if resource.ResourceType != models.ResourceTypePostgres {
		return respondError(c, fiber.StatusBadRequest, "unsupported_resource_type",
			"Backups are only supported for postgres resources today.")
	}

	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		slog.Error("backup.create.team_lookup_failed",
			"error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	// Tier gate (anonymous / free = 0/day → 402 with a claim nudge).
	perDay := h.plans.ManualBackupsPerDay(team.PlanTier)
	if perDay == 0 {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired, "upgrade_required",
			"Backups require a claimed paid account. Your team is on the "+team.PlanTier+" plan.",
			AgentActionBackupRequiresClaim, "https://instanode.dev/pricing")
	}

	// Per-day cap (hobby = 1, pro/growth = 100, team = 1000, -1 = unlimited).
	// Cap check runs against Redis with a UTC-day key. Fails OPEN on Redis
	// errors — same posture as provisioning rate limits (project rule #1).
	if perDay > 0 {
		key := fmt.Sprintf("manual_backup:%s:%s", teamID.String(), h.now().UTC().Format("2006-01-02"))
		allowed := true
		if h.rdb != nil {
			n, incErr := h.rdb.Incr(ctx, key).Result()
			if incErr != nil {
				slog.Warn("backup.create.rate_limit_redis_failed",
					"error", incErr, "team_id", teamID, "request_id", requestID)
				// Fail open — Redis must not block backups.
			} else {
				// First INCR of the day — pin TTL to 36h so a UTC-midnight
				// flip can't leave a stuck counter visible to the next day.
				if n == 1 {
					_ = h.rdb.Expire(ctx, key, 36*time.Hour).Err()
				}
				if n > int64(perDay) {
					allowed = false
					// Decrement back so a denied call doesn't burn a slot
					// the next legitimate retry could use.
					_ = h.rdb.Decr(ctx, key).Err()
				}
			}
		}
		if !allowed {
			return respondErrorWithAgentAction(c, fiber.StatusTooManyRequests, "rate_limited",
				fmt.Sprintf("Manual backup limit reached for today (%d/day on %s).", perDay, team.PlanTier),
				newAgentActionBackupRateLimited(team.PlanTier, perDay),
				"https://instanode.dev/pricing")
		}
	}

	// Insert the pending row. Worker takes it from here.
	row, err := models.CreateBackupRow(ctx, h.db, models.CreateBackupParams{
		ResourceID:   resource.ID,
		BackupKind:   models.BackupKindManual,
		TierAtBackup: team.PlanTier,
		TriggeredBy:  uuid.NullUUID{UUID: userID, Valid: userID != uuid.Nil},
	})
	if err != nil {
		slog.Error("backup.create.insert_failed",
			"error", err, "resource_id", resource.ID,
			"team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "backup_create_failed",
			"Failed to record backup request; retry in a few seconds.")
	}

	// Best-effort audit. Goroutine + ignored error — never block the response.
	emitBackupAudit(h.db, teamID, userID, resource, row, requestID)

	slog.Info("backup.requested",
		"backup_id", row.ID,
		"resource_id", resource.ID,
		"team_id", teamID,
		"tier", team.PlanTier,
		"request_id", requestID,
	)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"ok":         true,
		"backup_id":  row.ID,
		"status":     row.Status,
		"started_at": row.StartedAt,
		"message":    "Backup queued. The worker will pick it up within 30 seconds.",
	})
}

// ListBackups handles GET /api/v1/resources/:id/backups.
//
// Returns {ok, items[], total}. Cursor pagination via ?before=<RFC3339>
// (rows strictly older than the cursor), capped at ?limit=50 (max 200).
// 404 on cross-team access (cross-tenant existence stays opaque — see
// requireOwnedResource).
func (h *BackupHandler) ListBackups(c *fiber.Ctx) error {
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

	resource, err := h.requireOwnedResource(ctx, c, teamID, token, "backup.list")
	if err != nil {
		return err
	}

	limit, before, err := parseListCursor(c)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_cursor", err.Error())
	}

	items, err := models.ListBackupsByResource(ctx, h.db, resource.ID, limit, before)
	if err != nil {
		slog.Error("backup.list.failed",
			"error", err, "resource_id", resource.ID,
			"team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to list backups")
	}
	total, err := models.CountBackupsByResource(ctx, h.db, resource.ID)
	if err != nil {
		// Count failure should not break the page — the list itself succeeded.
		// Surface total=len(items) and log; the client just won't have an
		// accurate "how many more pages" hint.
		slog.Warn("backup.list.count_failed",
			"error", err, "resource_id", resource.ID, "request_id", requestID)
		total = len(items)
	}

	out := make([]fiber.Map, 0, len(items))
	for _, b := range items {
		out = append(out, backupToMap(b))
	}

	return c.JSON(fiber.Map{
		"ok":    true,
		"items": out,
		"total": total,
	})
}

// CreateRestore handles POST /api/v1/resources/:id/restore.
//
// Body:
//
//	{
//	  "backup_id": "<uuid>",                  // required
//	  "target_resource_id": "<uuid>",         // optional; restore into a different resource
//	  "destructive_acknowledgment": true      // required when target_resource_id is unset
//	}
//
// Tier policy: BackupRestoreEnabled from plans.yaml. False for hobby/free/
// anonymous; true for hobby_plus/pro/growth/team. The 402 envelope's
// agent_action points to Hobby Plus (the cheapest restore-enabled tier)
// for Hobby callers and to Pro for free/anonymous callers — see
// AgentActionRestoreRequiresHobbyPlus / RequiresPro (FIX-H #66/#Q48).
//
// Two safety gates on top of the prior version (FIX-H #57/#Q45):
//
//  1. HasInflightRestore precheck — a second POST while a prior restore
//     is still pending/running for the same resource returns 409
//     restore_in_progress. Failing to gate this would let pg_restore
//     --clean replay race itself.
//  2. destructive_acknowledgment — IN-PLACE restore (no
//     target_resource_id) requires destructive_acknowledgment: true so
//     an agent that "just wants to test a backup" can't accidentally
//     wipe a live customer DB.
//
// target_resource_id support (FIX-H #58/#A2): when set, the worker
// restores into THAT resource instead of the URL-path resource. The
// target must belong to the same team. The destructive ack is not
// required when restoring into a different resource — the agent has
// already opted into a fresh DB by choosing a different target.
//
// Cross-tenant backup_id guess returns 404 (not 400 as before — FIX-H
// #64/#Q46), matching the tenant-isolation pattern from FIX-B.
//
// Backup integrity (FIX-H #59): the worker verifies the SHA-256 of the
// S3 object before pg_restore runs. The api side doesn't compute the
// digest itself — it just makes sure the backup row HAS a stored
// digest, so that the worker has something to compare against. Rows
// pre-dating migration 043 lack the column; we accept them (legacy
// fail-open) but log a warn so an operator can see the coverage gap.
func (h *BackupHandler) CreateRestore(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)
	ctx := c.UserContext()

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	userID := parseUserIDFromCtx(c)
	if userID == uuid.Nil {
		// Restore requires a real user — the DB column is NOT NULL.
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Restore requires an authenticated user session")
	}

	tokenStr := c.Params("id")
	token, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	resource, err := h.requireOwnedResource(ctx, c, teamID, token, "restore.create")
	if err != nil {
		return err
	}

	// Decode body. Reject empty / malformed / missing backup_id up front
	// so a misconfigured dashboard doesn't insert orphan restore rows.
	var body struct {
		BackupID                  string `json:"backup_id"`
		TargetResourceID          string `json:"target_resource_id"`
		DestructiveAcknowledgment bool   `json:"destructive_acknowledgment"`
	}
	rawBody := c.Body()
	if len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, &body); err != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_body", "Body must be valid JSON")
		}
	}
	if body.BackupID == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_backup_id",
			"Request body must include backup_id (UUID of the resource_backups row to restore from).")
	}
	backupID, err := uuid.Parse(body.BackupID)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_backup_id", "backup_id must be a valid UUID")
	}

	// target_resource_id (FIX-H #58/#A2) — optional. When set, the
	// restore lands in a DIFFERENT resource than the URL :id. We
	// validate same-team ownership here; type-compat (postgres ↔
	// postgres) is enforced below.
	var targetResource *models.Resource
	if body.TargetResourceID != "" {
		targetID, parseErr := uuid.Parse(body.TargetResourceID)
		if parseErr != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_target_resource_id",
				"target_resource_id must be a valid UUID")
		}
		// Look up the target by token (matches the URL-path token shape).
		// Reuse requireOwnedResource semantics so cross-team targets return
		// the same 404 envelope as cross-team source attempts.
		tgt, lookupErr := models.GetResourceByToken(ctx, h.db, targetID)
		if lookupErr != nil {
			var notFound *models.ErrResourceNotFound
			if errors.As(lookupErr, &notFound) {
				return respondError(c, fiber.StatusNotFound, "target_not_found",
					"target_resource_id does not refer to a known resource")
			}
			slog.Error("restore.create.target_lookup_failed",
				"error", lookupErr, "target_resource_id", targetID, "request_id", requestID)
			return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch target resource")
		}
		if !tgt.TeamID.Valid || tgt.TeamID.UUID != teamID {
			return respondErrorWithAgentAction(c, fiber.StatusForbidden, "target_cross_team",
				"target_resource_id belongs to a different team.",
				AgentActionRestoreTargetCrossTeam, "")
		}
		if tgt.ResourceType != resource.ResourceType {
			return respondError(c, fiber.StatusBadRequest, "target_type_mismatch",
				"target_resource_id must be the same resource_type as the source")
		}
		targetResource = tgt
	}

	// destructive_acknowledgment (FIX-H #67/#Q49). Required ONLY for
	// in-place restores (target_resource_id unset). When restoring into
	// a different target the agent has opted into a clean DB by
	// choosing it explicitly, so the ack would just be ceremony.
	if targetResource == nil && !body.DestructiveAcknowledgment {
		return respondErrorWithAgentAction(c, fiber.StatusBadRequest, "destructive_ack_required",
			"In-place restore drops every table in the target DB. Re-send with destructive_acknowledgment: true or pass target_resource_id.",
			AgentActionRestoreDestructiveAckRequired, "")
	}

	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		slog.Error("restore.create.team_lookup_failed",
			"error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	// Tier gate: hobby/free/anonymous can take backups but cannot restore.
	// FIX-H #66/#Q48 — Hobby callers get the Hobby Plus copy (cheapest
	// restore-enabled tier, $19) instead of being routed past it onto Pro.
	if !h.plans.BackupRestoreEnabled(team.PlanTier) {
		action := AgentActionRestoreRequiresPro
		if plans.CanonicalTier(team.PlanTier) == "hobby" {
			action = AgentActionRestoreRequiresHobbyPlus
		}
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired, "upgrade_required",
			"Self-serve restore is not enabled on the "+team.PlanTier+" plan.",
			action, "https://instanode.dev/pricing")
	}

	// Resolve the backup. FIX-H #64/#Q46 — scope to team so a
	// cross-tenant backup_id guess returns 404 (matching FIX-B).
	backup, err := models.GetBackupByIDForTeam(ctx, h.db, backupID, teamID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, "backup_not_found",
				"No backup with that backup_id exists.")
		}
		slog.Error("restore.create.backup_lookup_failed",
			"error", err, "backup_id", backupID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "backup_lookup_failed", "Failed to look up backup")
	}
	if backup.ResourceID != resource.ID {
		// Distinct error from not_found so an honest mistake (right team,
		// wrong resource) is debuggable. Still safe to disclose — the
		// caller already authenticated as the resource owner.
		return respondError(c, fiber.StatusBadRequest, "backup_resource_mismatch",
			"backup_id belongs to a different resource than the one in the URL.")
	}
	if backup.Status != models.JobStatusOK {
		return respondErrorWithAgentAction(c, fiber.StatusConflict, "backup_not_ready",
			fmt.Sprintf("Backup is in status %q and cannot be restored from.", backup.Status),
			AgentActionRestoreBackupNotReady, "")
	}

	// Inflight guard (FIX-H #57/#Q45). Block a second POST while a
	// prior restore for the same resource is pending or running.
	// FAIL-CLOSED on DB error — a stuck restore is bad, but a corrupt
	// concurrent replay is worse.
	guardResourceID := resource.ID
	if targetResource != nil {
		guardResourceID = targetResource.ID
	}
	inflight, ifErr := models.HasInflightRestore(ctx, h.db, teamID, guardResourceID)
	if ifErr != nil {
		slog.Error("restore.create.inflight_check_failed",
			"error", ifErr, "resource_id", guardResourceID,
			"team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "inflight_check_failed",
			"Failed to check for inflight restores; retry in a few seconds.")
	}
	if inflight {
		return respondErrorWithAgentAction(c, fiber.StatusConflict, "restore_in_progress",
			"A restore for this resource is already pending or running.",
			AgentActionRestoreInflight, "")
	}

	// Integrity coverage check (FIX-H #59). Newer backups should carry
	// a stored sha256 the worker can compare against the freshly
	// re-read S3 object. Rows pre-dating migration 043 won't have one;
	// we log a warning but accept them (legacy fail-open).
	if !backup.SHA256.Valid || backup.SHA256.String == "" {
		slog.Warn("restore.create.backup_missing_sha256",
			"backup_id", backup.ID,
			"created_at", backup.CreatedAt,
			"request_id", requestID,
			"note", "row pre-dates migration 043; worker will skip the integrity check",
		)
	}

	// Idempotency-Key middleware would normally be in the router; we
	// also accept the header inline so a client retry within the same
	// minute that resolves to the same restore_id reads the cached
	// response. For this commit we just record the header for the
	// worker / audit log — the persistent cache is a separate piece.
	idempotencyKey := strings.TrimSpace(c.Get("Idempotency-Key"))

	// Choose the effective target — source if not overridden.
	restoreTargetResource := resource
	if targetResource != nil {
		restoreTargetResource = targetResource
	}

	row, err := models.CreateRestoreRow(ctx, h.db, models.CreateRestoreParams{
		ResourceID:  restoreTargetResource.ID,
		BackupID:    backup.ID,
		TriggeredBy: userID,
	})
	if err != nil {
		slog.Error("restore.create.insert_failed",
			"error", err, "resource_id", restoreTargetResource.ID,
			"backup_id", backup.ID, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "restore_create_failed",
			"Failed to record restore request; retry in a few seconds.")
	}

	emitRestoreAuditWithTarget(h.db, teamID, userID, resource, restoreTargetResource, backup, row, requestID, idempotencyKey)

	slog.Info("restore.requested",
		"restore_id", row.ID,
		"backup_id", backup.ID,
		"source_resource_id", resource.ID,
		"target_resource_id", restoreTargetResource.ID,
		"in_place", targetResource == nil,
		"team_id", teamID,
		"tier", team.PlanTier,
		"idempotency_key", idempotencyKey,
		"request_id", requestID,
	)

	resp := fiber.Map{
		"ok":         true,
		"restore_id": row.ID,
		"status":     row.Status,
		"started_at": row.StartedAt,
		"in_place":   targetResource == nil,
		"message":    "Restore queued. The worker will pick it up within 30 seconds.",
	}
	if targetResource != nil {
		resp["target_resource_id"] = targetResource.ID
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

// ListRestores handles GET /api/v1/resources/:id/restores.
// Same shape as ListBackups.
func (h *BackupHandler) ListRestores(c *fiber.Ctx) error {
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

	resource, err := h.requireOwnedResource(ctx, c, teamID, token, "restore.list")
	if err != nil {
		return err
	}

	limit, before, err := parseListCursor(c)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_cursor", err.Error())
	}

	items, err := models.ListRestoresByResource(ctx, h.db, resource.ID, limit, before)
	if err != nil {
		slog.Error("restore.list.failed",
			"error", err, "resource_id", resource.ID,
			"team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to list restores")
	}
	total, err := models.CountRestoresByResource(ctx, h.db, resource.ID)
	if err != nil {
		slog.Warn("restore.list.count_failed",
			"error", err, "resource_id", resource.ID, "request_id", requestID)
		total = len(items)
	}

	out := make([]fiber.Map, 0, len(items))
	for _, r := range items {
		out = append(out, restoreToMap(r))
	}

	return c.JSON(fiber.Map{
		"ok":    true,
		"items": out,
		"total": total,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// requireOwnedResource looks up the resource by token and 404's if the
// authenticated team does not own it. Writes the error response and returns
// a non-nil error in every failure path so the caller can just early-return.
//
// 404 (not 403) on cross-team mismatch: returning 403 would confirm the
// resource exists in another tenant. 404 keeps cross-team existence opaque,
// matching GetCredentials/Get/Delete/RotateCredentials/Pause/Resume.
func (h *BackupHandler) requireOwnedResource(ctx context.Context, c *fiber.Ctx, teamID uuid.UUID, token uuid.UUID, op string) (*models.Resource, error) {
	requestID := middleware.GetRequestID(c)
	resource, err := models.GetResourceByToken(ctx, h.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return nil, respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error(op+".lookup_failed",
			"error", err, "token", token.String(), "request_id", requestID)
		return nil, respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
	}
	if !resource.TeamID.Valid || resource.TeamID.UUID != teamID {
		return nil, respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
	}
	return resource, nil
}

// parseListCursor reads ?limit=&before=<RFC3339> from the query and
// applies bounds. Returns (limit, before, nil) on success or an error
// describing the bad input. An empty/missing "before" yields a zero
// time.Time, which the model functions treat as "no cursor".
func parseListCursor(c *fiber.Ctx) (int, time.Time, error) {
	limit := listBackupsDefaultLimit
	if raw := c.Query("limit"); raw != "" {
		v, err := parseIntStrict(raw)
		if err != nil || v <= 0 {
			return 0, time.Time{}, fmt.Errorf("limit must be a positive integer")
		}
		if v > listBackupsMaxLimit {
			v = listBackupsMaxLimit
		}
		limit = v
	}
	var before time.Time
	if raw := c.Query("before"); raw != "" {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			// Try the plain RFC3339 form too — agents pasting timestamps from
			// curl + jq commonly drop fractional seconds.
			t, err = time.Parse(time.RFC3339, raw)
			if err != nil {
				return 0, time.Time{}, fmt.Errorf("before must be an RFC3339 timestamp")
			}
		}
		before = t.UTC()
	}
	return limit, before, nil
}

// parseIntStrict is a small allocation-free atoi for the cursor parser.
// Rejects leading sign / whitespace / non-digit characters.
func parseIntStrict(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("non-digit")
		}
		n = n*10 + int(ch-'0')
		if n > 1<<20 {
			// Sanity ceiling. The handler caps at listBackupsMaxLimit anyway;
			// this just prevents arbitrarily large numbers from being parsed.
			return 0, fmt.Errorf("too large")
		}
	}
	return n, nil
}

// parseUserIDFromCtx pulls the user_id local set by RequireAuth (via
// middleware.GetUserID) and parses it as a UUID. Returns uuid.Nil when the
// local is absent or malformed — the caller decides whether that's an authz
// failure (Restore requires a real user; CreateBackup tolerates Nil).
func parseUserIDFromCtx(c *fiber.Ctx) uuid.UUID {
	s := middleware.GetUserID(c)
	if s == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// backupToMap converts a ResourceBackup row to the JSON shape returned by
// the list endpoint. Mirrors the contract documented in OpenAPI:
// {backup_id, status, started_at, finished_at, size_bytes, backup_kind,
//
//	tier_at_backup, error_summary}.
func backupToMap(b *models.ResourceBackup) fiber.Map {
	m := fiber.Map{
		"backup_id":   b.ID,
		"status":      b.Status,
		"started_at":  b.StartedAt,
		"backup_kind": b.BackupKind,
		"created_at":  b.CreatedAt,
	}
	if b.FinishedAt.Valid {
		m["finished_at"] = b.FinishedAt.Time
	} else {
		m["finished_at"] = nil
	}
	if b.SizeBytes.Valid {
		m["size_bytes"] = b.SizeBytes.Int64
	} else {
		m["size_bytes"] = nil
	}
	if b.TierAtBackup.Valid {
		m["tier_at_backup"] = b.TierAtBackup.String
	} else {
		m["tier_at_backup"] = nil
	}
	if b.ErrorSummary.Valid {
		m["error_summary"] = b.ErrorSummary.String
	} else {
		m["error_summary"] = nil
	}
	return m
}

// restoreToMap mirrors backupToMap for ResourceRestore rows.
func restoreToMap(r *models.ResourceRestore) fiber.Map {
	m := fiber.Map{
		"restore_id": r.ID,
		"backup_id":  r.BackupID,
		"status":     r.Status,
		"started_at": r.StartedAt,
		"created_at": r.CreatedAt,
	}
	if r.FinishedAt.Valid {
		m["finished_at"] = r.FinishedAt.Time
	} else {
		m["finished_at"] = nil
	}
	if r.ErrorSummary.Valid {
		m["error_summary"] = r.ErrorSummary.String
	} else {
		m["error_summary"] = nil
	}
	return m
}

// emitBackupAudit fires an AuditKindBackupRequested row in a goroutine.
// Best-effort — audit failure must never block the response.
func emitBackupAudit(db *sql.DB, teamID, userID uuid.UUID, resource *models.Resource, row *models.ResourceBackup, requestID string) {
	safego.Go("backup.bg", func() {
		metadata, _ := json.Marshal(map[string]any{
			"resource_id":  resource.ID.String(),
			"backup_id":    row.ID.String(),
			"triggered_by": userID.String(),
			"backup_kind":  row.BackupKind,
			"request_id":   requestID,
		})
		var userNullable uuid.NullUUID
		if userID != uuid.Nil {
			userNullable = uuid.NullUUID{UUID: userID, Valid: true}
		}
		_ = models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
			TeamID:       teamID,
			UserID:       userNullable,
			Actor:        "user",
			Kind:         models.AuditKindBackupRequested,
			ResourceType: resource.ResourceType,
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "queued backup of <strong>" + resource.ResourceType + "</strong> <code>" + resource.Token.String()[:8] + "</code>",
			Metadata:     metadata,
		})
	})
}

// emitRestoreAuditWithTarget fires an AuditKindRestoreRequested row in a
// goroutine. Includes the target resource id when the restore is a
// restore-to-new-DB (target_resource_id was set). The legacy
// emitRestoreAudit forwards into this with target = source so existing
// call sites stay backward-compatible.
func emitRestoreAuditWithTarget(
	db *sql.DB,
	teamID, userID uuid.UUID,
	sourceResource, targetResource *models.Resource,
	backup *models.ResourceBackup,
	row *models.ResourceRestore,
	requestID, idempotencyKey string,
) {
	safego.Go("backup.bg", func() {
		meta := map[string]any{
			"resource_id":        sourceResource.ID.String(),
			"target_resource_id": targetResource.ID.String(),
			"in_place":           sourceResource.ID == targetResource.ID,
			"backup_id":          backup.ID.String(),
			"restore_id":         row.ID.String(),
			"triggered_by":       userID.String(),
			"request_id":         requestID,
		}
		if idempotencyKey != "" {
			meta["idempotency_key"] = idempotencyKey
		}
		metadata, _ := json.Marshal(meta)
		_ = models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
			TeamID:       teamID,
			UserID:       uuid.NullUUID{UUID: userID, Valid: true},
			Actor:        "user",
			Kind:         models.AuditKindRestoreRequested,
			ResourceType: sourceResource.ResourceType,
			ResourceID:   uuid.NullUUID{UUID: targetResource.ID, Valid: true},
			Summary:      "restored <strong>" + sourceResource.ResourceType + "</strong> <code>" + sourceResource.Token.String()[:8] + "</code> from backup",
			Metadata:     metadata,
		})
	})
}
