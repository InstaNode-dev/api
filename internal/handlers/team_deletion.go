package handlers

// team_deletion.go — GDPR Article 17 right-to-be-forgotten endpoints.
//
//   DELETE /api/v1/team        — owner asks for deletion; 30-day grace begins.
//   POST   /api/v1/team/restore — owner cancels deletion inside the grace window.
//
// The destructive heavy lifting (drop customer DBs, hard-delete S3 backups,
// NULL PII) is done by the worker's team_deletion_executor sweep. The API
// handler is the contract surface: state-machine flip, resource pause, best-
// effort subscription cancel, audit emit. See worker/internal/jobs/
// team_deletion_executor.go for the post-grace destruction phase.
//
// Defense-in-depth:
//
//  1. RequireAuth must already have validated the session JWT.
//  2. RequireRole("owner") gates the route at the router — only the team
//     owner (or legacy primary user, the oldest 'owner' by created_at) can
//     call. Members / admins / developers / viewers all get 403.
//  3. Body MUST include {"confirm_team_slug":"<slug>"} matching the team's
//     slug. Mistype / copy-paste of the wrong slug short-circuits before
//     any state change.
//
// All three gates fire BEFORE any mutation. After the gates pass:
//
//  - Mark team status='deletion_requested' (atomic, ErrTeamNotPendingDeletion
//    on retry).
//  - Pause all team resources (status='paused' + paused_at).
//  - Best-effort cancel Razorpay subscription via CancelImmediately. Failure
//    is logged + recorded in audit metadata; the row state still flips so
//    the dangling subscription becomes an ops-team cleanup task, not a
//    blocker for the customer's GDPR request.
//  - Emit team.deletion_requested audit row.
//  - Respond 202 Accepted with deletion_at = now() + 30d.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/razorpaybilling"
)

// PortalSubscriptionCanceler is the production SubscriptionCanceler that
// routes through razorpaybilling.Portal. The router wires this once at
// boot. Returning nil when there is no subscription matches the contract
// the deletion handler expects ("no live sub → treat as success").
type PortalSubscriptionCanceler struct {
	DB  *sql.DB
	Cfg *config.Config
}

// CancelForTeam looks up the team's Razorpay subscription_id and issues a
// cancel-immediately. Treats the "no subscription" error as a no-op so
// claimed-but-unpaid teams don't generate a misleading audit entry.
func (p *PortalSubscriptionCanceler) CancelForTeam(ctx context.Context, teamID uuid.UUID) error {
	portal := &razorpaybilling.Portal{DB: p.DB, Cfg: p.Cfg}
	subID, err := portal.SubscriptionID(ctx, teamID)
	if err != nil {
		// "no subscription" / "team not found" / configuration errors
		// surface as plain errors here. The caller treats nil as success
		// and non-nil as a logged best-effort failure; for the most
		// common "free team" case there is no subscription to cancel,
		// so we return nil rather than bubble the error.
		msg := err.Error()
		if strings.Contains(msg, "no subscription") ||
			strings.Contains(msg, "billing not configured") {
			return nil
		}
		return err
	}
	return portal.CancelImmediately(subID)
}

// SubscriptionCanceler is the narrow seam the deletion handler uses to cancel
// the customer's Razorpay subscription at deletion-request time. Lifted to an
// interface so tests can pass a fake without dragging real Razorpay HTTP
// calls into a unit test.
//
// Returns nil when the cancellation succeeded OR when there is no live
// subscription to cancel (a free / claimed-but-unpaid team). The contract for
// the deletion endpoint is that any non-nil error is best-effort — the team
// state STILL transitions to deletion_requested, and the operator follow-up
// is signalled via the audit metadata.
type SubscriptionCanceler interface {
	CancelForTeam(ctx context.Context, teamID uuid.UUID) error
}

// TeamDeletionHandler serves DELETE /api/v1/team + POST /api/v1/team/restore.
//
// Subscription cancel is wired via a field so tests inject a fake. Production
// uses razorpayCancelerForTeam which routes to the existing Portal
// (razorpaybilling/portal.go) — same CancelImmediately call the admin demote
// flow uses.
type TeamDeletionHandler struct {
	db                *sql.DB
	cfg               *config.Config
	CancelSubscription SubscriptionCanceler
}

// NewTeamDeletionHandler constructs a TeamDeletionHandler. CancelSubscription
// is left nil here — the router wires the real Razorpay portal at
// registration time (mirror of AdminCustomersHandler.CancelSubscription).
func NewTeamDeletionHandler(db *sql.DB, cfg *config.Config) *TeamDeletionHandler {
	return &TeamDeletionHandler{db: db, cfg: cfg}
}

// teamDeletionRequestBody is the JSON body for DELETE /api/v1/team.
type teamDeletionRequestBody struct {
	ConfirmTeamSlug string `json:"confirm_team_slug"`
}

// Delete handles DELETE /api/v1/team. Owner only. 202 on success.
//
// Errors:
//
//	400 invalid_body / missing_confirm_slug
//	401 unauthorized
//	403 forbidden       (caller is not owner)
//	404 not_found       (team gone)
//	409 slug_mismatch   (confirm_team_slug does not match)
//	409 already_pending (a previous DELETE already flipped the row)
func (h *TeamDeletionHandler) Delete(c *fiber.Ctx) error {
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)

	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}
	userIDStr := middleware.GetUserID(c)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	// Body — confirm_team_slug is required.
	var body teamDeletionRequestBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Body must be JSON with confirm_team_slug")
	}
	provided := strings.TrimSpace(body.ConfirmTeamSlug)
	if provided == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_confirm_slug",
			"confirm_team_slug is required — echo back the visible team slug to confirm.")
	}

	// Fetch the team — we need its slug to compare and the current status to
	// short-circuit a redelivered DELETE.
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Team not found")
		}
		slog.Error("team.deletion.team_lookup_failed", "error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	expected := models.TeamSlug(team)
	if !strings.EqualFold(provided, expected) {
		// Defense-in-depth: the caller did not echo back the correct slug.
		// 409 (Conflict) is the right code — the precondition wasn't met.
		// Agent-action copy nudges the agent to fetch the team summary
		// rather than guessing.
		return respondErrorWithAgentAction(c, fiber.StatusConflict, "slug_mismatch",
			"confirm_team_slug does not match the team's slug. Refusing to proceed.",
			"Tell the user the safety check failed — the team slug they confirmed does not match the team being deleted. Have them GET /api/v1/team/summary to fetch the correct slug, then retry DELETE /api/v1/team with confirm_team_slug equal to that exact value.",
			"")
	}

	// State-machine flip. Atomic against the WHERE status='active' guard;
	// a redelivered call hits ErrTeamNotPendingDeletion and 409s.
	if err := models.RequestTeamDeletion(ctx, h.db, teamID); err != nil {
		if errors.Is(err, models.ErrTeamNotPendingDeletion) {
			return respondError(c, fiber.StatusConflict, "already_pending",
				"Team deletion is already pending or the team is tombstoned.")
		}
		slog.Error("team.deletion.flip_failed", "error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "deletion_request_failed",
			"Failed to record deletion request. Retry in a few seconds.")
	}

	// Pause all resources — stop accepting new traffic immediately.
	pausedCount, pauseErr := models.PauseAllTeamResources(ctx, h.db, teamID)
	if pauseErr != nil {
		// Pause failure does NOT block the request — the worker can pause
		// at execution time as a backstop. Log loudly so operators see it.
		slog.Error("team.deletion.pause_failed",
			"error", pauseErr,
			"team_id", teamID,
			"request_id", requestID,
		)
	}

	// Best-effort Razorpay subscription cancel. Failure logged + recorded
	// in audit metadata. The row state is already flipped — a dangling
	// subscription is an ops cleanup task, not a customer-blocking issue.
	cancelResult := "skipped" // no canceler injected (tests, free team paths)
	if h.CancelSubscription != nil {
		if cerr := h.CancelSubscription.CancelForTeam(ctx, teamID); cerr != nil {
			cancelResult = "failed: " + cerr.Error()
			slog.Warn("team.deletion.razorpay_cancel_failed",
				"error", cerr,
				"team_id", teamID,
				"request_id", requestID,
			)
		} else {
			cancelResult = "ok"
		}
	}

	// Emit audit. Best-effort — InsertAuditEvent failures never block the
	// response. Run inline (not goroutine) so the test asserting the row
	// shape doesn't race with the response write.
	meta := map[string]any{
		"requested_by_user_id":     userID.String(),
		"confirm_slug_provided":    provided,
		"razorpay_cancel_result":   cancelResult,
		"paused_resource_count":    pausedCount,
		"grace_window_days":        models.TeamDeletionGraceDays,
	}
	metaBytes, _ := json.Marshal(meta)
	if auditErr := models.InsertAuditEvent(ctx, h.db, models.AuditEvent{
		TeamID:   teamID,
		UserID:   uuid.NullUUID{UUID: userID, Valid: true},
		Actor:    "user",
		Kind:     models.AuditKindTeamDeletionRequested,
		Summary:  "team deletion requested — 30-day grace window begins",
		Metadata: metaBytes,
	}); auditErr != nil {
		slog.Warn("team.deletion.audit_emit_failed",
			"error", auditErr,
			"team_id", teamID,
			"request_id", requestID,
		)
	}

	deletionAt := time.Now().UTC().Add(time.Duration(models.TeamDeletionGraceDays) * 24 * time.Hour)

	slog.Info("team.deletion.requested",
		"team_id", teamID,
		"user_id", userID,
		"paused_resource_count", pausedCount,
		"razorpay_cancel_result", cancelResult,
		"request_id", requestID,
	)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"ok":                true,
		"deletion_at":       deletionAt.Format(time.RFC3339),
		"grace_window_days": models.TeamDeletionGraceDays,
		"how_to_cancel":     "POST /api/v1/team/restore within 30 days to halt deletion",
	})
}

// Restore handles POST /api/v1/team/restore. Owner only. 200 on success.
//
// Errors:
//
//	401 unauthorized
//	403 forbidden       (caller is not owner)
//	404 not_found
//	409 not_pending     (team is not in deletion_requested status)
//	410 grace_expired   (30 days elapsed — destruction effectively committed)
func (h *TeamDeletionHandler) Restore(c *fiber.Ctx) error {
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)

	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}
	userIDStr := middleware.GetUserID(c)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	// Snapshot pre-restore so we can record days_remaining_at_cancel in
	// the audit metadata.
	prior, err := models.GetTeamDeletionStatus(ctx, h.db, teamID)
	if err != nil {
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Team not found")
		}
		slog.Error("team.restore.status_lookup_failed",
			"error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "status_lookup_failed",
			"Failed to look up team status")
	}

	if err := models.RestoreTeam(ctx, h.db, teamID); err != nil {
		switch {
		case errors.Is(err, models.ErrTeamNotPendingDeletion):
			return respondError(c, fiber.StatusConflict, "not_pending",
				"Team is not in deletion_requested status — nothing to restore.")
		case errors.Is(err, models.ErrTeamRestoreGraceExpired):
			return respondError(c, fiber.StatusGone, "grace_expired",
				"The 30-day deletion grace window has expired. Restoration is no longer possible.")
		}
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Team not found")
		}
		slog.Error("team.restore.flip_failed",
			"error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "restore_failed",
			"Failed to restore team. Retry in a few seconds.")
	}

	// Resume paused resources — the customer gets their workload back.
	resumedCount, resumeErr := models.ResumeAllTeamResources(ctx, h.db, teamID)
	if resumeErr != nil {
		slog.Error("team.restore.resume_failed",
			"error", resumeErr,
			"team_id", teamID,
			"request_id", requestID,
		)
	}

	// Audit: emit team.deletion_canceled with days_remaining_at_cancel so
	// operators can see how close the customer was to the worker sweep.
	daysRemaining := 0
	if prior.DeletionRequestedAt.Valid {
		remaining := prior.DeletionAt().Sub(time.Now().UTC())
		if remaining > 0 {
			daysRemaining = int(remaining / (24 * time.Hour))
		}
	}
	meta := map[string]any{
		"canceled_by_user_id":      userID.String(),
		"days_remaining_at_cancel": daysRemaining,
		"resumed_resource_count":   resumedCount,
	}
	metaBytes, _ := json.Marshal(meta)
	if auditErr := models.InsertAuditEvent(ctx, h.db, models.AuditEvent{
		TeamID:   teamID,
		UserID:   uuid.NullUUID{UUID: userID, Valid: true},
		Actor:    "user",
		Kind:     models.AuditKindTeamDeletionCanceled,
		Summary:  "team deletion canceled — restored to active",
		Metadata: metaBytes,
	}); auditErr != nil {
		slog.Warn("team.restore.audit_emit_failed",
			"error", auditErr,
			"team_id", teamID,
			"request_id", requestID,
		)
	}

	slog.Info("team.restore.completed",
		"team_id", teamID,
		"user_id", userID,
		"resumed_resource_count", resumedCount,
		"days_remaining_at_cancel", daysRemaining,
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{
		"ok":                       true,
		"status":                   models.TeamStatusActive,
		"resumed_resource_count":   resumedCount,
		"days_remaining_at_cancel": daysRemaining,
	})
}
