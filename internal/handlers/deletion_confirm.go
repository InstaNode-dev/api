package handlers

// deletion_confirm.go — shared two-step deletion machinery for paid-tier
// deploys and stacks. Wave FIX-I.
//
// Why this lives in one file (not split deploy/stack):
//
// The contract surface is identical — request, confirm, cancel, expire —
// so a single helper avoids the drift that would happen if the deploy
// flow's "what counts as paid" definition diverged from the stack
// flow's. Per-resource specifics (tier check, actual deprovision call)
// land in tiny callbacks passed into requestEmailConfirmedDeletion /
// resolveEmailConfirmedDeletion.
//
// Header bypass: callers that pass `X-Skip-Email-Confirmation: yes`
// short-circuit the email step. Reserved for agents that have already
// obtained explicit user consent on their side (the agent's UI, an MCP
// confirm dialog, etc). The header is logged in audit metadata so a
// post-hoc review can correlate "the user actually saw a confirm" with
// the bypass.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/safego"
)

// SkipEmailConfirmationHeader is the request header an agent can set to
// bypass the two-step flow. Value must be the literal string "yes" to
// avoid an accidental truthy match on header echoes / debug tooling.
const SkipEmailConfirmationHeader = "X-Skip-Email-Confirmation"

// skipEmailConfirmationValue is the only accepted value for the header.
const skipEmailConfirmationValue = "yes"

// teamIsPaid reports whether the team's plan_tier qualifies for the
// email-confirmed flow. The set of paid tiers (hobby/pro/team/growth)
// is the same set that gets a verified user email by construction —
// the anonymous / free pre-claim tiers do NOT have an email to send to
// and fall through to immediate destruction (back-compat).
//
// We deliberately keep this list in one place rather than a plans.yaml
// lookup because the question "does this tier get the email step" is a
// policy decision, not a plan-config knob. Adding a new paid tier means
// editing this function — which is exactly the audit trail we want.
func teamIsPaid(t *models.Team) bool {
	if t == nil {
		return false
	}
	switch t.PlanTier {
	case "hobby", "pro", "team", "growth":
		return true
	}
	return false
}

// shouldSkipEmailConfirmation parses the X-Skip-Email-Confirmation
// header from the request. The match is case-insensitive on the value
// because Fiber preserves header-value case verbatim and we want a
// caller that types "Yes" / "YES" to succeed (the contract is about
// intent, not casing).
func shouldSkipEmailConfirmation(c *fiber.Ctx) bool {
	return strings.EqualFold(strings.TrimSpace(c.Get(SkipEmailConfirmationHeader)), skipEmailConfirmationValue)
}

// confirmationLinkBase chooses the host the email link routes through.
// API_PUBLIC_URL wins when set (production); otherwise DASHBOARD_BASE_URL
// (local dev). Returning the dashboard URL in dev lets `npm run dev`
// developers click the email link without a port-forward to the api —
// the dashboard's /app/confirm-deletion page calls the api over its
// VITE_API_BASE.
func confirmationLinkBase(apiPublicURL, dashboardBaseURL string) string {
	if strings.TrimSpace(apiPublicURL) != "" {
		return strings.TrimRight(apiPublicURL, "/")
	}
	return strings.TrimRight(dashboardBaseURL, "/")
}

// buildConfirmationLink composes the URL embedded in the deletion
// email. Always points at the API's /auth/email/confirm-deletion route
// (NOT the dashboard's /app/confirm-deletion page directly) — the API
// receives the click, validates the token, and 302s to the dashboard
// success/failure surface. Centralising this redirect at the API means
// a future dashboard URL change does not invalidate live email links.
//
// In dev (API_PUBLIC_URL unset), the link points at the dashboard's
// confirm page directly because the dev dashboard handles the POST
// flow itself.
func buildConfirmationLink(apiPublicURL, dashboardBaseURL, plaintextToken string) string {
	if strings.TrimSpace(apiPublicURL) != "" {
		return fmt.Sprintf("%s/auth/email/confirm-deletion?t=%s",
			strings.TrimRight(apiPublicURL, "/"), plaintextToken)
	}
	return fmt.Sprintf("%s/app/confirm-deletion?t=%s",
		strings.TrimRight(dashboardBaseURL, "/"), plaintextToken)
}

// requestDeletionDeps holds the dependencies the request helper needs.
// We pass everything in explicitly rather than reaching for h.db / h.email
// because the deploy and stack handlers carry different concrete types
// but share this dependency shape.
type requestDeletionDeps struct {
	DB               *sql.DB
	Email            *email.Client
	APIPublicURL     string
	DashboardBaseURL string
	TTLMinutes       int
}

// pendingDeletionResponse is the 202 envelope returned to the caller
// when a fresh pending_deletions row is created.
type pendingDeletionResponse struct {
	OK                    bool   `json:"ok"`
	ID                    string `json:"id"`
	DeletionStatus        string `json:"deletion_status"`
	ConfirmationSentTo    string `json:"confirmation_sent_to"`
	ConfirmationExpiresAt string `json:"confirmation_expires_at"`
	AgentAction           string `json:"agent_action"`
	CancellationNote      string `json:"cancellation_note"`
}

// requestEmailConfirmedDeletion is the shared "Step 1" implementation.
//
// resourceType MUST be one of models.PendingDeletionResourceDeploy /
// PendingDeletionResourceStack. resourceLabel is the human-facing name
// used in the email subject + body ("deployment my-app",
// "stack my-stack").
//
// Returns ErrResponseWritten when it has already written the response
// (the 202 envelope on success, or an error envelope on a failure path).
// The caller can ignore the returned error in either case — the contract
// is "I wrote, you return whatever I returned".
//
// The caller is responsible for verifying ownership BEFORE calling
// this helper; we trust the (team, resourceID, resourceType) tuple.
func requestEmailConfirmedDeletion(
	c *fiber.Ctx,
	deps requestDeletionDeps,
	team *models.Team,
	resourceID uuid.UUID,
	resourceType, resourceLabel string,
) error {
	// Resolve the owner email — required for the email path. Failure to
	// find an owner on a paid team is exotic enough (every claim flow
	// inserts a user row) that we surface a distinct 500-class
	// agent_action rather than silently falling back to immediate
	// destruction.
	owner, err := models.GetUserByTeamID(c.Context(), deps.DB, team.ID)
	if err != nil {
		slog.Warn("deletion_confirm.owner_lookup_failed",
			"team_id", team.ID, "resource_type", resourceType, "error", err)
		return respondError(c, http.StatusUnprocessableEntity,
			"deletion_email_disabled",
			"No verified owner email is on file for this team")
	}

	ttl := time.Duration(deps.TTLMinutes) * time.Minute
	pending, plaintextToken, err := models.CreatePendingDeletion(
		c.Context(), deps.DB,
		resourceID, resourceType,
		team.ID, owner.ID,
		owner.Email, ttl,
	)
	if err != nil {
		if errors.Is(err, models.ErrPendingDeletionAlreadyExists) {
			return respondError(c, http.StatusConflict,
				"deletion_already_pending",
				"A deletion email is already in flight for this resource")
		}
		slog.Error("deletion_confirm.create_failed",
			"team_id", team.ID, "resource_type", resourceType,
			"resource_id", resourceID, "error", err,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, http.StatusServiceUnavailable,
			"deletion_create_failed",
			"Failed to queue deletion confirmation")
	}

	link := buildConfirmationLink(deps.APIPublicURL, deps.DashboardBaseURL, plaintextToken)
	maskedEmail := models.MaskEmail(owner.Email)

	// Send the email synchronously so a transient Brevo outage surfaces
	// as a 503 the caller can retry — instead of the user getting a
	// "deletion queued" message they never see in their inbox. The
	// 10s default timeout on the Brevo client keeps the request handler
	// well under load-balancer limits.
	if err := deps.Email.SendDeletionConfirmation(
		c.Context(), owner.Email, resourceLabel, link, deps.TTLMinutes,
	); err != nil {
		// Roll back the pending row so a retry doesn't hit the
		// "already pending" wall. Best-effort: the worker's expirer
		// will clean it up after the TTL even if this fails.
		if _, cancelErr := models.MarkPendingDeletionCancelled(c.Context(), deps.DB, pending.ID); cancelErr != nil {
			slog.Warn("deletion_confirm.rollback_failed",
				"pending_id", pending.ID, "error", cancelErr)
		}
		slog.Error("deletion_confirm.email_send_failed",
			"team_id", team.ID, "resource_id", resourceID,
			"resource_type", resourceType, "error", err)
		return respondError(c, http.StatusServiceUnavailable,
			"email_send_failed",
			"Could not send confirmation email — retry shortly")
	}

	// Emit the request audit event. Best-effort: a failed audit insert
	// must never invalidate the user-visible 202.
	emitDeletionAudit(deps.DB, deletionAuditKindRequested(resourceType), team.ID, resourceID, pending.ID, map[string]any{
		"expires_at":     pending.ExpiresAt.UTC().Format(time.RFC3339),
		"email_sent_to":  maskedEmail,
		"resource_label": resourceLabel,
	})

	resp := pendingDeletionResponse{
		OK:                    true,
		ID:                    resourceID.String(),
		DeletionStatus:        "pending_confirmation",
		ConfirmationSentTo:    maskedEmail,
		ConfirmationExpiresAt: pending.ExpiresAt.UTC().Format(time.RFC3339),
		AgentAction:           newAgentActionDeletionPendingConfirmation(maskedEmail, deps.TTLMinutes),
		CancellationNote: fmt.Sprintf(
			"If the user changes their mind, they can cancel by calling DELETE on the same /confirm-deletion path, or simply let the %d-minute window expire.",
			deps.TTLMinutes),
	}
	return c.Status(http.StatusAccepted).JSON(resp)
}

// resolveEmailConfirmedDeletion is the shared "Step 2" implementation.
// Called by POST /api/v1/<kind>/:id/confirm-deletion?token=<tok>.
//
// deprovisionFn is the per-resource teardown callback. It runs AFTER
// the row has been atomically flipped to 'confirmed' — so a slow
// deprovision can't be re-triggered by a second click. The callback
// receives the resolved pending row so it can read resource_id +
// resource_type itself.
//
// On success returns ErrResponseWritten after writing the 200 envelope.
func resolveEmailConfirmedDeletion(
	c *fiber.Ctx,
	deps requestDeletionDeps,
	team *models.Team,
	plaintextToken string,
	deprovisionFn func(ctx context.Context, p *models.PendingDeletion) error,
) error {
	if strings.TrimSpace(plaintextToken) == "" {
		return respondError(c, http.StatusBadRequest, "missing_token",
			"Confirmation token query parameter is required")
	}

	hash := models.HashPendingDeletionToken(plaintextToken)
	pending, err := models.GetPendingDeletionByTokenHash(c.Context(), deps.DB, hash)
	if err != nil {
		if errors.Is(err, models.ErrPendingDeletionNotFound) {
			return respondError(c, http.StatusGone, "deletion_token_invalid",
				"Confirmation token is expired or already used")
		}
		slog.Error("deletion_confirm.lookup_failed", "error", err)
		return respondError(c, http.StatusServiceUnavailable,
			"deletion_lookup_failed", "Failed to validate confirmation token")
	}

	// Team gate — a token belongs to the team that created it. A
	// cross-team click (rare but defended-against here) returns 410 as
	// if the token were invalid, never leaking that the token IS valid
	// for some other team.
	if pending.TeamID != team.ID {
		return respondError(c, http.StatusGone, "deletion_token_invalid",
			"Confirmation token is expired or already used")
	}

	// Atomic CAS — only the winning click proceeds. A losing click
	// reads "already resolved" as a 410, same envelope as expired.
	won, err := models.MarkPendingDeletionConfirmed(c.Context(), deps.DB, pending.ID)
	if err != nil {
		slog.Error("deletion_confirm.mark_failed",
			"pending_id", pending.ID, "error", err)
		return respondError(c, http.StatusServiceUnavailable,
			"deletion_mark_failed", "Failed to confirm deletion")
	}
	if !won {
		return respondError(c, http.StatusGone, "deletion_token_invalid",
			"Confirmation token is expired or already used")
	}

	// Run the actual teardown. A failure here is loud — the row is
	// already flipped to 'confirmed' so the slot is released by quota
	// math even if the underlying provider didn't tear down. We log at
	// ERROR so on-call can chase the provider asynchronously without
	// blocking the user.
	//
	// P2 (2026-05-17): a teardown failure no longer reports a flat
	// "confirmed / Resource torn down" success. The response distinguishes
	// confirmed_teardown_pending (provider cleanup deferred to the worker
	// reconciler) from confirmed (cleanly torn down) so the caller is not
	// told something was destroyed when only the row was flipped.
	teardownOK := true
	if err := deprovisionFn(c.Context(), pending); err != nil {
		teardownOK = false
		slog.Error("deletion_confirm.deprovision_failed",
			"pending_id", pending.ID,
			"resource_id", pending.ResourceID,
			"resource_type", pending.ResourceType,
			"error", err,
			"request_id", middleware.GetRequestID(c))
		// Still return 200 — the user's intent is recorded and the slot is
		// freed by quota math. The provider cleanup is retried by the
		// worker reconciler, which sweeps confirmed rows whose backing
		// infra still exists. The response below makes the deferred state
		// explicit rather than claiming the resource is gone.
	}

	freedAt := time.Now().UTC()
	emitDeletionAudit(deps.DB, deletionAuditKindConfirmed(pending.ResourceType),
		team.ID, pending.ResourceID, pending.ID, map[string]any{
			"freed_at":               freedAt.Format(time.RFC3339),
			"age_seconds_in_pending": int64(freedAt.Sub(pending.RequestedAt).Seconds()),
			"teardown_ok":            teardownOK,
		})

	deletionStatus := "confirmed"
	note := "Resource torn down. The slot is now free — your next provision call will succeed."
	if !teardownOK {
		deletionStatus = "confirmed_teardown_pending"
		note = "Deletion confirmed and the slot is freed, but provider teardown did not complete. " +
			"The platform reconciler will retry teardown automatically — no further action is needed."
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"ok":              true,
		"id":              pending.ResourceID.String(),
		"resource_type":   pending.ResourceType,
		"deletion_status": deletionStatus,
		"freed_at":        freedAt.Format(time.RFC3339),
		"agent_action":    AgentActionDeletionConfirmed,
		"note":            note,
	})
}

// cancelEmailConfirmedDeletion is the shared "Step 2 (cancel)"
// implementation. Called by DELETE /api/v1/<kind>/:id/confirm-deletion.
// Cancels the pending row identified by (resource_id, resource_type)
// for the calling team. Does NOT require the plaintext token — the
// /confirm flow's URL parameter is for the user clicking from email,
// while cancel is a deliberate user action from the dashboard where
// they already have an authenticated session.
func cancelEmailConfirmedDeletion(
	c *fiber.Ctx,
	deps requestDeletionDeps,
	team *models.Team,
	resourceID uuid.UUID,
	resourceType string,
) error {
	pending, err := models.GetPendingDeletionByResource(c.Context(), deps.DB, resourceID, resourceType)
	if err != nil {
		if errors.Is(err, models.ErrPendingDeletionNotFound) {
			return respondError(c, http.StatusNotFound, "not_found",
				"No pending deletion to cancel for this resource")
		}
		return respondError(c, http.StatusServiceUnavailable,
			"deletion_lookup_failed", "Failed to look up pending deletion")
	}

	if pending.TeamID != team.ID {
		return respondError(c, http.StatusNotFound, "not_found",
			"No pending deletion to cancel for this resource")
	}

	won, err := models.MarkPendingDeletionCancelled(c.Context(), deps.DB, pending.ID)
	if err != nil {
		return respondError(c, http.StatusServiceUnavailable,
			"deletion_mark_failed", "Failed to cancel deletion")
	}
	if !won {
		return respondError(c, http.StatusGone, "deletion_token_invalid",
			"Pending deletion is already resolved")
	}

	emitDeletionAudit(deps.DB, deletionAuditKindCancelled(pending.ResourceType),
		team.ID, pending.ResourceID, pending.ID, nil)

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"ok":              true,
		"id":              pending.ResourceID.String(),
		"resource_type":   pending.ResourceType,
		"deletion_status": "cancelled",
		"agent_action":    AgentActionDeletionCancelled,
		"note":            "Pending deletion cancelled. The resource stays active and the slot stays consumed.",
	})
}

// deletionAuditKindRequested returns the per-resource audit kind for a
// fresh request. Keeping the mapping in this file (not the model) lets
// the audit kinds package own the constants — we just translate from
// (resource_type → kind) here.
func deletionAuditKindRequested(resourceType string) string {
	if resourceType == models.PendingDeletionResourceStack {
		return models.AuditKindStackDeletionRequested
	}
	return models.AuditKindDeployDeletionRequested
}

// deletionAuditKindConfirmed mirrors deletionAuditKindRequested for the
// confirmation event.
func deletionAuditKindConfirmed(resourceType string) string {
	if resourceType == models.PendingDeletionResourceStack {
		return models.AuditKindStackDeletionConfirmed
	}
	return models.AuditKindDeployDeletionConfirmed
}

// deletionAuditKindCancelled mirrors deletionAuditKindRequested for
// cancellation.
func deletionAuditKindCancelled(resourceType string) string {
	if resourceType == models.PendingDeletionResourceStack {
		return models.AuditKindStackDeletionCancelled
	}
	return models.AuditKindDeployDeletionCancelled
}

// emitDeletionAudit writes one audit_log row. Best-effort: a failed
// insert never invalidates the user-visible response (mirrors
// emitDeployAudit in deploy.go). teamID + resourceID land in the
// metadata so a downstream forwarder can correlate by resource.
func emitDeletionAudit(
	db *sql.DB,
	kind string,
	teamID, resourceID, pendingID uuid.UUID,
	extra map[string]any,
) {
	safego.Go("deletion_confirm.bg", func() {
		meta := map[string]any{
			"team_id":             teamID.String(),
			"resource_id":         resourceID.String(),
			"pending_deletion_id": pendingID.String(),
		}
		for k, v := range extra {
			meta[k] = v
		}
		metaBlob, _ := json.Marshal(meta)

		ev := models.AuditEvent{
			TeamID:       teamID,
			Actor:        "system",
			Kind:         kind,
			ResourceType: deletionAuditResourceType(kind),
			Summary:      kind,
			Metadata:     metaBlob,
		}
		if err := models.InsertAuditEvent(context.Background(), db, ev); err != nil {
			slog.Warn("audit.emit.failed",
				"kind", kind, "team_id", teamID, "error", err)
		}
	})
}

// deletionAuditResourceType maps a deletion audit kind back to the
// audit_log.resource_type column value ('deploy' or 'stack'). Keeps the
// audit shape consistent with non-deletion deploy.* / stack.* rows.
func deletionAuditResourceType(kind string) string {
	if strings.HasPrefix(kind, "stack.") {
		return "stack"
	}
	return "deploy"
}

// EmailConfirmDeletionRedirectHandler returns a tiny handler that 302s
// an email-link click to the dashboard's /app/confirm-deletion page.
// The API never validates the token here — the click is a navigation,
// not an action. The dashboard runs the POST (which requires the user's
// existing session) so we keep "click = open the dashboard, dashboard
// asks if you want to confirm" as the human-readable flow.
//
// Registered at GET /auth/email/confirm-deletion. The handler returns
// a 302 with no body so a browser pre-fetch by an email scanner can't
// inadvertently trigger destruction.
func EmailConfirmDeletionRedirectHandler(dashboardBaseURL string) fiber.Handler {
	base := strings.TrimRight(dashboardBaseURL, "/")
	return func(c *fiber.Ctx) error {
		token := c.Query("t")
		if strings.TrimSpace(token) == "" {
			return c.Status(http.StatusBadRequest).SendString("Missing token")
		}
		// We deliberately encode the token as a query param on the
		// dashboard URL so the dashboard's React router picks it up
		// via useSearchParams. Fragment-based passing would hide it
		// from server logs but break dashboard SSR-fallback paths.
		target := fmt.Sprintf("%s/app/confirm-deletion?t=%s", base, token)
		return c.Redirect(target, http.StatusFound)
	}
}
