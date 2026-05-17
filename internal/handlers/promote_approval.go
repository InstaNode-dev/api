package handlers

// promote_approval.go — surface for the email-link approval workflow that
// gates promotes / twin-provisions against non-development environments.
//
// Three endpoints live here:
//
//   GET  /approve/:token                    — public, HTML response. The
//     operator's email link lands here; this handler either (a) approves
//     the pending row and redirects to the dashboard, or (b) renders a
//     human-readable "expired" / "already used" page.
//
//   POST /api/v1/<admin-prefix>/promotions/:id/reject
//     — admin-only, marks a pending row 'rejected'. Wired under the
//     same admin gate as /admin/customers — the obscured path prefix
//     AND the ADMIN_EMAILS allowlist must both pass.
//
//   GET  /api/v1/<admin-prefix>/promotions?status=&limit=
//     — admin-only, lists rows for the operator dashboard.
//
// Why GET /approve/:token is at the root path (not /api/v1/...): the
// email URL needs to be short, memorable, and look like a control plane
// link to the user. The handler intentionally registers BEFORE the
// /api/v1 RequireAuth group so the public anonymous click works without
// a Bearer header — the token IS the credential.
//
// Why per-IP rate limit on GET /approve/:token: defends the 32-byte
// token space against an attacker who tries to brute-force a token.
// The math is overwhelmingly in our favour (2^256 search space, 10
// req/sec per IP would take more than the heat death of the universe),
// but the rate limit also bounds the cost of a benign click-loop bug in
// an email client.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/safego"
)

// PromoteApprovalDashboardURL is the dashboard route the GET /approve
// handler 302-redirects to after a successful approval. Plumbed as a
// package-level var so tests and self-hosted operators can override it
// (mirrors DefaultPricingURL in helpers.go).
var PromoteApprovalDashboardURL = "https://instanode.dev/app/promotions"

// promoteApprovalRateLimitPerSec is the per-IP request budget for the
// public GET /approve/:token endpoint. Defends the token space against
// brute-force probing. Pulled out as a constant so the test suite can
// reason about it without grepping for magic numbers.
const promoteApprovalRateLimitPerSec = 10

// PromoteApprovalHandler owns the three routes above. Composes the DB
// model layer + Redis for the per-IP rate limit. rdb may be nil in
// tests; rate limiting fails open in that case (consistent with the
// rest of the codebase's Redis-outage posture).
type PromoteApprovalHandler struct {
	db  *sql.DB
	rdb *redis.Client
}

// NewPromoteApprovalHandler constructs the handler. db is required;
// rdb may be nil (rate limit fails open).
func NewPromoteApprovalHandler(db *sql.DB, rdb *redis.Client) *PromoteApprovalHandler {
	return &PromoteApprovalHandler{db: db, rdb: rdb}
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /approve/:token — public, HTML response, rate-limited per IP.
// ─────────────────────────────────────────────────────────────────────────────

// Approve renders the click-through page for the email approval link.
// Four branches:
//
//  1. Token doesn't exist → 404 "this link is invalid" HTML.
//  2. Token exists but expires_at < now() → flips row to 'expired',
//     returns 410 "this link expired" HTML.
//  3. Token exists, status != 'pending' → 410 "already used" HTML.
//  4. Token valid + pending + unexpired → atomic ApprovePromoteApproval,
//     audit-log row, 302 redirect to the dashboard.
//
// The handler NEVER reveals which branch it took to a probing attacker
// who pings random tokens — they all yield "invalid or expired" pages.
// The only externally distinguishable branch is the success redirect
// (302 vs 4xx), which is unavoidable because the user MUST see they
// did the right thing.
func (h *PromoteApprovalHandler) Approve(c *fiber.Ctx) error {
	// Per-IP rate limit. Defends against a script that tries token
	// guesses one per request; fails open on Redis error so a Redis
	// outage doesn't break the genuine flow.
	if h.rdb != nil {
		if exceeded, err := h.checkApproveRateLimit(c.Context(), c.IP()); err != nil {
			// Fail open — never block a legitimate operator on a Redis blip.
			slog.Warn("promote_approval.rate_limit_redis_error",
				"error", err, "ip", c.IP(),
				"request_id", middleware.GetRequestID(c))
		} else if exceeded {
			c.Set("Content-Type", "text/html; charset=utf-8")
			c.Set("Retry-After", "1")
			return c.Status(fiber.StatusTooManyRequests).SendString(approvalHTMLRateLimit())
		}
	}

	token := c.Params("token")
	if token == "" {
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Status(fiber.StatusBadRequest).SendString(approvalHTMLInvalid())
	}

	row, err := models.GetPromoteApprovalByToken(c.Context(), h.db, token)
	if errors.Is(err, models.ErrPromoteApprovalNotFound) {
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Status(fiber.StatusNotFound).SendString(approvalHTMLInvalid())
	}
	if err != nil {
		slog.Error("promote_approval.lookup_failed",
			"error", err, "request_id", middleware.GetRequestID(c))
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Status(fiber.StatusServiceUnavailable).SendString(approvalHTMLServiceError())
	}

	// Expired? Flip the row and surface the "expired" copy. The flip is
	// best-effort — if the UPDATE fails the user still sees "expired."
	if !row.ExpiresAt.IsZero() && time.Now().UTC().After(row.ExpiresAt) {
		if mErr := models.MarkPromoteApprovalExpired(c.Context(), h.db, row.ID); mErr != nil {
			slog.Warn("promote_approval.mark_expired_failed",
				"error", mErr, "id", row.ID,
				"request_id", middleware.GetRequestID(c))
		}
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Status(fiber.StatusGone).SendString(approvalHTMLExpired())
	}

	// Already used / rejected / executed? Render the "already used" copy.
	if row.Status != models.PromoteApprovalStatusPending {
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Status(fiber.StatusGone).SendString(approvalHTMLAlreadyUsed())
	}

	// Happy path: atomic approval. If two clicks race, exactly one wins;
	// the loser sees "already used" via the WHERE status='pending' guard.
	ok, err := models.ApprovePromoteApproval(c.Context(), h.db, row.ID)
	if err != nil {
		slog.Error("promote_approval.approve_failed",
			"error", err, "id", row.ID,
			"request_id", middleware.GetRequestID(c))
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Status(fiber.StatusServiceUnavailable).SendString(approvalHTMLServiceError())
	}
	if !ok {
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Status(fiber.StatusGone).SendString(approvalHTMLAlreadyUsed())
	}

	// Audit row — best-effort, never blocks the redirect. The forwarder
	// turns this into the optional "approved" confirmation email.
	safego.Go("promote_approval.approved_audit", func() {
		emitPromoteAuditEvent(context.Background(), h.db, row, models.AuditKindPromoteApproved,
			"Promote approval clicked for "+row.FromEnv+" → "+row.ToEnv,
			map[string]any{
				"approval_id": row.ID.String(),
				"from_env":    row.FromEnv,
				"to_env":      row.ToEnv,
				"kind":        row.PromoteKind,
			})
	})

	// Redirect to the dashboard. The dashboard reads ?approved=1 from
	// the query string to render a success toast on first paint.
	redirect := PromoteApprovalDashboardURL + "/" + row.ID.String() + "?approved=1"
	return c.Redirect(redirect, fiber.StatusFound)
}

// checkApproveRateLimit returns (true, nil) when the caller has exceeded
// promoteApprovalRateLimitPerSec requests in the current 1-second window.
// Uses a Redis INCR with 2-second TTL keyed on IP — same pattern as the
// rate_limit middleware but with a per-second window instead of per-day.
func (h *PromoteApprovalHandler) checkApproveRateLimit(ctx context.Context, ip string) (bool, error) {
	if ip == "" {
		return false, nil
	}
	// Bucket key is the unix second. INCR + EXPIRE gives us a sliding-
	// second sized window with no further bookkeeping.
	bucket := time.Now().UTC().Unix()
	key := fmt.Sprintf("rl:approve:%s:%d", ip, bucket)

	pipe := h.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 2*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("approve rate-limit pipeline: %w", err)
	}
	count, err := incr.Result()
	if err != nil {
		return false, fmt.Errorf("approve rate-limit incr: %w", err)
	}
	return count > int64(promoteApprovalRateLimitPerSec), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v1/<admin-prefix>/promotions/:id/reject — admin-only.
// ─────────────────────────────────────────────────────────────────────────────

// RejectResponse is the success body for POST .../reject.
type RejectResponse struct {
	OK     bool   `json:"ok"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Reject flips a pending row to 'rejected'. Returns 404 if the row
// doesn't exist, 409 if the row is no longer pending (already approved /
// expired / rejected). Admin gating is enforced by RequireAdmin
// middleware on the route.
func (h *PromoteApprovalHandler) Reject(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "approval id must be a valid UUID")
	}

	row, err := models.GetPromoteApprovalByID(c.Context(), h.db, id)
	if errors.Is(err, models.ErrPromoteApprovalNotFound) {
		return respondError(c, fiber.StatusNotFound, "not_found", "approval not found")
	}
	if err != nil {
		slog.Error("promote_approval.reject_lookup_failed",
			"error", err, "id", id, "request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to look up approval")
	}

	if row.Status != models.PromoteApprovalStatusPending {
		return respondError(c, fiber.StatusConflict, "not_pending",
			"approval is no longer pending (status="+row.Status+")")
	}

	ok, err := models.RejectPromoteApproval(c.Context(), h.db, id)
	if err != nil {
		slog.Error("promote_approval.reject_failed",
			"error", err, "id", id, "request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "reject_failed", "Failed to reject approval")
	}
	if !ok {
		// Lost the race: someone else moved the row out of pending
		// between our read and our UPDATE. Treat as 409 — the resource
		// state changed under us.
		return respondError(c, fiber.StatusConflict, "not_pending",
			"approval is no longer pending — somebody beat us to it")
	}

	// Audit row — best-effort.
	safego.Go("promote_approval.rejected_audit", func() {
		emitPromoteAuditEvent(context.Background(), h.db, row, models.AuditKindPromoteRejected,
			"Promote approval rejected by admin for "+row.FromEnv+" → "+row.ToEnv,
			map[string]any{
				"approval_id": row.ID.String(),
				"from_env":    row.FromEnv,
				"to_env":      row.ToEnv,
				"kind":        row.PromoteKind,
				"rejected_by": middleware.GetEmail(c),
			})
	})

	return c.JSON(RejectResponse{
		OK:     true,
		ID:     id.String(),
		Status: models.PromoteApprovalStatusRejected,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/<admin-prefix>/promotions?status=&limit= — admin-only.
// ─────────────────────────────────────────────────────────────────────────────

// ListItem is the JSON shape per row in the list response. Excludes the
// raw token (security) and the promote_payload (size + the dashboard
// doesn't need it inline).
type ListItem struct {
	ID               string  `json:"id"`
	TeamID           string  `json:"team_id"`
	RequestedByEmail string  `json:"requested_by_email"`
	PromoteKind      string  `json:"promote_kind"`
	FromEnv          string  `json:"from_env"`
	ToEnv            string  `json:"to_env"`
	Status           string  `json:"status"`
	CreatedAt        string  `json:"created_at"`
	ExpiresAt        string  `json:"expires_at"`
	ApprovedAt       *string `json:"approved_at,omitempty"`
	ExecutedAt       *string `json:"executed_at,omitempty"`
	RejectedAt       *string `json:"rejected_at,omitempty"`
}

// ListResponse is the success body of GET .../promotions.
type ListResponse struct {
	OK    bool       `json:"ok"`
	Items []ListItem `json:"items"`
	Total int        `json:"total"`
}

// List returns recent promote_approvals rows for the admin dashboard.
// Accepts ?status= and ?limit= query parameters (both optional).
func (h *PromoteApprovalHandler) List(c *fiber.Ctx) error {
	status := c.Query("status")
	limit := 50
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}

	rows, err := models.ListPromoteApprovals(c.Context(), h.db, models.ListPromoteApprovalsParams{
		Status: status,
		Limit:  limit,
	})
	if err != nil {
		slog.Error("promote_approval.list_failed",
			"error", err, "status", status, "limit", limit,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to list approvals")
	}

	items := make([]ListItem, 0, len(rows))
	for _, r := range rows {
		item := ListItem{
			ID:               r.ID.String(),
			TeamID:           r.TeamID.String(),
			RequestedByEmail: r.RequestedByEmail,
			PromoteKind:      r.PromoteKind,
			FromEnv:          r.FromEnv,
			ToEnv:            r.ToEnv,
			Status:           r.Status,
			CreatedAt:        r.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt:        r.ExpiresAt.UTC().Format(time.RFC3339),
		}
		if r.ApprovedAt.Valid {
			s := r.ApprovedAt.Time.UTC().Format(time.RFC3339)
			item.ApprovedAt = &s
		}
		if r.ExecutedAt.Valid {
			s := r.ExecutedAt.Time.UTC().Format(time.RFC3339)
			item.ExecutedAt = &s
		}
		if r.RejectedAt.Valid {
			s := r.RejectedAt.Time.UTC().Format(time.RFC3339)
			item.RejectedAt = &s
		}
		items = append(items, item)
	}

	return c.JSON(ListResponse{
		OK:    true,
		Items: items,
		Total: len(items),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers — used by stack.Promote / twin.ProvisionTwin so the
// "create pending row + emit audit + return 202" flow lives in one place.
// ─────────────────────────────────────────────────────────────────────────────

// approveURLForToken returns the canonical click-through URL for an
// approval token. Pulled out so the email forwarder and the audit-log
// metadata agree on the same shape.
func approveURLForToken(token string) string {
	return "https://api.instanode.dev/approve/" + url.PathEscape(token)
}

// PromoteApprovalRequest is the typed input used by callers (stack /
// twin handlers) to create a pending row. Carrying a struct (vs a long
// arg list) makes future additions (e.g. team-wide policy linkage)
// non-breaking.
type PromoteApprovalRequest struct {
	TeamID           uuid.UUID
	RequestedByEmail string
	PromoteKind      string // models.PromoteApprovalKindStack | KindResourceTwin
	PromotePayload   []byte
	FromEnv          string
	ToEnv            string
	// Summary is used in the audit_log row's summary column AND in the
	// email subject. Keep short — "Promote staging → production for app-x".
	Summary string
	// EmailMetaExtras carries kind-specific metadata the Brevo template
	// needs (e.g. stack_slug for stack promotes, resource_id for twins).
	// Merged into the audit row's metadata JSON so the forwarder gets
	// one consolidated read.
	EmailMetaExtras map[string]any
}

// CreatePromoteApprovalAndEmit is the shared "create pending row + emit
// audit_log row that triggers the email" routine called by both the
// stack Promote handler and the twin ProvisionTwin handler.
//
// Returns the freshly-inserted row so the handler can serialize the
// 202 response (approval_id + expires_at) for the caller. The audit
// emit is best-effort and never blocks the handler's success path —
// it runs in a goroutine and logs on failure.
func CreatePromoteApprovalAndEmit(
	ctx context.Context,
	db *sql.DB,
	req PromoteApprovalRequest,
) (*models.PromoteApproval, error) {
	token, err := models.GeneratePromoteApprovalToken()
	if err != nil {
		return nil, fmt.Errorf("CreatePromoteApprovalAndEmit: gen token: %w", err)
	}

	row, err := models.CreatePromoteApproval(ctx, db, models.CreatePromoteApprovalParams{
		Token:            token,
		TeamID:           req.TeamID,
		RequestedByEmail: req.RequestedByEmail,
		PromoteKind:      req.PromoteKind,
		PromotePayload:   req.PromotePayload,
		FromEnv:          req.FromEnv,
		ToEnv:            req.ToEnv,
	})
	if err != nil {
		return nil, fmt.Errorf("CreatePromoteApprovalAndEmit: insert: %w", err)
	}

	// Build the audit metadata. The Brevo forwarder template
	// `instanode-promote-approval-v1` reads:
	//   - from_env, to_env, requested_by_email, approve_url
	//   - plus whatever kind-specific extras (e.g. stack_slug,
	//     resource_id) the caller passed in EmailMetaExtras.
	meta := map[string]any{
		"approval_id":        row.ID.String(),
		"from_env":           req.FromEnv,
		"to_env":             req.ToEnv,
		"requested_by_email": req.RequestedByEmail,
		"approve_url":        approveURLForToken(token),
		"promote_kind":       req.PromoteKind,
		"expires_at":         row.ExpiresAt.UTC().Format(time.RFC3339),
	}
	for k, v := range req.EmailMetaExtras {
		// Caller wins on key collision so extras can override the
		// defaults if the template needs the exact same key under a
		// different value (rare; today the maps never collide).
		meta[k] = v
	}
	metaJSON, mErr := json.Marshal(meta)
	if mErr != nil {
		// A marshal failure here is essentially impossible (we control
		// the map shape), but log + persist NULL rather than a panic.
		slog.Warn("promote_approval.audit_meta_marshal_failed",
			"error", mErr, "approval_id", row.ID)
		metaJSON = nil
	}

	summary := req.Summary
	if summary == "" {
		summary = "Promote approval requested for " + req.FromEnv + " → " + req.ToEnv
	}

	// Emit the audit event in a goroutine — best-effort. The forwarder
	// picks the row up downstream and sends the actual email.
	safego.Go("promote_approval.audit", func() {
		(func(teamID uuid.UUID, kind, summary string, metadata []byte) {
			bgCtx := context.Background()
			ev := models.AuditEvent{
				TeamID:   teamID,
				Actor:    "agent",
				Kind:     kind,
				Summary:  summary,
				Metadata: metadata,
			}
			if aErr := models.InsertAuditEvent(bgCtx, db, ev); aErr != nil {
				slog.Warn("promote_approval.audit_emit_failed",
					"error", aErr, "kind", kind, "team_id", teamID)
			}
		})(req.TeamID, models.AuditKindPromoteApprovalRequested, summary, metaJSON)
	})

	return row, nil
}

// emitPromoteAuditEvent is a small helper used by the Approve and Reject
// handlers to emit the secondary audit rows (.approved / .rejected) with
// the same metadata shape as the original .approval_requested row. Keeps
// the audit timeline coherent for downstream consumers.
func emitPromoteAuditEvent(
	ctx context.Context,
	db *sql.DB,
	row *models.PromoteApproval,
	kind, summary string,
	extras map[string]any,
) {
	meta := map[string]any{
		"approval_id":        row.ID.String(),
		"from_env":           row.FromEnv,
		"to_env":             row.ToEnv,
		"requested_by_email": row.RequestedByEmail,
		"promote_kind":       row.PromoteKind,
	}
	for k, v := range extras {
		meta[k] = v
	}
	metaJSON, mErr := json.Marshal(meta)
	if mErr != nil {
		slog.Warn("promote_approval.audit_meta_marshal_failed",
			"error", mErr, "approval_id", row.ID, "kind", kind)
		metaJSON = nil
	}
	ev := models.AuditEvent{
		TeamID:   row.TeamID,
		Actor:    "agent",
		Kind:     kind,
		Summary:  summary,
		Metadata: metaJSON,
	}
	if aErr := models.InsertAuditEvent(ctx, db, ev); aErr != nil {
		slog.Warn("promote_approval.audit_emit_failed",
			"error", aErr, "kind", kind, "approval_id", row.ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML response copy. Kept inline so the handler binary has no external
// template dependency — these pages are tiny and rarely change.
// ─────────────────────────────────────────────────────────────────────────────

// approvalPageWrapper renders the shared layout shell. h2 carries the
// headline; body is the prose underneath.
func approvalPageWrapper(title, h2, body string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>` + title + ` — instanode.dev</title>
  <meta name="robots" content="noindex,nofollow" />
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:560px;margin:48px auto;padding:0 24px;color:#111;line-height:1.5}
    h2{margin-top:0}
    a.btn{display:inline-block;background:#111;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;margin-top:16px}
    .muted{color:#666;font-size:13px;margin-top:32px}
  </style>
</head>
<body>
  <h2>` + h2 + `</h2>
  <div>` + body + `</div>
  <p class="muted">— instanode.dev</p>
</body>
</html>`
}

func approvalHTMLInvalid() string {
	return approvalPageWrapper(
		"Invalid approval link",
		"This approval link is invalid",
		`<p>The token in this URL does not match any pending promote approval. It may have been mistyped, or it was never issued.</p>
<p>If you believe this is wrong, re-request the promote from the dashboard.</p>
<a class="btn" href="https://instanode.dev/app">Open dashboard</a>`,
	)
}

func approvalHTMLExpired() string {
	return approvalPageWrapper(
		"This link has expired",
		"This approval link has expired",
		`<p>Promote approval links are valid for 24 hours. Re-request the promote from the dashboard to receive a fresh link.</p>
<a class="btn" href="https://instanode.dev/app">Open dashboard</a>`,
	)
}

func approvalHTMLAlreadyUsed() string {
	return approvalPageWrapper(
		"This link has already been used",
		"This approval link has already been used",
		`<p>The promote request has already been approved, rejected, or executed. View its status in the dashboard.</p>
<a class="btn" href="https://instanode.dev/app/promotions">View promotions</a>`,
	)
}

func approvalHTMLRateLimit() string {
	return approvalPageWrapper(
		"Slow down",
		"Too many requests",
		`<p>Wait a moment and try again.</p>`,
	)
}

func approvalHTMLServiceError() string {
	return approvalPageWrapper(
		"Service unavailable",
		"Service temporarily unavailable",
		`<p>We could not process this approval right now. Please retry in a moment, or check <a href="https://instanode.dev/status">https://instanode.dev/status</a>.</p>`,
	)
}
