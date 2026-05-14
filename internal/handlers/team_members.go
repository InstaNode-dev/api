package handlers

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
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// TeamMembersHandler serves REST team membership endpoints (mirrors dashboard gRPC behaviour).
type TeamMembersHandler struct {
	db    *sql.DB
	cfg   *config.Config
	plans *plans.Registry
	mail  *email.Client
	rdb   *redis.Client
}

// NewTeamMembersHandler constructs a TeamMembersHandler.
//
// rdb is optional — when nil the per-team invite rate limit (POST
// /team/members/invite) degrades to "no limit" rather than failing the
// request. Production callers always pass a real client; tests that don't
// need rate-limit assertions can pass nil to keep their setup tiny.
func NewTeamMembersHandler(db *sql.DB, cfg *config.Config, reg *plans.Registry, mail *email.Client, rdb *redis.Client) *TeamMembersHandler {
	return &TeamMembersHandler{db: db, cfg: cfg, plans: reg, mail: mail, rdb: rdb}
}

func (h *TeamMembersHandler) teamPlanTier(c *fiber.Ctx, teamID uuid.UUID) (string, error) {
	var tier string
	err := h.db.QueryRowContext(c.Context(), `SELECT plan_tier FROM teams WHERE id = $1`, teamID).Scan(&tier)
	return tier, err
}

func (h *TeamMembersHandler) requireOwner(c *fiber.Ctx, teamID, userID uuid.UUID) bool {
	role, err := models.GetUserRole(c.Context(), h.db, teamID, userID)
	if err != nil {
		slog.Error("team_members.role_lookup", "error", err)
		return false
	}
	return role == "owner"
}

// ListMembers handles GET /api/v1/team/members
func (h *TeamMembersHandler) ListMembers(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	// Any team member may list — owner, admin, developer, viewer, or legacy "member".
	role, err := models.GetUserRole(c.Context(), h.db, teamID, userID)
	if err != nil || role == "" {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Not a member of this team")
	}
	members, err := models.ListTeamMembers(c.Context(), h.db, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "list_failed", "Failed to list members")
	}
	tier, err := h.teamPlanTier(c, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "tier_failed", "Failed to read team plan")
	}
	limit := h.plans.TeamMemberLimit(tier)
	items := make([]fiber.Map, 0, len(members))
	for _, m := range members {
		items = append(items, fiber.Map{
			"user_id":   m.ID.String(),
			"email":     m.Email,
			"role":      m.Role,
			"joined_at": m.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return c.JSON(fiber.Map{"ok": true, "members": items, "member_limit": limit})
}

type inviteBody struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// allowedSimpleInviteRoles bounds the set of roles accepted by the simpler
// /api/v1/team/members/invite endpoint. "member" is retained as a legacy
// alias of the owner/member flow; admin/developer/viewer use the RBAC flow.
var allowedSimpleInviteRoles = map[string]struct{}{
	"admin":     {},
	"developer": {},
	"viewer":    {},
	"member":    {},
}

// InviteMember handles POST /api/v1/team/members/invite
//
// Rate limit: 10 invites / hour / team_id (Redis sliding counter, fail-open
// on Redis errors — see checkInviteRateLimit). Idempotency-Key support
// short-circuits replays before any DB work.
//
// Seat-limit enforcement: BOTH the legacy "member" flow and the RBAC
// (admin/developer/viewer) flow consult plans.TeamMemberLimit and refuse
// the (n+1)th seat. Pre-fix this branch silently bypassed the cap for
// RBAC invites — finding #50.
func (h *TeamMembersHandler) InviteMember(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}

	// Idempotency-Key + rate limit: both layer in front of role/auth checks
	// so a replay or a brute-force attempt costs the budget for the
	// original request, not for the gated re-check. The replay short-
	// circuit happens INSIDE checkInviteIdempotency — if it returns
	// handled=true the caller must return immediately.
	idemKey := strings.TrimSpace(c.Get("Idempotency-Key"))
	if idemKey != "" {
		handled, err := h.replayInviteIfCached(c, teamID, idemKey)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}
	if h.rdb != nil {
		over, rlErr := h.checkInviteRateLimit(c.Context(), teamID)
		if rlErr != nil {
			slog.Warn("team_members.invite_rate_limit_redis_error", "error", rlErr, "team_id", teamID)
			// Fail open — do not block legitimate invites on a Redis
			// hiccup. The cap will re-engage when Redis returns.
		} else if over {
			return respondError(c, fiber.StatusTooManyRequests, "rate_limit_exceeded",
				"Too many team invites — limit is 10 per hour per team. Wait and retry, or reach out to support if you need a higher cap.")
		}
	}

	// Owner OR admin may invite (legacy "owner" was sole inviter; RBAC adds admin).
	actorRole, err := models.GetUserRole(c.Context(), h.db, teamID, userID)
	if err != nil {
		slog.Error("team_members.role_lookup", "error", err)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Request failed")
	}
	if actorRole != "owner" && actorRole != "admin" {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner or admin only")
	}
	var body inviteBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON")
	}
	emailAddr := strings.TrimSpace(body.Email)
	if emailAddr == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_email", "email is required")
	}
	role := strings.TrimSpace(strings.ToLower(body.Role))
	if role == "" {
		role = "member"
	}
	if _, ok := allowedSimpleInviteRoles[role]; !ok {
		return respondError(c, fiber.StatusBadRequest, "invalid_role",
			"role must be one of: admin, developer, viewer, member")
	}
	tier, err := h.teamPlanTier(c, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "tier_failed", "Failed to read team plan")
	}
	limit := h.plans.TeamMemberLimit(tier)

	teamRow, _ := models.GetTeamByID(c.Context(), h.db, teamID)
	teamName := ""
	if teamRow != nil && teamRow.Name.Valid {
		teamName = teamRow.Name.String
	}
	base := strings.TrimRight(h.cfg.DashboardBaseURL, "/")

	// Legacy "member" role uses the owner/member flow with seat-limit enforcement.
	// admin/developer/viewer use the RBAC token flow.
	if role == "member" {
		// Owner/member flow currently requires owner; admins fall back to the
		// RBAC flow with role="developer" since legacy seats can't be granted
		// by non-owners.
		if actorRole != "owner" {
			return respondError(c, fiber.StatusForbidden, "forbidden",
				"Only the team owner can invite legacy members; use role=developer instead")
		}
		inv, err := models.InviteMember(c.Context(), h.db, teamID, emailAddr, role, userID, limit)
		if err != nil {
			return teamMembersModelError(c, err)
		}
		if h.mail != nil {
			acceptURL := base + "/settings?section=team&invite=" + inv.ID.String()
			if mailErr := h.mail.SendTeamInvite(c.Context(), inv.Email, teamName, acceptURL); mailErr != nil {
				slog.Warn("team_members.invite_email_failed", "error", mailErr)
			}
		}
		respBody := fiber.Map{
			"ok": true,
			"invitation": fiber.Map{
				"id":         inv.ID.String(),
				"email":      inv.Email,
				"role":       inv.Role,
				"status":     inv.Status,
				"invited_by": inv.InvitedBy.String(),
				"created_at": inv.CreatedAt.UTC().Format(time.RFC3339),
				"expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
			},
		}
		h.cacheInviteResponse(c.Context(), teamID, idemKey, fiber.StatusCreated, respBody)
		// Audit: team.member.invited (legacy path).
		h.emitInviteAudit(c.Context(), teamID, userID, inv.ID, inv.Email, role)
		return c.Status(fiber.StatusCreated).JSON(respBody)
	}

	// RBAC flow: admin / developer / viewer — token-based single-use invite.
	// SEAT-LIMIT FIX (finding #50): pre-fix this branch SKIPPED the seat
	// cap entirely, letting an admin upgrade-bypass the per-tier
	// member_limit by inviting unlimited admins/developers/viewers. We
	// now enforce the same cap here that the legacy "member" path
	// enforces inside models.InviteMember.
	ok, seatErr := h.checkTeamSeatLimit(c.Context(), teamID, limit)
	if seatErr != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to check seat availability")
	}
	if !ok {
		return respondError(c, fiber.StatusConflict, "member_limit",
			fmt.Sprintf("Team is at the member limit for the %s plan (limit=%d). Remove a member or upgrade.", tier, limit))
	}
	inv, err := models.CreateRBACInvitation(c.Context(), h.db, teamID, emailAddr, role, userID)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	if h.mail != nil {
		acceptURL := base + "/invitations/" + inv.Token + "/accept"
		if mailErr := h.mail.SendTeamInvite(c.Context(), inv.Email, teamName, acceptURL); mailErr != nil {
			slog.Warn("team_members.invite_email_failed", "error", mailErr)
		}
	}
	respBody := fiber.Map{
		"ok": true,
		"invitation": fiber.Map{
			"id":         inv.ID.String(),
			"email":      inv.Email,
			"role":       inv.Role,
			"token":      inv.Token,
			"status":     inv.Status(),
			"invited_by": inv.InvitedBy.String(),
			"created_at": inv.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}
	h.cacheInviteResponse(c.Context(), teamID, idemKey, fiber.StatusCreated, respBody)
	h.emitInviteAudit(c.Context(), teamID, userID, inv.ID, inv.Email, role)
	return c.Status(fiber.StatusCreated).JSON(respBody)
}

// checkTeamSeatLimit reports whether the team has room for one more seat.
// Reads members + pending invitations and returns true iff the sum is
// strictly less than the supplied limit. -1 limit = unlimited.
//
// Shared with the legacy /api/v1/team/members/invite "member" path via
// models.InviteMember's withinMemberLimit. This wrapper is the canonical
// pre-check for the RBAC path so seat math lives in one model-facing
// helper, not duplicated across handler branches.
func (h *TeamMembersHandler) checkTeamSeatLimit(ctx context.Context, teamID uuid.UUID, limit int) (bool, error) {
	if limit < 0 {
		return true, nil
	}
	members, err := models.CountTeamMembers(ctx, h.db, teamID)
	if err != nil {
		return false, err
	}
	pending, err := models.CountPendingInvitations(ctx, h.db, teamID)
	if err != nil {
		return false, err
	}
	return (members + pending) < limit, nil
}

// inviteRateLimitWindow + inviteRateLimitMax bound POST /team/members/invite
// to 10 invites/hour/team_id. Sliding window via a sorted set keyed by
// rl_invite:<team_id>.
const (
	inviteRateLimitWindow = time.Hour
	inviteRateLimitMax    = 10
)

// checkInviteRateLimit returns (over=true) when this team has already hit
// the per-hour invite cap. Fail-open: a Redis error returns (false, err) so
// the caller can log the error and continue rather than block legit work.
//
// Algorithm: ZREMRANGEBYSCORE old entries, ZCARD remaining, ZADD this
// attempt. Mirror of middleware/admin_rate_limit.go's pattern, scoped to
// invites instead of admin probes.
func (h *TeamMembersHandler) checkInviteRateLimit(ctx context.Context, teamID uuid.UUID) (bool, error) {
	key := "rl_invite:" + teamID.String()
	now := time.Now()
	cutoff := now.Add(-inviteRateLimitWindow).UnixNano()
	score := now.UnixNano()
	member := fmt.Sprintf("%d:%d", score, score%1000003)
	pipe := h.rdb.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("(%d", cutoff))
	cardCmd := pipe.ZCard(ctx, key)
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(score), Member: member})
	pipe.Expire(ctx, key, inviteRateLimitWindow+time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("invite_rate_limit pipe: %w", err)
	}
	count, err := cardCmd.Result()
	if err != nil {
		return false, fmt.Errorf("invite_rate_limit zcard: %w", err)
	}
	return count >= int64(inviteRateLimitMax), nil
}

// inviteIdempotencyEntry is the Redis-stored shape of a cached invite
// response. Pre-fix the path had no idempotency at all (finding #55) — an
// agent retrying on a transient network error created duplicate
// invitations + sent duplicate emails. The handler-local cache is scoped
// per team_id+key so a key collision across teams is impossible.
type inviteIdempotencyEntry struct {
	Status int             `json:"s"`
	Body   json.RawMessage `json:"b"`
}

// inviteIdempotencyTTL bounds how long a cached response lives. 24h
// matches Stripe/AWS convention and the global middleware (see
// middleware/idempotency.go). Long-tail retries (an agent that gives up
// for hours then re-fires the same key) hit the cache; brand-new keys
// always proceed.
const inviteIdempotencyTTL = 24 * time.Hour

// inviteIdempotencyKey returns the Redis key for a cached invite response.
func inviteIdempotencyKey(teamID uuid.UUID, key string) string {
	return "idem:team_invite:" + teamID.String() + ":" + key
}

// replayInviteIfCached short-circuits the request when an Idempotency-Key
// hits the cache. Returns (handled=true, nil) after writing the cached
// response; (handled=false, nil) when no cache entry exists; (handled=false,
// err) when a respondError already wrote the body.
func (h *TeamMembersHandler) replayInviteIfCached(c *fiber.Ctx, teamID uuid.UUID, key string) (bool, error) {
	if h.rdb == nil {
		return false, nil
	}
	val, err := h.rdb.Get(c.Context(), inviteIdempotencyKey(teamID, key)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		slog.Warn("team_members.invite_idempotency_redis_error", "error", err)
		return false, nil
	}
	var ent inviteIdempotencyEntry
	if err := json.Unmarshal([]byte(val), &ent); err != nil {
		slog.Warn("team_members.invite_idempotency_decode_error", "error", err)
		return false, nil
	}
	c.Set("X-Idempotent-Replay", "true")
	c.Set("Content-Type", "application/json")
	if err := c.Status(ent.Status).Send(ent.Body); err != nil {
		return true, err
	}
	return true, nil
}

// cacheInviteResponse stores the success response so a subsequent call
// carrying the same Idempotency-Key replays it verbatim. Best-effort —
// Redis failures log and continue (the next replay attempt will just
// re-run the handler).
func (h *TeamMembersHandler) cacheInviteResponse(ctx context.Context, teamID uuid.UUID, key string, status int, body fiber.Map) {
	if h.rdb == nil || key == "" {
		return
	}
	b, err := json.Marshal(body)
	if err != nil {
		slog.Warn("team_members.invite_idempotency_marshal_error", "error", err)
		return
	}
	ent := inviteIdempotencyEntry{Status: status, Body: b}
	payload, err := json.Marshal(ent)
	if err != nil {
		slog.Warn("team_members.invite_idempotency_marshal_error", "error", err)
		return
	}
	if err := h.rdb.Set(ctx, inviteIdempotencyKey(teamID, key), payload, inviteIdempotencyTTL).Err(); err != nil {
		slog.Warn("team_members.invite_idempotency_store_error", "error", err)
	}
}

// emitInviteAudit fires a team.member.invited audit row. Best-effort.
func (h *TeamMembersHandler) emitInviteAudit(ctx context.Context, teamID, actorID, invID uuid.UUID, inviteEmail, role string) {
	metadata, _ := json.Marshal(map[string]any{
		"invitation_id": invID.String(),
		"invitee_email": inviteEmail,
		"role":          role,
	})
	if err := models.InsertAuditEvent(ctx, h.db, models.AuditEvent{
		TeamID:   teamID,
		UserID:   uuid.NullUUID{UUID: actorID, Valid: true},
		Actor:    "user",
		Kind:     "team.member.invited",
		Summary:  fmt.Sprintf("invited %s as %s", inviteEmail, role),
		Metadata: metadata,
	}); err != nil {
		slog.Warn("audit.team_member_invited.insert_failed", "error", err, "team_id", teamID)
	}
}

// RemoveMember handles DELETE /api/v1/team/members/:user_id.
//
// Refuses to remove the team's primary user (finding #49) — the legacy
// guard checked only role='owner', which silently allowed an owner who
// had been demoted via role-update to be removed. is_primary is the
// post-029 source of truth.
//
// Returns orphan_team_id in the response body (finding #52) so the
// caller knows which new personal team the removed user was reassigned
// to. Pre-fix the orphan team spawned silently and the caller had no
// way to audit it.
func (h *TeamMembersHandler) RemoveMember(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	actorID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, actorID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	targetID, err := uuid.Parse(c.Params("user_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_user_id", "Invalid user id")
	}
	orphanTeamID, err := models.RemoveMember(c.Context(), h.db, teamID, targetID)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	// Audit: team.member.removed. Best-effort.
	metadata, _ := json.Marshal(map[string]any{
		"target_user_id": targetID.String(),
		"orphan_team_id": orphanTeamID.String(),
	})
	if auditErr := models.InsertAuditEvent(c.Context(), h.db, models.AuditEvent{
		TeamID:   teamID,
		UserID:   uuid.NullUUID{UUID: actorID, Valid: true},
		Actor:    "user",
		Kind:     "team.member.removed",
		Summary:  "removed member " + targetID.String(),
		Metadata: metadata,
	}); auditErr != nil {
		slog.Warn("audit.team_member_removed.insert_failed", "error", auditErr, "team_id", teamID)
	}
	return c.JSON(fiber.Map{
		"ok":             true,
		"orphan_team_id": orphanTeamID.String(),
	})
}

// updateRoleBody is the JSON body for PATCH /api/v1/team/members/:user_id.
type updateRoleBody struct {
	Role string `json:"role"`
}

// UpdateRole handles PATCH /api/v1/team/members/:user_id with body {role}.
// Owner-only. Refuses role="owner" (use POST .../promote-to-primary for an
// atomic ownership transfer). Refuses unknown roles. Refuses to touch a
// user not on the caller's team.
func (h *TeamMembersHandler) UpdateRole(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	actorID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, actorID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	targetID, err := uuid.Parse(c.Params("user_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_user_id", "Invalid user id")
	}
	var body updateRoleBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON")
	}
	newRole, err := models.UpdateMemberRole(c.Context(), h.db, teamID, targetID, body.Role)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	// Audit: team.member.role_changed. Best-effort.
	metadata, _ := json.Marshal(map[string]any{
		"target_user_id": targetID.String(),
		"new_role":       newRole,
	})
	if auditErr := models.InsertAuditEvent(c.Context(), h.db, models.AuditEvent{
		TeamID:   teamID,
		UserID:   uuid.NullUUID{UUID: actorID, Valid: true},
		Actor:    "user",
		Kind:     "team.member.role_changed",
		Summary:  "set role of " + targetID.String() + " to " + newRole,
		Metadata: metadata,
	}); auditErr != nil {
		slog.Warn("audit.team_member_role_changed.insert_failed", "error", auditErr, "team_id", teamID)
	}
	return c.JSON(fiber.Map{
		"ok":      true,
		"user_id": targetID.String(),
		"role":    newRole,
	})
}

// PromoteToPrimary handles POST /api/v1/team/members/:user_id/promote-to-primary.
// Atomic transfer of the team's primary slot (and the owner role) from
// whoever currently holds it to the path-param target. Owner-only. Backed
// by models.PromoteMemberToPrimary which serializes through SELECT FOR
// UPDATE so concurrent transfers can't strand the team without a primary.
func (h *TeamMembersHandler) PromoteToPrimary(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	actorID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, actorID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	targetID, err := uuid.Parse(c.Params("user_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_user_id", "Invalid user id")
	}
	if err := models.PromoteMemberToPrimary(c.Context(), h.db, teamID, targetID); err != nil {
		return teamMembersModelError(c, err)
	}
	// Audit: team.member.promoted_to_primary. Best-effort.
	metadata, _ := json.Marshal(map[string]any{
		"new_primary_user_id": targetID.String(),
		"former_primary_id":   actorID.String(),
	})
	if auditErr := models.InsertAuditEvent(c.Context(), h.db, models.AuditEvent{
		TeamID:   teamID,
		UserID:   uuid.NullUUID{UUID: actorID, Valid: true},
		Actor:    "user",
		Kind:     "team.member.promoted_to_primary",
		Summary:  "promoted " + targetID.String() + " to primary",
		Metadata: metadata,
	}); auditErr != nil {
		slog.Warn("audit.team_member_promoted_to_primary.insert_failed", "error", auditErr, "team_id", teamID)
	}
	return c.JSON(fiber.Map{
		"ok":              true,
		"team_id":         teamID.String(),
		"primary_user_id": targetID.String(),
	})
}

// LeaveTeam handles POST /api/v1/team/members/leave
func (h *TeamMembersHandler) LeaveTeam(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if err := models.LeaveTeam(c.Context(), h.db, teamID, userID); err != nil {
		return teamMembersModelError(c, err)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// ListInvitations handles GET /api/v1/team/invitations
func (h *TeamMembersHandler) ListInvitations(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, userID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	invs, err := models.ListInvitations(c.Context(), h.db, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "list_failed", "Failed to list invitations")
	}
	items := make([]fiber.Map, 0, len(invs))
	for _, inv := range invs {
		items = append(items, fiber.Map{
			"id":         inv.ID.String(),
			"email":      inv.Email,
			"role":       inv.Role,
			"status":     inv.Status,
			"invited_by": inv.InvitedBy.String(),
			"created_at": inv.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	return c.JSON(fiber.Map{"ok": true, "invitations": items})
}

// RevokeInvitation handles DELETE /api/v1/team/invitations/:id
func (h *TeamMembersHandler) RevokeInvitation(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, userID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	invID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Invalid invitation id")
	}
	inv, err := models.GetInvitationByID(c.Context(), h.db, invID)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	if inv.TeamID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Invitation does not belong to this team")
	}
	if err := models.RevokeInvitation(c.Context(), h.db, invID); err != nil {
		return teamMembersModelError(c, err)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// AcceptInvitation handles POST /api/v1/team/invitations/:id/accept
func (h *TeamMembersHandler) AcceptInvitation(c *fiber.Ctx) error {
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	invID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Invalid invitation id")
	}
	inv, err := models.GetInvitationByID(c.Context(), h.db, invID)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	tier, terr := h.teamPlanTier(c, inv.TeamID)
	if terr != nil {
		return respondError(c, fiber.StatusInternalServerError, "tier_failed", "Failed to read team plan")
	}
	limit := h.plans.TeamMemberLimit(tier)
	result, err := models.AcceptInvitation(c.Context(), h.db, invID, userID, limit)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	resp := fiber.Map{"ok": true, "role": result.Role}
	if result.Warning != "" {
		// Finding #53: surface the silent owner→member demote so the
		// caller (and downstream LLM) can act on it. The handler
		// previously returned just {ok:true} and the agent had no
		// idea its requested role had been quietly downgraded.
		resp["warning"] = result.Warning
	}
	return c.JSON(resp)
}

func teamMembersModelError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, models.ErrNotTeamOwner):
		return respondError(c, fiber.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, models.ErrCannotRemovePrimary):
		// 400 + agent_action explains exactly the next step. The
		// canonical envelope is emitted by respondError; the
		// codeToAgentAction registry carries the agent_action text.
		return respondError(c, fiber.StatusBadRequest, "cannot_remove_primary", err.Error())
	case errors.Is(err, models.ErrCannotRemoveOwner), errors.Is(err, models.ErrOwnerCannotLeave):
		return respondError(c, fiber.StatusConflict, "failed_precondition", err.Error())
	case errors.Is(err, models.ErrInvitationNotFound):
		return respondError(c, fiber.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, models.ErrInvitationExpired), errors.Is(err, models.ErrInvitationNotPending):
		return respondError(c, fiber.StatusConflict, "invitation_invalid", err.Error())
	case errors.Is(err, models.ErrEmailMismatchInvite):
		return respondError(c, fiber.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, models.ErrMemberLimitReached):
		return respondError(c, fiber.StatusConflict, "member_limit", err.Error())
	case errors.Is(err, models.ErrAlreadyTeamMember), errors.Is(err, models.ErrDuplicatePendingInvite):
		return respondError(c, fiber.StatusConflict, "duplicate", err.Error())
	case errors.Is(err, models.ErrInvalidInviteRole), errors.Is(err, models.ErrInvalidMemberRole):
		return respondError(c, fiber.StatusBadRequest, "invalid_role", err.Error())
	case errors.Is(err, models.ErrCannotAssignOwnerRole):
		return respondError(c, fiber.StatusBadRequest, "cannot_assign_owner_role", err.Error())
	case errors.Is(err, models.ErrTargetNotOnTeam):
		return respondError(c, fiber.StatusNotFound, "not_found", err.Error())
	default:
		var notFound *models.ErrUserNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", notFound.Error())
		}
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Request failed")
	}
}
