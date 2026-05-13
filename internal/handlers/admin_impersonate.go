package handlers

// admin_impersonate.go — POST /api/v1/admin/customers/:team_id/impersonate.
//
// Mints a short-lived (10 minute), read-only JWT scoped to the target
// customer's team so a platform admin can debug the dashboard "as" the
// customer without touching their data. Every mutating endpoint under
// /api/v1/* is gated by RequireWritable, which 403s any request whose
// JWT carries `read_only:true`. The flag is irrevocable for the session
// lifetime — there is no "downgrade to writable" path within a single
// token's validity.
//
// Audit trail: every issuance writes an audit_log row with
// kind=admin.impersonation_started. The metadata blob carries the admin
// email, the target team_id, and the absolute expiry time so a future BI
// consumer can reconstruct "who viewed which customer, when, for how
// long" without re-deriving the impersonation token's claims.
//
// What the minted token DOES NOT carry:
//
//   - uid (user_id) of any real user on the target team. We pass a NIL
//     uuid string for the `uid` claim so downstream handlers that read
//     GetUserID() don't accidentally assign a write to a real user's
//     account. The RequireAuth middleware requires a non-empty uid, so
//     we use the team's nominal owner user id (resolved at mint time) —
//     no user-creation, no shadow account. Document-of-record: every
//     write attempt is rejected by RequireWritable before it reaches the
//     handler, so the uid-owning user never sees the impersonation in
//     their own write audit trail.
//
//   - audience (`aud`). Audience checking is opt-in per claim (see
//     middleware.RequireAuth) — by omitting it we keep the impersonation
//     token compatible with every existing handler without having to
//     thread an env-specific canonical URL through the mint path.
//
//   - dpop (`cnf.jkt`). Impersonation tokens are bearer-only; the admin
//     is on a trusted device by definition.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// AuditKindAdminImpersonationStarted is the audit_log.kind written on
// every successful impersonation-token issuance. Single source of truth so
// the Loops forwarder + BI exports key on the constant rather than a
// drift-prone string literal. NOT yet listed in audit_kinds.go (which is
// for kinds Loops actively forwards) — admin impersonation is internal
// telemetry, not a customer-lifecycle email trigger.
const AuditKindAdminImpersonationStarted = "admin.impersonation_started"

// impersonationTokenTTL is the absolute lifetime of a minted impersonation
// JWT. 10 minutes is short enough to make a leaked token's blast radius
// trivial (the admin re-mints when their session naturally ages out) and
// long enough for a real debugging session ("click around, reproduce the
// bug, close the tab").
const impersonationTokenTTL = 10 * time.Minute

// AdminImpersonateHandler serves POST /admin/customers/:team_id/impersonate.
type AdminImpersonateHandler struct {
	db  *sql.DB
	cfg *config.Config
}

// NewAdminImpersonateHandler constructs the handler.
func NewAdminImpersonateHandler(db *sql.DB, cfg *config.Config) *AdminImpersonateHandler {
	return &AdminImpersonateHandler{db: db, cfg: cfg}
}

// impersonateClaims mirrors the relevant subset of middleware.sessionClaims
// — `read_only` and `impersonated_by` are the two new fields the
// RequireWritable middleware reads off the parsed JWT. The struct is
// duplicated here (rather than imported) because middleware.sessionClaims
// is package-private; both copies serialize to the same JSON wire shape
// so the consumer doesn't care which producer minted the token.
type impersonateClaims struct {
	UserID         string `json:"uid"`
	TeamID         string `json:"tid"`
	Email          string `json:"email"`
	ReadOnly       bool   `json:"read_only"`
	ImpersonatedBy string `json:"impersonated_by"`
	jwt.RegisteredClaims
}

// impersonationAuditMetadata is the audit_log.metadata payload emitted on
// every successful issuance. Typed (rather than an inline map) so the
// audit schema is a contract a future BI consumer can program against.
type impersonationAuditMetadata struct {
	ByAdminEmail    string    `json:"by_admin_email"`
	TargetTeamID    string    `json:"target_team_id"`
	TargetUserID    string    `json:"target_user_id"`
	TargetUserEmail string    `json:"target_user_email,omitempty"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	TTLSeconds      int       `json:"ttl_seconds"`
}

// Impersonate handles POST /api/v1/admin/customers/:team_id/impersonate.
//
// Response shape:
//
//	{
//	  "ok": true,
//	  "token": "<jwt>",
//	  "expires_at": "<RFC3339Nano>",
//	  "team_id": "<target>"
//	}
//
// No agent_action — this endpoint is operator-facing only and never hits
// an LLM agent's wall (callers are the founder, on a trusted device).
func (h *AdminImpersonateHandler) Impersonate(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("team_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	// 1. Verify the target team exists. Without this an admin could mint
	//    a session-token-shaped JWT for any team id they invent — which
	//    would pass JWT validation but yield 404s on every read. Failing
	//    fast here saves the operator a debugging round trip.
	if _, err := models.GetTeamByID(c.Context(), h.db, teamID); err != nil {
		var nf *models.ErrTeamNotFound
		if errors.As(err, &nf) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "no such team")
		}
		slog.Error("admin.impersonate.team_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load team")
	}

	// 2. Resolve a target user on the team to back the `uid` claim. The
	//    RequireAuth middleware rejects tokens with an empty `uid`, so the
	//    minted JWT MUST carry one — but we don't want to make up a user.
	//    Picking the team's owner (or earliest-joined member as fallback)
	//    keeps the impersonation token referencing a real, existing row.
	//    Every mutating endpoint will still be rejected by RequireWritable
	//    so this user never accumulates writes from the admin's session.
	targetUser, err := h.resolveTargetUser(c.Context(), teamID)
	if err != nil {
		if errors.Is(err, errImpersonateNoUsers) {
			return respondError(c, fiber.StatusConflict, "team_has_no_users",
				"target team has no users to impersonate — only teams with at least one user are debuggable")
		}
		slog.Error("admin.impersonate.user_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to resolve target user")
	}

	adminEmail := middleware.GetEmail(c)

	// 3. Mint the JWT. ReadOnly + ImpersonatedBy are the two flags
	//    RequireWritable + /auth/me read off the parsed claims. iat/exp
	//    are explicit so the audit-row metadata's issued_at/expires_at
	//    line up with what middleware.RequireAuth will enforce.
	now := time.Now().UTC()
	expiresAt := now.Add(impersonationTokenTTL)
	claims := impersonateClaims{
		UserID:         targetUser.ID.String(),
		TeamID:         teamID.String(),
		Email:          targetUser.Email,
		ReadOnly:       true,
		ImpersonatedBy: adminEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(h.cfg.JWTSecret))
	if err != nil {
		slog.Error("admin.impersonate.sign_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "sign_failed", "Failed to mint impersonation token")
	}

	// 4. Audit row — best-effort. A failure to record audit must NEVER
	//    surface as a 5xx (would leave the admin with a minted token they
	//    can't recall but can't audit either). Same fail-open posture as
	//    the rest of the audit-log call sites.
	meta, _ := json.Marshal(impersonationAuditMetadata{
		ByAdminEmail:    adminEmail,
		TargetTeamID:    teamID.String(),
		TargetUserID:    targetUser.ID.String(),
		TargetUserEmail: targetUser.Email,
		IssuedAt:        now,
		ExpiresAt:       expiresAt,
		TTLSeconds:      int(impersonationTokenTTL.Seconds()),
	})
	if err := models.InsertAuditEvent(c.Context(), h.db, models.AuditEvent{
		TeamID:  teamID,
		Actor:   "admin",
		Kind:    AuditKindAdminImpersonationStarted,
		Summary: fmt.Sprintf("admin %s started impersonation of team %s (target user %s, 10min)", adminEmail, teamID, targetUser.Email),
		Metadata: meta,
	}); err != nil {
		slog.Warn("admin.impersonate.audit_insert_failed", "error", err, "team_id", teamID)
	}

	return c.JSON(fiber.Map{
		"ok":         true,
		"token":      signed,
		"team_id":    teamID.String(),
		"expires_at": expiresAt.Format(time.RFC3339Nano),
	})
}

// errImpersonateNoUsers is returned by resolveTargetUser when the target
// team has zero users on file. Surfaces as a 409 — an empty team is
// technically a valid team row but isn't useful to impersonate (every
// read would 404 with no team_id-scoped data to display).
var errImpersonateNoUsers = errors.New("admin_impersonate: target team has no users")

// targetUserRow is the narrow projection resolveTargetUser returns. We
// don't need the full models.User shape — just the id + email for the JWT
// claims and the audit metadata.
type targetUserRow struct {
	ID    uuid.UUID
	Email string
}

// resolveTargetUser picks the team's nominal "primary" user — owner role
// when present, else earliest-joined member. The result is what backs the
// minted JWT's `uid` claim. Same DISTINCT ON ordering the
// admin-customer-list query uses (admin_customers.go's primary_user CTE)
// so an admin who clicks "view as" on a team listed in the dashboard
// gets impersonated as the same user the dashboard surfaces.
func (h *AdminImpersonateHandler) resolveTargetUser(ctx context.Context, teamID uuid.UUID) (*targetUserRow, error) {
	row := &targetUserRow{}
	err := h.db.QueryRowContext(ctx, `
		SELECT id, email
		FROM users
		WHERE team_id = $1
		ORDER BY (role = 'owner') DESC, created_at ASC
		LIMIT 1
	`, teamID).Scan(&row.ID, &row.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errImpersonateNoUsers
		}
		return nil, fmt.Errorf("resolveTargetUser: %w", err)
	}
	return row, nil
}
