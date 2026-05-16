package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/email"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// OnboardingHandler handles the anonymous-to-registered conversion flow.
type OnboardingHandler struct {
	db    *sql.DB
	cfg   *config.Config
	email *email.Client
}

// NewOnboardingHandler constructs an OnboardingHandler.
func NewOnboardingHandler(db *sql.DB, cfg *config.Config, emailClient *email.Client) *OnboardingHandler {
	return &OnboardingHandler{db: db, cfg: cfg, email: emailClient}
}

// StartLanding handles GET /start?t={jwt}
// Validates the JWT and redirects to the dashboard ClaimPage.
func (h *OnboardingHandler) StartLanding(c *fiber.Ctx) error {
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)
	jwtStr := c.Query("t")
	if jwtStr == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_token", "Upgrade token is required")
	}

	claims, err := crypto.VerifyOnboardingJWT([]byte(h.cfg.JWTSecret), jwtStr)
	if err != nil {
		slog.Warn("onboarding.start.invalid_jwt",
			"error", err,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Upgrade token is invalid or expired")
	}

	// Verify JTI exists and hasn't been converted.
	ev, err := models.GetOnboardingByJTI(ctx, h.db, claims.ID)
	if err != nil {
		var notFound *models.ErrOnboardingNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusBadRequest, "invalid_token", "Upgrade token not recognized")
		}
		slog.Error("onboarding.start.db_error", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to verify upgrade token")
	}

	if ev.ConvertedAt.Valid {
		return c.Redirect(h.cfg.DashboardBaseURL+"/claim?already_claimed=true", fiber.StatusFound)
	}

	metrics.ConversionFunnel.WithLabelValues("landing_viewed").Inc()

	return c.Redirect(h.cfg.DashboardBaseURL+"/claim?t="+url.QueryEscape(jwtStr), fiber.StatusFound)
}

// ClaimPreview handles GET /claim/preview?t={jwt}
// Returns the list of resources the caller is about to claim, without performing the claim.
// Authentication: the onboarding JWT in the query parameter IS the auth — no session needed.
func (h *OnboardingHandler) ClaimPreview(c *fiber.Ctx) error {
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)
	jwtStr := c.Query("t")
	if jwtStr == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_token", "Token is required")
	}

	claims, err := crypto.VerifyOnboardingJWT([]byte(h.cfg.JWTSecret), jwtStr)
	if err != nil {
		slog.Warn("onboarding.claim_preview.invalid_jwt",
			"error", err,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Token is invalid or expired")
	}

	ev, err := models.GetOnboardingByJTI(ctx, h.db, claims.ID)
	if err != nil {
		var notFound *models.ErrOnboardingNotFound
		if errors.As(err, &notFound) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok":    false,
				"error": "invalid_token",
				"msg":   "Token not recognized",
			})
		}
		slog.Error("onboarding.claim_preview.db_error", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to verify token")
	}

	if ev.ConvertedAt.Valid {
		return c.JSON(fiber.Map{
			"ok":              true,
			"token_valid":     false,
			"already_claimed": true,
			"resources":       []fiber.Map{},
		})
	}

	// Build deduplicated resource list — same logic as StartLanding.
	seenTokens := map[string]bool{}
	var resources []fiber.Map

	for _, tokenStr := range claims.Tokens {
		seenTokens[tokenStr] = true
		tok, parseErr := uuid.Parse(tokenStr)
		if parseErr != nil {
			continue
		}
		r, lookupErr := models.GetResourceByToken(ctx, h.db, tok)
		if lookupErr != nil {
			continue
		}
		resources = append(resources, fiber.Map{
			"id":            r.ID,
			"token":         r.Token,
			"resource_type": r.ResourceType,
			"tier":          r.Tier,
			"status":        r.Status,
			"created_at":    r.CreatedAt,
		})
	}

	// Also include any resources provisioned after JWT issuance for this fingerprint.
	if claims.Fingerprint != "" {
		fpResources, fpErr := models.GetAllActiveResourcesByFingerprint(ctx, h.db, claims.Fingerprint)
		if fpErr != nil {
			slog.Warn("onboarding.claim_preview.fingerprint_lookup_failed", "error", fpErr, "request_id", requestID)
		}
		for _, r := range fpResources {
			tokStr := r.Token.String()
			if seenTokens[tokStr] {
				continue
			}
			seenTokens[tokStr] = true
			resources = append(resources, fiber.Map{
				"id":            r.ID,
				"token":         r.Token,
				"resource_type": r.ResourceType,
				"tier":          r.Tier,
				"status":        r.Status,
				"created_at":    r.CreatedAt,
			})
		}
	}

	if resources == nil {
		resources = []fiber.Map{}
	}

	// Compute expires_at from the JWT's ExpiresAt claim.
	var expiresAt string
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time.UTC().Format(time.RFC3339)
	}

	return c.JSON(fiber.Map{
		"ok":          true,
		"token_valid": true,
		"resources":   resources,
		"expires_at":  expiresAt,
	})
}

// ClaimRequest is the body expected by POST /claim.
type ClaimRequest struct {
	JWT      string `json:"jwt"`
	TeamName string `json:"team_name"`
	Email    string `json:"email"`
}

// Claim handles POST /claim — converts an anonymous session to a registered team.
func (h *OnboardingHandler) Claim(c *fiber.Ctx) error {
	ctx, span := otel.Tracer("instant.dev/handlers").Start(c.UserContext(), "onboarding.claim")
	defer span.End()

	requestID := middleware.GetRequestID(c)

	var body ClaimRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}

	if body.JWT == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_token", "jwt field is required")
	}
	if body.Email == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_email", "email field is required")
	}

	claims, err := crypto.VerifyOnboardingJWT([]byte(h.cfg.JWTSecret), body.JWT)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "JWT is invalid or expired")
	}
	if claims.Fingerprint != "" {
		span.SetAttributes(attribute.String("fingerprint", claims.Fingerprint))
	}

	// Pre-check: verify the JTI exists and has not already been converted.
	// This is a fast-path read before the atomic gate below.
	ev, err := models.GetOnboardingByJTI(ctx, h.db, claims.ID)
	if err != nil {
		var notFound *models.ErrOnboardingNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusBadRequest, "invalid_token", "Upgrade token not recognized")
		}
		slog.Error("onboarding.claim.jti_lookup_failed", "error", err, "jti", claims.ID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to verify upgrade token")
	}
	if ev.ConvertedAt.Valid {
		return respondError(c, fiber.StatusConflict, "already_claimed", "This upgrade token has already been used")
	}

	// A01 (P1): Mark the JWT as consumed BEFORE creating team+user.
	//
	// Problem (original order): Create team → Create user → MarkConverted.
	// If MarkConverted fails after a successful team+user creation, we return
	// 503 but leave orphaned team+user rows AND an unconsumed JWT — re-claimable
	// by the same or a different caller. Under concurrent load (race between two
	// POST /claim with the same JWT), both could slip past the pre-check SELECT
	// and both create their own team+user before either MarkConverted runs,
	// producing two orphaned teams and a data-integrity gap.
	//
	// Fix: flip the order so MarkOnboardingConvertedPreliminary (atomic UPDATE
	// … WHERE converted_at IS NULL) is the first write. Exactly one concurrent
	// caller wins (0 rows affected → ErrOnboardingAlreadyUsed → 409). The
	// winner then creates team+user. If team/user creation subsequently fails,
	// the JWT is already consumed — the caller sees a 503 and must contact
	// support to re-issue a fresh JWT (acceptable: far better than orphaned
	// rows or a re-claimable JWT).
	//
	// We use the "preliminary" variant which sets only converted_at (leaves
	// team_id NULL). A best-effort UPDATE below patches in the real team_id
	// after the team is created — see onboarding_events patch below.
	if markErr := models.MarkOnboardingConvertedPreliminary(ctx, h.db, claims.ID); markErr != nil {
		var alreadyUsed *models.ErrOnboardingAlreadyUsed
		if errors.As(markErr, &alreadyUsed) {
			return respondError(c, fiber.StatusConflict, "already_claimed", "This upgrade token has already been used")
		}
		slog.Error("onboarding.claim.mark_converted_failed",
			"error", markErr,
			"jti", claims.ID,
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "mark_converted_failed", "Failed to mark upgrade token as used")
	}

	// Resolve team + user: if the email already has an account (e.g. created by
	// dashboard-api during login before the claim page was loaded), reuse it.
	// Otherwise create a fresh team + user as in the standalone onboarding flow.
	var team *models.Team
	var newUser *models.User

	teamName := body.TeamName
	if teamName == "" {
		teamName = body.Email
	}

	existingUser, lookupErr := models.GetUserByEmail(ctx, h.db, body.Email)
	if lookupErr == nil {
		// User already exists (e.g. created by dashboard-api during magic-link login
		// before the user reached the claim page) — reuse existing team + user.
		newUser = existingUser
		existingTeam, teamErr := models.GetTeamByID(ctx, h.db, existingUser.TeamID.UUID)
		if teamErr != nil {
			slog.Error("onboarding.claim.get_team_failed",
				"error", teamErr,
				"email", body.Email,
				"request_id", requestID,
			)
			return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up existing team")
		}
		team = existingTeam
	} else {
		// New user — create team then user.
		createdTeam, teamErr := models.CreateTeam(ctx, h.db, teamName)
		if teamErr != nil {
			slog.Error("onboarding.claim.create_team_failed",
				"error", teamErr,
				"email", body.Email,
				"request_id", requestID,
			)
			return respondError(c, fiber.StatusServiceUnavailable, "team_creation_failed", "Failed to create team")
		}
		team = createdTeam

		createdUser, userErr := models.CreateUser(ctx, h.db, team.ID, body.Email, "", "", "owner")
		if userErr != nil {
			slog.Error("onboarding.claim.create_user_failed",
				"error", userErr,
				"email", body.Email,
				"request_id", requestID,
			)
			return respondError(c, fiber.StatusServiceUnavailable, "user_creation_failed", "Failed to create user")
		}
		newUser = createdUser
	}

	// Patch the real team_id onto the onboarding_event row now that we have it.
	// This is best-effort: a failure here is non-fatal because the JWT is already
	// consumed (converted_at is set) and the team+user exist. The team_id column
	// on the row is only informational at this point.
	if _, patchErr := h.db.ExecContext(ctx,
		`UPDATE onboarding_events SET team_id = $1 WHERE jti = $2`,
		team.ID, claims.ID,
	); patchErr != nil {
		slog.Warn("onboarding.claim.patch_team_id_failed",
			"error", patchErr,
			"jti", claims.ID,
			"team_id", team.ID,
			"request_id", requestID,
		)
	}

	// Transfer anonymous resources to new team.
	// Collect all resource IDs to transfer: start from JWT-listed tokens, then
	// augment with any resources for this fingerprint that were provisioned after
	// the JWT was issued (e.g. DB provisioned after the onboarding JWT was created).
	claimedIDs := map[uuid.UUID]bool{}

	for _, tokenStr := range claims.Tokens {
		tok, parseErr := uuid.Parse(tokenStr)
		if parseErr != nil {
			continue
		}
		resource, fetchErr := models.GetResourceByToken(ctx, h.db, tok)
		if fetchErr != nil {
			continue
		}
		if resource.TeamID.Valid {
			continue // already claimed
		}
		claimedIDs[resource.ID] = true
		// Pay-from-day-one: claim transfers ownership AND flips the tier
		// from `anonymous` -> `free`. Both share identical limits + 24h TTL,
		// but `free` signals "claimed but unpaid" — useful for marketing,
		// dashboard copy, and analytics. expires_at stays untouched: only
		// the Razorpay subscription.charged webhook clears it (via
		// ElevateResourceTiersByTeam). If the user never pays, the reaper
		// deletes the resource at expires_at — same fate as an anonymous one.
		_, _ = h.db.ExecContext(ctx, `
			UPDATE resources SET team_id = $1, tier = 'free'
			WHERE id = $2 AND team_id IS NULL
		`, team.ID, resource.ID)
	}

	// Also claim any additional fingerprint resources not yet in the JWT.
	if claims.Fingerprint != "" {
		fpResources, fpErr := models.GetAllActiveResourcesByFingerprint(ctx, h.db, claims.Fingerprint)
		if fpErr != nil {
			slog.Warn("onboarding.claim.fingerprint_lookup_failed",
				"error", fpErr, "request_id", requestID)
		}
		for _, r := range fpResources {
			if claimedIDs[r.ID] || r.TeamID.Valid {
				continue
			}
			_, _ = h.db.ExecContext(ctx, `
				UPDATE resources SET team_id = $1, tier = 'free'
				WHERE id = $2 AND team_id IS NULL
			`, team.ID, r.ID)
		}
	}

	// "Pay from day one" — no trial, no auto-elevation. The team is created
	// at the default plan_tier; resources keep their anonymous tier + 24h
	// TTL until the Razorpay subscription.charged webhook fires
	// ElevateResourceTiersByTeam (see billing.handleSubscriptionCharged).
	// The dashboard's /claim page is expected to route the user to checkout
	// immediately — if they don't pay within 24h, the resource expires.

	metrics.ConversionFunnel.WithLabelValues("claimed").Inc()

	// Issue a session JWT so the caller can immediately use authenticated endpoints.
	sessionToken, jwtErr := signSessionJWT(h.cfg.JWTSecret, newUser, team)
	if jwtErr != nil {
		slog.Error("onboarding.claim.session_jwt_failed",
			"error", jwtErr,
			"team_id", team.ID,
			"request_id", requestID,
		)
		// Non-fatal: return success without a token rather than failing the claim.
		sessionToken = ""
	}

	slog.Info("onboarding.claim.success",
		"team_id", team.ID,
		"email", body.Email,
		"jti", claims.ID,
		"tokens_transferred", len(claims.Tokens),
		"request_id", requestID,
	)

	// Best-effort audit emit — feeds the Loops forwarder for the welcome
	// email. Fails open: a Loops miss must NEVER fail an otherwise-successful
	// claim. Detached context so the goroutine outlives the request cycle.
	go emitOnboardingClaimedAudit(h.db, team.ID, newUser.ID, len(claimedIDs), body.Email)

	resp := fiber.Map{
		"ok":      true,
		"team_id": team.ID,
		"user_id": newUser.ID,
		"message": "Account created. Your resource tokens have been transferred.",
	}
	if sessionToken != "" {
		resp["session_token"] = sessionToken
	}
	return c.Status(fiber.StatusCreated).JSON(resp)
}

// emitOnboardingClaimedAudit writes one audit_log row signalling that an
// anonymous session was upgraded into a registered team. Best-effort —
// callers fire this in a goroutine and ignore the outcome. The Loops
// forwarder picks the row up and triggers the welcome email; a miss here
// only loses the email, never the claim itself.
func emitOnboardingClaimedAudit(db *sql.DB, teamID, userID uuid.UUID, resourcesTransferred int, email string) {
	// Detached context so the goroutine outlives the request cycle.
	ctx := context.Background()

	// Metadata is serialized into JSONB. Marshal failure is fundamentally
	// impossible for this fixed shape, but we still fall through with nil
	// rather than panicking — same convention as experiments.go.
	metaBlob, _ := json.Marshal(map[string]string{
		"email":                 email,
		"resources_transferred": strconv.Itoa(resourcesTransferred),
	})

	if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:   teamID,
		UserID:   uuid.NullUUID{UUID: userID, Valid: userID != uuid.Nil},
		Actor:    "user",
		Kind:     models.AuditKindOnboardingClaimed,
		Summary:  "team claimed and onboarded",
		Metadata: metaBlob,
	}); err != nil {
		slog.Warn("audit.emit.failed",
			"kind", models.AuditKindOnboardingClaimed,
			"team_id", teamID,
			"error", err,
		)
	}
}
