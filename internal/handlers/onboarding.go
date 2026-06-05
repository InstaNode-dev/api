package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
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
	"instant.dev/internal/safego"
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

// StartLanding handles GET /start?t={jwt}.
//
// API-5 (QA 2026-05-29): per CLAUDE.md "Live API surface", /start must ALWAYS
// 302 to the dashboard `/claim?t=jwt` — the dashboard is the user-facing
// landing page that renders any token error (expired / unrecognised /
// already-claimed) in a friendly UI. Previously, an invalid token surfaced
// the raw `{"ok":false,"error":"invalid_token"}` JSON envelope with HTTP 400,
// which is what an upgrade link printed in an agent's terminal log lands on
// when copy-pasted into a browser — the user sees naked JSON, not a recovery
// flow.
//
// The new contract: pass the token through verbatim and let the dashboard's
// ClaimPage handle validation. Bonus: the platform side avoids a DB lookup on
// every drive-by /start hit (the JTI lookup now happens once, at /claim time,
// where it's actually load-bearing).
//
// Edge cases:
//   - Missing `t` query: 302 to /claim (no token) — the dashboard's ClaimPage
//     renders its "no token" empty state.
//   - Token shape is preserved (url.QueryEscape on the raw value); no
//     validation, no decoding — invalidity is the dashboard's concern.
//
// The landing-viewed metric still increments so the funnel pivot of
// "agents that surface /start in their tool output" stays measurable.
func (h *OnboardingHandler) StartLanding(c *fiber.Ctx) error {
	jwtStr := c.Query("t")

	metrics.ConversionFunnel.WithLabelValues("landing_viewed").Inc()
	// WS4: top-of-funnel landing custom event. No tier/team/fingerprint is known
	// at /start (an unauthenticated drive-by hit), so only the step + service are
	// carried — the funnel's denominator for anon->claimed.
	recordFunnelEvent(c.UserContext(), funnelStepLanding, funnelAttrs{})

	if jwtStr == "" {
		return c.Redirect(h.cfg.DashboardBaseURL+"/claim", fiber.StatusFound)
	}
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
			// Canonical envelope: respondError adds request_id and uses the
			// standard "message" key (this branch previously emitted a bespoke
			// "msg" field with no request_id — agents couldn't correlate it).
			return respondError(c, fiber.StatusBadRequest, "invalid_token", "Token not recognized")
		}
		slog.Error("onboarding.claim_preview.db_error", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to verify token")
	}

	if ev.ConvertedAt.Valid {
		// `items` is the canonical envelope field for every list endpoint on
		// the platform (`/api/v1/resources`, `/api/v1/deployments`, audit,
		// backups). `/claim/preview` originally shipped with `resources` —
		// kept as a legacy alias so the dashboard / sdk-go don't break; new
		// callers should read `items`. B5-P1-3 (BugBash 2026-05-20).
		empty := []fiber.Map{}
		return c.JSON(fiber.Map{
			"ok":              true,
			"token_valid":     false,
			"already_claimed": true,
			"items":           empty,
			"resources":       empty,
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

	// Emit BOTH `items` (canonical) and `resources` (legacy alias). Both
	// point at the same slice — no allocation overhead. See B5-P1-3
	// note on the already_claimed branch above for rationale.
	return c.JSON(fiber.Map{
		"ok":          true,
		"token_valid": true,
		"items":       resources,
		"resources":   resources,
		"expires_at":  expiresAt,
	})
}

// ClaimRequest is the body expected by POST /claim.
//
// Field-name policy (B5-P1, 2026-05-20): `token` is the canonical field. The
// legacy `jwt` alias is still accepted for backward compatibility with the
// dashboard, sdk-go, mcp, and existing curl recipes — when both are present,
// `token` wins. The OpenAPI spec documents `token` as the primary field with
// `jwt` marked deprecated. The wire `error` code on a missing/invalid value
// is `missing_token` (the historical name); every human/agent message
// consistently says "token" — closing the three-name drift (jwt / token /
// INSTANODE_TOKEN) the brief flagged.
type ClaimRequest struct {
	Token    string `json:"token"`
	JWT      string `json:"jwt"` // deprecated — kept for backward compatibility; use `token`.
	TeamName string `json:"team_name"`
	Email    string `json:"email"`
}

// claimToken returns the canonical onboarding token from a ClaimRequest,
// preferring the new `token` field and falling back to the deprecated `jwt`
// field for backward compatibility. Centralised here so every read site
// agrees on the precedence.
func (r ClaimRequest) claimToken() string {
	if r.Token != "" {
		return r.Token
	}
	return r.JWT
}

const (
	// claimLoginPath is the dashboard route an existing-account caller is sent
	// to so they can authenticate before claiming. Appended to DashboardBaseURL.
	claimLoginPath = "/login"
	// errCodeAccountExists is the error code returned by POST /claim when the
	// supplied email already belongs to a registered account. The claim is
	// refused (no resource attach, no session token) because the request
	// carries no proof the caller owns that account — see P0-1.
	errCodeAccountExists = "account_exists"
)

// Claim handles POST /claim — converts an anonymous session to a registered team.
func (h *OnboardingHandler) Claim(c *fiber.Ctx) error {
	ctx, span := otel.Tracer("instant.dev/handlers").Start(c.UserContext(), "onboarding.claim")
	defer span.End()

	requestID := middleware.GetRequestID(c)

	var body ClaimRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}

	tokenStr := body.claimToken()
	if tokenStr == "" {
		// B5-P1 (2026-05-20): canonical field name is `token` (was `jwt`).
		// Use respondErrorWithAgentAction so the agent_action sentence
		// references the onboarding `token` field instead of the
		// codeToAgentAction default for `missing_token` (which is auth-
		// context: "no INSTANODE_TOKEN was provided"). The dashboard,
		// sdk-go, and existing curl recipes still send `jwt` — both
		// names are accepted (see ClaimRequest doc), but every
		// human-facing string now says `token`.
		return respondErrorWithAgentAction(c, fiber.StatusBadRequest, "missing_token",
			"token field is required",
			"Tell the user POST /claim requires a `token` field carrying the onboarding token (the upgrade_jwt value from any anonymous /db/new, /cache/new, /storage/new, ... response). See https://instanode.dev/docs/claim.",
			"")
	}
	if body.Email == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_email", "email field is required")
	}
	// P7: normalise the email (lower-case + trim) up-front so the
	// account-takeover guard, the CreateUser write, the team name, and
	// the audit row all operate on one canonical identity. Without this
	// "Victim@X.com" would slip past the exact-match existing-account
	// check below and mint a duplicate-identity account — defeating the
	// Wave-1 P0-1 takeover fix. NormalizeEmail is the same canonicaliser
	// the model layer applies to every users.email read/write.
	body.Email = models.NormalizeEmail(body.Email)
	if body.Email == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_email", "email field is required")
	}
	// B5-P0 (2026-05-20): RFC 5322 email validation. The previous gate
	// only checked emptiness, so any string ("not-an-email", "x", a
	// 1MB blob, etc.) created a user row whose `users.email` value
	// could never receive a magic-link callback — silently breaking
	// account recovery, billing emails, and the email-verified flow.
	// Worse, it let abusers spray garbage emails to inflate the
	// platform's user count and bypass the per-email dedup gates the
	// downstream auth/billing stack relies on. mail.ParseAddress is the
	// stdlib RFC-5322 parser (rejects missing @, length cap closes the
	// obvious abuse vector); see isValidEmail for the full rule set.
	if !isValidEmail(body.Email) {
		return respondErrorWithAgentAction(c, fiber.StatusBadRequest, "invalid_email_format",
			"email must be a valid RFC 5322 address (e.g. you@example.com)",
			"Tell the user the email they entered is not a valid address. Have them retype it with an @ and a TLD (e.g. you@example.com) — see https://instanode.dev/docs/claim.",
			"")
	}

	claims, err := crypto.VerifyOnboardingJWT([]byte(h.cfg.JWTSecret), tokenStr)
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

	// P0-1: account-takeover guard — checked BEFORE the JWT is consumed.
	//
	// POST /claim accepts an attacker-controlled body.Email and is an
	// unauthenticated route (no RequireAuth — see router.go). The original
	// code, on finding an EXISTING account for that email, silently reused
	// that team+user, grafted the anonymous resources into the victim's team,
	// and minted a session JWT for the victim's account — with no proof the
	// caller owns the email. That let any caller hijack any email-only
	// account and exfiltrate a session for it.
	//
	// Fix: refuse the existing-account branch entirely. The caller must first
	// authenticate to that account (magic-link / OAuth) and claim from within
	// an authenticated session via the dashboard. We perform this lookup
	// BEFORE MarkOnboardingConvertedPreliminary so a refused claim does NOT
	// burn the JWT — the caller can log in and retry with the same token.
	//
	// The brand-new-email path (GetUserByEmail returns not-found) is
	// unchanged: it falls through to the JWT-consume + create-fresh-team flow.
	if existing, lookupErr := models.GetUserByEmail(ctx, h.db, body.Email); lookupErr == nil && existing != nil {
		slog.Warn("onboarding.claim.existing_account_refused",
			"email", body.Email,
			"jti", claims.ID,
			"request_id", requestID,
		)
		return respondErrorWithAgentAction(c, fiber.StatusConflict, errCodeAccountExists,
			"An account already exists for this email. Log in to that account first, then claim your resources from the dashboard.",
			"Sign in to the existing account via magic-link or OAuth at "+h.cfg.DashboardBaseURL+claimLoginPath+
				", then open the claim page while authenticated to attach these resources.",
			"")
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

	// Resolve team + user. By this point the email is guaranteed NOT to belong
	// to an existing account — the P0-1 guard above already refused (and did
	// not consume the JWT) for any pre-existing email. So this is always the
	// brand-new-user path: create a fresh team + user.
	var team *models.Team
	var newUser *models.User

	teamName := body.TeamName
	if teamName == "" {
		teamName = body.Email
	}

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
	// WS4: anonymous->claimed funnel custom event (the >2% KPI). team.PlanTier is
	// the just-created team's tier; claims.Fingerprint is the already-hashed
	// anonymous bucket the claim consolidated. Per-entity (teamId) so retention
	// can be cohorted, alongside the aggregate counter above.
	recordFunnelEvent(ctx, funnelStepClaim, funnelAttrs{
		Tier:        team.PlanTier,
		Fingerprint: claims.Fingerprint,
		TeamID:      team.ID.String(),
	})

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
	safego.Go("onboarding.claimed_audit", func() { emitOnboardingClaimedAudit(h.db, team.ID, newUser.ID, len(claimedIDs), body.Email) })

	// T10 P2-4 (BugHunt 2026-05-20): /claim mints a session for an email
	// the caller never proved they own. The session is still issued so
	// the dashboard works, but `email_verified=false` (above) already
	// gates billing actions. To give the rightful inbox-owner a way to
	// take over, we proactively dispatch a magic-link verification email
	// — clicking it sets `email_verified=true` via the existing
	// markEmailVerified path in magic_link.Callback. If the caller is an
	// attacker squatting victim@example.com, the real victim receives a
	// verification email and can sign in; their magic-link sign-in finds
	// the pre-seeded user row (matched by email), consumes the link, and
	// flips email_verified — which is the moment ownership is proven.
	//
	// Best-effort + detached: a dispatch failure is logged but never
	// fails the claim (the claim's 201 is already returned). The
	// per-email rate limit applies — see checkEmailRateLimit.
	safego.Go("onboarding.claim_verification_email", func() {
		sendClaimVerificationEmail(h.db, h.email, body.Email, h.cfg.DashboardBaseURL+"/app")
	})

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

// claimVerificationEmailMailer is the minimum surface from
// *email.Client that the claim verification helper needs. Extracted to
// keep the helper testable without spinning up a real mail client.
type claimVerificationEmailMailer interface {
	SendMagicLink(ctx context.Context, toEmail, link string) error
}

// sendClaimVerificationEmail dispatches a magic-link verification email
// to the address /claim created an account for. T10 P2-4 (BugHunt
// 2026-05-20): /claim mints a session JWT for an unverified email; this
// gives the rightful inbox-owner a path to prove control and (via
// markEmailVerified inside the magic-link callback) flip the
// email_verified flag that gates billing.
//
// Best-effort by design — no error is propagated. The /claim caller
// already got a 201; this is a side-channel to the inbox.
//
// `mailer` MAY be nil (e.g. local dev with no email backend configured)
// — we no-op in that case.
//
// Note we deliberately route the magic-link through the same
// CreateMagicLink → /auth/email/callback?t= path the regular sign-in
// flow uses, so the callback's existing markEmailVerified runs and the
// returnTo lands the user back in the dashboard.
func sendClaimVerificationEmail(db *sql.DB, mailer claimVerificationEmailMailer, emailAddr, returnTo string) {
	if mailer == nil || db == nil {
		return
	}
	emailAddr = models.NormalizeEmail(emailAddr)
	if emailAddr == "" {
		return
	}
	plaintext, err := models.GenerateMagicLinkPlaintext()
	if err != nil {
		slog.Warn("onboarding.claim.verification.generate_token_failed", "error", err)
		return
	}
	// Detached context — request ctx has long since been cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	row, err := models.CreateMagicLink(ctx, db, emailAddr, plaintext, returnTo, magicLinkTTL)
	if err != nil {
		slog.Warn("onboarding.claim.verification.create_link_failed",
			"error", err)
		return
	}
	link := canonicalAPIBase + "/auth/email/callback?t=" + plaintext
	sendErr := mailer.SendMagicLink(ctx, emailAddr, link)
	persistMagicLinkSendStatus(ctx, db, row.ID, sendErr, "")
	if sendErr != nil {
		slog.Warn("onboarding.claim.verification.send_failed",
			"error", sendErr,
			"email_masked", maskEmailForLog(emailAddr))
		return
	}
	slog.Info("onboarding.claim.verification.sent",
		"email_masked", maskEmailForLog(emailAddr))
}

// isValidEmail returns true when s is a syntactically-valid RFC 5322 email
// address with a dotted domain part and total length within the RFC 5321
// §4.5.3.1.3 limit of 254 characters. Used to gate POST /claim so a request
// body cannot mint a user row with a structurally-invalid email — which
// would silently break magic-link recovery, billing notifications, and the
// email-verified gate downstream. Strict on the obvious failure modes:
//   - empty
//   - > 254 chars
//   - missing @ (delegates to mail.ParseAddress)
//   - any inner whitespace (kills "user @example.com" and quoted-string
//     edge cases that mail.ParseAddress quietly tolerates)
//   - display-name form ("Name <addr>") — /claim wants the bare address
//   - dotless TLD (e.g. "x@localhost") — closes the most-common abuse
//     path without rejecting "user@x.y" which mail.ParseAddress accepts
//
// Caller is expected to pass the already-NormalizeEmail'd value (lowercased
// + trimmed) — that guarantees parser-equivalent inputs across the codebase.
func isValidEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	// Reject any inner whitespace before parsing — closes both leading-
	// space (e.g. " you@x.com") and embedded tab/CRLF abuse vectors. The
	// outer-trim from NormalizeEmail strips leading/trailing whitespace,
	// but a body that bypassed normalisation would still reach here.
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	// mail.ParseAddress accepts both "you@example.com" and the display
	// form "Name <you@example.com>". The /claim contract only wants
	// the bare address — reject any display-name form by comparing the
	// parsed address back against the input.
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return false
	}
	if addr.Address != s {
		return false
	}
	// Require a dotted domain. mail.ParseAddress accepts "user@local"
	// (RFC 5322 §3.4.1 permits it) but every real email has a dot in
	// the domain; this is the cheapest abuse-spray gate.
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return false
	}
	domain := s[at+1:]
	if domain == "" || !strings.Contains(domain, ".") {
		return false
	}
	// Reject empty local-part and trailing dot in domain.
	if at == 0 || strings.HasSuffix(domain, ".") || strings.HasPrefix(domain, ".") {
		return false
	}
	return true
}

// maskEmailForLog returns the first character + "***" + the domain so a
// claim-verification log entry doesn't leak the full email address.
func maskEmailForLog(s string) string {
	at := -1
	for i, r := range s {
		if r == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return "***"
	}
	return s[:1] + "***" + s[at:]
}
