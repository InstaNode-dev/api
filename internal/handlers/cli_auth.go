package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/experiments"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

const (
	// cliSessionTTL is how long a CLI login session is valid.
	// 10 minutes gives the user enough time to complete OAuth in the browser.
	cliSessionTTL = 10 * time.Minute

	// cliSessionPrefix is the Redis key prefix for CLI sessions.
	cliSessionPrefix = "cli_session:"
)

// CLIAuthHandler handles the CLI device-flow-style login.
//
// Flow:
//  1. CLI calls POST /auth/cli  → gets {session_id, auth_url}
//  2. User completes OAuth in browser → server writes result to Redis
//  3. CLI polls GET /auth/cli/:id → 202 (pending) or 200 (complete with API key)
type CLIAuthHandler struct {
	db           *sql.DB
	rdb          *redis.Client
	cfg          *config.Config
	planRegistry *plans.Registry
}

// NewCLIAuthHandler constructs a CLIAuthHandler.
func NewCLIAuthHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, planRegistry *plans.Registry) *CLIAuthHandler {
	return &CLIAuthHandler{db: db, rdb: rdb, cfg: cfg, planRegistry: planRegistry}
}

// cliSessionState is stored in Redis while the user completes OAuth.
type cliSessionState struct {
	// Pending = true until the user completes OAuth.
	Pending bool `json:"pending"`

	// AnonTokens are passed by the CLI so the server can pre-associate them.
	AnonTokens []string `json:"anon_tokens,omitempty"`

	// Completed fields — populated by the OAuth callback.
	APIKey        string   `json:"api_key,omitempty"`
	Email         string   `json:"email,omitempty"`
	Tier          string   `json:"tier,omitempty"`
	TeamName      string   `json:"team_name,omitempty"`
	ClaimedTokens []string `json:"claimed_tokens,omitempty"`
}

// CreateCLISession handles POST /auth/cli.
// Creates a pending session and returns the browser URL for the user to visit.
func (h *CLIAuthHandler) CreateCLISession(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	var body struct {
		AnonTokens []string `json:"anon_tokens"`
	}
	// Body is optional — anonymous tokens are a nice-to-have.
	_ = c.BodyParser(&body)

	sessionID, err := generateSessionID()
	if err != nil {
		slog.Error("cli_auth.create_session.generate_id",
			"request_id", requestID, "error", err)
		return respondError(c, fiber.StatusInternalServerError,
			"internal_error", "Could not create login session")
	}

	state := cliSessionState{
		Pending:    true,
		AnonTokens: body.AnonTokens,
	}
	stateJSON, _ := json.Marshal(state)

	key := cliSessionPrefix + sessionID
	if err := h.rdb.Set(c.Context(), key, stateJSON, cliSessionTTL).Err(); err != nil {
		slog.Error("cli_auth.create_session.redis_set",
			"request_id", requestID, "error", err)
		return respondError(c, fiber.StatusInternalServerError,
			"internal_error", "Could not create login session")
	}

	// The auth URL includes the session_id so the OAuth callback knows which
	// CLI session to complete.
	authURL := fmt.Sprintf("%s/login?cli_session=%s", frontendURL(h.cfg), sessionID)

	slog.Info("cli_auth.session_created",
		"request_id", requestID,
		"session_id", sessionID,
		"anon_token_count", len(body.AnonTokens))

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":         true,
		"session_id": sessionID,
		"auth_url":   authURL,
		"expires_in": int(cliSessionTTL.Seconds()),
	})
}

// PollCLISession handles GET /auth/cli/:id.
// Returns 202 Accepted while pending, 200 OK when the user has completed OAuth.
func (h *CLIAuthHandler) PollCLISession(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)
	sessionID := c.Params("id")

	if sessionID == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_session_id", "Session ID required")
	}

	key := cliSessionPrefix + sessionID
	raw, err := h.rdb.Get(c.Context(), key).Bytes()
	if err == redis.Nil {
		return respondError(c, fiber.StatusNotFound, "session_not_found",
			"Login session not found or expired")
	}
	if err != nil {
		slog.Error("cli_auth.poll.redis_get",
			"request_id", requestID, "session_id", sessionID, "error", err)
		// Fail open — return pending rather than an error so the CLI keeps polling.
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
			"ok":      true,
			"pending": true,
		})
	}

	var state cliSessionState
	if err := json.Unmarshal(raw, &state); err != nil {
		slog.Error("cli_auth.poll.unmarshal",
			"request_id", requestID, "session_id", sessionID, "error", err)
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
			"ok":      true,
			"pending": true,
		})
	}

	if state.Pending {
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
			"ok":      true,
			"pending": true,
		})
	}

	// Auth complete — delete session from Redis (single-use).
	h.rdb.Del(c.Context(), key)

	slog.Info("cli_auth.poll.completed",
		"request_id", requestID,
		"session_id", sessionID,
		"email", state.Email,
		"tier", state.Tier)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"ok":             true,
		"api_key":        state.APIKey,
		"email":          state.Email,
		"tier":           state.Tier,
		"team_name":      state.TeamName,
		"claimed_tokens": state.ClaimedTokens,
	})
}

// CompleteCLISession is called by the OAuth callback handler after a user
// successfully authenticates. It writes the result into Redis so the CLI's
// polling loop picks it up.
func CompleteCLISession(
	ctx context.Context,
	rdb *redis.Client,
	sessionID string,
	apiKey, email, tier, teamName string,
	claimedTokens []string,
) error {
	key := cliSessionPrefix + sessionID
	state := cliSessionState{
		Pending:       false,
		APIKey:        apiKey,
		Email:         email,
		Tier:          tier,
		TeamName:      teamName,
		ClaimedTokens: claimedTokens,
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return err
	}
	// Keep the completed session for 5 minutes in case the poll arrives late.
	return rdb.Set(ctx, key, stateJSON, 5*time.Minute).Err()
}

// GetCurrentUser handles GET /auth/me — returns the current user's plan and tier from the DB.
func (h *CLIAuthHandler) GetCurrentUser(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	userID := middleware.GetUserID(c)
	if userID == "" {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}

	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}

	team, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "Team not found")
		}
		slog.Error("cli_auth.get_current_user.team_lookup",
			"request_id", requestID,
			"team_id", teamIDStr,
			"error", err,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "db_error", "Failed to fetch team")
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}

	user, err := models.GetUserByID(c.Context(), h.db, userUUID)
	if err != nil {
		var notFound *models.ErrUserNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "user_not_found", "User not found")
		}
		slog.Error("cli_auth.get_current_user.user_lookup",
			"request_id", requestID,
			"user_id", userID,
			"error", err,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "db_error", "Failed to fetch user")
	}

	plan := h.planRegistry.Get(team.PlanTier)

	// Experiment bucketing — identifier is team_id for claimed
	// users (always set here since RequireAuth has already run and
	// populated GetTeamID). This keeps every authenticated session
	// for the same team in the same variant, which is what the
	// "Upgrade to Pro" copy test needs (a user must not see two
	// labels in one session). Anonymous bucketing uses the
	// fingerprint at the unauthenticated provision endpoints —
	// /auth/me is auth-only so there's no fingerprint fallback
	// path to consider here.
	exps := experiments.PickAll(team.ID.String())

	resp := fiber.Map{
		"ok":                true,
		"user_id":           user.ID,
		"team_id":           team.ID,
		"email":             user.Email,
		"tier":              team.PlanTier,
		"plan_display_name": plan.DisplayName,
		"experiments":       exps,
	}
	// trial_ends_at removed — see policy memory project_no_trial_pay_day_one.md.
	// The platform has no trial period; the column was dropped in migration 034.

	// Admin-only surface: when the caller's email is on the ADMIN_EMAILS
	// allowlist AND the operator has configured ADMIN_PATH_PREFIX, hand
	// the caller the unguessable URL segment they need to reach the
	// founder-only customer-management endpoints. Silence is golden for
	// every non-admin caller — we never even send an empty-string field,
	// because the field's mere presence would leak that the endpoint
	// exists. The dashboard's admin page reads this value and builds
	// /api/v1/<prefix>/customers/... URLs from it; non-admin sessions
	// have no way to learn the prefix from the wire.
	//
	// Two gates collaborating here:
	//   1. middleware.IsAdminEmail — second factor (ADMIN_EMAILS)
	//   2. cfg.AdminPathPrefix     — secret URL segment
	//
	// If either is missing the field is omitted; the admin UI then
	// hides the route because the URL builder has nothing to build with.
	if h.cfg != nil && h.cfg.AdminPathPrefix != "" && middleware.IsAdminEmail(user.Email) {
		resp["admin_path_prefix"] = h.cfg.AdminPathPrefix
	}

	// Impersonation surfacing — when the caller's JWT carries read_only=true
	// (i.e. the session was minted via POST /api/v1/admin/customers/:id/impersonate)
	// expose two read-only fields so the dashboard can render the "viewing
	// as <customer>" banner + grey out mutating UI. We only emit the keys
	// when the flag is set; non-impersonated sessions see a clean response
	// shape. The wire surface (read_only:bool, impersonated_by:string)
	// matches what the RequireWritable middleware reads from the same JWT.
	if middleware.IsReadOnly(c) {
		resp["read_only"] = true
		if by := middleware.GetImpersonatedBy(c); by != "" {
			resp["impersonated_by"] = by
		}
	}

	return c.JSON(resp)
}

// generateSessionID produces a cryptographically random 16-byte hex string.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// frontendURL returns the base URL for the frontend.
// In production this is https://instant.dev; in local dev it falls back to localhost.
func frontendURL(cfg *config.Config) string {
	if cfg.Environment == "production" {
		return "https://instant.dev"
	}
	return "http://localhost:3000"
}

