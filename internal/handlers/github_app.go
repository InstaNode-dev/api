package handlers

// github_app.go — GitHub App install flow (P4.1). Distinct from the GitHub
// OAuth *login* (auth.go) and from the manual per-repo webhook
// (github_deploy.go): here a team installs the InstaNode GitHub App once, and we
// persist the installation↔team link (github_installations) so the App webhook
// can resolve pushes and the token-minter (internal/github) can mint short-lived
// clone tokens for private repos.
//
// Routes (registered in router.go), all gated by cfg.GitHubAppEnabled:
//   GET /integrations/github/install   RequireAuth → 302 to the App install page
//                                       with a signed anti-CSRF state.
//   GET /integrations/github/callback  GitHub redirects here post-install with
//                                       installation_id + state → persist link,
//                                       302 to the dashboard.
//
// Token minting + push-to-deploy wiring land in P4.2; P4.1 stops at "installed".

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// githubAppStatePurpose tags the state JWT so it can't be confused with a
// session or OAuth-login token.
const githubAppStatePurpose = "gh_app_install"

// githubAppStateTTL bounds the install→callback round-trip.
const githubAppStateTTL = 10 * time.Minute

// signInstallStateFn is the state signer the Install handler uses — a package
// var so a test can force the (otherwise unreachable, HS256-never-fails) sign
// error path.
var signInstallStateFn = signGitHubAppState

// GitHubAppHandler serves the install/callback flow.
type GitHubAppHandler struct {
	db   *sql.DB
	cfg  *config.Config
	plan *plans.Registry
}

// NewGitHubAppHandler constructs the handler.
func NewGitHubAppHandler(db *sql.DB, cfg *config.Config, planRegistry *plans.Registry) *GitHubAppHandler {
	return &GitHubAppHandler{db: db, cfg: cfg, plan: planRegistry}
}

// disabledOrMisconfigured returns a non-nil error response when the App feature
// is off or its config is incomplete, so both handlers fail the same way.
func (h *GitHubAppHandler) disabledOrMisconfigured(c *fiber.Ctx) error {
	if !h.cfg.GitHubAppEnabled {
		return respondError(c, fiber.StatusNotImplemented, "github_app_disabled",
			"GitHub App install is rolling out and not yet enabled. Use POST /api/v1/deployments/:id/github (manual webhook) or source=git with a token for now.")
	}
	if h.cfg.GitHubAppSlug == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "github_app_misconfigured",
			"GitHub App is enabled but GITHUB_APP_SLUG is unset")
	}
	return nil
}

// Install (GET /integrations/github/install) redirects the authed team to the
// GitHub App install page, carrying a signed state that binds the eventual
// callback to this team.
func (h *GitHubAppHandler) Install(c *fiber.Ctx) error {
	if err := h.disabledOrMisconfigured(c); err != nil {
		return err
	}
	teamID := middleware.GetTeamID(c)
	if teamID == "" {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "A session token is required")
	}
	state, err := signInstallStateFn(h.cfg.JWTSecret, teamID, time.Now())
	if err != nil {
		slog.Error("github_app.install.state_sign_failed", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "state_unavailable",
			"Could not start the GitHub App install")
	}
	installURL := fmt.Sprintf("https://github.com/apps/%s/installations/new?state=%s",
		url.PathEscape(h.cfg.GitHubAppSlug), url.QueryEscape(state))
	return c.Redirect(installURL, fiber.StatusFound)
}

// Callback (GET /integrations/github/callback) is where GitHub returns the user
// after install. It verifies the state, persists the installation↔team link, and
// bounces to the dashboard.
func (h *GitHubAppHandler) Callback(c *fiber.Ctx) error {
	if err := h.disabledOrMisconfigured(c); err != nil {
		return err
	}
	teamID, err := verifyGitHubAppState(h.cfg.JWTSecret, c.Query("state"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_state",
			"The install state is missing, expired, or invalid — restart the install from the dashboard")
	}
	instIDStr := c.Query("installation_id")
	instID, perr := strconv.ParseInt(instIDStr, 10, 64)
	if perr != nil || instID <= 0 {
		return respondError(c, fiber.StatusBadRequest, "invalid_installation_id",
			"GitHub did not return a valid installation_id")
	}
	teamUUID, terr := parseTeamID(teamID)
	if terr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in state is not a valid UUID")
	}
	// account_login is enriched by the installation webhook (P4.2); empty here.
	if _, err := models.UpsertGitHubInstallation(c.Context(), h.db, instID, teamUUID, ""); err != nil {
		var conflict *models.ErrGitHubInstallationTeamConflict
		if errors.As(err, &conflict) {
			// The installation is already linked to a different team — refuse
			// rather than rebind (anti-hijack, review HIGH-2).
			slog.Warn("github_app.callback.team_conflict", "installation_id", instID, "team_id", teamID)
			return respondError(c, fiber.StatusConflict, "install_conflict",
				"This GitHub installation is already linked to another InstaNode team")
		}
		slog.Error("github_app.callback.persist_failed", "error", err, "installation_id", instID)
		return respondError(c, fiber.StatusServiceUnavailable, "install_persist_failed",
			"Could not save the GitHub installation")
	}
	slog.Info("github_app.callback.installed", "installation_id", instID, "team_id", teamID,
		"setup_action", c.Query("setup_action"))
	dest := h.cfg.DashboardBaseURL + "/integrations/github?installed=" + strconv.FormatInt(instID, 10)
	return c.Redirect(dest, fiber.StatusFound)
}

// signGitHubAppState mints a short-lived HS256 state token binding an install to
// a team (anti-CSRF — the callback must present a state WE issued).
func signGitHubAppState(secret, teamID string, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"team_id": teamID,
		"purpose": githubAppStatePurpose,
		"iat":     now.Unix(),
		"exp":     now.Add(githubAppStateTTL).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte(secret))
}

// verifyGitHubAppState validates the state token (signature, HS256-only, exp via
// the jwt package's default clock) and returns the bound team_id.
func verifyGitHubAppState(secret, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("empty state")
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))
	_, err := parser.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return "", err
	}
	if p, _ := claims["purpose"].(string); p != githubAppStatePurpose {
		return "", fmt.Errorf("state purpose mismatch")
	}
	teamID, _ := claims["team_id"].(string)
	if teamID == "" {
		return "", fmt.Errorf("state missing team_id")
	}
	return teamID, nil
}
