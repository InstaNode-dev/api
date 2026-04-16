package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// AuthHandler handles OAuth login flows.
type AuthHandler struct {
	db  *sql.DB
	cfg *config.Config
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(db *sql.DB, cfg *config.Config) *AuthHandler {
	return &AuthHandler{db: db, cfg: cfg}
}

// sessionClaims is the JWT payload issued after a successful OAuth login.
type sessionClaims struct {
	UserID string `json:"uid"`
	TeamID string `json:"tid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// GitHubAuthRequest is the body for POST /auth/github.
type GitHubAuthRequest struct {
	Code string `json:"code"`
}

// GoogleAuthRequest is the body for POST /auth/google (ID token flow).
type GoogleAuthRequest struct {
	IDToken string `json:"id_token"`
}

// GoogleAuthCallbackRequest is the body for POST /auth/google/callback (authorization code flow).
type GoogleAuthCallbackRequest struct {
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
}

// GitHub handles POST /auth/github — exchanges an OAuth code for a session JWT.
func (h *AuthHandler) GitHub(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	var body GitHubAuthRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}
	if body.Code == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_code", "code field is required")
	}

	if h.cfg.GitHubClientID == "" || h.cfg.GitHubClientSecret == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "oauth_not_configured", "GitHub OAuth is not configured")
	}

	ghUser, err := exchangeGitHubCode(c.Context(), h.cfg.GitHubClientID, h.cfg.GitHubClientSecret, body.Code)
	if err != nil {
		slog.Error("auth.github.exchange_failed", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusUnauthorized, "oauth_failed", "GitHub authentication failed")
	}

	user, team, err := h.findOrCreateUserGitHub(c.Context(), ghUser)
	if err != nil {
		slog.Error("auth.github.user_upsert_failed", "error", err, "github_id", ghUser.ID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "user_upsert_failed", "Failed to create or find user")
	}

	sessionToken, err := h.issueSessionJWT(user, team)
	if err != nil {
		slog.Error("auth.github.jwt_failed", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "token_issue_failed", "Failed to issue session token")
	}

	slog.Info("auth.github.success",
		"user_id", user.ID,
		"team_id", team.ID,
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{
		"ok":      true,
		"token":   sessionToken,
		"user_id": user.ID,
		"team_id": team.ID,
		"email":   user.Email,
	})
}

// Google handles POST /auth/google — verifies a Google ID token and issues a session JWT.
func (h *AuthHandler) Google(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	var body GoogleAuthRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}
	if body.IDToken == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_id_token", "id_token field is required")
	}

	if h.cfg.GoogleClientID == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "oauth_not_configured", "Google OAuth is not configured")
	}

	gUser, err := verifyGoogleIDToken(c.Context(), h.cfg.GoogleClientID, body.IDToken)
	if err != nil {
		slog.Error("auth.google.verify_failed", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusUnauthorized, "oauth_failed", "Google authentication failed")
	}

	user, team, err := h.findOrCreateUserGoogle(c.Context(), gUser)
	if err != nil {
		slog.Error("auth.google.user_upsert_failed", "error", err, "google_id", gUser.Sub, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "user_upsert_failed", "Failed to create or find user")
	}

	sessionToken, err := h.issueSessionJWT(user, team)
	if err != nil {
		slog.Error("auth.google.jwt_failed", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "token_issue_failed", "Failed to issue session token")
	}

	slog.Info("auth.google.success",
		"user_id", user.ID,
		"team_id", team.ID,
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{
		"ok":      true,
		"token":   sessionToken,
		"user_id": user.ID,
		"team_id": team.ID,
		"email":   user.Email,
	})
}

// GoogleCallback handles POST /auth/google/callback — exchanges an OAuth authorization code for a session JWT.
func (h *AuthHandler) GoogleCallback(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	if h.cfg.GoogleClientID == "" || h.cfg.GoogleClientSecret == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "oauth_not_configured", "Google OAuth is not configured")
	}

	var body GoogleAuthCallbackRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}
	if body.Code == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_code", "code field is required")
	}
	if body.RedirectURI == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_redirect_uri", "redirect_uri field is required")
	}

	accessToken, err := exchangeGoogleAuthorizationCode(c.Context(), h.cfg.GoogleClientID, h.cfg.GoogleClientSecret, body.Code, body.RedirectURI)
	if err != nil {
		slog.Error("auth.google.callback.exchange_failed", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusUnauthorized, "oauth_failed", "Google authentication failed")
	}

	gUser, err := fetchGoogleUserInfoOAuth2V2(c.Context(), accessToken)
	if err != nil {
		slog.Error("auth.google.callback.userinfo_failed", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusUnauthorized, "oauth_failed", "Google authentication failed")
	}

	user, team, err := h.findOrCreateUserGoogle(c.Context(), gUser)
	if err != nil {
		slog.Error("auth.google.callback.user_upsert_failed", "error", err, "google_id", gUser.Sub, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "user_upsert_failed", "Failed to create or find user")
	}

	sessionToken, err := h.issueSessionJWT(user, team)
	if err != nil {
		slog.Error("auth.google.callback.jwt_failed", "error", err, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "token_issue_failed", "Failed to issue session token")
	}

	slog.Info("auth.google.callback.success",
		"user_id", user.ID,
		"team_id", team.ID,
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{
		"ok":      true,
		"token":   sessionToken,
		"user_id": user.ID,
		"team_id": team.ID,
		"email":   user.Email,
	})
}

// GoogleAuthURL handles GET /auth/google/url — returns the Google OAuth authorization URL.
// Query: redirect_uri (optional if GOOGLE_REDIRECT_URI is configured).
func (h *AuthHandler) GoogleAuthURL(c *fiber.Ctx) error {
	if h.cfg.GoogleClientID == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "oauth_not_configured", "Google OAuth is not configured")
	}

	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))
	if redirectURI == "" {
		redirectURI = strings.TrimSpace(h.cfg.GoogleRedirectURI)
	}
	if redirectURI == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_redirect_uri", "redirect_uri query parameter or GOOGLE_REDIRECT_URI is required")
	}

	u, err := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to build authorization URL")
	}
	q := u.Query()
	q.Set("client_id", h.cfg.GoogleClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("access_type", "offline")
	q.Set("include_granted_scopes", "true")
	u.RawQuery = q.Encode()

	return c.JSON(fiber.Map{
		"ok":  true,
		"url": u.String(),
	})
}

// issueSessionJWT signs a short-lived session JWT (24h) for an authenticated user.
func (h *AuthHandler) issueSessionJWT(user *models.User, team *models.Team) (string, error) {
	return signSessionJWT(h.cfg.JWTSecret, user, team)
}

// signSessionJWT is the package-level helper used by any handler that needs to
// issue a session token (AuthHandler after OAuth, OnboardingHandler after /claim).
func signSessionJWT(jwtSecret string, user *models.User, team *models.Team) (string, error) {
	now := time.Now().UTC()
	claims := sessionClaims{
		UserID: user.ID.String(),
		TeamID: team.ID.String(),
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// --- GitHub OAuth helpers ---

type gitHubUser struct {
	ID    string
	Login string
	Email string
}

func exchangeGitHubCode(ctx context.Context, clientID, clientSecret, code string) (*gitHubUser, error) {
	// Step 1: exchange code for access token
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("github token decode: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("github oauth error: %s", tokenResp.Error)
	}

	// Step 2: fetch user profile
	userReq, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github+json")

	userResp, err := client.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("github user fetch: %w", err)
	}
	defer userResp.Body.Close()

	var profile struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("github profile decode: %w", err)
	}

	if profile.Email == "" {
		// Fetch primary email separately
		emailReq, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
		emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		emailResp, err := client.Do(emailReq)
		if err == nil {
			defer emailResp.Body.Close()
			body, _ := io.ReadAll(emailResp.Body)
			var emails []struct {
				Email   string `json:"email"`
				Primary bool   `json:"primary"`
			}
			if json.Unmarshal(body, &emails) == nil {
				for _, e := range emails {
					if e.Primary {
						profile.Email = e.Email
						break
					}
				}
			}
		}
	}

	return &gitHubUser{
		ID:    fmt.Sprint(profile.ID),
		Login: profile.Login,
		Email: profile.Email,
	}, nil
}

func (h *AuthHandler) findOrCreateUserGitHub(ctx context.Context, gh *gitHubUser) (*models.User, *models.Team, error) {
	user, err := models.GetUserByGitHubID(ctx, h.db, gh.ID)
	if err == nil {
		// Existing user — return their team
		team, teamErr := models.GetTeamByID(ctx, h.db, user.TeamID.UUID)
		if teamErr != nil {
			return nil, nil, fmt.Errorf("findOrCreateUserGitHub: %w", teamErr)
		}
		return user, team, nil
	}

	var notFound *models.ErrUserNotFound
	if !errors.As(err, &notFound) {
		// Unexpected DB error
		return nil, nil, fmt.Errorf("findOrCreateUserGitHub lookup: %w", err)
	}

	// New user — create team + user
	team, err := models.CreateTeam(ctx, h.db, gh.Login)
	if err != nil {
		return nil, nil, fmt.Errorf("findOrCreateUserGitHub create team: %w", err)
	}
	user, err = models.CreateUser(ctx, h.db, team.ID, gh.Email, gh.ID, "", "owner")
	if err != nil {
		return nil, nil, fmt.Errorf("findOrCreateUserGitHub create user: %w", err)
	}
	return user, team, nil
}

// --- Google OAuth helpers ---

type googleUser struct {
	Sub   string
	Email string
	Name  string
}

func verifyGoogleIDToken(ctx context.Context, clientID, idToken string) (*googleUser, error) {
	verifyURL := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", url.QueryEscape(idToken))
	req, _ := http.NewRequestWithContext(ctx, "GET", verifyURL, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google token verify: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("google token invalid (status %d)", resp.StatusCode)
	}

	var payload struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Aud   string `json:"aud"`
		Error string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("google payload decode: %w", err)
	}
	if payload.Error != "" {
		return nil, fmt.Errorf("google token error: %s", payload.Error)
	}
	if payload.Aud != clientID {
		return nil, fmt.Errorf("google token audience mismatch: got %s, want %s", payload.Aud, clientID)
	}

	return &googleUser{
		Sub:   payload.Sub,
		Email: payload.Email,
		Name:  payload.Name,
	}, nil
}

func exchangeGoogleAuthorizationCode(ctx context.Context, clientID, clientSecret, code, redirectURI string) (accessToken string, err error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("google token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("google token decode: %w", err)
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("google oauth error: %s (%s)", tokenResp.Error, tokenResp.Description)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("google token response missing access_token")
	}
	return tokenResp.AccessToken, nil
}

func fetchGoogleUserInfoOAuth2V2(ctx context.Context, accessToken string) (*googleUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google userinfo: status %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("google userinfo decode: %w", err)
	}
	if payload.ID == "" {
		return nil, fmt.Errorf("google userinfo: missing id")
	}
	if payload.Email == "" {
		return nil, fmt.Errorf("google userinfo: missing email")
	}

	return &googleUser{
		Sub:   payload.ID,
		Email: payload.Email,
		Name:  payload.Name,
	}, nil
}

func (h *AuthHandler) findOrCreateUserGoogle(ctx context.Context, g *googleUser) (*models.User, *models.Team, error) {
	user, err := models.GetUserByGoogleID(ctx, h.db, g.Sub)
	if err == nil {
		team, teamErr := models.GetTeamByID(ctx, h.db, user.TeamID.UUID)
		if teamErr != nil {
			return nil, nil, fmt.Errorf("findOrCreateUserGoogle: %w", teamErr)
		}
		return user, team, nil
	}

	var notFound *models.ErrUserNotFound
	if !errors.As(err, &notFound) {
		return nil, nil, fmt.Errorf("findOrCreateUserGoogle lookup: %w", err)
	}

	// Match existing account by email and link google_id when unset.
	if g.Email != "" {
		byEmail, errEmail := models.GetUserByEmail(ctx, h.db, strings.ToLower(strings.TrimSpace(g.Email)))
		if errEmail == nil {
			if byEmail.GoogleID.Valid && byEmail.GoogleID.String != g.Sub {
				return nil, nil, fmt.Errorf("findOrCreateUserGoogle: email already linked to another Google account")
			}
			if !byEmail.GoogleID.Valid {
				if linkErr := models.LinkGoogleID(ctx, h.db, byEmail.ID, g.Sub); linkErr != nil {
					return nil, nil, fmt.Errorf("findOrCreateUserGoogle link: %w", linkErr)
				}
				byEmail.GoogleID = sql.NullString{String: g.Sub, Valid: true}
			}
			team, teamErr := models.GetTeamByID(ctx, h.db, byEmail.TeamID.UUID)
			if teamErr != nil {
				return nil, nil, fmt.Errorf("findOrCreateUserGoogle: %w", teamErr)
			}
			return byEmail, team, nil
		}
		if !errors.As(errEmail, &notFound) {
			return nil, nil, fmt.Errorf("findOrCreateUserGoogle email lookup: %w", errEmail)
		}
	}

	teamName := strings.TrimSpace(g.Name)
	if teamName == "" {
		teamName = strings.Split(g.Email, "@")[0]
	}
	team, err := models.CreateTeam(ctx, h.db, teamName)
	if err != nil {
		return nil, nil, fmt.Errorf("findOrCreateUserGoogle create team: %w", err)
	}
	user, err = models.CreateUser(ctx, h.db, team.ID, g.Email, "", g.Sub, "owner")
	if err != nil {
		return nil, nil, fmt.Errorf("findOrCreateUserGoogle create user: %w", err)
	}
	return user, team, nil
}
