package handlers

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
)

// --- Browser OAuth flow shared helpers ---

// defaultReturnTo is where we send a browser when ?return_to= is missing or
// fails the allowlist check. It MUST be on an allowed origin (instanode.dev).
const defaultReturnTo = "https://instanode.dev/login/callback"

// canonicalAPIBase is the public-facing origin of the API. Used to build
// OAuth redirect_uri values and the magic-link callback URL we email out.
// Hardcoded rather than reading from cfg because the registered redirect_uri
// at GitHub/Google is fixed at app-registration time — varying it per
// deployment would require multiple OAuth apps.
// canonicalAPIBase is preserved as an alias of urls.PublicAPIBase so any
// external reference keeps compiling. New code should use urls.PublicAPIBase.
const canonicalAPIBase = urls.PublicAPIBase

// allowedReturnOrigins is the static allowlist for ?return_to= validation.
// Anything not on this list collapses to defaultReturnTo. The list is
// intentionally small and code-reviewable; do not load it from a config
// flag, since an open-redirect bug here gives an attacker a phishing primitive
// (we'd be appending a real session_token to a URL they control).
//
// T10 P1-4 (BugHunt 2026-05-20): the http://localhost entries are dev-only.
// In production, a victim on a machine where an attacker controls a localhost
// listener could have the session_token redirected there. allowedReturnOrigins
// keeps both for back-compat; validateReturnTo gates them on
// returnToAllowsLocalhost which is wired from cfg.Environment at startup.
var allowedReturnOrigins = []string{
	"https://instanode.dev",
	"https://www.instanode.dev",
}

// allowedReturnOriginsDev contains the http://localhost entries used in
// development only. validateReturnTo merges these with allowedReturnOrigins
// when returnToAllowsLocalhost is true.
var allowedReturnOriginsDev = []string{
	"http://localhost:5173",
	"http://localhost:3000",
}

// OAuth provider endpoint base URLs. Declared as package vars (not consts)
// solely so the test suite can repoint them at an httptest server — production
// never mutates them. Each is the exact URL the corresponding helper used to
// hardcode inline; behaviour is unchanged in prod.
var (
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubUserEmailURL = "https://api.github.com/user/emails"
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	googleTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"
	googleTokenURL     = "https://oauth2.googleapis.com/token"
	googleUserInfoURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
	googleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
)

// returnToAllowsLocalhost controls whether validateReturnTo treats
// http://localhost:5173 and http://localhost:3000 as allowed return-to
// origins. Set to true in development at startup, false in production.
// T10 P1-4 (BugHunt 2026-05-20).
var returnToAllowsLocalhost = true

// SetReturnToAllowsLocalhost is called from router wiring at startup.
// Pass cfg.Environment != "production" to enable localhost allowlisting
// for local dev and tests only.
func SetReturnToAllowsLocalhost(allow bool) {
	returnToAllowsLocalhost = allow
}

// validateReturnTo accepts a raw ?return_to= value and returns either the
// original (when its origin is on the allowlist) or defaultReturnTo. Empty,
// malformed, or off-allowlist URLs collapse to the default — never error,
// since the user is in the middle of an OAuth dance and a 400 here would
// strand them.
func validateReturnTo(raw string) string {
	if raw == "" {
		return defaultReturnTo
	}
	u, err := url.Parse(raw)
	if err != nil {
		return defaultReturnTo
	}
	if u.Scheme == "" || u.Host == "" {
		return defaultReturnTo
	}
	origin := u.Scheme + "://" + u.Host
	for _, ok := range allowedReturnOrigins {
		if origin == ok {
			return raw
		}
	}
	if returnToAllowsLocalhost {
		for _, ok := range allowedReturnOriginsDev {
			if origin == ok {
				return raw
			}
		}
	}
	return defaultReturnTo
}

// generateOAuthState returns a cryptographically random 16-byte hex string
// used as the OAuth `state` parameter to defend against CSRF.
func generateOAuthState() (string, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// appendSessionToken returns returnTo with ?session_token=<jwt> (or &) appended.
// Preserves any existing query string on returnTo.
//
// AUTH-004 (2026-05-29): no longer used by the magic-link / OAuth callback
// paths — the JWT now rides in a Secure HttpOnly cookie and only a
// `signed_in=1` marker lands in the redirect URL. Retained for
// backwards-compatibility with the JSON OAuth handlers (POST /auth/github,
// POST /auth/google) which return the session token in the response body,
// not a redirect.
func appendSessionToken(returnTo, sessionToken string) string {
	u, err := url.Parse(returnTo)
	if err != nil {
		// Fallback: trust the default + token. validateReturnTo should make
		// this branch unreachable in practice.
		return defaultReturnTo + "?session_token=" + url.QueryEscape(sessionToken)
	}
	q := u.Query()
	q.Set("session_token", sessionToken)
	u.RawQuery = q.Encode()
	return u.String()
}

// appendSignedInMarker adds ?signed_in=1 to returnTo. AUTH-004: replaces
// the JWT-in-URL pattern. The marker tells the dashboard SPA that the
// session cookie has been set and it should call /auth/me to pick up the
// user/team, without leaking any secret material into URL logs / Referer.
func appendSignedInMarker(returnTo string) string {
	u, err := url.Parse(returnTo)
	if err != nil {
		return defaultReturnTo + "?signed_in=1"
	}
	q := u.Query()
	q.Set("signed_in", "1")
	// Be explicit that the old key is gone — if any code path ever set it
	// upstream, strip it here so we don't accidentally pass through a
	// leaked token.
	q.Del("session_token")
	u.RawQuery = q.Encode()
	return u.String()
}

// exchangeCookieName is the transient cookie that bridges the magic-link
// / OAuth browser callback into the SPA. It carries the session JWT for
// at most 30 seconds and is scoped to POST /auth/exchange so the only
// surface that ever reads it is the exchange handler — RequireAuth is
// strictly Bearer-only (CLAUDE.md "Live API surface").
//
// AUTH-004 flow:
//
//  1. /auth/email/callback (or github/google browser callback) mints the
//     session JWT, sets it in this cookie, 302s to the dashboard with
//     ?signed_in=1 (no token in URL).
//  2. SPA loads, sees signed_in=1, POSTs /auth/exchange with credentials.
//  3. Exchange handler reads the cookie, deletes it (Max-Age=0), returns
//     {token: <jwt>} in the body. SPA stores it in memory and from then
//     on uses Authorization: Bearer like every other client.
const exchangeCookieName = "instanode_session_exchange"

// exchangeCookieMaxAge — 30s ceiling on the bridge window. Long enough
// for the SPA to load and POST /auth/exchange after the 302, short
// enough that an attacker with momentary cookie-jar access can't extract
// the JWT later. Cookie expiry is enforced by the browser; the handler
// additionally rejects an absent / empty cookie with 400.
const exchangeCookieMaxAge = 30

// exchangeCookiePath confines the cookie's send scope to the exchange
// endpoint. Browsers will NOT attach it to /api/v1/* or any other path,
// which is what keeps the cookie out of the API contract.
const exchangeCookiePath = "/auth/exchange"

// setExchangeCookie writes the session JWT into a transient
// Secure; HttpOnly; SameSite=Lax cookie scoped to Path=/auth/exchange
// with Max-Age=30. HttpOnly blocks the XSS exfil path (AUTH-003);
// Secure forces TLS in prod; SameSite=Lax preserves the top-level
// navigation flow from the 302 redirect while blocking third-party
// POST CSRF. No Domain attribute — the cookie stays on the api host
// where /auth/exchange lives; the SPA fetches it cross-origin with
// credentials:'include'.
func setExchangeCookie(c *fiber.Ctx, jwt string, prod bool) {
	c.Cookie(&fiber.Cookie{
		Name:     exchangeCookieName,
		Value:    jwt,
		Path:     exchangeCookiePath,
		MaxAge:   exchangeCookieMaxAge,
		Secure:   prod,
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

// clearExchangeCookie writes a cookie with the same name/path but an
// expired Expires attribute so the browser drops the bridge cookie
// immediately after the SPA consumes it. Single-use semantics: even if
// the response body is lost to a network hiccup, the cookie is gone and
// the SPA has to restart the sign-in flow rather than retry from a
// still-live cookie.
//
// Fiber's cookie codec lower-cases Path and does NOT emit Max-Age=0 for
// MaxAge<=0 — it omits the attribute entirely. Use a fixed-past Expires
// instead, which both Fiber and the browser treat as "drop immediately".
func clearExchangeCookie(c *fiber.Ctx, prod bool) {
	c.Cookie(&fiber.Cookie{
		Name:     exchangeCookieName,
		Value:    "",
		Path:     exchangeCookiePath,
		Expires:  time.Unix(0, 0).UTC(),
		Secure:   prod,
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

// Exchange handles POST /auth/exchange: reads the transient
// instanode_session_exchange cookie set by the magic-link / OAuth
// browser callback, clears it (Max-Age=0), and returns the embedded
// session JWT in the response body. Browser-only path — the SPA is the
// sole consumer.
//
// On any failure (no cookie, empty cookie, expired-by-browser) the
// handler returns 400 cookie_missing_or_expired so the SPA can surface
// "please sign in again" rather than wedge with an infinite spinner.
//
// The cookie is cleared on BOTH the success and failure paths to
// prevent a partial-failure leak (e.g. the SPA crashed before reading
// the body but the cookie is still alive). The single-use guarantee
// is what keeps this path's blast radius bounded to the 30-second
// transient window.
func (h *AuthHandler) Exchange(c *fiber.Ctx) error {
	prod := h.cfg.Environment == "production"
	token := c.Cookies(exchangeCookieName)
	if token == "" {
		clearExchangeCookie(c, prod)
		return respondError(c, fiber.StatusBadRequest, "cookie_missing_or_expired",
			"No session-exchange cookie present. Start the sign-in flow again.")
	}
	clearExchangeCookie(c, prod)
	return c.JSON(fiber.Map{"ok": true, "token": token})
}

// returnToSchemeIsAllowed reports whether the URL's scheme is in the
// per-environment allow-list:
//
//	prod:  {https}
//	dev:   {https, http} (http only via the host gate downstream — we
//	       reject javascript:/data:/file: etc. regardless of environment)
//
// AUTH-016 / AUTH-017: javascript: and data: were previously silently
// downgraded to the default by validateReturnTo. The new gate rejects
// up-front with a clear 400 instead. Callers with no return_to (empty
// string) still get the default behaviour.
func returnToSchemeIsAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		// HTTP only for the localhost-dev allowlist. The host check still
		// runs in validateReturnTo downstream, so http://evil.com falls
		// to the default — but javascript:/data:/file: are rejected
		// outright at this gate, which is the user-visible win.
		return returnToAllowsLocalhost
	default:
		return false
	}
}

// AuthHandler handles OAuth login flows.
type AuthHandler struct {
	db  *sql.DB
	cfg *config.Config
	// rdb backs the single-use OAuth `state` consume (P1-K). Optional: when
	// nil (unit tests, local dev without Redis) the state check fails open to
	// the pre-existing cookie-only comparison — a Redis outage must never
	// block sign-in. Wired by SetRedis from the router.
	rdb *redis.Client
}

// emitAuthLoginAudit writes the auth.login audit row best-effort. Provider is
// one of "email" (magic-link), "github", "google", or "impersonation".
// Failures only log — a stale audit_log row must never prevent the user from
// completing their sign-in. Called in a goroutine so the writer never blocks
// the HTTP response.
func emitAuthLoginAudit(db *sql.DB, teamID, userID uuid.UUID, email, provider, ip, userAgent string) {
	// Data-race fix: ip and userAgent reach this function as c.IP() /
	// c.Get("User-Agent") results, whose backing bytes live inside the
	// fasthttp request Ctx. fiber recycles that Ctx into a pool the instant
	// the handler returns, so the background goroutine below MUST read
	// heap-owned copies, never aliases into the recycled Ctx. provider is
	// already heap-owned (DB column / package const) but cloned for symmetry;
	// teamID/userID are value types. email is accepted for call-site symmetry
	// but is not read in the background goroutine below, so it is intentionally
	// not cloned (cloning it was an ineffectual assignment).
	provider = strings.Clone(provider)
	ip = strings.Clone(ip)
	userAgent = strings.Clone(userAgent)
	safego.Go("auth.bg", func() {
		meta := map[string]string{
			"provider":   provider,
			"ip":         ip,
			"user_agent": userAgent,
		}
		metaBlob, _ := json.Marshal(meta)
		summary := "user signed in via " + provider
		ev := models.AuditEvent{
			TeamID:   teamID,
			UserID:   uuid.NullUUID{UUID: userID, Valid: userID != uuid.Nil},
			Actor:    "user",
			Kind:     models.AuditKindAuthLogin,
			Summary:  summary,
			Metadata: metaBlob,
		}
		if err := models.InsertAuditEvent(context.Background(), db, ev); err != nil {
			slog.Warn("audit.emit.failed",
				"kind", models.AuditKindAuthLogin,
				"team_id", teamID,
				"provider", provider,
				"error", err,
			)
		}
	})
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(db *sql.DB, cfg *config.Config) *AuthHandler {
	return &AuthHandler{db: db, cfg: cfg}
}

// SetRedis wires the Redis client used for the single-use OAuth state consume
// (P1-K). Separate setter rather than a constructor arg so every existing
// NewAuthHandler caller (including unit tests) stays source-compatible —
// matches the SetEmailClient pattern on DeployHandler. The router calls this
// once after construction with the shared client.
func (h *AuthHandler) SetRedis(rdb *redis.Client) {
	h.rdb = rdb
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
		// BUG-API-184 (QA 2026-05-29): the error message used to read
		// "code field is required" — accurate but agent-unhelpful. An
		// LLM agent that 4xx'd here needed to either know the GitHub
		// OAuth code-exchange contract already or open /openapi.json to
		// learn what to send. Stamp the full required-fields list inline
		// (the request body has only one field today, but the contract
		// shape is what the agent needs — `{ "code": "<github_oauth_code>" }`)
		// so the message is a self-contained instruction. Keep the
		// `missing_code` error code stable for back-compat (agents
		// branching on .error stay green).
		return respondError(c, fiber.StatusBadRequest, "missing_code",
			"Request body is missing the required `code` field. POST `{\"code\": \"<github_oauth_code>\"}` after exchanging your OAuth authorization code at GitHub.")
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

	emitAuthLoginAudit(h.db, team.ID, user.ID, user.Email, "github", c.IP(), c.Get("User-Agent"))

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

	emitAuthLoginAudit(h.db, team.ID, user.ID, user.Email, "google", c.IP(), c.Get("User-Agent"))

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
		// BUG-API-184 (QA 2026-05-29): mirror the GitHub surface so the
		// agent-actionable message names BOTH fields the Google callback
		// expects (code + redirect_uri). Same code stays for back-compat;
		// only the human/agent-facing message gains the shape hint.
		return respondError(c, fiber.StatusBadRequest, "missing_code",
			"Request body is missing the required `code` field. POST `{\"code\": \"<google_oauth_code>\", \"redirect_uri\": \"<uri>\"}` after exchanging your OAuth authorization code at Google.")
	}
	if body.RedirectURI == "" {
		// BUG-API-184: same treatment — name the field and the body shape
		// so an LLM hitting this 4xx has everything it needs to retry.
		return respondError(c, fiber.StatusBadRequest, "missing_redirect_uri",
			"Request body is missing the required `redirect_uri` field. POST `{\"code\": \"<google_oauth_code>\", \"redirect_uri\": \"<uri>\"}` matching the redirect_uri you registered with Google.")
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

	emitAuthLoginAudit(h.db, team.ID, user.ID, user.Email, "google", c.IP(), c.Get("User-Agent"))

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

	// url.Parse of a compile-time-constant string never errors — the err
	// branch was dead code. GoogleStart handles the identical parse the same
	// way (u, _ := url.Parse(...)).
	u, _ := url.Parse(googleAuthorizeURL)
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

// sessionAudience returns the canonical resource URL stamped into the `aud`
// claim of every session JWT this package mints. RFC 8707 §3: a token MUST
// declare the resource server it is bound to. The middleware's opt-in
// audience check (middleware.audienceMatches) only fires once a token carries
// an `aud` — so without this every dashboard/CLI session was unbound and the
// check was dead code. Resolution mirrors middleware.CanonicalResourceURLFor:
// API_PUBLIC_URL when set, else the compiled-in public API base. Never a
// client-settable value — see middleware/auth.go for the rationale.
func sessionAudience() string {
	if v := strings.TrimRight(os.Getenv("API_PUBLIC_URL"), "/"); v != "" {
		return v
	}
	return urls.PublicAPIBase
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
			Audience:  jwt.ClaimStrings{sessionAudience()},
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
	req, _ := http.NewRequestWithContext(ctx, "POST", githubTokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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
	userReq, _ := http.NewRequestWithContext(ctx, "GET", githubUserURL, nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github+json")

	userResp, err := client.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("github user fetch: %w", err)
	}
	defer func() { _ = userResp.Body.Close() }()

	var profile struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("github profile decode: %w", err)
	}

	// SECURITY (bug bash #9): GitHub's /user endpoint returns the account's
	// PUBLIC profile email, which can be UNVERIFIED and is attacker-settable —
	// trusting it lets an attacker link into a victim's account by email. We
	// therefore IGNORE profile.Email entirely and ALWAYS resolve the address
	// from /user/emails, accepting ONLY a primary+verified entry. If none
	// exists, Email stays "" and findOrCreateUserGitHub refuses to link/create.
	profile.Email = ""
	emailReq, _ := http.NewRequestWithContext(ctx, "GET", githubUserEmailURL, nil)
	emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	emailResp, err := client.Do(emailReq)
	if err == nil {
		defer func() { _ = emailResp.Body.Close() }()
		body, _ := io.ReadAll(emailResp.Body)
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if json.Unmarshal(body, &emails) == nil {
			for _, e := range emails {
				// Only accept the primary AND verified address — an unverified
				// email is attacker-controllable and must never seed/link a
				// platform identity.
				if e.Primary && e.Verified {
					profile.Email = e.Email
					break
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

	// SECURITY (bug bash #9): an EXISTING github_id match (handled above) may
	// proceed regardless, but link-by-email / new-identity creation MUST have a
	// verified primary email (fetchGitHubUser only sets gh.Email from a
	// primary+verified /user/emails entry). Refuse otherwise.
	if gh.Email == "" {
		return nil, nil, errOAuthEmailUnverified
	}

	// No GitHub-ID match. Before creating a brand-new team/user — which
	// fragments the identity of someone who already signed up via magic-link
	// or Google — try to match an existing account by email and attach the
	// GitHub ID to it. Mirrors findOrCreateUserGoogle.
	if gh.Email != "" {
		byEmail, errEmail := models.GetUserByEmail(ctx, h.db, gh.Email)
		if errEmail == nil {
			if byEmail.GitHubID.Valid && byEmail.GitHubID.String != gh.ID {
				return nil, nil, fmt.Errorf("findOrCreateUserGitHub: email already linked to another GitHub account")
			}
			if !byEmail.GitHubID.Valid {
				if linkErr := models.LinkGitHubID(ctx, h.db, byEmail.ID, gh.ID); linkErr != nil {
					return nil, nil, fmt.Errorf("findOrCreateUserGitHub link: %w", linkErr)
				}
				byEmail.GitHubID = sql.NullString{String: gh.ID, Valid: true}
			}
			// A successful GitHub OAuth proves identity control of a verified
			// GitHub email (gitHubUser.Email is sourced only from a /user/emails
			// entry whose Verified flag is true — see the P2 bug-hunt fix), so
			// mark the linked account verified. Best-effort: a flip failure must
			// not block the login.
			markEmailVerified(ctx, h.db, byEmail)
			team, teamErr := models.GetTeamByID(ctx, h.db, byEmail.TeamID.UUID)
			if teamErr != nil {
				return nil, nil, fmt.Errorf("findOrCreateUserGitHub: %w", teamErr)
			}
			return byEmail, team, nil
		}
		if !errors.As(errEmail, &notFound) {
			return nil, nil, fmt.Errorf("findOrCreateUserGitHub email lookup: %w", errEmail)
		}
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
	// GitHub OAuth supplies a verified email (see the link-by-email branch
	// above for the rationale) — flip the new account's flag true.
	markEmailVerified(ctx, h.db, user)
	return user, team, nil
}

// markEmailVerified flips a user's email_verified flag to true and reflects
// the change on the in-memory User so the rest of the request sees it. It is
// the shared best-effort helper for the OAuth find-or-create paths: a verify
// flip failure is logged and swallowed — it must never break an otherwise
// successful login. /claim deliberately does NOT call this (a claim does not
// prove inbox ownership); magic-link uses models.SetEmailVerified directly.
func markEmailVerified(ctx context.Context, db *sql.DB, user *models.User) {
	if user == nil || user.EmailVerified {
		return
	}
	if err := models.SetEmailVerified(ctx, db, user.ID); err != nil {
		slog.Error("auth.set_email_verified_failed", "error", err, "user_id", user.ID)
		return
	}
	user.EmailVerified = true
}

// --- Google OAuth helpers ---

type googleUser struct {
	Sub   string
	Email string
	Name  string
	// EmailVerified is Google's assertion that it controls/verified the
	// address. Populated from the ID-token's `email_verified` (a STRING
	// "true"/"false" on the tokeninfo endpoint) or the userinfo v2
	// `verified_email` (bool). We refuse to link-by-email or seed a new
	// identity on an unverified email (bug bash #7).
	EmailVerified bool
}

// errOAuthEmailUnverified is returned by findOrCreateUserGitHub /
// findOrCreateUserGoogle when an OAuth provider could not assert a verified
// primary email and the request would otherwise create or link an identity
// by that email. Closes the account-takeover vector (bug bash #7/#9). The
// OAuth callbacks map it to a 4xx login failure.
var errOAuthEmailUnverified = errors.New("oauth provider did not supply a verified email")

func verifyGoogleIDToken(ctx context.Context, clientID, idToken string) (*googleUser, error) {
	verifyURL := fmt.Sprintf("%s?id_token=%s", googleTokenInfoURL, url.QueryEscape(idToken))
	req, _ := http.NewRequestWithContext(ctx, "GET", verifyURL, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google token verify: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("google token invalid (status %d)", resp.StatusCode)
	}

	var payload struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Aud           string `json:"aud"`
		Error         string `json:"error_description"`
		EmailVerified string `json:"email_verified"` // tokeninfo returns "true"/"false" as a string
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
		Sub:           payload.Sub,
		Email:         payload.Email,
		Name:          payload.Name,
		EmailVerified: payload.EmailVerified == "true",
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
	req, err := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("google token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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
	req, err := http.NewRequestWithContext(ctx, "GET", googleUserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google userinfo: status %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		VerifiedEmail bool   `json:"verified_email"` // userinfo v2 returns a bool
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
		Sub:           payload.ID,
		Email:         payload.Email,
		Name:          payload.Name,
		EmailVerified: payload.VerifiedEmail,
	}, nil
}

// FindOrCreateUserByEmail is the shared find-or-create path for email-only
// flows (magic-link login). Identity-provider-bound flows (GitHub/Google)
// keep their own helpers because they have an external ID to match on first.
//
// Tier behaviour: a fresh team gets the default tier set by the DB
// (`teams.plan_tier` defaults to 'anonymous' per migration 001). For a
// brand-new magic-link user with nothing to claim, we leave them on the
// default; an explicit upgrade path (Razorpay or /internal/set-tier) will
// move them off it. There is no trial — see policy memory
// project_no_trial_pay_day_one.md. Hobby/pro/team are paid from day one;
// anonymous (24h TTL) is the only free tier.
func (h *AuthHandler) FindOrCreateUserByEmail(ctx context.Context, email string) (*models.User, *models.Team, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, nil, fmt.Errorf("FindOrCreateUserByEmail: empty email")
	}

	user, err := models.GetUserByEmail(ctx, h.db, email)
	if err == nil {
		team, teamErr := models.GetTeamByID(ctx, h.db, user.TeamID.UUID)
		if teamErr != nil {
			return nil, nil, fmt.Errorf("FindOrCreateUserByEmail team lookup: %w", teamErr)
		}
		return user, team, nil
	}

	var notFound *models.ErrUserNotFound
	if !errors.As(err, &notFound) {
		return nil, nil, fmt.Errorf("FindOrCreateUserByEmail user lookup: %w", err)
	}

	// New user — create a team named after the local-part of the email.
	teamName := strings.Split(email, "@")[0]
	if teamName == "" {
		teamName = "team"
	}
	team, err := models.CreateTeam(ctx, h.db, teamName)
	if err != nil {
		return nil, nil, fmt.Errorf("FindOrCreateUserByEmail create team: %w", err)
	}
	user, err = models.CreateUser(ctx, h.db, team.ID, email, "", "", "owner")
	if err != nil {
		return nil, nil, fmt.Errorf("FindOrCreateUserByEmail create user: %w", err)
	}
	return user, team, nil
}

// IssueSessionJWT exposes the package-level signSessionJWT through the
// handler so other handlers (magic-link) can mint tokens without importing
// the package's unexported helpers.
func (h *AuthHandler) IssueSessionJWT(user *models.User, team *models.Team) (string, error) {
	return h.issueSessionJWT(user, team)
}

// --- Browser GET-based OAuth handlers (complement the existing POST API) ---

const (
	oauthStateCookie = "oauth_state"
	oauthStateMaxAge = 5 * 60 // 5 minutes
)

// setOAuthStateCookie writes "<state>|<returnTo>" into a short-lived,
// HTTP-only, SameSite=Lax cookie. The Lax policy lets the cookie ride along
// with the redirect back from the OAuth provider while still blocking CSRF
// from third-party origins.
func setOAuthStateCookie(c *fiber.Ctx, secure bool, state, returnTo string) {
	c.Cookie(&fiber.Cookie{
		Name:     oauthStateCookie,
		Value:    state + "|" + returnTo,
		Path:     "/",
		MaxAge:   oauthStateMaxAge,
		Secure:   secure,
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

// readOAuthStateCookie returns (state, returnTo, ok). ok is false when the
// cookie is missing or malformed.
func readOAuthStateCookie(c *fiber.Ctx) (string, string, bool) {
	raw := c.Cookies(oauthStateCookie)
	if raw == "" {
		return "", "", false
	}
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// clearOAuthStateCookie expires the oauth_state cookie immediately.
//
// The Secure + SameSite attributes MUST mirror setOAuthStateCookie: some
// browsers refuse to overwrite a Secure cookie from a write that omits
// Secure, so an attribute-stripped expiring write can silently no-op and
// leave the single-use state token readable. Keep this in sync with
// setOAuthStateCookie.
func clearOAuthStateCookie(c *fiber.Ctx, secure bool) {
	c.Cookie(&fiber.Cookie{
		Name:     oauthStateCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

// oauthStateRedisPrefix namespaces the single-use OAuth state keys in Redis.
const oauthStateRedisPrefix = "oauth_state:"

// registerOAuthState records a freshly-minted OAuth `state` token in Redis so
// the matching callback can consume it exactly once (P1-K). The key lives for
// the same window as the state cookie. Best-effort: a Redis failure (or a nil
// client in tests) just means the callback falls back to the cookie-only
// check — a Redis outage must not block sign-in.
func (h *AuthHandler) registerOAuthState(ctx context.Context, state string) {
	if h.rdb == nil || state == "" {
		return
	}
	if err := h.rdb.Set(ctx, oauthStateRedisPrefix+state, "1",
		time.Duration(oauthStateMaxAge)*time.Second).Err(); err != nil {
		slog.Warn("auth.oauth.state_register_failed", "error", err)
	}
}

// consumeOAuthState atomically deletes the OAuth `state` key, returning true
// only for the FIRST caller (P1-K — single-use). A replayed callback within
// the 5-minute window finds the key already gone and gets false.
//
// Redis GETDEL is atomic, so two concurrent replays cannot both win.
//
// Fail-open contract: when the client is nil (tests / no-Redis dev) or Redis
// errors, it returns true so the cookie-only comparison in the callers still
// gates the request — exactly the pre-P1-K behaviour. The single-use
// guarantee is a defence-in-depth hardening on top of the cookie check, never
// a hard dependency that a Redis outage could turn into a sign-in outage.
func (h *AuthHandler) consumeOAuthState(ctx context.Context, state string) bool {
	if h.rdb == nil || state == "" {
		return true
	}
	val, err := h.rdb.GetDel(ctx, oauthStateRedisPrefix+state).Result()
	if err == redis.Nil {
		// Key absent — either already consumed (replay) or never registered
		// (e.g. minted before this fix deployed). Reject: a genuine first-use
		// always has the key because GitHubStart/GoogleStart just wrote it.
		return false
	}
	if err != nil {
		// T10 P1-3 (BugHunt 2026-05-20): fail CLOSED on Redis error.
		// Previously this fell back to "cookie check still gates" — but
		// the oauth_state cookie is replayable inside its 5-minute MaxAge
		// window, so failing open here means a Redis blip silently strips
		// the single-use defence. An attacker who captures a victim's
		// in-flight state cookie + code can mint a second session within
		// 5 minutes. Treat Redis errors as "we cannot prove this is a
		// first-use" → reject. Genuine sign-ins re-try the entire OAuth
		// dance, which writes a fresh state into Redis.
		slog.Error("auth.oauth.state_consume_failed_failclosed", "error", err)
		return false
	}
	return val != ""
}

// renderAuthError sends a 400 with a small HTML page so a browser landing on
// a broken callback URL gets a readable message instead of raw JSON.
//
// SEC-API FINDING-23 (2026-05-29): headline + detail are interpolated into HTML
// via fmt.Sprintf. Every existing caller passes static literals, but the function
// itself is the only HTML emitter in the api and was unsafe-by-default — any
// future caller passing a user-influenced value (OAuth profile name, JWT claim,
// upstream error string) would have introduced reflected XSS on api.instanode.dev
// (cookies for that host stealable). Both arguments are now html.EscapeString'd
// at the sink so the helper is safe for every caller without forcing them to
// remember to escape — defense in depth.
func renderAuthError(c *fiber.Ctx, status int, headline, detail string) error {
	c.Set("Content-Type", "text/html; charset=utf-8")
	// BUG-API-404 (QA 2026-05-29): the OAuth / magic-link callback HTML
	// is a per-request rendering of session-bound state — a back-button,
	// browser-history-restore, or service-worker re-fetch must NOT replay
	// it (the underlying token has been consumed or expired). Without
	// Cache-Control, the body could be re-served by the browser fetch
	// cache or any intermediary, which both leaks the "you tried this
	// link" UX state across sessions AND, in the success-redirect cousin
	// of this surface, would re-set the exchange cookie. `no-store`
	// (RFC 9111 §5.2.2.5) is the strongest stop-cache directive and
	// matches the contract every other auth-result surface in the api
	// already follows.
	c.Set(fiber.HeaderCacheControl, "no-store")
	// BUG-API-257 (QA 2026-05-29): the <html> element used to ship with
	// no `lang` attribute. WCAG 3.1.1 "Language of Page" requires a
	// programmatically determinable primary language; assistive tech
	// (VoiceOver, NVDA) falls back to the OS locale otherwise, mis-
	// pronouncing English copy in non-English locales. `lang="en"` is
	// the correct value for the static English-only copy below.
	body := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Sign-in error</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:48px auto;padding:24px;color:#111;">
  <h2>%s</h2>
  <p style="color:#444;">%s</p>
  <p><a href="https://instanode.dev/login">Try signing in again &rarr;</a></p>
</body>
</html>`, html.EscapeString(headline), html.EscapeString(detail))
	return c.Status(status).SendString(body)
}

// GitHubStart handles GET /auth/github/start?return_to=<url>.
// Redirects the browser to GitHub's OAuth consent screen. The CSRF state and
// the validated return_to are stashed in a short-lived cookie that the
// callback handler reads.
func (h *AuthHandler) GitHubStart(c *fiber.Ctx) error {
	if h.cfg.GitHubClientID == "" {
		return renderAuthError(c, fiber.StatusServiceUnavailable, "GitHub sign-in is not configured", "Ask the operator to set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.")
	}

	// AUTH-016 / AUTH-017: fail-closed on hostile return_to schemes.
	// Previously validateReturnTo silently downgraded javascript:/data:/
	// file:/ etc. to the default — we now reject with 400 invalid_return_to
	// up-front so the contract is explicit and abuse leaves a clean signal.
	// Empty / missing return_to is permitted and collapses to the default.
	if rawReturnTo := strings.TrimSpace(c.Query("return_to")); rawReturnTo != "" {
		if !returnToSchemeIsAllowed(rawReturnTo) {
			return respondError(c, fiber.StatusBadRequest, "invalid_return_to",
				"Query 'return_to' must use https:// (or http://localhost for dev). javascript:, data:, file: and other schemes are rejected.")
		}
	}

	state, err := generateOAuthState()
	if err != nil {
		return renderAuthError(c, fiber.StatusInternalServerError, "Could not start sign-in", "Random source unavailable.")
	}
	returnTo := validateReturnTo(c.Query("return_to"))
	setOAuthStateCookie(c, h.cfg.Environment == "production", state, returnTo)
	// P1-K: record the state in Redis so the callback can consume it once.
	h.registerOAuthState(c.Context(), state)

	authURL := fmt.Sprintf(
		githubAuthorizeURL+"?client_id=%s&redirect_uri=%s&state=%s&scope=%s",
		url.QueryEscape(h.cfg.GitHubClientID),
		url.QueryEscape(canonicalAPIBase+"/auth/github/callback"),
		url.QueryEscape(state),
		url.QueryEscape("user:email"),
	)
	return c.Redirect(authURL, fiber.StatusFound)
}

// GitHubCallback handles GET /auth/github/callback?code=...&state=...
// Verifies state matches the cookie, exchanges the code for a user, mints a
// session JWT, and 302s to <return_to>?session_token=<jwt>.
func (h *AuthHandler) GitHubCallback(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	if h.cfg.GitHubClientID == "" || h.cfg.GitHubClientSecret == "" {
		return renderAuthError(c, fiber.StatusServiceUnavailable, "GitHub sign-in is not configured", "")
	}

	code := strings.TrimSpace(c.Query("code"))
	stateParam := strings.TrimSpace(c.Query("state"))
	if code == "" || stateParam == "" {
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in didn't complete", "Missing code or state from GitHub.")
	}

	cookieState, returnTo, ok := readOAuthStateCookie(c)
	if !ok || cookieState != stateParam {
		clearOAuthStateCookie(c, h.cfg.Environment == "production")
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in expired", "The sign-in link expired or was opened in a different browser. Please try again.")
	}
	clearOAuthStateCookie(c, h.cfg.Environment == "production")

	// P1-K: single-use consume. The cookie check above proves the state was
	// minted by us, but a cookie can be replayed within its 5-minute window.
	// consumeOAuthState atomically deletes the Redis key — only the FIRST
	// callback wins; a replay finds it gone and is rejected.
	if !h.consumeOAuthState(c.Context(), stateParam) {
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in already used", "This sign-in link was already used. Please start sign-in again.")
	}

	// Re-validate returnTo as defence-in-depth; the cookie isn't user-supplied
	// but a copy-paste of an old cookie shouldn't be able to redirect off-domain.
	returnTo = validateReturnTo(returnTo)

	ghUser, err := exchangeGitHubCode(c.Context(), h.cfg.GitHubClientID, h.cfg.GitHubClientSecret, code)
	if err != nil {
		slog.Error("auth.github.start_callback.exchange_failed", "error", err, "request_id", requestID)
		return renderAuthError(c, fiber.StatusUnauthorized, "GitHub sign-in failed", "We couldn't verify your GitHub account. Please try again.")
	}

	user, team, err := h.findOrCreateUserGitHub(c.Context(), ghUser)
	if err != nil {
		slog.Error("auth.github.start_callback.user_upsert_failed", "error", err, "github_id", ghUser.ID, "request_id", requestID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in failed", "Could not create your account.")
	}

	sessionToken, err := h.issueSessionJWT(user, team)
	if err != nil {
		slog.Error("auth.github.start_callback.jwt_failed", "error", err, "request_id", requestID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in failed", "Could not issue session token.")
	}

	slog.Info("auth.github.start_callback.success",
		"user_id", user.ID, "team_id", team.ID, "request_id", requestID,
	)

	emitAuthLoginAudit(h.db, team.ID, user.ID, user.Email, "github", c.IP(), c.Get("User-Agent"))

	// AUTH-004: do NOT put the session JWT in the Location header.
	// See comment on the magic-link callback for the full rationale.
	setExchangeCookie(c, sessionToken, h.cfg.Environment == "production")
	return c.Redirect(appendSignedInMarker(returnTo), fiber.StatusFound)
}

// GoogleStart handles GET /auth/google/start?return_to=<url>.
func (h *AuthHandler) GoogleStart(c *fiber.Ctx) error {
	if h.cfg.GoogleClientID == "" {
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Google sign-in is not configured", "Ask the operator to set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")
	}

	// AUTH-016 / AUTH-017: mirror the GitHubStart fail-closed gate.
	if rawReturnTo := strings.TrimSpace(c.Query("return_to")); rawReturnTo != "" {
		if !returnToSchemeIsAllowed(rawReturnTo) {
			return respondError(c, fiber.StatusBadRequest, "invalid_return_to",
				"Query 'return_to' must use https:// (or http://localhost for dev). javascript:, data:, file: and other schemes are rejected.")
		}
	}

	state, err := generateOAuthState()
	if err != nil {
		return renderAuthError(c, fiber.StatusInternalServerError, "Could not start sign-in", "Random source unavailable.")
	}
	returnTo := validateReturnTo(c.Query("return_to"))
	setOAuthStateCookie(c, h.cfg.Environment == "production", state, returnTo)
	// P1-K: record the state in Redis so the callback can consume it once.
	h.registerOAuthState(c.Context(), state)

	u, _ := url.Parse(googleAuthorizeURL)
	q := u.Query()
	q.Set("client_id", h.cfg.GoogleClientID)
	q.Set("redirect_uri", canonicalAPIBase+"/auth/google/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("access_type", "online")
	q.Set("include_granted_scopes", "true")
	u.RawQuery = q.Encode()

	return c.Redirect(u.String(), fiber.StatusFound)
}

// GoogleCallbackBrowser handles GET /auth/google/callback?code=...&state=...
// Distinct from the existing POST GoogleCallback which serves the
// programmatic / SPA flow with a body-supplied redirect_uri.
func (h *AuthHandler) GoogleCallbackBrowser(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	if h.cfg.GoogleClientID == "" || h.cfg.GoogleClientSecret == "" {
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Google sign-in is not configured", "")
	}

	code := strings.TrimSpace(c.Query("code"))
	stateParam := strings.TrimSpace(c.Query("state"))
	if code == "" || stateParam == "" {
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in didn't complete", "Missing code or state from Google.")
	}

	cookieState, returnTo, ok := readOAuthStateCookie(c)
	if !ok || cookieState != stateParam {
		clearOAuthStateCookie(c, h.cfg.Environment == "production")
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in expired", "The sign-in link expired or was opened in a different browser. Please try again.")
	}
	clearOAuthStateCookie(c, h.cfg.Environment == "production")

	// P1-K: single-use consume — see GitHubCallback for the rationale.
	if !h.consumeOAuthState(c.Context(), stateParam) {
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in already used", "This sign-in link was already used. Please start sign-in again.")
	}

	returnTo = validateReturnTo(returnTo)

	accessToken, err := exchangeGoogleAuthorizationCode(c.Context(), h.cfg.GoogleClientID, h.cfg.GoogleClientSecret, code, canonicalAPIBase+"/auth/google/callback")
	if err != nil {
		slog.Error("auth.google.start_callback.exchange_failed", "error", err, "request_id", requestID)
		return renderAuthError(c, fiber.StatusUnauthorized, "Google sign-in failed", "We couldn't verify your Google account. Please try again.")
	}

	gUser, err := fetchGoogleUserInfoOAuth2V2(c.Context(), accessToken)
	if err != nil {
		slog.Error("auth.google.start_callback.userinfo_failed", "error", err, "request_id", requestID)
		return renderAuthError(c, fiber.StatusUnauthorized, "Google sign-in failed", "We couldn't read your Google profile. Please try again.")
	}

	user, team, err := h.findOrCreateUserGoogle(c.Context(), gUser)
	if err != nil {
		slog.Error("auth.google.start_callback.user_upsert_failed", "error", err, "google_id", gUser.Sub, "request_id", requestID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in failed", "Could not create your account.")
	}

	sessionToken, err := h.issueSessionJWT(user, team)
	if err != nil {
		slog.Error("auth.google.start_callback.jwt_failed", "error", err, "request_id", requestID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in failed", "Could not issue session token.")
	}

	slog.Info("auth.google.start_callback.success",
		"user_id", user.ID, "team_id", team.ID, "request_id", requestID,
	)

	emitAuthLoginAudit(h.db, team.ID, user.ID, user.Email, "google", c.IP(), c.Get("User-Agent"))

	// AUTH-004: session cookie + signed_in marker (no JWT in Location).
	setExchangeCookie(c, sessionToken, h.cfg.Environment == "production")
	return c.Redirect(appendSignedInMarker(returnTo), fiber.StatusFound)
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

	// SECURITY (bug bash #7): only an EXISTING google_id match (handled above)
	// may proceed on an unverified email. For link-by-email or new-identity
	// creation we MUST require a Google-verified email — otherwise an attacker
	// who controls an unverified Google account whose email equals a victim's
	// could link into / impersonate the victim's account.
	if !g.EmailVerified {
		return nil, nil, errOAuthEmailUnverified
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
			// Google only ever returns a verified email address, so a
			// successful Google OAuth proves inbox control — mark the linked
			// account verified. Best-effort: see markEmailVerified.
			markEmailVerified(ctx, h.db, byEmail)
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
	// Google supplies a verified email — flip the new account's flag true.
	markEmailVerified(ctx, h.db, user)
	return user, team, nil
}
