package middleware

import (
	"errors"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"instant.dev/internal/config"
	"instant.dev/internal/urls"
)

const (
	// LocalKeyUserID is the fiber.Locals key for the authenticated user ID.
	LocalKeyUserID = "auth_user_id"
	// LocalKeyTeamID is the fiber.Locals key for the authenticated team ID.
	LocalKeyTeamID = "auth_team_id"
	// LocalKeyDPoPKeyThumbprint is set when the bearer token carries a DPoP
	// proof-of-possession constraint (cnf.jkt). Consumed by RequireDPoP.
	LocalKeyDPoPKeyThumbprint = "auth_dpop_jkt"

	// audienceMismatchError is the error keyword used when an RFC 8707
	// audience check fails. Distinct from the generic "unauthorized" so that
	// agents can distinguish "wrong server" from "bad credentials".
	audienceMismatchError = "invalid_token"
)

// AuthLoginURL is the URL agents should show users when their session
// token is rejected. Exposed as a package-level variable so tests and
// self-hosted operators can override it. Mirrors handlers.DefaultLoginURL —
// duplicated rather than imported because the handlers package consumes
// middleware (not the other way around), and a circular import would
// otherwise be required to share the constant.
var AuthLoginURL = "https://instanode.dev/login"

// unauthorizedAgentAction is the canonical agent_action sentence served on
// every 401 from RequireAuth. Mirrors the "unauthorized" entry in
// handlers.codeToAgentAction so an agent inspecting either a handler-emitted
// 401 (e.g. a stale session bouncing off /api/v1/billing/usage) or a
// middleware-emitted 401 (e.g. no Authorization header at all) gets the same
// remediation prose either way.
const unauthorizedAgentAction = "The user's INSTANODE_TOKEN is invalid or expired. Have them log in at https://instanode.dev/login to mint a new one."

// respondUnauthorized writes the canonical 401 body shape used by RequireAuth:
//
//	{
//	  "ok": false,
//	  "error": "unauthorized",
//	  "agent_action": "The user's INSTANODE_TOKEN is invalid or expired...",
//	  "upgrade_url": "https://instanode.dev/login"
//	}
//
// agent_action is the verbatim sentence the calling agent should surface to
// the human user, per the §10.15 agent-action contract. upgrade_url points
// at the login page because re-auth is the remediation for every variant of
// this error (no header, malformed JWT, expired JWT, wrong secret, missing
// claims, invalid PAT). Kept as a single helper so adding RFC 6750
// WWW-Authenticate headers in a future PR happens in one place.
func respondUnauthorized(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":           false,
		"error":        "unauthorized",
		"agent_action": unauthorizedAgentAction,
		"upgrade_url":  AuthLoginURL,
	})
}

// defaultCanonicalResourceURL is the audience used when neither API_PUBLIC_URL
// nor the live request host is available. Aliased to urls.PublicAPIBase to
// keep the literal "https://api.instanode.dev" in exactly one place.
const defaultCanonicalResourceURL = urls.PublicAPIBase

// confirmation captures the OAuth 2.0 PoP "cnf" claim shape (RFC 7800).
// Currently only the JWK thumbprint variant ("jkt") used by DPoP is consumed.
type confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

// sessionClaims mirrors the JWT payload issued by auth.go.
//
// Two extra claims back the agent-auth standards work:
//
//   - Audience (`aud`) — RFC 8707 Resource Indicators. A token MUST declare
//     the canonical resource URL of this API. Missing/wrong audience → 401.
//   - Confirmation (`cnf`) — RFC 7800. When present and JKT is populated the
//     request MUST also carry a matching DPoP proof (enforced by RequireDPoP).
//
// The audience check is OPT-IN: if the JWT carries no `aud` claim at all the
// request is allowed through (back-compat with existing dashboard tokens).
// Once a token does declare an audience it MUST match the canonical URL of
// this API; mismatched tokens are rejected.
type sessionClaims struct {
	UserID       string        `json:"uid"`
	TeamID       string        `json:"tid"`
	Email        string        `json:"email"`
	Confirmation *confirmation `json:"cnf,omitempty"`
	jwt.RegisteredClaims
}

// Valid overrides RegisteredClaims.Valid to skip IssuedAt validation.
// iat-in-future errors cause spurious 401s when there is any sub-second clock
// skew between the token issuer and the API server. exp still enforces expiry.
func (c sessionClaims) Valid() error {
	c.RegisteredClaims.IssuedAt = nil
	return c.RegisteredClaims.Valid()
}

// CanonicalResourceURLFor returns the canonical resource URL for an incoming
// request. It is also used to populate the
// `/.well-known/oauth-protected-resource` metadata document.
//
// Resolution order:
//  1. API_PUBLIC_URL env var (when set and non-empty)
//  2. X-Forwarded-Proto + Host headers from the live request
//  3. defaultCanonicalResourceURL constant
//
// Exposed as a package-level variable so individual tests can override the
// resolution without threading a dependency through call sites.
var CanonicalResourceURLFor = func(c *fiber.Ctx) string {
	if v := strings.TrimRight(os.Getenv("API_PUBLIC_URL"), "/"); v != "" {
		return v
	}
	if c != nil {
		host := c.Get("X-Forwarded-Host")
		if host == "" {
			host = c.Hostname()
		}
		scheme := c.Get("X-Forwarded-Proto")
		if scheme == "" {
			if p := c.Protocol(); p != "" {
				scheme = p
			} else {
				scheme = "https"
			}
		}
		if host != "" {
			u := url.URL{Scheme: scheme, Host: host}
			return strings.TrimRight(u.String(), "/")
		}
	}
	return defaultCanonicalResourceURL
}

// audienceMatches reports whether the JWT `aud` claim contains the canonical
// resource URL for this server. RFC 8707 §3 — the resource server MUST reject
// tokens whose audience does not include its own resource indicator.
func audienceMatches(aud jwt.ClaimStrings, canonical string) bool {
	if canonical == "" {
		return false
	}
	for _, a := range aud {
		if a == canonical {
			return true
		}
	}
	return false
}

// rejectAudienceMismatch writes an RFC 6750 §3.1-style 401 with a structured
// error keyword agents can branch on.
func rejectAudienceMismatch(c *fiber.Ctx) error {
	canonical := CanonicalResourceURLFor(c)
	c.Set("WWW-Authenticate",
		`Bearer realm="instanode", error="invalid_token", error_description="audience mismatch", resource="`+canonical+`"`)
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":                false,
		"error":             audienceMismatchError,
		"error_description": "audience mismatch",
	})
}

// RequireAuth validates the Authorization: Bearer {jwt} header.
// On success it stores user_id and team_id in fiber.Locals and calls Next.
//
// On failure it returns 401 with the canonical agent-action body shape:
//
//	{
//	  "ok": false,
//	  "error": "unauthorized",
//	  "agent_action": "The user's INSTANODE_TOKEN is invalid or expired...",
//	  "upgrade_url": "https://instanode.dev/login"
//	}
//
// agent_action mirrors the "unauthorized" entry in handlers.codeToAgentAction
// so a Claude / Cursor / MCP agent inspecting any 401 from this API gets the
// same remediation prose whether the rejection happened in this middleware
// or in a downstream handler (e.g. a session that decoded but had stale
// claims). Audience-mismatch responses (RFC 8707) still go through
// rejectAudienceMismatch and keep their distinct `invalid_token` error
// keyword so agents can branch "wrong server" from "bad credentials".
func RequireAuth(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if len(header) < 8 || header[:7] != "Bearer " {
			return respondUnauthorized(c)
		}
		tokenStr := header[7:]

		// Dispatch on token shape. PATs (ink_<base64>) hit the api_keys
		// table; JWTs go through HMAC validation. Both populate the same
		// auth_team_id / auth_user_id locals so handlers don't branch.
		if IsAPIKey(tokenStr) {
			ok, err := AuthenticateAPIKey(c, tokenStr)
			if err != nil || !ok {
				return respondUnauthorized(c)
			}
			return c.Next()
		}

		claims := &sessionClaims{}
		parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil || !parsed.Valid {
			return respondUnauthorized(c)
		}

		if claims.UserID == "" || claims.TeamID == "" {
			return respondUnauthorized(c)
		}

		// RFC 8707 audience check — only enforced when the token actually
		// declares an `aud` claim. Existing dashboard sessions issued before
		// this change have no audience and continue to work; tokens that DO
		// declare an audience must include the canonical resource URL.
		if len(claims.Audience) > 0 {
			if !audienceMatches(claims.Audience, CanonicalResourceURLFor(c)) {
				return rejectAudienceMismatch(c)
			}
		}

		c.Locals(LocalKeyUserID, claims.UserID)
		c.Locals(LocalKeyTeamID, claims.TeamID)
		if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
			c.Locals(LocalKeyDPoPKeyThumbprint, claims.Confirmation.JKT)
		}
		return c.Next()
	}
}

// GetUserID retrieves the authenticated user ID from Fiber locals.
// Returns an empty string if not set.
func GetUserID(c *fiber.Ctx) string {
	if v, ok := c.Locals(LocalKeyUserID).(string); ok {
		return v
	}
	return ""
}

// GetTeamID retrieves the authenticated team ID from Fiber locals.
// Returns an empty string if not set.
func GetTeamID(c *fiber.Ctx) string {
	if v, ok := c.Locals(LocalKeyTeamID).(string); ok {
		return v
	}
	return ""
}

// GetDPoPKeyThumbprint returns the JWK thumbprint (`cnf.jkt`) bound to the
// current bearer token, or "" if the token is not key-bound. Consumed by
// RequireDPoP to decide whether to enforce DPoP for this request.
func GetDPoPKeyThumbprint(c *fiber.Ctx) string {
	if v, ok := c.Locals(LocalKeyDPoPKeyThumbprint).(string); ok {
		return v
	}
	return ""
}

// OptionalAuth is like RequireAuth but does not return 401 when the header is absent or invalid.
// If a valid bearer token is present it populates the same Fiber locals as RequireAuth.
// Use on routes where anonymous access is allowed but authenticated users get elevated behaviour.
func OptionalAuth(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if len(header) < 8 || header[:7] != "Bearer " {
			return c.Next()
		}
		tokenStr := header[7:]

		// PAT path: invalid PATs continue as anonymous (do NOT block in OptionalAuth).
		if IsAPIKey(tokenStr) {
			_, _ = AuthenticateAPIKey(c, tokenStr) //nolint:errcheck — drop on error
			return c.Next()
		}

		claims := &sessionClaims{}
		parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil || !parsed.Valid || claims.UserID == "" || claims.TeamID == "" {
			// Invalid or expired token — continue as anonymous, don't block.
			return c.Next()
		}

		// RFC 8707 audience check (opt-in: only enforced if token has `aud`).
		// In OptionalAuth a mismatch must NOT block the request — we just
		// drop the credential and continue as anonymous.
		if len(claims.Audience) > 0 && !audienceMatches(claims.Audience, CanonicalResourceURLFor(c)) {
			return c.Next()
		}

		c.Locals(LocalKeyUserID, claims.UserID)
		c.Locals(LocalKeyTeamID, claims.TeamID)
		if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
			c.Locals(LocalKeyDPoPKeyThumbprint, claims.Confirmation.JKT)
		}
		return c.Next()
	}
}
