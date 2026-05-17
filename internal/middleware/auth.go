package middleware

import (
	"errors"
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
	// LocalKeyEmail is the fiber.Locals key for the authenticated user's email
	// address (read from the JWT `email` claim). Populated by RequireAuth so
	// downstream middleware/handlers can branch on identity without a DB hit —
	// in particular RequireAdmin reads it to check the ADMIN_EMAILS allowlist.
	LocalKeyEmail = "auth_email"
	// LocalKeyReadOnly is the fiber.Locals key set to true when the JWT
	// carries `read_only:true` — i.e. the session was minted via
	// POST /api/v1/admin/customers/:team_id/impersonate. Consumed by
	// RequireWritable, which 403s any POST/PATCH/PUT/DELETE while the flag
	// is set. The flag is irrevocable for the session's lifetime.
	LocalKeyReadOnly = "auth_read_only"
	// LocalKeyImpersonatedBy is the fiber.Locals key holding the admin email
	// that minted an impersonation token (`impersonated_by` JWT claim).
	// Empty when the session is a normal (non-impersonated) one. Surfaced
	// in logs / audit trails so a future investigation can answer "who
	// caused this read?" — and emitted on /auth/me so the dashboard can
	// render the "you are viewing as <customer>" banner.
	LocalKeyImpersonatedBy = "auth_impersonated_by"

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

// unauthorizedMessage is the human-readable explanation paired with the
// "unauthorized" error code in the envelope. Required by the canonical
// ErrorResponse schema (see handlers/openapi.go) — programmatic clients
// branch on `error`, humans/dashboards render `message`.
const unauthorizedMessage = "Authentication required: missing, malformed, or expired session token."

// respondUnauthorized writes the canonical 401 body shape used by RequireAuth.
// It mirrors the handlers.ErrorResponse schema so an agent inspecting any 401
// from this API sees one envelope regardless of which layer wrote the body:
//
//	{
//	  "ok": false,
//	  "error": "unauthorized",
//	  "message": "Authentication required: ...",
//	  "request_id": "<x-request-id>",
//	  "retry_after_seconds": null,
//	  "agent_action": "The user's INSTANODE_TOKEN is invalid or expired...",
//	  "upgrade_url": "https://instanode.dev/login"
//	}
//
// Why request_id + retry_after_seconds + message live in the middleware
// envelope (W12, retro-3 finding): every documented field in
// handlers.ErrorResponse is in the response — agents that learn the envelope
// shape once via /openapi.json don't have to special-case the
// middleware-emitted 401. request_id is pulled from the same Fiber local
// that RequestID() populates, so it echoes the X-Request-ID header (the
// agent can quote it when emailing support). retry_after_seconds is
// unconditionally null on a 401 — re-auth is the remediation, not a retry.
//
// agent_action is the verbatim sentence the calling agent should surface to
// the human user, per the §10.15 agent-action contract. upgrade_url points
// at the login page because re-auth is the remediation for every variant of
// this error (no header, malformed JWT, expired JWT, wrong secret, missing
// claims, invalid PAT). Kept as a single helper so adding RFC 6750
// WWW-Authenticate headers in a future PR happens in one place.
func respondUnauthorized(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":                  false,
		"error":               "unauthorized",
		"message":             unauthorizedMessage,
		"request_id":          GetRequestID(c),
		"retry_after_seconds": nil,
		"agent_action":        unauthorizedAgentAction,
		"upgrade_url":         AuthLoginURL,
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
	// ReadOnly + ImpersonatedBy back the read-only "view-as-customer"
	// impersonation surface: a platform admin mints a 10-minute JWT scoped
	// to a target customer's team via POST /api/v1/admin/customers/:id/impersonate.
	// RequireWritable consumes ReadOnly to 403 every POST/PATCH/PUT/DELETE
	// the impersonated session attempts; ImpersonatedBy is surfaced on
	// /auth/me and emitted in audit/log lines so the admin's identity is
	// preserved across the session boundary. Both default to zero values
	// for normal (non-impersonated) sessions — JSON omitempty keeps the
	// wire shape unchanged for the common path.
	ReadOnly       bool   `json:"read_only,omitempty"`
	ImpersonatedBy string `json:"impersonated_by,omitempty"`
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
//  2. defaultCanonicalResourceURL constant
//
// P2 (2026-05-17): the canonical URL is used for the RFC 8707 audience check
// and RFC 9449 DPoP htu check — both are security boundaries. It MUST NOT be
// derived from client-settable headers (X-Forwarded-Host / X-Forwarded-Proto):
// behind an ingress that does not strip those headers, an attacker could spoof
// the host so a token minted for a different audience validates here. The
// canonical host is therefore a fixed config value (API_PUBLIC_URL) or the
// compiled-in default — never the request. The `*fiber.Ctx` parameter is
// retained for call-site compatibility but intentionally unused.
//
// Exposed as a package-level variable so individual tests can override the
// resolution without threading a dependency through call sites.
var CanonicalResourceURLFor = func(_ *fiber.Ctx) string {
	if v := strings.TrimRight(os.Getenv("API_PUBLIC_URL"), "/"); v != "" {
		return v
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
//
// W12: the envelope carries the same full shape as respondUnauthorized —
// message, request_id, retry_after_seconds, agent_action, upgrade_url — so
// an agent inspecting either flavour of 401 sees the same field set.
// error_description is retained alongside `message` because RFC 6750 §3.1
// names that exact field as the human-readable detail paired with the
// error keyword in the WWW-Authenticate header; downstream OAuth-aware
// clients look for it.
func rejectAudienceMismatch(c *fiber.Ctx) error {
	canonical := CanonicalResourceURLFor(c)
	c.Set("WWW-Authenticate",
		`Bearer realm="instanode", error="invalid_token", error_description="audience mismatch", resource="`+canonical+`"`)
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":                  false,
		"error":               audienceMismatchError,
		"error_description":   "audience mismatch",
		"message":             "Token audience does not match this server (RFC 8707). Mint a new token bound to " + canonical + ".",
		"request_id":          GetRequestID(c),
		"retry_after_seconds": nil,
		"agent_action":        unauthorizedAgentAction,
		"upgrade_url":         AuthLoginURL,
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

		// A03 (P1): server-side JTI revocation check.
		// POST /auth/logout stores "session.revoked:<jti>" in Redis with TTL =
		// remaining token lifetime. Fail-open (convention 1): a Redis outage
		// returns (false, err) and we continue — see revocation.go.
		if jti := claims.ID; jti != "" {
			if revoked, err := IsJTIRevoked(c.UserContext(), jti); err != nil {
				// Redis error — log and fail-open (continue to serve the request).
				// Logged inside IsJTIRevoked; no additional log here to avoid duplication.
				_ = err
			} else if revoked {
				return respondUnauthorized(c)
			}
		}

		c.Locals(LocalKeyUserID, claims.UserID)
		c.Locals(LocalKeyTeamID, claims.TeamID)
		if claims.Email != "" {
			c.Locals(LocalKeyEmail, claims.Email)
		}
		if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
			c.Locals(LocalKeyDPoPKeyThumbprint, claims.Confirmation.JKT)
		}
		// Impersonation locals — set unconditionally when the claims carry
		// them (omitempty on the wire means the receiver only sees them when
		// the issuer set them). RequireWritable reads LocalKeyReadOnly to
		// gate mutating routes.
		if claims.ReadOnly {
			c.Locals(LocalKeyReadOnly, true)
		}
		if claims.ImpersonatedBy != "" {
			c.Locals(LocalKeyImpersonatedBy, claims.ImpersonatedBy)
		}
		return c.Next()
	}
}

// GetEmail retrieves the authenticated user's email from Fiber locals.
// Returns an empty string if not set. The value originates from the JWT
// `email` claim populated by RequireAuth and is the canonical input to
// RequireAdmin's ADMIN_EMAILS allowlist check.
func GetEmail(c *fiber.Ctx) string {
	if v, ok := c.Locals(LocalKeyEmail).(string); ok {
		return v
	}
	return ""
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

// IsReadOnly reports whether the current request's JWT carried
// `read_only:true` — i.e. it was minted by the admin impersonation flow.
// Centralised so RequireWritable, audit-log emitters, and the /auth/me
// surfacing all agree on the single source of truth (LocalKeyReadOnly).
func IsReadOnly(c *fiber.Ctx) bool {
	v, ok := c.Locals(LocalKeyReadOnly).(bool)
	return ok && v
}

// GetImpersonatedBy returns the admin email that minted the current
// impersonation token, or "" when the session is a normal one. Surfaced
// on /auth/me so the dashboard can render the impersonation banner.
func GetImpersonatedBy(c *fiber.Ctx) string {
	if v, ok := c.Locals(LocalKeyImpersonatedBy).(string); ok {
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

		// A03 (P1) — JTI revocation check, mirrored from RequireAuth. A token
		// revoked via POST /auth/logout must not grant elevated behaviour on
		// an OptionalAuth route either. As elsewhere in OptionalAuth, a
		// revoked JTI drops the credential and continues anonymous rather
		// than 401-ing. Redis errors fail-open (convention 1) — IsJTIRevoked
		// logs and returns (false, err), so the credential is kept.
		if jti := claims.ID; jti != "" {
			if revoked, err := IsJTIRevoked(c.UserContext(), jti); err != nil {
				_ = err // logged inside IsJTIRevoked; fail-open per convention 1
			} else if revoked {
				return c.Next()
			}
		}

		c.Locals(LocalKeyUserID, claims.UserID)
		c.Locals(LocalKeyTeamID, claims.TeamID)
		if claims.Email != "" {
			c.Locals(LocalKeyEmail, claims.Email)
		}
		if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
			c.Locals(LocalKeyDPoPKeyThumbprint, claims.Confirmation.JKT)
		}
		// Mirror the impersonation-locals population done in RequireAuth so
		// downstream RequireWritable (when attached to an OptionalAuth route)
		// sees the read_only flag and gates mutations. An impersonated session
		// presenting an Authorization header on an OptionalAuth route must
		// still be blocked from writing — that's exactly the /db/new etc.
		// case test #5 in the brief exercises.
		if claims.ReadOnly {
			c.Locals(LocalKeyReadOnly, true)
		}
		if claims.ImpersonatedBy != "" {
			c.Locals(LocalKeyImpersonatedBy, claims.ImpersonatedBy)
		}
		return c.Next()
	}
}
