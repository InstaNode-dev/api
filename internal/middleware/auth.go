package middleware

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"instant.dev/internal/config"
)

const (
	// LocalKeyUserID is the fiber.Locals key for the authenticated user ID.
	LocalKeyUserID = "auth_user_id"
	// LocalKeyTeamID is the fiber.Locals key for the authenticated team ID.
	LocalKeyTeamID = "auth_team_id"
)

// sessionClaims mirrors the JWT payload issued by auth.go.
type sessionClaims struct {
	UserID string `json:"uid"`
	TeamID string `json:"tid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// Valid overrides RegisteredClaims.Valid to skip IssuedAt validation.
// iat-in-future errors cause spurious 401s when there is any sub-second clock
// skew between the token issuer and the API server. exp still enforces expiry.
func (c sessionClaims) Valid() error {
	c.RegisteredClaims.IssuedAt = nil
	return c.RegisteredClaims.Valid()
}

// RequireAuth validates the Authorization: Bearer {jwt} header.
// On success it stores user_id and team_id in fiber.Locals and calls Next.
// On failure it returns 401 { ok: false, error: "unauthorized" }.
func RequireAuth(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if len(header) < 8 || header[:7] != "Bearer " {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"ok":    false,
				"error": "unauthorized",
			})
		}
		tokenStr := header[7:]

		claims := &sessionClaims{}
		parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil || !parsed.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"ok":    false,
				"error": "unauthorized",
			})
		}

		if claims.UserID == "" || claims.TeamID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"ok":    false,
				"error": "unauthorized",
			})
		}

		c.Locals(LocalKeyUserID, claims.UserID)
		c.Locals(LocalKeyTeamID, claims.TeamID)
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

		c.Locals(LocalKeyUserID, claims.UserID)
		c.Locals(LocalKeyTeamID, claims.TeamID)
		return c.Next()
	}
}
