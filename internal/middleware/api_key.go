package middleware

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/models"
)

// LocalKeyAPIKey marks requests authenticated via Personal Access Token rather
// than session JWT. Handlers can branch on this for stricter scope checks.
const LocalKeyAPIKey = "auth_api_key"

// LocalKeyAPIKeyScopes carries the scopes granted to the PAT so handlers can
// gate fine-grained operations (e.g., admin actions require "admin" scope).
const LocalKeyAPIKeyScopes = "auth_api_key_scopes"

// apiKeyDB is the platform DB handle used by the PAT branch of RequireAuth.
// Set via SetAPIKeyDB at startup. nil → PATs are rejected silently.
var (
	apiKeyDBMu sync.RWMutex
	apiKeyDB   *sql.DB
)

// SetAPIKeyDB registers the DB handle for PAT lookup.
func SetAPIKeyDB(db *sql.DB) {
	apiKeyDBMu.Lock()
	defer apiKeyDBMu.Unlock()
	apiKeyDB = db
}

func getAPIKeyDB() *sql.DB {
	apiKeyDBMu.RLock()
	defer apiKeyDBMu.RUnlock()
	return apiKeyDB
}

// IsAPIKey reports whether the bearer token shape matches a PAT prefix.
// Cheap pattern check, never compares secrets.
func IsAPIKey(token string) bool {
	return strings.HasPrefix(token, models.APIKeyPrefix)
}

// AuthenticateAPIKey looks up the PAT by SHA-256 and populates Fiber locals
// with team_id, user_id (creator), api_key id, and scopes. Returns a
// boolean (true = authenticated, false = invalid/revoked) and the error
// from the lookup if any (errors are logged but not surfaced to clients to
// avoid leaking key existence).
func AuthenticateAPIKey(c *fiber.Ctx, plaintext string) (bool, error) {
	db := getAPIKeyDB()
	if db == nil {
		return false, errors.New("api_key db not initialised")
	}
	hash := models.HashAPIKey(plaintext)
	ctx, cancel := context.WithTimeout(c.UserContext(), 1500*time.Millisecond)
	defer cancel()
	key, err := models.GetAPIKeyByHash(ctx, db, hash)
	if err != nil {
		if errors.Is(err, models.ErrAPIKeyNotFound) {
			return false, nil
		}
		slog.Warn("api_key.lookup_failed", "error", err)
		return false, err
	}

	c.Locals(LocalKeyTeamID, key.TeamID.String())
	if key.CreatedBy.Valid {
		c.Locals(LocalKeyUserID, key.CreatedBy.UUID.String())
	}
	c.Locals(LocalKeyAPIKey, key.ID.String())
	c.Locals(LocalKeyAPIKeyScopes, key.Scopes)

	// Best-effort touch — never block the request.
	go func(id string) {
		bgCtx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
		defer cancel()
		if err := models.TouchAPIKey(bgCtx, db, key.ID); err != nil {
			slog.Debug("api_key.touch_failed", "error", err, "id", id)
		}
	}(key.ID.String())

	return true, nil
}

// GetAPIKeyScopes returns the scopes attached by AuthenticateAPIKey, or nil
// when the request was authenticated via JWT (not a PAT).
func GetAPIKeyScopes(c *fiber.Ctx) []string {
	if v, ok := c.Locals(LocalKeyAPIKeyScopes).([]string); ok {
		return v
	}
	return nil
}

// IsAuthedViaAPIKey reports whether the request was authenticated via a PAT.
func IsAuthedViaAPIKey(c *fiber.Ctx) bool {
	v, ok := c.Locals(LocalKeyAPIKey).(string)
	return ok && v != ""
}
