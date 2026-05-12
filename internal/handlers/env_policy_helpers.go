package handlers

// env_policy_helpers.go — Helpers wired into the env-policy middleware that
// need to reach into models / DB but can't live in the middleware package
// (which avoids a middleware→models import cycle, mirroring rbac.go).
//
// The middleware accepts a `func(c *fiber.Ctx) (string, error)` env-lookup
// callback (middleware.WithEnvLookup). For endpoints where the env is
// stored on a DB row rather than supplied as a request param, the lookup
// goes through one of the helpers in this file.

import (
	"database/sql"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/models"
)

// ResourceEnvByTokenForMiddleware reads the env stored on a resource row
// addressed by the URL :id param (a public token UUID). Returns the env on
// success or "" on any error — the env-policy middleware fails OPEN on
// lookup error so a malformed/non-existent :id falls through to the
// handler's own 400/404 instead of a confusing 403/env_policy_denied.
//
// Exported with the verbose suffix so its single intended caller (the
// router wiring) is unambiguous; this is not a general-purpose helper.
func ResourceEnvByTokenForMiddleware(c *fiber.Ctx, db *sql.DB) (string, error) {
	tokenStr := c.Params("id")
	token, err := uuid.Parse(tokenStr)
	if err != nil {
		return "", nil
	}
	r, err := models.GetResourceByToken(c.Context(), db, token)
	if err != nil {
		// Including ErrResourceNotFound — fail open so the handler returns
		// its own 404 (which contains a stable, agent-readable shape).
		return "", nil
	}
	return r.Env, nil
}
