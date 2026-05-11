package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

// ErrResponseWritten is the sentinel respondError returns to signal "I
// already wrote the response body — propagate me up but DO NOT let Fiber's
// generic ErrorHandler overwrite the response."
//
// Callers that do `return ..., respondError(...)` from a helper get a
// non-nil error and short-circuit correctly even when the underlying
// c.Status().JSON() returned nil (the normal success case for body write).
//
// The router and test ErrorHandlers both detect this sentinel and return
// nil without writing — preserving the 400/403/etc. response respondError
// already committed. See router/router.go and testhelpers/testhelpers.go.
var ErrResponseWritten = errors.New("response already written by respondError")

// respondError writes a structured JSON error and returns ErrResponseWritten.
//
// Always returns a non-nil error so multi-return helpers compose safely:
//
//	teamID, err := h.requireTeamMatch(c)
//	if err != nil { return err }
//
// The caller's `if err != nil` branch fires correctly even when the
// underlying response-write succeeded. Before this change, respondError
// returned c.Status().JSON()'s result (nil on success), so the caller's
// check was false and execution continued past the validation gate —
// producing 500s and silent provisioning of invalid input.
func respondError(c *fiber.Ctx, status int, code, message string) error {
	_ = c.Status(status).JSON(fiber.Map{
		"ok":      false,
		"error":   code,
		"message": message,
	})
	return ErrResponseWritten
}
