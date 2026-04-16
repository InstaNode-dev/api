package handlers

import "github.com/gofiber/fiber/v2"

// respondError returns a structured JSON error response.
func respondError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"ok":      false,
		"error":   code,
		"message": message,
	})
}
