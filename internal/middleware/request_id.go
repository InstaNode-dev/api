package middleware

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// HeaderRequestID is the HTTP header name used to propagate a unique request identifier.
const HeaderRequestID = "X-Request-ID"

// requestIDCtxKey is the context key for the request ID stored in the Go context.
type requestIDCtxKey struct{}

// RequestID generates or propagates an X-Request-ID header on every request and response.
// If the incoming request already carries a valid UUID in X-Request-ID, that value is reused.
// The request ID is stored in:
//   - Fiber locals under the key "request_id" (for handlers)
//   - The Go context from c.Context() (for gRPC propagation via provisioner.ContextWithRequestID)
func RequestID() fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Get(HeaderRequestID)
		if id == "" {
			id = uuid.New().String()
		}
		c.Locals("request_id", id)
		c.Set(HeaderRequestID, id)
		// Store in the underlying Go context so it propagates into gRPC metadata.
		// Handlers retrieve it from Fiber locals; the provisioner client reads it
		// from the Go context via provisioner.ContextWithRequestID.
		c.SetUserContext(context.WithValue(c.UserContext(), requestIDCtxKey{}, id))
		return c.Next()
	}
}

// GetRequestID retrieves the request ID from Fiber locals.
func GetRequestID(c *fiber.Ctx) string {
	if id, ok := c.Locals("request_id").(string); ok {
		return id
	}
	return ""
}

// RequestIDFromContext extracts the request ID from a Go context.
// Returns empty string if not present.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDCtxKey{}).(string); ok {
		return id
	}
	return ""
}
