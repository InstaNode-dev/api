package middleware

import (
	"github.com/gofiber/fiber/v2"

	"instant.dev/common/logctx"
)

// LoggerContext copies the request_id (from RequestID middleware) and the
// authenticated team_id (from RequireAuth / OptionalAuth, when present)
// from Fiber locals onto the underlying Go context using the logctx
// helpers. Any slog call made with that context downstream — handler
// code, provider calls, gRPC metadata — gets trace_id and team_id
// stamped automatically by the logctx.Handler wrapper.
//
// Must be registered AFTER RequestID() so the request_id local exists,
// and is most useful AFTER auth (OptionalAuth / RequireAuth) so team_id
// is also populated. To keep wiring simple we register it once globally
// in router.New, immediately after RequestID(); team_id will be empty on
// pre-auth log lines (anonymous probes, /healthz, etc.) which is the
// correct behavior — the log field elides itself when empty.
func LoggerContext() fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()

		if id := GetRequestID(c); id != "" {
			ctx = logctx.WithTraceID(ctx, id)
		}
		if tid := GetTeamID(c); tid != "" {
			ctx = logctx.WithTeamID(ctx, tid)
		}

		c.SetUserContext(ctx)
		return c.Next()
	}
}
