package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/metrics"
)

// Telemetry records HTTP request duration and error counts for every route.
// Must be registered early in the middleware chain (after RequestID, before handlers).
//
// Labels:
//   - method: HTTP verb (GET, POST, etc.)
//   - route:  Fiber route template, e.g. "/cache/new" (not the raw URL, no cardinality explosion)
//   - status_class: "2xx", "4xx", or "5xx"
func Telemetry() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Proceed through the handler chain.
		err := c.Next()

		dur := time.Since(start).Seconds()
		code := c.Response().StatusCode()
		sc := metrics.StatusClass(code)

		// Use the route template, not the raw URL.
		// Fiber sets Route() after routing is resolved.
		route := c.Route().Path
		if route == "" {
			route = "unknown"
		}
		// IMPORTANT: Fiber's c.Method() uses UnsafeString — it returns a string that
		// shares memory with fasthttp's internal request buffer. After the request
		// completes, that buffer may be returned to the pool and reused. If we pass the
		// unsafe string directly to prometheus as a label, the label value stored in the
		// registry can be corrupted at collection time (bytes overwritten by the next
		// request), causing "collected before with the same name and label values" errors.
		// Force a heap-allocated copy so the string outlives the request context.
		method := string([]byte(c.Method()))

		metrics.HTTPRequestDuration.WithLabelValues(method, route, sc).Observe(dur)

		if code >= 400 {
			metrics.HTTPErrors.WithLabelValues(method, route, sc).Inc()
		}

		return err
	}
}
