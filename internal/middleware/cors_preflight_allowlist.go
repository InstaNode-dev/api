package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// cors_preflight_allowlist.go — close BUG-API-066 / BUG-API-067.
//
// Fiber's bundled CORS middleware (github.com/gofiber/fiber/v2/middleware/cors)
// sets Access-Control-Allow-Origin / -Methods / -Headers on the preflight
// response from its static Config, but does NOT cross-check the inbound
// Access-Control-Request-Method / Access-Control-Request-Headers against
// that allowlist. A browser (or a probing script) sending
//
//	OPTIONS /any-route
//	Origin: <legit>
//	Access-Control-Request-Method: TRACE
//	Access-Control-Request-Headers: Cookie
//
// still gets a 204 with Allow-Methods=GET,POST,...,OPTIONS even though
// TRACE and Cookie are absent from the allowlist. That is harmless on its
// own (a compliant browser would block the real request because TRACE
// isn't in the returned Allow-Methods), but it nudges security audits and
// vendor scanners to flag the API for "permissive preflight." It also
// teaches future maintainers the wrong model — that the preflight is a
// rubber stamp.
//
// PreflightAllowlist is a tiny pre-CORS gate. For OPTIONS requests carrying
// an Access-Control-Request-* header, it rejects (403) when:
//   - the requested method is not in the allowed-methods list
//   - any requested header is not in the allowed-headers list
//
// Same allowlist strings are passed in from router.go so the two stay in
// lockstep — no second source of truth to drift. Non-preflight OPTIONS
// (no Origin or no Access-Control-Request-Method) fall through unchanged.

// PreflightAllowlist returns a Fiber handler that validates CORS preflight
// requests against the allowed-methods and allowed-headers lists. Pass the
// same comma-separated strings used in the downstream fiberCORS config.
func PreflightAllowlist(allowMethods, allowHeaders string) fiber.Handler {
	methodSet := commaSet(allowMethods, true)  // methods are case-insensitive
	headerSet := commaSet(allowHeaders, false) // canonicalised lower-case

	return func(c *fiber.Ctx) error {
		if c.Method() != fiber.MethodOptions {
			return c.Next()
		}
		reqMethod := strings.TrimSpace(c.Get("Access-Control-Request-Method"))
		if reqMethod == "" {
			// Not a preflight (no AC-Request-Method) — let the CORS layer
			// or downstream router decide.
			return c.Next()
		}

		// 1. Reject methods outside the allowlist (e.g. TRACE).
		if _, ok := methodSet[strings.ToUpper(reqMethod)]; !ok {
			return c.SendStatus(fiber.StatusForbidden)
		}

		// 2. Reject headers outside the allowlist (e.g. Cookie, Authorization
		//    is fine because it's in the static config). The browser sends
		//    a comma-separated list in Access-Control-Request-Headers.
		reqHeaders := c.Get("Access-Control-Request-Headers")
		if reqHeaders != "" {
			for _, h := range strings.Split(reqHeaders, ",") {
				name := strings.ToLower(strings.TrimSpace(h))
				if name == "" {
					continue
				}
				if _, ok := headerSet[name]; !ok {
					return c.SendStatus(fiber.StatusForbidden)
				}
			}
		}
		return c.Next()
	}
}

// commaSet splits a comma-separated string into a set, trimming whitespace.
// When upper=true the keys are upper-cased; otherwise lower-cased.
func commaSet(raw string, upper bool) map[string]struct{} {
	out := make(map[string]struct{})
	for _, tok := range strings.Split(raw, ",") {
		t := strings.TrimSpace(tok)
		if t == "" {
			continue
		}
		if upper {
			t = strings.ToUpper(t)
		} else {
			t = strings.ToLower(t)
		}
		out[t] = struct{}{}
	}
	return out
}
