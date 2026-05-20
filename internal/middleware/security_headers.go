package middleware

// security_headers.go — adds defense-in-depth response headers on every
// request handled by the API.
//
// Wired ahead of RequestID() in router.go so the headers land on every
// path that flows through Fiber, INCLUDING the cheap-path responses
// (livez, healthz, metrics, openapi.json, 404, 405) that the request-id
// middleware would otherwise tag. The headers are static — no per-request
// computation, no allocations — so the ordering cost is negligible.
//
// Headers set:
//
//   - Strict-Transport-Security (HSTS, prod only) — instructs every
//     compliant browser to upgrade `http://api.instanode.dev` to https
//     for the next 6 months WITHOUT touching the cleartext socket. Set
//     only when the binary booted with ENVIRONMENT=production so local
//     dev (http://localhost:8080) doesn't poison the host's HSTS cache
//     and force browsers to refuse cleartext loopback. `includeSubDomains`
//     extends the directive to *.api.instanode.dev (we own the apex too).
//     `preload` is NOT set today — opting into the chromium preload list
//     is a one-way door and operator-level decision.
//
//   - Permissions-Policy — declines every powerful browser API on this
//     origin. The API surface is JSON and SSE only; the dashboard origin
//     is a different host. A misconfigured proxy or a CDN rewrite that
//     accidentally points a browser at the api host has no business
//     reaching microphone/camera/geolocation/etc. Explicit "(),..." with
//     empty allowlist denies the feature for any caller.
//
//   - Referrer-Policy: strict-origin-when-cross-origin — what every
//     modern browser already defaults to, but pinning it makes the
//     contract auditable. Same-origin requests keep the full Referer;
//     cross-origin requests over https send only the origin; cross-origin
//     downgrades to http send nothing. The API doesn't issue redirects
//     to third-party hosts in the happy path, but the magic-link callback
//     does redirect to the dashboard — strict-origin-when-cross-origin
//     ensures the URL token never leaks via Referer.
//
//   - X-Content-Type-Options: nosniff — disables MIME sniffing. Some
//     browsers will guess "this looks like HTML even though the server
//     said application/json" and execute scripts. Since this API returns
//     user-controlled bytes in some surfaces (webhook receive bodies,
//     deploy logs SSE), nosniff is a cheap belt-and-suspenders against
//     a content-sniffing XSS.
//
// CSP is deliberately NOT set here — the API does not serve HTML on any
// route, so a CSP would be meaningless. The dashboard host's CSP lives
// in instanode-web's nginx config.
//
// X-Frame-Options is also NOT set — there is no HTML to frame.

import (
	"github.com/gofiber/fiber/v2"
)

// SecurityHeaders returns a Fiber middleware that sets the static
// security response headers documented above. envIsProd controls whether
// the HSTS header is emitted (prod-only — see file-level doc comment for
// why local dev/HTTP must not advertise HSTS).
//
// Wire ahead of RequestID() in router.go so the headers land on every
// path Fiber serves, including livez/healthz/metrics/openapi/4xx-default
// surfaces that the canonical request-id middleware also covers.
func SecurityHeaders(envIsProd bool) fiber.Handler {
	// Pre-compute the Permissions-Policy header string — it is static and
	// the same value on every request. Each feature is set to "()" (empty
	// allowlist) which denies the feature for any origin including self.
	//
	// The feature list is the canonical set of "powerful APIs" per
	// W3C Permissions Policy spec; we deny every one because the API
	// origin never legitimately needs any of them. Adding a new browser
	// feature to the spec doesn't auto-grant it on this origin — the
	// browser falls back to its own default, which is itself "deny" for
	// every feature that requires user activation today.
	const permissionsPolicy = "accelerometer=(),autoplay=(),camera=(),clipboard-read=(),clipboard-write=(),display-capture=(),encrypted-media=(),fullscreen=(),geolocation=(),gyroscope=(),hid=(),idle-detection=(),magnetometer=(),microphone=(),midi=(),payment=(),publickey-credentials-get=(),screen-wake-lock=(),serial=(),storage-access=(),usb=(),web-share=(),xr-spatial-tracking=()"

	// HSTS pinning: 6 months. Long enough that a transient mis-deploy
	// can't roll the directive back, short enough that an operator
	// recovers in a year if a domain migration ever happens.
	const hstsValue = "max-age=15552000; includeSubDomains"

	return func(c *fiber.Ctx) error {
		// Order matches the documented header list at the file head so an
		// auditor reading the response sees them in this canonical
		// sequence.
		if envIsProd {
			c.Set("Strict-Transport-Security", hstsValue)
		}
		c.Set("Permissions-Policy", permissionsPolicy)
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Set("X-Content-Type-Options", "nosniff")
		return c.Next()
	}
}
