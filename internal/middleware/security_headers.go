package middleware

// security_headers.go — adds defense-in-depth response headers on every
// request handled by the API.
//
// Wired ahead of RequestID() in router.go so the headers land on every
// path that flows through Fiber, INCLUDING the cheap-path responses
// (livez, healthz, metrics, openapi.json, 404, 405) that the request-id
// middleware would otherwise tag — and the 4xx/5xx envelopes returned
// from auth/quota/validation rejections inside handler bodies. The
// headers are static — no per-request computation, no allocations — so
// the ordering cost is negligible.
//
// Headers set (spec source: api task #311 wave-3 chaos-verify redo):
//
//   - Strict-Transport-Security: max-age=63072000; includeSubDomains
//     (prod-only — gated by ENVIRONMENT=production). 2-year max-age,
//     includeSubDomains so *.api.instanode.dev is also covered. Local
//     dev MUST NOT advertise HSTS — a developer running `make run`
//     against `http://localhost:8080` should not poison the host's
//     browser HSTS cache and force every subsequent localhost service
//     onto https.
//
//   - X-Content-Type-Options: nosniff — disables MIME sniffing. The
//     api returns user-controlled bytes through webhook receive bodies
//     and deploy logs SSE; nosniff is a belt-and-suspenders against a
//     content-sniffing XSS that misinterprets JSON as HTML.
//
//   - X-Frame-Options: SAMEORIGIN — clickjacking defense. The api
//     serves no HTML in the happy path, but error pages and 404s
//     occasionally surface plain text the browser could render; pinning
//     SAMEORIGIN ensures no third-party origin can frame any API
//     response.
//
//   - Referrer-Policy: strict-origin-when-cross-origin — same-origin
//     requests keep the full Referer; cross-origin requests over https
//     send only the origin; cross-origin downgrades to http send
//     nothing. The magic-link callback redirects to the dashboard with
//     a token in the URL — strict-origin-when-cross-origin ensures the
//     URL token never leaks via Referer.
//
//   - Permissions-Policy — declines the powerful browser APIs called
//     out in the spec (geolocation, microphone, camera, payment) on
//     this origin. The api surface is JSON and SSE only; a misconfigured
//     proxy or CDN rewrite that points a browser at the api host has no
//     business reaching any of these features. Explicit empty allowlist
//     `feature=()` denies the feature for any caller including self.
//
//   - Cross-Origin-Resource-Policy: same-origin — blocks no-cors
//     loads of api responses from third-party origins. Defense against
//     speculative side-channel attacks (Spectre-class) that try to
//     pull cross-origin responses into the victim renderer process.
//
// CSP is deliberately NOT set here — the api serves no HTML, so a CSP
// would be meaningless. The dashboard host's CSP lives in instanode-web's
// nginx config.

import (
	"github.com/gofiber/fiber/v2"
)

// Exported header constants — referenced by handler/middleware tests and
// (eventually) by the OpenAPI response-headers documentation. Spec
// values match the api task #311 wave-3 chaos-verify redo.
const (
	// HSTSValue: 2-year max-age + includeSubDomains + preload.
	//
	// SRR security-cluster 2026-05-21 / PB03: added the `preload` directive
	// so api.instanode.dev is eligible for inclusion on the Chromium HSTS
	// preload list (https://hstspreload.org). Browser preload moves the
	// TLS-only guarantee from "after first successful HTTPS visit" to
	// "from the very first navigation", closing the bootstrap-MITM window
	// where a hostile network could downgrade the initial HTTP request.
	//
	// Preload is operationally a one-way door — removal from the list
	// can take 6+ months once Chrome ships the update — so the value is
	// only safe to advertise when ALL of the following are true:
	//   1. The apex domain (and every subdomain referenced via
	//      includeSubDomains) serves HTTPS, with a valid cert, full-time.
	//   2. No HTTP-only sibling service exists on any subdomain that a
	//      browser might try to load (e.g. a legacy `staging.` HTTP host).
	//   3. The deployment plan accepts the rollback latency.
	//
	// Local dev / docker-compose builds NEVER emit this header — see the
	// SecurityHeaders constructor's `envIsProd` gate below — so a developer
	// running `make run` against http://localhost:8080 cannot poison their
	// browser's HSTS cache and force every subsequent localhost service
	// onto https.
	HSTSValue = "max-age=63072000; includeSubDomains; preload"

	// PermissionsPolicyValue: the spec-mandated subset (geolocation,
	// microphone, camera, payment). The wider "deny everything" set the
	// previous iteration used was strictly safer but the canonical task
	// spec is this exact string — locking it in here so any future
	// drift fails a coverage test (TestSecurityHeaders_PermissionsPolicy_Exact).
	PermissionsPolicyValue = "geolocation=(), microphone=(), camera=(), payment=()"

	// ReferrerPolicyValue: same value every modern browser already
	// defaults to, but pinning it makes the contract auditable.
	ReferrerPolicyValue = "strict-origin-when-cross-origin"

	// XContentTypeOptionsValue: only one legal value; pinning it as a
	// constant so a refactor that "improves" the spelling fails the
	// coverage test.
	XContentTypeOptionsValue = "nosniff"

	// XFrameOptionsValue: SAMEORIGIN, NOT DENY — the dashboard occasionally
	// frames health checks/status pages from the same apex during incident
	// reviews. DENY would break that without adding any real defense
	// (frame-ancestors via CSP is the modern equivalent but the api
	// doesn't serve HTML).
	XFrameOptionsValue = "SAMEORIGIN"

	// CrossOriginResourcePolicyValue: same-origin — only same-origin
	// callers can fetch api responses. A third-party site that tries to
	// `<img src="https://api.instanode.dev/...">` will have the browser
	// reject the load.
	CrossOriginResourcePolicyValue = "same-origin"
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
	return func(c *fiber.Ctx) error {
		// Order matches the documented header list at the file head so an
		// auditor reading the response sees them in this canonical
		// sequence.
		if envIsProd {
			c.Set("Strict-Transport-Security", HSTSValue)
		}
		c.Set("X-Content-Type-Options", XContentTypeOptionsValue)
		c.Set("X-Frame-Options", XFrameOptionsValue)
		c.Set("Referrer-Policy", ReferrerPolicyValue)
		c.Set("Permissions-Policy", PermissionsPolicyValue)
		c.Set("Cross-Origin-Resource-Policy", CrossOriginResourcePolicyValue)
		return c.Next()
	}
}
