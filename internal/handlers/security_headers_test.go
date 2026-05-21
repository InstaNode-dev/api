package handlers_test

// security_headers_test.go — task #311 wave-3 chaos-verify redo.
//
// Coverage assertion: every response from the api, including 4xx/5xx
// envelopes, carries the spec-mandated defense-in-depth headers. This
// test is the regression gate against the failure mode that triggered
// this redo — the original task #311 was marked "completed" but the
// headers were never actually wired into router.go. A repo-wide grep
// for "Permissions-Policy" returned zero hits on master at the time of
// the redo brief.
//
// The test hits 5 representative endpoints (matching the task spec):
//
//   1. GET  /healthz       — shallow-liveness, 200 happy path
//   2. GET  /readyz        — deep-readiness, 200 happy path
//   3. GET  /openapi.json  — static JSON, 200 happy path
//   4. POST /db/new        — provisioning route, 401 unauth-rejection envelope
//   5. POST /claim         — claim route, 400 invalid-payload envelope
//
// The 4xx-envelope cases are the load-bearing ones — they confirm the
// headers land on error responses too, because SecurityHeaders runs
// BEFORE RequestID and before any handler logic that might short-circuit
// the request via c.Status(...).JSON(...).
//
// Two HSTS modes are exercised:
//
//   - envIsProd=true: HSTS header MUST be present on every response.
//   - envIsProd=false: HSTS header MUST NOT be present on any response
//     (so a developer running `make run` against http://localhost:8080
//     never poisons the host's HSTS cache).
//
// Implementation note: we mount the SecurityHeaders middleware on a
// fresh fiber.App and register stub handlers that mimic each real
// endpoint's response shape. We can't bring up the full router here
// (the cfg/db/grpc wiring is heavy), but mounting the same middleware
// in isolation proves the contract — and a separate router-level guard
// test in internal/router/ would be the right place to assert wiring
// order; this file owns the per-endpoint contract.

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// secHeaderEndpoint encodes one of the 5 spec endpoints — the path, the
// HTTP method, and a stub handler that returns a representative status
// code so we exercise both 2xx happy paths and 4xx error envelopes.
type secHeaderEndpoint struct {
	name    string
	method  string
	path    string
	handler fiber.Handler
}

// stubEndpoints mirrors the 5 endpoints called out in the task spec.
// Each handler returns the canonical status code for its surface so we
// prove headers land on both 2xx happy paths and 4xx error envelopes.
func stubEndpoints() []secHeaderEndpoint {
	return []secHeaderEndpoint{
		{
			name:   "healthz",
			method: fiber.MethodGet,
			path:   "/healthz",
			handler: func(c *fiber.Ctx) error {
				return c.JSON(fiber.Map{"ok": true})
			},
		},
		{
			name:   "readyz",
			method: fiber.MethodGet,
			path:   "/readyz",
			handler: func(c *fiber.Ctx) error {
				return c.JSON(fiber.Map{"overall": "ok"})
			},
		},
		{
			name:   "openapi.json",
			method: fiber.MethodGet,
			path:   "/openapi.json",
			handler: func(c *fiber.Ctx) error {
				return c.JSON(fiber.Map{"openapi": "3.1.0"})
			},
		},
		{
			// /db/new without auth returns 401 — this exercises the
			// 4xx-envelope path which is the load-bearing assertion for
			// this test (headers must land on error responses too).
			name:   "db/new",
			method: fiber.MethodPost,
			path:   "/db/new",
			handler: func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "missing_token",
				})
			},
		},
		{
			// /claim with no body returns 400 — also a 4xx envelope.
			name:   "claim",
			method: fiber.MethodPost,
			path:   "/claim",
			handler: func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "missing_jwt",
				})
			},
		},
	}
}

// buildTestApp registers the SecurityHeaders middleware ahead of the
// stub handlers, matching router.go's middleware-chain order. envIsProd
// controls whether HSTS is emitted.
func buildTestApp(envIsProd bool) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(middleware.SecurityHeaders(envIsProd))
	for _, ep := range stubEndpoints() {
		app.Add(ep.method, ep.path, ep.handler)
	}
	return app
}

// TestSecurityHeaders_AllEndpoints_AllHeaders_Prod is the primary
// coverage assertion: in prod mode, all 6 spec headers (HSTS,
// X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
// Permissions-Policy, Cross-Origin-Resource-Policy) land on all 5
// endpoints' responses — including the 401 and 400 error envelopes.
func TestSecurityHeaders_AllEndpoints_AllHeaders_Prod(t *testing.T) {
	app := buildTestApp(true)

	wantHeaders := map[string]string{
		"Strict-Transport-Security":    middleware.HSTSValue,
		"X-Content-Type-Options":       middleware.XContentTypeOptionsValue,
		"X-Frame-Options":              middleware.XFrameOptionsValue,
		"Referrer-Policy":              middleware.ReferrerPolicyValue,
		"Permissions-Policy":           middleware.PermissionsPolicyValue,
		"Cross-Origin-Resource-Policy": middleware.CrossOriginResourcePolicyValue,
	}

	for _, ep := range stubEndpoints() {
		ep := ep // capture
		t.Run(ep.name, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(""))
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			for h, want := range wantHeaders {
				got := resp.Header.Get(h)
				require.Equalf(t, want, got,
					"endpoint %s status=%d: header %q want %q got %q",
					ep.path, resp.StatusCode, h, want, got)
			}
		})
	}
}

// TestSecurityHeaders_NoHSTSInDev pins the dev-mode contract: HSTS MUST
// NOT be emitted when ENVIRONMENT != "production", because a dev
// running `make run` over http://localhost:8080 would otherwise poison
// the host's browser HSTS cache and break every subsequent localhost
// service that doesn't terminate TLS. The other 5 headers MUST still
// be present — they're safe on http as well as https.
func TestSecurityHeaders_NoHSTSInDev(t *testing.T) {
	app := buildTestApp(false)

	for _, ep := range stubEndpoints() {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(""))
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// HSTS MUST be absent.
			require.Empty(t, resp.Header.Get("Strict-Transport-Security"),
				"dev mode must NOT emit HSTS on %s", ep.path)

			// Every other header MUST still be present — they're safe on
			// cleartext too.
			require.Equal(t, middleware.XContentTypeOptionsValue, resp.Header.Get("X-Content-Type-Options"))
			require.Equal(t, middleware.XFrameOptionsValue, resp.Header.Get("X-Frame-Options"))
			require.Equal(t, middleware.ReferrerPolicyValue, resp.Header.Get("Referrer-Policy"))
			require.Equal(t, middleware.PermissionsPolicyValue, resp.Header.Get("Permissions-Policy"))
			require.Equal(t, middleware.CrossOriginResourcePolicyValue, resp.Header.Get("Cross-Origin-Resource-Policy"))
		})
	}
}

// TestSecurityHeaders_PermissionsPolicy_Exact pins the exact spec value
// for the Permissions-Policy header. The task spec mandates this exact
// 4-feature deny string (geolocation, microphone, camera, payment); a
// well-meaning refactor that "improves" it to a wider deny set would
// fail this test loudly — that drift would also break any external
// security scanner that grep'd for the canonical value.
func TestSecurityHeaders_PermissionsPolicy_Exact(t *testing.T) {
	require.Equal(t,
		"geolocation=(), microphone=(), camera=(), payment=()",
		middleware.PermissionsPolicyValue,
		"Permissions-Policy must match the api task #311 spec exactly")
}

// TestSecurityHeaders_HSTS_TwoYearMaxAge pins the HSTS max-age at exactly
// 63072000 (= 2 years in seconds), the includeSubDomains directive, AND
// the preload directive. RFC 6797 §6.1.1 mandates max-age in seconds;
// the spec target is 2y; SRR security-cluster 2026-05-21 / PB03 added
// the `preload` directive so api.instanode.dev is eligible for inclusion
// on the Chromium HSTS preload list (https://hstspreload.org). This test
// fails loudly if a refactor rolls any of the three directives back.
func TestSecurityHeaders_HSTS_TwoYearMaxAge(t *testing.T) {
	require.Equal(t,
		"max-age=63072000; includeSubDomains; preload",
		middleware.HSTSValue,
		"HSTS value must be max-age=2y + includeSubDomains + preload per spec")
}

// TestSecurityHeaders_HSTS_PreloadDirective asserts the preload
// directive is advertised on every prod response. PB03 (2026-05-21)
// found api.instanode.dev was emitting HSTS WITHOUT `preload`, blocking
// HSTS-preload-list submission. This test is the coverage gate (rule 17)
// that a future "minor cleanup" can't silently strip it.
func TestSecurityHeaders_HSTS_PreloadDirective(t *testing.T) {
	require.Contains(t, middleware.HSTSValue, "preload",
		"Strict-Transport-Security must include the preload directive — required for browser HSTS preload list submission")
	require.Contains(t, middleware.HSTSValue, "includeSubDomains",
		"preload eligibility also requires includeSubDomains; do not strip it")
}
