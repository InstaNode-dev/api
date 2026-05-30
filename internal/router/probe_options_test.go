package router

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// TestProbeOptionsHandlerShape pins the exact wire shape returned by
// probeOptionsHandler — 204 No Content, an `Allow` header carrying
// the allow set passed in, and an empty body. BUG-API-024 / BUG-API-025
// (QA 2026-05-29): a bare `OPTIONS /<probe>` from a curl /
// uptime-checker / SDK probe (no `Origin` header → fiberCORS skips)
// used to fall through to Fiber's "no route for verb" path and return
// 405. The handler closes that gap on the shallow probe surfaces
// (/livez, /healthz, /readyz, /openapi.json).
func TestProbeOptionsHandlerShape(t *testing.T) {
	app := fiber.New()
	app.Options("/probe", probeOptionsHandler("GET, HEAD, OPTIONS"))

	resp, err := app.Test(httptest.NewRequest("OPTIONS", "/probe", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNoContent, resp.StatusCode,
		"BUG-API-024/025: bare OPTIONS without Origin must be 204, not 405")
	require.Equal(t, "GET, HEAD, OPTIONS", resp.Header.Get("Allow"),
		"BUG-API-024/025: Allow header must mirror the handler argument so HTTP-conformant clients see the same allow set whether they read it from a 405 envelope or a 204 OPTIONS body")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "", string(body),
		"BUG-API-024/025: 204 body must be empty per RFC 7231 §6.3.5")
}

// TestProbeOptionsHandlerCoversAllShallowProbes is the registry-style
// guarantee (rule 18 — "registry-iterating regression tests, not
// hand-typed lists"). Every shallow probe surface registered in
// router.go MUST have an OPTIONS handler that returns 204 — adding a
// new probe surface without the matching OPTIONS shim is exactly the
// bug class BUG-API-024 / BUG-API-025 logged.
//
// The list below is the registry of shallow probe paths. It is kept
// in this test file so a future contributor adding a new probe MUST
// either add it here (and wire the OPTIONS handler) or document the
// exemption inline.
func TestProbeOptionsHandlerCoversAllShallowProbes(t *testing.T) {
	app := fiber.New()
	shallowProbes := []string{
		"/livez",
		"/healthz",
		"/readyz",
		"/openapi.json",
	}
	for _, p := range shallowProbes {
		app.Options(p, probeOptionsHandler("GET, HEAD, OPTIONS"))
	}

	for _, p := range shallowProbes {
		resp, err := app.Test(httptest.NewRequest("OPTIONS", p, nil))
		require.NoError(t, err, "OPTIONS %s should not error", p)
		require.Equal(t, fiber.StatusNoContent, resp.StatusCode,
			"BUG-API-024/025: OPTIONS %s must return 204 (got %d)", p, resp.StatusCode)
		allow := resp.Header.Get("Allow")
		require.Contains(t, strings.Split(allow, ", "), "OPTIONS",
			"BUG-API-024/025: Allow header on OPTIONS %s must list OPTIONS itself; got %q", p, allow)
		require.Contains(t, strings.Split(allow, ", "), "GET",
			"BUG-API-024/025: Allow header on OPTIONS %s must list GET; got %q", p, allow)
	}
}
