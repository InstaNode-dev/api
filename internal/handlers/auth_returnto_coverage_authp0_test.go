package handlers

// auth_returnto_coverage_authp0_test.go — patch-coverage backfill for
// the AUTH-016 / AUTH-017 / AUTH-004 helpers introduced in PR #176 and
// the same-shaped fail-closed gates added on GitHubStart + GoogleStart.
//
// Lives in `package handlers` so it can exercise the unexported helpers
// (returnToSchemeIsAllowed, appendSignedInMarker) directly. The
// scheme-rejection contract is also exercised end-to-end via the
// GitHubStart / GoogleStart handlers so the call-site branch — not just
// the helper — is covered.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

// helper — build a minimal OAuth-Start app with the canonical error
// handler so respondError's sentinel is unwrapped to a plain JSON body.
func returnToCoverageApp(t *testing.T) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:          "returnto-coverage-secret-32-bytes-minimum-len",
		GitHubClientID:     "gh-client",
		GitHubClientSecret: "gh-secret",
		GoogleClientID:     "g-client",
		GoogleClientSecret: "g-secret",
	}
	authH := NewAuthHandler(nil, cfg)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Get("/auth/github/start", authH.GitHubStart)
	app.Get("/auth/google/start", authH.GoogleStart)
	return app
}

// TestReturnToSchemeIsAllowed_Branches covers every arm of
// returnToSchemeIsAllowed:
//   - url.Parse error → false (line 292)
//   - https → true
//   - http → returnToAllowsLocalhost (line 302)
//   - any other scheme → false (default)
func TestReturnToSchemeIsAllowed_Branches(t *testing.T) {
	// url.Parse error path. A control character in the URL forces
	// url.Parse to fail.
	assert.False(t, returnToSchemeIsAllowed("ht\x7ftp://x"),
		"unparseable URL must fall through to false (line 292)")

	assert.True(t, returnToSchemeIsAllowed("https://instanode.dev/x"))
	assert.False(t, returnToSchemeIsAllowed("javascript:alert(1)"))
	assert.False(t, returnToSchemeIsAllowed("data:text/html,x"))

	// http is gated by returnToAllowsLocalhost — assert both arms
	// without touching package-global state for any other test.
	prev := returnToAllowsLocalhost
	defer func() { returnToAllowsLocalhost = prev }()
	returnToAllowsLocalhost = true
	assert.True(t, returnToSchemeIsAllowed("http://localhost:5173"),
		"http must be allowed when localhost flag is on (line 302 true arm)")
	returnToAllowsLocalhost = false
	assert.False(t, returnToSchemeIsAllowed("http://localhost:5173"),
		"http must be rejected when localhost flag is off (line 302 false arm)")
}

// TestAppendSignedInMarker_MalformedFallback covers the url.Parse error
// branch of appendSignedInMarker (lines 168-169) — a malformed returnTo
// must fall back to defaultReturnTo + "?signed_in=1".
func TestAppendSignedInMarker_MalformedFallback(t *testing.T) {
	got := appendSignedInMarker("%%%not-a-url")
	assert.True(t, strings.HasPrefix(got, defaultReturnTo),
		"malformed returnTo must collapse to defaultReturnTo, got %q", got)
	assert.Contains(t, got, "signed_in=1",
		"fallback must still carry the SPA signed_in marker")
}

// TestAppendSignedInMarker_StripsSessionToken — defence-in-depth: even
// if upstream code path ever passed a returnTo that already carries
// ?session_token=, the marker helper strips it. This is asserted both
// because it's documented in the helper's comment AND because the
// stripping is what makes the helper safe to call on arbitrary returnTo
// values without regressing AUTH-004.
func TestAppendSignedInMarker_StripsSessionToken(t *testing.T) {
	got := appendSignedInMarker("https://instanode.dev/x?session_token=leaked")
	assert.NotContains(t, got, "session_token",
		"appendSignedInMarker must strip any leaked session_token")
	assert.Contains(t, got, "signed_in=1")
}

// TestGitHubStart_RejectsJavascriptReturnTo covers the AUTH-016 fail-closed
// gate on the GitHub OAuth start (lines 1143-1145). Mirrors the magic-link
// regression test in auth_returnto_authp0_test.go.
func TestGitHubStart_RejectsJavascriptReturnTo(t *testing.T) {
	app := returnToCoverageApp(t)
	req := httptest.NewRequest(http.MethodGet,
		"/auth/github/start?return_to=javascript:alert(1)", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"AUTH-016 (GitHub): javascript: in return_to must 400")
	body, _ := readBodyAuthP0(resp)
	assert.Contains(t, body, "invalid_return_to")
}

// TestGoogleStart_RejectsJavascriptReturnTo covers the same fail-closed
// gate on the Google OAuth start (lines 1241-1243). Same shape, same
// rationale.
func TestGoogleStart_RejectsJavascriptReturnTo(t *testing.T) {
	app := returnToCoverageApp(t)
	req := httptest.NewRequest(http.MethodGet,
		"/auth/google/start?return_to=javascript:alert(1)", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"AUTH-016 (Google): javascript: in return_to must 400")
	body, _ := readBodyAuthP0(resp)
	assert.Contains(t, body, "invalid_return_to")
}

// TestScopesFieldKind_NonJSONBodyEarlyReturn covers the AUTH-164 fast
// path in scopesFieldKind (api_keys.go:275-276): a body that doesn't
// start with '{' is treated as "not present" so the canonical
// BodyParser path produces the existing invalid_body 400 rather than
// the new invalid_scopes envelope.
func TestScopesFieldKind_NonJSONBodyEarlyReturn(t *testing.T) {
	for _, body := range []string{"", "   ", "not-json", "[\"scopes\"]"} {
		present, isNull := scopesFieldKind([]byte(body))
		assert.False(t, present, "non-object body %q must report present=false", body)
		assert.False(t, isNull, "non-object body %q must report isNull=false", body)
	}
}

// readBodyAuthP0 is a tiny string-body helper that doesn't fight with
// io.ReadAll's error-return signature in assertions.
func readBodyAuthP0(resp *http.Response) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			if err.Error() == "EOF" {
				return sb.String(), nil
			}
			return sb.String(), err
		}
	}
}
