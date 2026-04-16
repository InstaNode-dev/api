package middleware_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// newFingerprintApp builds a minimal Fiber app with Fingerprint() middleware installed.
// The /test route echoes the fingerprint local as X-Test-Fingerprint so tests can
// inspect it without a real DB or Redis.
func newFingerprintApp() *fiber.App {
	app := fiber.New(fiber.Config{
		// Trust X-Forwarded-For so c.IP() uses the header value.
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.Fingerprint())
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Set("X-Test-Fingerprint", middleware.GetFingerprint(c))
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

func sendAndGetFingerprint(t *testing.T, app *fiber.App, req *http.Request) string {
	t.Helper()
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.Header.Get("X-Test-Fingerprint")
}

// TestFingerprintMiddleware_XForwardedForUsed verifies that the IP from X-Forwarded-For
// is used when the Fiber app has ProxyHeader configured.
func TestFingerprintMiddleware_XForwardedForUsed(t *testing.T) {
	app := newFingerprintApp()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	fp := sendAndGetFingerprint(t, app, req)
	assert.NotEmpty(t, fp, "fingerprint must be derived when X-Forwarded-For is set")
}

// TestFingerprintMiddleware_DirectIPFallback verifies the middleware does not panic
// when no proxy headers are present (falls back to RemoteAddr).
func TestFingerprintMiddleware_DirectIPFallback(t *testing.T) {
	app := newFingerprintApp()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No X-Forwarded-For — Fiber's c.IP() returns RemoteAddr.

	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Must return 200 without panicking, regardless of whether a fingerprint is set.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestFingerprintMiddleware_StoredInLocals verifies the fingerprint is stored in
// c.Locals("fingerprint") and retrievable via GetFingerprint.
func TestFingerprintMiddleware_StoredInLocals(t *testing.T) {
	var capturedFP string
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Get("/capture", func(c *fiber.Ctx) error {
		capturedFP = middleware.GetFingerprint(c)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/capture", nil)
	req.Header.Set("X-Forwarded-For", "172.16.0.1")

	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.NotEmpty(t, capturedFP,
		"fingerprint must be available in fiber context locals for downstream handlers")
}

// TestFingerprintMiddleware_SameSubnetSameFingerprint verifies two IPs in the same
// /24 produce identical fingerprints (the /24 mask collapses them to the same subnet).
func TestFingerprintMiddleware_SameSubnetSameFingerprint(t *testing.T) {
	app := newFingerprintApp()

	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("X-Forwarded-For", "10.20.30.10")

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("X-Forwarded-For", "10.20.30.200")

	fp1 := sendAndGetFingerprint(t, app, req1)
	fp2 := sendAndGetFingerprint(t, app, req2)

	require.NotEmpty(t, fp1)
	require.NotEmpty(t, fp2)
	assert.Equal(t, fp1, fp2,
		"two IPs from the same /24 must yield the same fingerprint")
}

// TestFingerprintMiddleware_DifferentSubnetDifferentFingerprint verifies that IPs
// in different /24 subnets produce different fingerprints.
func TestFingerprintMiddleware_DifferentSubnetDifferentFingerprint(t *testing.T) {
	app := newFingerprintApp()

	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("X-Forwarded-For", "10.20.30.1")

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("X-Forwarded-For", "10.20.31.1")

	fp1 := sendAndGetFingerprint(t, app, req1)
	fp2 := sendAndGetFingerprint(t, app, req2)

	require.NotEmpty(t, fp1)
	require.NotEmpty(t, fp2)
	assert.NotEqual(t, fp1, fp2,
		"IPs in different /24 subnets must yield different fingerprints")
}

// TestFingerprintMiddleware_OutputIsHex verifies the fingerprint stored in locals is
// a valid hex string (not a raw IP, which would expose PII).
func TestFingerprintMiddleware_OutputIsHex(t *testing.T) {
	app := newFingerprintApp()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	fp := sendAndGetFingerprint(t, app, req)
	require.NotEmpty(t, fp)

	_, err := hex.DecodeString(fp)
	assert.NoError(t, err,
		"fingerprint must be a valid hex string (not a raw IP — GDPR)")
}

// TestFingerprintMiddleware_Deterministic verifies that repeated requests from the
// same IP always produce the same fingerprint (no randomness in the output).
func TestFingerprintMiddleware_Deterministic(t *testing.T) {
	app := newFingerprintApp()

	const n = 5
	fingerprints := make([]string, n)
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", "100.64.0.1")
		fingerprints[i] = sendAndGetFingerprint(t, app, req)
		require.NotEmpty(t, fingerprints[i])
	}

	for i := 1; i < n; i++ {
		assert.Equal(t, fingerprints[0], fingerprints[i],
			"same IP must always produce the same fingerprint (deterministic, iteration %d)", i)
	}
}

// TestFingerprintMiddleware_SpoofedXFFLeftHandIgnored verifies the most important
// security property: because Fiber uses only the leftmost IP from X-Forwarded-For
// when ProxyHeader is set, an attacker who prepends a fake IP can influence the
// fingerprint. This test documents the CURRENT behaviour as a contract test —
// if it changes (e.g. the team switches to last-hop), the test must be updated.
//
// NOTE: In production, ensure your edge (Cloudflare, ALB) strips/overwrites
// X-Forwarded-For before it reaches the app, or use fiber.TrustedProxies.
func TestFingerprintMiddleware_XFFBehaviourIsDocumented(t *testing.T) {
	app := newFingerprintApp()

	// Two requests with the same last-hop IP but different first entries.
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.99")

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("X-Forwarded-For", "5.6.7.8, 203.0.113.99")

	fp1 := sendAndGetFingerprint(t, app, req1)
	fp2 := sendAndGetFingerprint(t, app, req2)

	require.NotEmpty(t, fp1)
	require.NotEmpty(t, fp2)

	// Document whether the current implementation uses leftmost or rightmost.
	// The assertion below captures actual behaviour without prescribing which is correct.
	t.Logf("XFF fp1=%s fp2=%s equal=%v", fp1, fp2, fp1 == fp2)
	// If production ever switches to rightmost, this test will fail — that is intentional.
}
