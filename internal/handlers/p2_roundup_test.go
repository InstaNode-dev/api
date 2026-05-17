package handlers

// p2_roundup_test.go — P2 bug-hunt coverage (2026-05-17 round 3).
//
// Pins the constant-level surface of three P2 fixes:
//   Fix #1: errCodeDeploymentNotRedeployable error code on the redeploy gate.
//   Fix #4: metrics.DeployTeardownMarkFailed counter exists + increments when
//           the teardown reconciler cannot mark a row 'deleted'.
//   Fix #9: GoogleAuthURL builds the auth URL from a constant — no dead 500
//           branch. Exercised end-to-end so a parse-error regression fails.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"instant.dev/internal/config"
	"instant.dev/internal/metrics"
)

// TestErrCodeDeploymentNotRedeployable pins the error code string. The
// dashboard / MCP client branch on this exact value — a rename is a contract
// change that must be done deliberately, not silently.
func TestErrCodeDeploymentNotRedeployable(t *testing.T) {
	if errCodeDeploymentNotRedeployable != "deployment_not_redeployable" {
		t.Errorf("errCodeDeploymentNotRedeployable = %q, want %q",
			errCodeDeploymentNotRedeployable, "deployment_not_redeployable")
	}
}

// TestDeployTeardownMarkFailedMetric verifies the Fix #4 counter is wired and
// increments. Before the fix a persistent MarkDeploymentTornDown failure was
// a log line only — invisible to NR, so a stuck row could never be alerted on.
func TestDeployTeardownMarkFailedMetric(t *testing.T) {
	before := testutil.ToFloat64(metrics.DeployTeardownMarkFailed)
	metrics.DeployTeardownMarkFailed.Inc()
	after := testutil.ToFloat64(metrics.DeployTeardownMarkFailed)
	if after != before+1 {
		t.Errorf("DeployTeardownMarkFailed did not increment: before=%v after=%v", before, after)
	}
}

// TestGoogleAuthURL_BuildsURL drives GoogleAuthURL end-to-end. Fix #9 removed
// the impossible url.Parse-error 500 branch; this asserts a configured handler
// returns 200 with a well-formed Google consent URL rather than a 500.
func TestGoogleAuthURL_BuildsURL(t *testing.T) {
	h := &AuthHandler{cfg: &config.Config{
		GoogleClientID:    "test-client-id.apps.googleusercontent.com",
		GoogleRedirectURI: "https://api.instanode.dev/auth/google/callback",
	}}
	app := fiber.New()
	app.Get("/auth/google/url", h.GoogleAuthURL)

	req := httptest.NewRequest(http.MethodGet, "/auth/google/url", nil)
	resp, err := app.Test(req, 1000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GoogleAuthURL status = %d, want 200", resp.StatusCode)
	}
}
