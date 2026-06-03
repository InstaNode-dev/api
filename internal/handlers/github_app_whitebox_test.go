package handlers

// github_app_whitebox_test.go — branch coverage for github_app.go arms that the
// routed integration tests can't reach: the no-team guard (RequireAuth normally
// guarantees a team), the unreachable state-sign error (HS256 never fails — via
// the signInstallStateFn seam), and the Callback disabled-feature early return.
// No DB: these arms return before any DB access.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

func ghAppTestHandler(enabled bool, slug string) *GitHubAppHandler {
	return NewGitHubAppHandler(nil, &config.Config{
		JWTSecret:        "whitebox-secret-aaaaaaaaaaaaaaaaaaaa",
		GitHubAppEnabled: enabled,
		GitHubAppSlug:    slug,
		DashboardBaseURL: "http://localhost:5173",
	}, nil)
}

// ghAppFiberApp builds a fiber app whose ErrorHandler swallows respondError's
// ErrResponseWritten sentinel (mirrors the production/testhelpers router), so a
// handler that already wrote its status isn't overwritten with a 500.
func ghAppFiberApp() *fiber.App {
	return fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
}

// Install with no team in context (no RequireAuth in front) → 401.
func TestGitHubAppInstall_NoTeam_WhiteBox(t *testing.T) {
	h := ghAppTestHandler(true, "instanode")
	app := ghAppFiberApp()
	app.Get("/install", h.Install) // deliberately no RequireAuth / no team locals
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/install", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no team must 401, got %d", resp.StatusCode)
	}
}

// Force the (otherwise unreachable) state-sign error via the seam → 503.
func TestGitHubAppInstall_SignError_WhiteBox(t *testing.T) {
	orig := signInstallStateFn
	signInstallStateFn = func(string, string, time.Time) (string, error) {
		return "", errors.New("forced sign failure")
	}
	defer func() { signInstallStateFn = orig }()

	h := ghAppTestHandler(true, "instanode")
	app := ghAppFiberApp()
	// Inject a team so we pass the auth guard and reach the sign step.
	app.Get("/install", func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, "11111111-1111-1111-1111-111111111111")
		return h.Install(c)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/install", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("sign failure must 503, got %d", resp.StatusCode)
	}
}

// Callback with the feature flag OFF → 501 (the disabled early-return).
func TestGitHubAppCallback_Disabled_WhiteBox(t *testing.T) {
	h := ghAppTestHandler(false, "")
	app := ghAppFiberApp()
	app.Get("/cb", h.Callback)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/cb?installation_id=1&state=x", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("callback with feature off must 501, got %d", resp.StatusCode)
	}
}
