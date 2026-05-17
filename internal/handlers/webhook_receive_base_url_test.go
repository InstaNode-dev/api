package handlers

// webhook_receive_base_url_test.go — P2 bug-hunt coverage (2026-05-17 round 3).
//
// Fix #7: the webhook receive_url is encrypted + persisted, so its base host
// MUST NOT come from the client-controllable Host / X-Forwarded-* headers.
// webhookReceiveBaseURL resolves the base from server config only —
// API_PUBLIC_URL when set, the compiled-in public base in production, and
// only in non-production does it fall back to the request host for local dev.
//
// Internal-package test so it can call the unexported helper directly.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/config"
	"instant.dev/internal/urls"
)

// callWebhookReceiveBaseURL spins up a one-route Fiber app, drives a request
// through it with the given Host header, and returns whatever
// webhookReceiveBaseURL produced for that request context.
func callWebhookReceiveBaseURL(t *testing.T, cfg *config.Config, host string) string {
	t.Helper()
	h := &WebhookHandler{cfg: cfg}
	var got string
	app := fiber.New()
	app.Get("/_t", func(c *fiber.Ctx) error {
		got = h.webhookReceiveBaseURL(c)
		return c.SendStatus(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/_t", nil)
	req.Host = host
	resp, err := app.Test(req, 1000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	_ = resp.Body.Close()
	return got
}

func TestWebhookReceiveBaseURL(t *testing.T) {
	const attackerHost = "attacker.evil.test"

	t.Run("production never trusts the client Host header", func(t *testing.T) {
		cfg := &config.Config{Environment: "production"}
		got := callWebhookReceiveBaseURL(t, cfg, attackerHost)
		if got == "http://"+attackerHost || got == "https://"+attackerHost {
			t.Fatalf("receive base leaked client Host header: %q", got)
		}
		if got != urls.PublicAPIBase {
			t.Errorf("production base = %q, want compiled-in %q", got, urls.PublicAPIBase)
		}
	})

	t.Run("API_PUBLIC_URL wins over the client Host header", func(t *testing.T) {
		cfg := &config.Config{Environment: "production", APIPublicURL: "https://api.instanode.dev"}
		got := callWebhookReceiveBaseURL(t, cfg, attackerHost)
		if got != "https://api.instanode.dev" {
			t.Errorf("base = %q, want API_PUBLIC_URL value", got)
		}
	})

	t.Run("dev falls back to the request host for local dev", func(t *testing.T) {
		cfg := &config.Config{Environment: "development"}
		got := callWebhookReceiveBaseURL(t, cfg, "localhost:8080")
		// c.BaseURL() yields scheme://host — the host portion must be the
		// dev request host so local webhook receivers stay reachable.
		if got == urls.PublicAPIBase {
			t.Errorf("dev base = %q, expected the request host, not the prod default", got)
		}
	})
}
