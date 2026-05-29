package handlers

// auth_returnto_authp0_test.go — regression tests for AUTH-016, AUTH-017
// shipped 2026-05-29 (the fail-closed return_to scheme allow-list on
// POST /auth/email/start).
//
// The AUTH-004 callback-doesn't-leak-JWT test lives in
// auth_callback_nojwt_authp0_test.go (handlers_test package) because it
// needs testhelpers.SetupTestDB, which imports the handlers package and
// would create a test-import cycle if used from inside `package handlers`.

import (
	"encoding/json"
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

// authReturnToApp wires JUST the magic-link Start route — the same shape
// as newMagicLinkApp but without depending on a live Redis (the bug we're
// testing fires BEFORE the rate-limit check).
func authReturnToApp(t *testing.T) (*fiber.App, *recordingMailer) {
	t.Helper()
	cfg := &config.Config{JWTSecret: logoutTestSecret}
	authH := NewAuthHandler(nil, cfg)
	mailer := &recordingMailer{}
	h := NewMagicLinkHandlerWithMailer(nil, cfg, mailer, authH)
	app := fiber.New(fiber.Config{
		// respondError returns the ErrResponseWritten sentinel; the
		// project's canonical error handler turns that into a no-op so
		// the already-written JSON envelope is what the client sees.
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
	app.Post("/auth/email/start", h.Start)
	return app, mailer
}

func postJSON(t *testing.T, app *fiber.App, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestAuthStart_RejectsJavascriptReturnTo — AUTH-016.
// Original exploit: {"email":"x@y.com","return_to":"javascript:alert(1)"} → 202.
// Fix: scheme allow-list = [https, http], javascript: rejected with 400 invalid_return_to.
func TestAuthStart_RejectsJavascriptReturnTo(t *testing.T) {
	app, mailer := authReturnToApp(t)

	resp := postJSON(t, app, "/auth/email/start",
		`{"email":"qa@example.com","return_to":"javascript:alert(1)"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"AUTH-016: javascript: scheme in return_to must be 400, not 202")

	var envelope struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.Equal(t, "invalid_return_to", envelope.Error)
	assert.Empty(t, mailer.calls, "no mail must be sent when return_to is hostile")
}

// TestAuthStart_RejectsDataReturnTo — AUTH-017.
func TestAuthStart_RejectsDataReturnTo(t *testing.T) {
	app, mailer := authReturnToApp(t)

	resp := postJSON(t, app, "/auth/email/start",
		`{"email":"qa@example.com","return_to":"data:text/html,<script>alert(1)</script>"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"AUTH-017: data: scheme in return_to must be 400, not 202")

	var envelope struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.Equal(t, "invalid_return_to", envelope.Error)
	assert.Empty(t, mailer.calls)
}

// TestAuthStart_AllowsValidHTTPS_LegitimateFlow — guardrail.
// Asserts the fail-closed gate doesn't break the legitimate dashboard
// flow that hands return_to=https://instanode.dev/.... Uses a malformed
// email so the request body fails BEFORE we hit the DB (which is nil in
// this fixture) — the assertion is that we get 400 invalid_email, NOT
// 400 invalid_return_to. That proves the return_to gate accepted the
// https URL.
func TestAuthStart_AllowsValidHTTPS_LegitimateFlow(t *testing.T) {
	app, _ := authReturnToApp(t)

	resp := postJSON(t, app, "/auth/email/start",
		`{"email":"not-an-email","return_to":"https://instanode.dev/login/callback"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var envelope struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	// The email gate (which runs AFTER the new return_to gate) is what
	// must fire. invalid_return_to firing would mean we rejected a
	// legitimate https URL — a regression on the legitimate UI flow.
	assert.Equal(t, "invalid_email", envelope.Error,
		"valid https return_to must NOT hit the new fail-closed gate")
}
