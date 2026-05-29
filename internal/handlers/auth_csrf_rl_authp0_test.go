package handlers

// auth_csrf_rl_authp0_test.go — regression tests for AUTH-163, AUTH-107,
// AUTH-097 shipped 2026-05-29.
//
// Lives in package handlers so it can use the same in-package
// recordingMailer / setupCoverageRedis fixtures established by
// magic_link_coverage_test.go and cli_auth_coverage_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

// csrfRLApp wires the magic-link Start route with an isolated Redis
// connection so the per-IP counter can be observed independently from
// other tests. setupCoverageRedis flushes-on-cleanup via DB-14 isolation.
func csrfRLApp(t *testing.T, rdb *redis.Client) (*fiber.App, *recordingMailer) {
	t.Helper()
	cfg := &config.Config{JWTSecret: logoutTestSecret}
	authH := NewAuthHandler(nil, cfg)
	mailer := &recordingMailer{}
	h := NewMagicLinkHandlerWithMailerAndRedis(nil, cfg, mailer, authH, rdb)
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
	app.Post("/auth/email/start", h.Start)
	return app, mailer
}

// flushPerIPRL clears the per-IP Redis budget so tests in the same
// package don't poison each other. Mirrors the cleanup the per-email
// limit relies on (setupCoverageRedis uses DB 14 which is otherwise
// untouched, but the magicLinkPerIPRLKeyPrefix is new and not auto-
// flushed by any existing helper — so we clear it explicitly).
func flushPerIPRL(t *testing.T, rdb *redis.Client) {
	t.Helper()
	ctx := context.Background()
	iter := rdb.Scan(ctx, 0, magicLinkPerIPRLKeyPrefix+":*", 1000).Iterator()
	for iter.Next(ctx) {
		_ = rdb.Del(ctx, iter.Val()).Err()
	}
}

// TestAuthEmailStart_RejectsFormUrlencoded — AUTH-163.
//
// Original exploit (QA confirmed):
//
//	POST /auth/email/start
//	Content-Type: application/x-www-form-urlencoded
//	email=qa@x.com
//	→ HTTP 202 + magic-link inserted in platform_db.
//
// Combined with no Origin enforcement this was a textbook CSRF: any
// malicious site could <form action="..."> to spam an arbitrary email
// with magic-links from the victim's IP.
//
// Fix: Content-Type must be application/json (charset suffix permitted).
// Form-encoded bodies are rejected with 400 invalid_content_type BEFORE
// the body is parsed or the DB is touched.
func TestAuthEmailStart_RejectsFormUrlencoded(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	defer flushPerIPRL(t, rdb)
	app, mailer := csrfRLApp(t, rdb)

	req := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader("email=qa%40example.com&return_to=https%3A%2F%2Finstanode.dev"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"AUTH-163: urlencoded bodies must be 400, not 202")
	var envelope struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.Equal(t, "invalid_content_type", envelope.Error)
	assert.Empty(t, mailer.calls, "no mail must be sent on the CSRF path")
}

// TestAuthEmailStart_AcceptsJSONWithCharset — guardrail.
// The legitimate dashboard flow sometimes sets
// Content-Type: application/json; charset=utf-8. The new gate must
// accept that — only the bare media type is checked.
func TestAuthEmailStart_AcceptsJSONWithCharset(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	defer flushPerIPRL(t, rdb)
	app, _ := csrfRLApp(t, rdb)

	req := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader(`{"email":"not-an-email"}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// We send an invalid email so we don't need a DB; the load-bearing
	// assertion is that the response is NOT invalid_content_type.
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var envelope struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.Equal(t, "invalid_email", envelope.Error,
		"application/json; charset=utf-8 must NOT trip the new content-type gate")
}

// TestAuthEmailStart_PerIPRateLimit — AUTH-097 / AUTH-107.
//
// The per-email-hash limit is bypassed by rotating the email. The new
// per-IP limit caps to magicLinkPerIPRateLimit calls per IP per window.
// The (limit+1)th request from the same IP must be silently absorbed.
//
// Two-layer assertion:
//
//  1. Function-level (checkPerIPRateLimit): exercise the counter
//     boundary directly so the cap value and Redis expiry semantics are
//     pinned regardless of handler wiring.
//
//  2. Handler-level (POST /auth/email/start): pre-populate the Redis
//     counter for the test's source IP (0.0.0.0 — fiber app.Test uses
//     this for in-process requests) to one over the cap, then hit the
//     handler with a valid Content-Type + valid-syntax email and assert
//     202 + no mailer call. This proves the gate is wired into Start.
func TestAuthEmailStart_PerIPRateLimit(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	defer flushPerIPRL(t, rdb)

	const probeIP = "203.0.113.99" // TEST-NET-3, RFC 5737.
	ctx := context.Background()

	// Layer 1: function-level boundary check.
	for i := 1; i <= magicLinkPerIPRateLimit; i++ {
		limited, err := checkPerIPRateLimit(ctx, rdb, probeIP)
		require.NoError(t, err, "call %d: Redis must be healthy", i)
		assert.False(t, limited, "call %d under the per-IP cap must NOT be limited", i)
	}
	limited, err := checkPerIPRateLimit(ctx, rdb, probeIP)
	require.NoError(t, err)
	assert.True(t, limited,
		"AUTH-097: the (magicLinkPerIPRateLimit+1)th call from the same IP must be limited")

	// Layer 2: handler integration. Fiber's app.Test connects from
	// 0.0.0.0 — pre-populate that key directly so the next handler
	// call hits the over-cap path WITHOUT us having to drive a full
	// magic-link flow with a wired DB.
	const fiberTestIP = "0.0.0.0"
	key := perIPRateLimitKey(fiberTestIP)
	require.NoError(t, rdb.Set(ctx, key, magicLinkPerIPRateLimit+1, magicLinkPerIPRateLimitWindow).Err(),
		"pre-populate the per-IP counter for the fiber-test source IP")

	app, mailer := csrfRLApp(t, rdb)
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start",
		strings.NewReader(`{"email":"survivor@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode,
		"AUTH-097: silent-absorb path returns 202 with no enumeration signal")
	assert.Empty(t, mailer.calls,
		"the limited call must NOT invoke the mailer")
}
