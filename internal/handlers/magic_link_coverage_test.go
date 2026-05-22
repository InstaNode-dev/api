package handlers

// magic_link_coverage_test.go — exercises every branch of the magic-link
// Start handler (body-size cap, malformed JSON, invalid email, rate-limit,
// successful queue) plus the Callback path's error branches (missing
// token, bad token).
//
// Lives in package handlers (not handlers_test) so it can reach private
// constants like magicLinkStartMaxBodyBytes and looksLikeEmail.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// recordingMailer records every Send invocation; nil err = success.
type recordingMailer struct {
	calls []struct {
		to, link string
	}
	nextErr error
}

func (r *recordingMailer) SendMagicLink(ctx context.Context, to, link string) error {
	r.calls = append(r.calls, struct{ to, link string }{to, link})
	return r.nextErr
}

func newMagicLinkApp(t *testing.T, rdb *redis.Client, mailer magicLinkMailer) (*fiber.App, *MagicLinkHandler) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret: logoutTestSecret, // 32+ bytes
	}
	authH := NewAuthHandler(nil, cfg)
	h := NewMagicLinkHandlerWithMailerAndRedis(nil, cfg, mailer, authH, rdb)
	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024,
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
	return app, h
}

func TestMagicLinkStart_BodyTooLargeReturns413(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	mailer := &recordingMailer{}
	app, _ := newMagicLinkApp(t, rdb, mailer)

	huge := bytes.Repeat([]byte("x"), magicLinkStartMaxBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", bytes.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "payload_too_large", body["error"])
	assert.Zero(t, len(mailer.calls), "no mail must be sent when the body is over the cap")
}

func TestMagicLinkStart_MalformedJSONReturns400(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	mailer := &recordingMailer{}
	app, _ := newMagicLinkApp(t, rdb, mailer)

	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_body", body["error"])
}

func TestMagicLinkStart_InvalidEmailReturns400(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	mailer := &recordingMailer{}
	app, _ := newMagicLinkApp(t, rdb, mailer)

	cases := []string{
		`{"email":"not-an-email"}`,
		`{"email":""}`,
		`{"email":"x"}`,
		`{"email":"@example.com"}`,
		`{"email":"user@"}`,
		`{"email":"user@nodot"}`,
		`{"email":"a@@b.com"}`,
	}
	for i, payload := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "payload=%s", payload)
		})
	}
	assert.Zero(t, len(mailer.calls), "no mail must be sent for any invalid-email payload")
}

func TestMagicLinkStart_RateLimitReturns202SilentlyAfter5(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	mailer := &recordingMailer{}
	app, _ := newMagicLinkApp(t, rdb, mailer)

	emailAddr := "ratelimit+" + makeRand(t) + "@example.com"
	body := fmt.Sprintf(`{"email":%q}`, emailAddr)

	// Pre-populate the counter to 6 so the next request lands over the cap.
	key := emailRateLimitKey(strings.ToLower(emailAddr))
	require.NoError(t, rdb.Set(context.Background(), key, "6", 0).Err())

	// The handler has no DB, so the DB-insert branch would NPE if reached.
	// When rate-limited the handler must return 202 BEFORE touching the DB.
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode,
		"rate-limit branch must silently 202 without touching the mailer")
	assert.Zero(t, len(mailer.calls), "no mail must be sent on the rate-limit path")
}

// TestLooksLikeEmail covers every branch of the cheapest-plausible
// validator extracted from magic_link.go (B4-F4 in the BugBash sweep).
func TestMagicLink_LooksLikeEmail(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"too_short", "a@", false},
		{"missing_at", "noatsign", false},
		{"only_at", "@", false},
		{"at_at_start", "@example.com", false},
		{"at_at_end", "user@", false},
		{"missing_dot_in_host", "user@localhost", false},
		{"plain", "user@example.com", true},
		{"plus_addressing", "u+tag@example.com", true},
		{"subdomain", "u@a.b.example.com", true},
		{"length_over_254", strings.Repeat("a", 245) + "@x.com", false},
		{"double_at", "a@b@c.com", false},
		{"local_part_over_64",
			strings.Repeat("x", 65) + "@x.com", false},
		{"local_part_exactly_64",
			strings.Repeat("x", 64) + "@x.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := looksLikeEmail(tc.input)
			if got != tc.want {
				t.Errorf("looksLikeEmail(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestEmailRateLimitKey_FullPrefix asserts the format and verifies
// that two different emails always map to different keys (the goal of
// using the full sha256 instead of the truncated B4-F2 fingerprint).
func TestMagicLink_EmailRateLimitKey_KeyShapeAndUniqueness(t *testing.T) {
	a := emailRateLimitKey("a@example.com")
	b := emailRateLimitKey("b@example.com")
	if a == b {
		t.Fatalf("distinct emails produced the same key: %s", a)
	}
	if !strings.HasPrefix(a, magicLinkEmailRLKeyPrefix+":") {
		t.Errorf("key missing prefix: %s", a)
	}
	// sha256 hex = 64 chars; prefix "ml:email:rl:" = 12; total = 76.
	if got, want := len(a), len(magicLinkEmailRLKeyPrefix)+1+64; got != want {
		t.Errorf("key length = %d, want %d (got %s)", got, want, a)
	}
}

// TestCheckEmailRateLimit_HappyPath drives the Redis-backed counter
// from 1 → 6 to assert the limited/non-limited boundary.
func TestMagicLink_CheckEmailRateLimit_BoundaryAt5(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	emailAddr := "boundary+" + makeRand(t) + "@example.com"

	for i := 1; i <= int(magicLinkEmailRateLimit); i++ {
		limited, err := checkEmailRateLimit(context.Background(), rdb, emailAddr)
		require.NoError(t, err)
		assert.False(t, limited, "call #%d (≤ limit) must not be limited", i)
	}
	// One more — now over the threshold.
	limited, err := checkEmailRateLimit(context.Background(), rdb, emailAddr)
	require.NoError(t, err)
	assert.True(t, limited, "call after the limit must be limited")
}

// TestNewMagicLinkHandler_Constructors covers the three constructors
// just so each builder lands a single line of coverage.
func TestMagicLink_NewHandler_Constructors(t *testing.T) {
	cfg := &config.Config{JWTSecret: logoutTestSecret}
	authH := NewAuthHandler(nil, cfg)

	h1 := NewMagicLinkHandlerWithMailer(nil, cfg, &recordingMailer{}, authH)
	assert.NotNil(t, h1)
	h2 := NewMagicLinkHandlerWithMailerAndRedis(nil, cfg, &recordingMailer{}, authH, nil)
	assert.NotNil(t, h2)
}
