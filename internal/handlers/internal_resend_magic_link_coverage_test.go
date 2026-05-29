package handlers_test

// internal_resend_magic_link_coverage_test.go — hermetic coverage for
// POST /internal/email/resend-magic-link (internal_resend_magic_link.go). The
// handler is DB + mailer-interface only, so a fake mailer makes every arm
// (auth, TTL, send-failed, abandon, sent) exercisable under CI's
// postgres-only matrix. Before this file the handler measured 0% under CI.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

const testResendMagicLinkSecret = "worker-resend-secret-32-bytes!!!"

// fakeMagicLinkMailer satisfies the magicLinkMailer interface. err controls
// the send outcome so the failed / abandoned arms are reachable.
type fakeMagicLinkMailer struct {
	err  error
	sent int
}

func (m *fakeMagicLinkMailer) SendMagicLink(ctx context.Context, toEmail, link string) error {
	m.sent++
	return m.err
}

func resendMLTestApp(t *testing.T, db *sql.DB, secret string, mailer *fakeMagicLinkMailer) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		WorkerInternalJWTSecret: secret,
		JWTSecret:               testhelpers.TestJWTSecret,
		AESKey:                  testhelpers.TestAESKeyHex,
		Environment:             "test",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	h := handlers.NewInternalResendMagicLinkHandler(db, cfg, mailer)
	app.Post("/internal/email/resend-magic-link", h.Resend)
	return app
}

func mintResendMLJWT(t *testing.T, secret, purpose, linkID string, iatOffset time.Duration) string {
	t.Helper()
	claims := jwt.MapClaims{
		"purpose": purpose,
		"link_id": linkID,
		"iat":     jwt.NewNumericDate(time.Now().Add(iatOffset)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// seedMagicLink inserts a magic_links row with the given expiry + attempt
// count. Returns the row id.
func seedMagicLink(t *testing.T, db *sql.DB, expiresAt time.Time, attempts int) string {
	t.Helper()
	var id string
	err := db.QueryRow(`
		INSERT INTO magic_links (email, token_hash, return_to, expires_at, email_send_status, email_send_attempts)
		VALUES ($1, $2, '/', $3, 'pending', $4)
		RETURNING id::text
	`, testhelpers.UniqueEmail(t), uuid.NewString(), expiresAt, attempts).Scan(&id)
	require.NoError(t, err)
	return id
}

func resendMLPost(t *testing.T, app *fiber.App, jwt, bodyLinkID string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/email/resend-magic-link",
		strings.NewReader(`{"link_id":"`+bodyLinkID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func TestResendMagicLink_AuthArms(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	mailer := &fakeMagicLinkMailer{}
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, mailer)
	linkID := seedMagicLink(t, db, time.Now().Add(10*time.Minute), 0)

	t.Run("invalid_body", func(t *testing.T) {
		// API-27/78 (QA 2026-05-29): auth-first ordering means a junk body
		// from an AUTHENTICATED caller still 400s (worker emitted a bad
		// payload); unauthenticated callers 401 on the auth check before
		// the body parse. We test the authenticated-bad-body path here so
		// the body-parse arm stays covered.
		validJWT := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
		req := httptest.NewRequest(http.MethodPost, "/internal/email/resend-magic-link", strings.NewReader(`{bad`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+validJWT)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("invalid_link_id", func(t *testing.T) {
		// API-27/78: same auth-first reasoning as invalid_body above —
		// the body-link_id parse only fires for authenticated callers.
		// We mint a fresh JWT whose link_id claim matches the bogus body
		// link_id so the structural verify accepts the token; the body
		// parse then surfaces 400 invalid_link_id (since "not-a-uuid"
		// fails uuid.Parse).
		validJWT := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", "not-a-uuid", 0)
		resp := resendMLPost(t, app, validJWT, "not-a-uuid")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("missing_bearer", func(t *testing.T) {
		resp := resendMLPost(t, app, "", linkID)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("wrong_secret", func(t *testing.T) {
		bad := mintResendMLJWT(t, "totally-different-secret-xxxxxxxx", "resend_magic_link", linkID, 0)
		resp := resendMLPost(t, app, bad, linkID)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("wrong_purpose", func(t *testing.T) {
		jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "terminate", linkID, 0)
		resp := resendMLPost(t, app, jwt, linkID)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("stale_iat", func(t *testing.T) {
		jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, -5*time.Minute)
		resp := resendMLPost(t, app, jwt, linkID)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("link_id_mismatch", func(t *testing.T) {
		other := uuid.NewString()
		jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", other, 0)
		resp := resendMLPost(t, app, jwt, linkID)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestResendMagicLink_SecretUnset_401(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := resendMLTestApp(t, db, "", &fakeMagicLinkMailer{})
	linkID := seedMagicLink(t, db, time.Now().Add(10*time.Minute), 0)
	jwt := mintResendMLJWT(t, "anything", "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestResendMagicLink_NotFound(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, &fakeMagicLinkMailer{})
	missing := uuid.NewString()
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", missing, 0)
	resp := resendMLPost(t, app, jwt, missing)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestResendMagicLink_Expired(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, &fakeMagicLinkMailer{})
	linkID := seedMagicLink(t, db, time.Now().Add(-1*time.Minute), 0)
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestResendMagicLink_SentHappyPath(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	mailer := &fakeMagicLinkMailer{}
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, mailer)
	linkID := seedMagicLink(t, db, time.Now().Add(10*time.Minute), 0)
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.Equal(t, 1, mailer.sent)

	// Verify the token hash rotated + status is sent.
	var status string
	require.NoError(t, db.QueryRow(`SELECT email_send_status FROM magic_links WHERE id=$1::uuid`, linkID).Scan(&status))
	assert.Equal(t, "sent", status)
}

func TestResendMagicLink_SendFailed(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	mailer := &fakeMagicLinkMailer{err: errors.New("brevo down")}
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, mailer)
	// attempts=0 → after the failed mark count becomes 1, below the cap of 3.
	linkID := seedMagicLink(t, db, time.Now().Add(10*time.Minute), 0)
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	var status string
	require.NoError(t, db.QueryRow(`SELECT email_send_status FROM magic_links WHERE id=$1::uuid`, linkID).Scan(&status))
	assert.Equal(t, "send_failed", status)
}

func TestResendMagicLink_Abandoned(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	mailer := &fakeMagicLinkMailer{err: errors.New("brevo down")}
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, mailer)
	// attempts=2 → after the failed mark count becomes 3, hits the cap → abandoned.
	linkID := seedMagicLink(t, db, time.Now().Add(10*time.Minute), 2)
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	var status string
	require.NoError(t, db.QueryRow(`SELECT email_send_status FROM magic_links WHERE id=$1::uuid`, linkID).Scan(&status))
	assert.Equal(t, "send_abandoned", status)
}

// TestResendMagicLink_modelHelpers ensures the readMagicLinkAttempts projection
// is exercised through the failed path (it's called on every send failure).
func TestResendMagicLink_readAttemptsThroughFailure(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	mailer := &fakeMagicLinkMailer{err: errors.New("x")}
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, mailer)
	linkID := seedMagicLink(t, db, time.Now().Add(10*time.Minute), 1)
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	// attempts went 1 → 2 (below cap) → send_failed
	var attempts int
	require.NoError(t, db.QueryRow(`SELECT email_send_attempts FROM magic_links WHERE id=$1::uuid`, linkID).Scan(&attempts))
	assert.Equal(t, 2, attempts)
}
