package handlers_test

// magic_link_persist_test.go — integration tests for the send-status
// persistence path added after the 2026-05-14 outage. These drive the
// Start handler end-to-end (via httptest) and assert the row's
// email_send_status reflects what the mailer returned.
//
// Both tests need TEST_DATABASE_URL — they skip cleanly otherwise.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// magicLinkPersistMigration brings up the magic_links table with the
// migration-041 columns. Uses ALTER ... ADD COLUMN IF NOT EXISTS so it's
// safe to run against a test DB that already has the pre-041 shape
// (SetupTestDB may have applied an older inline migration).
const magicLinkPersistMigration = `
CREATE TABLE IF NOT EXISTS magic_links (
    id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                         TEXT NOT NULL,
    token_hash                    TEXT NOT NULL,
    return_to                     TEXT NOT NULL DEFAULT '',
    expires_at                    TIMESTAMPTZ NOT NULL,
    consumed_at                   TIMESTAMPTZ,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE magic_links
    ADD COLUMN IF NOT EXISTS email_send_status TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS email_send_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS email_send_last_error TEXT,
    ADD COLUMN IF NOT EXISTS email_send_last_attempted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links (token_hash) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links (email, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_magic_links_reconcile
    ON magic_links (created_at, email_send_status)
    WHERE email_send_status IN ('pending', 'send_failed');
`

// stubMagicLinkMailer is a test double for the magicLinkMailer interface.
// Returns errToReturn on every Send. Records the most recent (toEmail, link)
// for assertions that don't care about ordering across multiple sends.
type stubMagicLinkMailer struct {
	errToReturn error
	lastTo      string
	lastLink    string
	callCount   int
}

func (s *stubMagicLinkMailer) SendMagicLink(ctx context.Context, toEmail, link string) error {
	s.callCount++
	s.lastTo = toEmail
	s.lastLink = link
	return s.errToReturn
}

// startTestApp builds a minimal Fiber app exposing only POST /auth/email/start
// and wires the real MagicLinkHandler against a stub mailer. The stub lets
// us drive both the success and failure paths deterministically.
func startTestApp(t *testing.T, db *sql.DB, stub *stubMagicLinkMailer) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret,
		AESKey:    testhelpers.TestAESKeyHex,
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
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	app.Use(middleware.RequestID())
	authH := handlers.NewAuthHandler(db, cfg)
	mlH := handlers.NewMagicLinkHandlerWithMailer(db, cfg, stub, authH)
	app.Post("/auth/email/start", mlH.Start)
	return app
}

// fetchSendStatusRow returns the (status, attempts, last_error) tuple for
// the most-recently-inserted magic_links row matching emailAddr. Polls
// briefly because the status write happens AFTER the 202 response, so
// the test can race the DB update if it reads immediately.
func fetchSendStatusRow(t *testing.T, db *sql.DB, emailAddr string) (status string, attempts int, lastErr sql.NullString) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		row := db.QueryRowContext(context.Background(), `
			SELECT email_send_status, email_send_attempts, email_send_last_error
			FROM magic_links
			WHERE email = $1
			ORDER BY created_at DESC
			LIMIT 1
		`, emailAddr)
		if err := row.Scan(&status, &attempts, &lastErr); err == nil {
			// We can't filter on "status != pending" in the SELECT
			// because the test wants to assert "sent" explicitly; instead
			// poll until status is no longer the DEFAULT 'pending' (which
			// means the handler has finished writing) OR until deadline.
			if status != "pending" || time.Now().After(deadline) {
				return
			}
		} else if err == sql.ErrNoRows {
			if time.Now().After(deadline) {
				t.Fatalf("no magic_links row found for %s within deadline", emailAddr)
			}
		} else {
			t.Fatalf("fetchSendStatusRow: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestStart_PersistsSentStatusOnSuccess walks the happy path. After the
// 202 response the magic_links row must show status='sent' and attempts=1.
// This is the post-2026-05-14 invariant: the row is the durable record of
// "we tried, it succeeded" — not just the slog line.
func TestStart_PersistsSentStatusOnSuccess(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	_, err := db.Exec(magicLinkPersistMigration)
	require.NoError(t, err)

	emailAddr := testhelpers.UniqueEmail(t)
	stub := &stubMagicLinkMailer{errToReturn: nil}
	app := startTestApp(t, db, stub)

	body := fmt.Sprintf(`{"email":%q,"return_to":""}`, emailAddr)
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusAccepted, resp.StatusCode)

	status, attempts, lastErr := fetchSendStatusRow(t, db, emailAddr)
	assert.Equal(t, "sent", status, "row must be flipped to sent on success")
	assert.Equal(t, 1, attempts, "exactly one attempt counted on first success")
	assert.False(t, lastErr.Valid, "no last_error on success path")
	assert.Equal(t, 1, stub.callCount, "mailer must be invoked exactly once")
	assert.Equal(t, emailAddr, stub.lastTo, "mailer must receive the requested address")
}

// TestStart_PersistsSendFailedStatusOnError drives the failure path: the
// mailer returns an error, the handler still 202s (enumeration defense),
// the row is flipped to 'send_failed' with attempts=1, and the error
// string lands in email_send_last_error so an operator can triage from
// the DB without trawling logs.
//
// This is the exact regression test for the live 2026-05-14 outage —
// before this PR, the failure was invisible at the row level; only the
// slog line carried the signal, and operators missed it because the
// .sent line fired alongside it.
func TestStart_PersistsSendFailedStatusOnError(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	_, err := db.Exec(magicLinkPersistMigration)
	require.NoError(t, err)

	emailAddr := testhelpers.UniqueEmail(t)
	stub := &stubMagicLinkMailer{
		errToReturn: errors.New("API key is invalid"),
	}
	app := startTestApp(t, db, stub)

	body := fmt.Sprintf(`{"email":%q,"return_to":""}`, emailAddr)
	req := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Failure must NOT bubble to the client — same 202 as success.
	require.Equal(t, fiber.StatusAccepted, resp.StatusCode,
		"enumeration defense: send-failure must not leak through HTTP status")

	status, attempts, lastErr := fetchSendStatusRow(t, db, emailAddr)
	assert.Equal(t, "send_failed", status, "row must record send_failed when mailer errors")
	assert.Equal(t, 1, attempts, "attempts must increment on failure")
	assert.True(t, lastErr.Valid, "last_error must be set on failure")
	assert.Contains(t, lastErr.String, "API key is invalid",
		"last_error must capture the provider message so an operator can triage from the DB")
}

// Avoid unused-import linter complaints if the package layout shifts.
var _ = uuid.Nil
