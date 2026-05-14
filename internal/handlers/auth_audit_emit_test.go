package handlers_test

// auth_audit_emit_test.go — guards the auth.login audit emit added in the
// audit-emit-vault-login-deploy slice. Drives the magic-link callback (the
// simplest auth path to set up — no OAuth provider HTTP needed) end-to-end
// and asserts the audit_log row lands.
//
// Integration test — needs TEST_DATABASE_URL. Skips cleanly otherwise.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// magicLinkMigration mirrors db/migrations/013_magic_links.sql so tests can
// bring up the table without depending on the full migration set. Idempotent.
const magicLinkMigration = `
CREATE TABLE IF NOT EXISTS magic_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email        TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    return_to    TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links (token_hash) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links (email, created_at DESC);
`

// magicLinkTestApp builds a minimal Fiber app exposing only the magic-link
// callback route, wired to the real handler chain (auth + magic-link
// handlers) so emitAuthLoginAudit fires on the success path.
func magicLinkTestApp(t *testing.T, db *sql.DB) *fiber.App {
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
	mlH := handlers.NewMagicLinkHandler(db, cfg, email.New(""), authH)
	app.Get("/auth/email/callback", mlH.Callback)
	return app
}

// TestAuthLogin_AuditEmittedOnMagicLinkCallback walks the magic-link sign-in
// happy path: insert a fresh link, hit the callback, assert the auth.login
// row lands with provider=email.
func TestAuthLogin_AuditEmittedOnMagicLinkCallback(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	// magic_links is not in testhelpers.runMigrations — install it inline so
	// this test doesn't depend on a separate test-DB bootstrap.
	_, err := db.Exec(magicLinkMigration)
	require.NoError(t, err)

	emailAddr := testhelpers.UniqueEmail(t)

	// Drop an existing user row so the magic-link path finds it and reuses
	// the team rather than creating one (which would race the audit assert
	// — we want a deterministic team_id to query against).
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	teamID := uuid.MustParse(teamIDStr)
	_, err = db.Exec(`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, emailAddr)
	require.NoError(t, err)

	// Mint a magic-link plaintext + insert the hashed row.
	plaintext, err := models.GenerateMagicLinkPlaintext()
	require.NoError(t, err)
	_, err = models.CreateMagicLink(context.Background(), db, emailAddr, plaintext, "https://instanode.dev/login/callback", 5*time.Minute)
	require.NoError(t, err)

	app := magicLinkTestApp(t, db)

	req := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t="+plaintext, nil)
	req.Header.Set("User-Agent", "auth-audit-test/1.0")
	req.Header.Set("X-Forwarded-For", "10.99.0.42")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Successful callback is a 302 redirect with ?session_token=<jwt>.
	require.Equal(t, http.StatusFound, resp.StatusCode,
		"magic-link callback must redirect after issuing the session JWT")

	// Poll for the auth.login audit row — the emit fires from a goroutine.
	deadline := time.Now().Add(2 * time.Second)
	var rows []*models.AuditEvent
	for {
		rows, err = models.ListAuditEventsByTeam(context.Background(), db, teamID, 20, models.AuditKindAuthLogin)
		require.NoError(t, err)
		if len(rows) >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.Len(t, rows, 1, "exactly one auth.login row must land after a successful magic-link callback")

	row := rows[0]
	assert.Equal(t, models.AuditKindAuthLogin, row.Kind)
	assert.Equal(t, "user", row.Actor)
	assert.True(t, row.UserID.Valid, "user_id must be set on the audit row")

	var meta map[string]string
	require.NoError(t, json.Unmarshal(row.Metadata, &meta))
	assert.Equal(t, "email", meta["provider"], "magic-link callback must report provider=email")
	assert.NotEmpty(t, meta["ip"], "ip must be captured")
	assert.Equal(t, "auth-audit-test/1.0", meta["user_agent"], "user_agent must reach metadata")
}
