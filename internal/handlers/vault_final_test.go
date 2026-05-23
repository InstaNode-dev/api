package handlers_test

// vault_final_test.go — FINAL coverage pass for vault.go's encryptPlaintext
// aes-key-invalid arm (vault.go:163) via a handler configured with a bad AES
// key, driven through PutSecret.

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func vaultBadAESApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret,
		AESKey:    "not-a-valid-hex-aes-key", // ParseAESKey fails → encryptPlaintext errors
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	h := handlers.NewVaultHandler(db, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Put("/vault/:env/:key", h.PutSecret)
	return app
}

// PutSecret with a bad AES key → encryptPlaintext fails → 500 (vault.go:163).
func TestVaultFinal_PutSecret_BadAESKey_500(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	_, _, jwt := makeTeamUser(t, db)

	app := vaultBadAESApp(t, db)
	req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/MY_KEY", jwt, map[string]string{"value": "s3cr3t"})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
