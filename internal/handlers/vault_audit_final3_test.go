package handlers_test

// vault_audit_final3_test.go — FINAL serial pass #3. Drives the
// AppendVaultAudit-error arm of (*VaultHandler).audit (vault.go:187-195): a
// fault DB makes the audit INSERT error, exercising the best-effort warn branch
// that must never surface to the caller.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func TestVaultAuditFinal3_AppendError(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	// Fault DB: AppendVaultAudit's INSERT errors → the warn arm runs.
	h := handlers.NewVaultHandler(openFaultDB(t, 0), cfg, plans.Default())

	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/a", func(c *fiber.Ctx) error {
		h.VaultAuditForTest(c, uuid.New(), uuid.NullUUID{UUID: uuid.New(), Valid: true},
			"get", "production", "MY_KEY", "10.0.0.1")
		return c.SendString("ok")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/a", nil), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The handler must still return 200 — audit failure is swallowed.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (audit error swallowed), got %d", resp.StatusCode)
	}
}
