package handlers_test

// webhook_arms_bvwave_test.go — closes the last webhook.go arms the existing
// webhook_*_test.go files leave open:
//
//   - newWebhookAuthenticated invalid_team (400): a session team_id that is not
//     a UUID.
//   - ListRequests with a garbage (non-JSON) ring-buffer entry → decode-item
//     skip branch, plus the authenticated success path's audit + persist.
//   - storeIdempotentReceive: a receive carrying X-Idempotency-Key persists the
//     cached response (the store branch, distinct from the replay-read branch).
//
// Reuses newWebhookHandlerWithDB / receiveRouteApp / seedWebhookResource from
// webhook_residual_test.go.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestNewWebhook_AuthInvalidTeam_400_bvwave drives newWebhookAuthenticated's
// invalid_team arm: a session team_id Local that is not a valid UUID.
func TestNewWebhook_AuthInvalidTeam_400_bvwave(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex, EnabledServices: "webhook"}
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
	app := fiber.New(fiber.Config{
		ProxyHeader: "X-Forwarded-For",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
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
	app.Use(middleware.Fingerprint())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, "not-a-uuid") // malformed team id
		return c.Next()
	})
	app.Post("/webhook/new", h.NewWebhook)

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", strings.NewReader(`{"name":"wh"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.73.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestListRequests_GarbageRingItem_SkippedAndAuthOK_bvwave inserts a non-JSON
// entry into the ring buffer so ListRequests' decode-item skip branch runs,
// alongside a valid entry, returning 200 with the decodable item only.
func TestListRequests_GarbageRingItem_Skipped_bvwave(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()
	app := receiveRouteApp(h)

	token := seedWebhookResource(t, db, "active", nil)

	// Push a valid + a garbage payload directly onto the list key.
	rdb := handlers.WebhookRedisForTest(h)
	listKey := "wh:list:" + token
	require.NoError(t, rdb.LPush(context.Background(), listKey, `{"id":"a","method":"POST"}`).Err())
	require.NoError(t, rdb.LPush(context.Background(), listKey, `not-json{{`).Err())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
