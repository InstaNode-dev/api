package handlers_test

// webhook_residual_test.go — residual coverage for webhook.go (82.6% → ≥95%).
// Targets:
//
//   storeEncryptedURL:  the crypto.Encrypt-failed arm (905-907) via the
//                       SetWebhookCryptoEncryptForTest seam (encrypt with a
//                       valid key never fails in prod).
//   NewWebhook (anon):  missing-name 400 (220-222), invalid-env 400 (226-228).
//   Receive:            lookup_failed (brokenDB), inactive 410, expired 410,
//                       idempotency replay, rotation header.
//   ListRequests:       lookup_failed (brokenDB), inactive 410, expired 410.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// ── storeEncryptedURL encrypt-fail seam ─────────────────────────────────────

// TestStoreEncryptedURL_EncryptFails drives the crypto.Encrypt-failed arm
// (905-907). A valid AES key parses fine, so the only way to reach the
// encrypt error is the package-level cryptoEncrypt seam.
func TestStoreEncryptedURL_EncryptFails(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())

	restore := handlers.SetWebhookCryptoEncryptForTest(
		func([]byte, string) (string, error) { return "", errors.New("encrypt boom") })
	defer restore()

	err := handlers.StoreEncryptedURLForTest(h, context.Background(),
		uuid.New(), "https://hook.example/x", "req-enc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt")
}

// ── webhook receive/list app wired to an arbitrary DB ───────────────────────

// newWebhookHandlerWithDB builds a WebhookHandler over the given DB + a real
// test Redis, with webhook enabled.
func newWebhookHandlerWithDB(t *testing.T, db *sql.DB) (*handlers.WebhookHandler, func()) {
	t.Helper()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	cfg := &config.Config{
		Environment:     "test",
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "webhook",
	}
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
	return h, rClean
}

// receiveRouteApp mounts Receive + ListRequests on a handler.
func receiveRouteApp(h *handlers.WebhookHandler) *fiber.App {
	app := fiber.New(fiber.Config{
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
	app.All("/webhook/receive/:token", h.Receive)
	app.Get("/api/v1/webhooks/:token/requests", h.ListRequests)
	return app
}

// TestReceive_LookupFailed_BrokenDB drives the Receive lookup_failed arm
// (534-536) via a brokenDB.
func TestReceive_LookupFailed_BrokenDB(t *testing.T) {
	h, clean := newWebhookHandlerWithDB(t, brokenDB(t))
	defer clean()
	app := receiveRouteApp(h)
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+uuid.NewString(), nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestListRequests_LookupFailed_BrokenDB drives the ListRequests lookup_failed
// arm (816-818) via a brokenDB.
func TestListRequests_LookupFailed_BrokenDB(t *testing.T) {
	h, clean := newWebhookHandlerWithDB(t, brokenDB(t))
	defer clean()
	app := receiveRouteApp(h)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+uuid.NewString()+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// seedWebhookResource inserts a webhook resource row with the given status +
// optional expiry, returning its token.
func seedWebhookResource(t *testing.T, db *sql.DB, status string, expiresAt *time.Time) string {
	t.Helper()
	token := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (token, resource_type, tier, env, status, expires_at)
		VALUES ($1, 'webhook', 'anonymous', 'production', $2, $3)
	`, token, status, expiresAt)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })
	return token
}

// TestReceive_InactiveResource_410 drives the inactive-status arm (548-550).
func TestReceive_InactiveResource_410(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()
	app := receiveRouteApp(h)
	token := seedWebhookResource(t, db, "suspended", nil)
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+token, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// TestReceive_ExpiredResource_410 drives the past-TTL arm (557-559).
func TestReceive_ExpiredResource_410(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()
	app := receiveRouteApp(h)
	past := time.Now().Add(-time.Hour)
	token := seedWebhookResource(t, db, "active", &past)
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+token, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// TestListRequests_InactiveResource_410 drives the ListRequests inactive arm
// (834-837).
func TestListRequests_InactiveResource_410(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()
	app := receiveRouteApp(h)
	token := seedWebhookResource(t, db, "suspended", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// TestListRequests_ExpiredResource_410 drives the ListRequests past-TTL arm
// (842-844).
func TestListRequests_ExpiredResource_410(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()
	app := receiveRouteApp(h)
	past := time.Now().Add(-time.Hour)
	token := seedWebhookResource(t, db, "active", &past)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// TestReceive_IdempotencyReplay drives the idempotency-replay arm (607-610):
// the second request with the same X-Idempotency-Key returns the cached
// response without writing a new ring-buffer entry.
func TestReceive_IdempotencyReplay(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()
	app := receiveRouteApp(h)
	token := seedWebhookResource(t, db, "active", nil)

	idem := "idem-" + uuid.NewString()
	send := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+token, bytes.NewReader([]byte(`{"x":1}`)))
		req.Header.Set("X-Idempotency-Key", idem)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}
	r1 := send()
	r1.Body.Close()
	require.Equal(t, http.StatusOK, r1.StatusCode)
	r2 := send()
	r2.Body.Close()
	require.Equal(t, http.StatusOK, r2.StatusCode, "idempotent replay must succeed")
}

// ── NewWebhook anonymous validation arms ─────────────────────────────────────

// newWebhookProvisionApp mounts POST /webhook/new on a webhook-enabled
// handler over a real DB + Redis.
func newWebhookProvisionApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	h, clean := newWebhookHandlerWithDB(t, db)
	t.Cleanup(clean)
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
	app.Post("/webhook/new", h.NewWebhook)
	return app
}

func postWebhookNew(t *testing.T, app *fiber.App, ip, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook/new", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestNewWebhook_MissingName_400 drives the requireName error arm (219-222).
func TestNewWebhook_MissingName_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := newWebhookProvisionApp(t, db)
	status, _ := postWebhookNew(t, app, "10.70.0.1", `{}`)
	assert.Equal(t, http.StatusBadRequest, status)
}

// TestNewWebhook_InvalidEnv_400 drives the resolveEnv error arm (225-228).
func TestNewWebhook_InvalidEnv_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := newWebhookProvisionApp(t, db)
	status, _ := postWebhookNew(t, app, "10.71.0.1", `{"name":"wh","env":"not a valid env!!"}`)
	assert.Equal(t, http.StatusBadRequest, status)
}

// TestReceive_RedisStoreFailed_FailsOpen drives the Receive LLen-error +
// pipeline-Exec-failed arms (659-661 + 667-672): a dead Redis makes both the
// pre-length read and the store pipeline fail, but the receiver still 200s
// (fail open — never block the sender).
func TestReceive_RedisStoreFailed_FailsOpen(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	deadRDB := redis.NewClient(&redis.Options{Addr: "127.0.0.1:19995"})
	defer deadRDB.Close()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex, EnabledServices: "webhook"}
	h := handlers.NewWebhookHandler(db, deadRDB, cfg, plans.Default())

	token := seedWebhookResource(t, db, "active", nil)
	app := receiveRouteApp(h)
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+token, bytes.NewReader([]byte(`{"x":1}`)))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "redis store failure must fail open with 200")
}

// TestNewWebhook_AuthTeamLookupFailed_503 drives newWebhookAuthenticated's
// team_lookup_failed arm (407-410): a session-authed caller (team_id pinned in
// Locals) over a brokenDB → GetTeamByID errors → 503.
func TestNewWebhook_AuthTeamLookupFailed_503(t *testing.T) {
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex, EnabledServices: "webhook"}
	h := handlers.NewWebhookHandler(brokenDB(t), rdb, cfg, plans.Default())
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
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString()) // authenticated path
		return c.Next()
	})
	app.Post("/webhook/new", h.NewWebhook)

	status, _ := postWebhookNew(t, app, "10.72.0.1", `{"name":"auth-wh"}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
}

// ── ListRequests cross-team + redis arms ─────────────────────────────────────

// TestListRequests_CrossTeamSession_403 drives the cross_team_session arm
// (864-872): a claimed (team-owned) webhook + a session JWT for a different
// team.
func TestListRequests_CrossTeamSession_403(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()

	ownerTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status)
		VALUES ($1::uuid, $2, 'webhook', 'pro', 'production', 'active')
	`, ownerTeam, token)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	// fake-auth pins a session for the OTHER team.
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, otherTeam)
		return c.Next()
	})
	app.Get("/api/v1/webhooks/:token/requests", h.ListRequests)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestListRequests_RedisReadFailed_FailsOpen drives the redis-read-failed arm
// (877-883): a claimed webhook + a dead Redis → LRange errors → empty list,
// still 200 (fail open).
func TestListRequests_RedisReadFailed_FailsOpen(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	deadRDB := redis.NewClient(&redis.Options{Addr: "127.0.0.1:19996"})
	defer deadRDB.Close()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex, EnabledServices: "webhook"}
	h := handlers.NewWebhookHandler(db, deadRDB, cfg, plans.Default())

	token := seedWebhookResource(t, db, "active", nil)
	app := receiveRouteApp(h)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "redis read failure must fail open with empty list")
}

// TestListRequests_DecodeItemFailed_Skips drives the decode-item-failed arm
// (889-892): a malformed (non-JSON) item in the ring buffer is skipped.
func TestListRequests_DecodeItemFailed_Skips(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex, EnabledServices: "webhook"}
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())

	token := seedWebhookResource(t, db, "active", nil)
	// Inject a malformed (non-JSON) entry directly into the ring buffer.
	listKey := "wh:list:" + token
	require.NoError(t, rdb.LPush(context.Background(), listKey, "not-json-{").Err())
	// Best-effort: also push a valid one so the loop runs both arms.
	require.NoError(t, rdb.LPush(context.Background(), listKey, `{"id":"x"}`).Err())

	app := receiveRouteApp(h)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestReceive_RotationHeader drives the rotation arm (684-693): filling the
// ring buffer past the anonymous max-stored cap sets X-Webhook-Rotated.
func TestReceive_RotationHeader(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	h, clean := newWebhookHandlerWithDB(t, db)
	defer clean()
	app := receiveRouteApp(h)
	token := seedWebhookResource(t, db, "active", nil)

	maxStored := int(handlers.WebhookMaxStoredForTest(h, "anonymous"))
	var lastRotated string
	for i := 0; i < maxStored+2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+token,
			bytes.NewReader([]byte(fmt.Sprintf(`{"n":%d}`, i))))
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		if h := resp.Header.Get("X-Webhook-Rotated"); h != "" {
			lastRotated = h
		}
		resp.Body.Close()
	}
	assert.Equal(t, token, lastRotated, "ring-buffer rotation must set X-Webhook-Rotated once over cap")
}
