package handlers_test

// provision_finalize_final2_test.go — FINAL SERIAL PASS #2 coverage for the
// finalizeProvision-failure persist arms across every provisioning handler.
//
// The backend provision RPC SUCCEEDS (working customer-Postgres / Redis /
// Mongo) but finalizeProvision then fails because the AES key is invalid hex
// (ParseAESKey error → MR-P0-3 persistence-failure path → SoftDeleteResource +
// respondProvisionFailed). This reaches the handler-level persist arms that
// the closed-DB suite (which fails at CreateResource, BEFORE the backend call)
// and the happy-path suite (valid AES) both miss:
//
//   db.go / cache.go / nosql.go / queue.go / vector.go / webhook.go
//   finalize-failure → 503 provision_failed / persist_error arms.
//
// Anonymous path (no JWT) so the flow is deterministic; a unique IP per
// handler keeps the per-fingerprint cap counters isolated.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// badAESProvisionApp builds the provisioning handlers over a healthy DB +
// working backends but with an INVALID-hex AES key so finalizeProvision fails
// after a successful backend provision.
func badAESProvisionApp(t *testing.T) (*fiber.App, *redis.Client) {
	t.Helper()
	liveDB, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { liveDB.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	customersURL := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if customersURL == "" {
		customersURL = "postgres://postgres:postgres@localhost:5432/instant_customers?sslmode=disable"
	}
	mongoURI := os.Getenv("TEST_MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	cfg := &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   "not-a-valid-hex-key", // forces finalizeProvision failure
		EnabledServices:          "postgres,redis,mongodb,vector,webhook,queue,storage",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		PostgresCustomersURL:     customersURL,
		RedisProvisionBackend:    "local",
		RedisProvisionHost:       "localhost",
		MongoAdminURI:            mongoURI,
		MongoHost:                "localhost",
		ObjectStoreBucket:        "instant-shared",
		ObjectStoreEndpoint:      "nyc3.test.local",
		ObjectStoreAccessKey:     "MK",
		ObjectStoreSecretKey:     "MS",
		NATSHost:                 "127.0.0.1", // 8222 probe unreachable → queue provision fails (soft-delete arm)
	}
	planReg := plans.Default()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlbadaes"}))

	dbH := handlers.NewDBHandler(liveDB, rdb, cfg, nil, planReg)
	cacheH := handlers.NewCacheHandler(liveDB, rdb, cfg, nil, planReg)
	nosqlH := handlers.NewNoSQLHandler(liveDB, rdb, cfg, nil, planReg)
	vectorH := handlers.NewVectorHandler(liveDB, rdb, cfg, nil, planReg)
	webhookH := handlers.NewWebhookHandler(liveDB, rdb, cfg, planReg)
	queueH := handlers.NewQueueHandler(liveDB, rdb, cfg, nil, planReg)
	storageH := handlers.NewStorageHandler(liveDB, rdb, cfg, newDOSpacesProvider(t), planReg)

	app.Post("/db/new", middleware.OptionalAuth(cfg), dbH.NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), cacheH.NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), nosqlH.NewNoSQL)
	app.Post("/vector/new", middleware.OptionalAuth(cfg), vectorH.NewVector)
	app.Post("/webhook/new", middleware.OptionalAuth(cfg), webhookH.NewWebhook)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), queueH.NewQueue)
	app.Post("/storage/new", middleware.OptionalAuth(cfg), storageH.NewStorage)
	return app, rdb
}

func postBadAES(t *testing.T, app *fiber.App, path, ip string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env.Error
}

// TestProvisionFinalizeFinal2_BadAES_AllHandlers drives every provisioning
// handler through a successful backend provision + failed finalizeProvision
// (invalid AES key) → the persist-failure soft-delete arm + 503.
func TestProvisionFinalizeFinal2_BadAES_AllHandlers(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	app, _ := badAESProvisionApp(t)
	paths := []string{"/db/new", "/cache/new", "/nosql/new", "/vector/new", "/webhook/new", "/queue/new", "/storage/new"}
	for i, path := range paths {
		status, errCode := postBadAES(t, app, path, "10.230."+digitStr(i)+".3")
		// Backend provisions OK, finalize fails on the bad AES key → 503.
		assert.Equalf(t, http.StatusServiceUnavailable, status,
			"%s finalize-fail must 503 (got %d / %s)", path, status, errCode)
	}
}

// TestProvisionFinalizeFinal2_BadAES_Authenticated drives the AUTHENTICATED
// provision paths (newDBAuthenticated / newCacheAuthenticated / ...) through the
// same backend-OK + finalize-fail shape, hitting the auth-path persist arms the
// anonymous test above doesn't reach.
func TestProvisionFinalizeFinal2_BadAES_Authenticated(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	app, _ := badAESProvisionApp(t)
	// Auth path needs a real team; reuse the pooled DB the app already wired.
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "auth-finz-user", teamID, "authfinz@example.com")

	paths := []string{"/db/new", "/cache/new", "/nosql/new", "/vector/new", "/storage/new"}
	for i, path := range paths {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("X-Forwarded-For", "10.231."+digitStr(i)+".4")
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Equalf(t, http.StatusServiceUnavailable, resp.StatusCode,
			"%s auth finalize-fail must 503 (body=%s)", path, raw)
	}
}
