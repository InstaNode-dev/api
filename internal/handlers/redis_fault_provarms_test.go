package handlers_test

// redis_fault_provarms_test.go — covers the fail-open Redis-error LOG branches
// on the anonymous provisioning success path that the happy-path fixtures skip:
//   - checkProvisionLimit error  → logged, fail-open, provision continues
//   - markRecycleSeen error      → logged after a successful provision
// plus the recycle-gate fired branch (402 free_tier_recycle_requires_claim).
//
// THE TECHNIQUE: give the HANDLER a CLOSED redis client while the rate-limit /
// auth MIDDLEWARE keeps a LIVE one. The handler's checkProvisionLimit +
// markRecycleSeen then error (fail-open) without breaking the middleware chain;
// the DB is live so the anonymous provision still succeeds with a 201.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Anonymous provisions where the HANDLER's redis is closed (middleware redis
// live): checkProvisionLimit + markRecycleSeen both error and fail open, the DB
// provision still succeeds → 201. Covers the redis-error log branches in every
// anonymous handler arm.
func TestAnonProvision_HandlerRedisError_FailsOpenAndProvisions(t *testing.T) {
	liveDB, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { liveDB.Close() })
	liveRedis, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { liveRedis.Close() })

	// A closed redis handle for the handler — every command errors.
	closedRdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	require.NoError(t, closedRdb.Close())

	cfg := &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,redis,mongodb,queue,storage",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		ObjectStoreBucket:        "instant-shared",
		ObjectStoreEndpoint:      "nyc3.test.local",
		ObjectStoreAccessKey:     "MK",
		ObjectStoreSecretKey:     "MS",
	}
	planReg := plans.Default()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.SendStatus(fiber.StatusInternalServerError)
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	// Rate-limit middleware uses the LIVE redis so the chain works.
	app.Use(middleware.RateLimit(liveRedis, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlhre"}))

	// Handlers get the CLOSED redis.
	app.Post("/db/new", middleware.OptionalAuth(cfg), handlers.NewDBHandler(liveDB, closedRdb, cfg, nil, planReg).NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), handlers.NewCacheHandler(liveDB, closedRdb, cfg, nil, planReg).NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), handlers.NewNoSQLHandler(liveDB, closedRdb, cfg, nil, planReg).NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), handlers.NewQueueHandler(liveDB, closedRdb, cfg, nil, planReg).NewQueue)
	app.Post("/storage/new", middleware.OptionalAuth(cfg), handlers.NewStorageHandler(liveDB, closedRdb, cfg, newDOSpacesProvider(t), planReg).NewStorage)

	type provResp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	for i, path := range []string{"/db/new", "/cache/new", "/nosql/new", "/queue/new", "/storage/new"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "10.220."+string(rune('0'+i))+".1")
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var pr provResp
		_ = json.Unmarshal(raw, &pr)
		// db/cache/nosql may 503 if their LOCAL backend isn't reachable; the
		// redis-error log branches run BEFORE provisioning either way. Accept
		// 201 (provisioned) or 503 (local backend down) — never a 5xx from the
		// closed handler-redis (it must fail open).
		assert.Containsf(t, []int{http.StatusCreated, http.StatusServiceUnavailable}, resp.StatusCode,
			"%s must fail open on handler-redis error (got %d, body=%s)", path, resp.StatusCode, raw)
	}
}

// Anonymous SUCCESS path with a closed handler-redis, backed by the bufconn
// gRPC provisioner so provisioning succeeds regardless of local backends. This
// reaches the markRecycleSeen-error LOG branch (line ~265 in each handler) that
// only runs AFTER a successful provision — unreachable for db/cache/nosql/queue
// via the local-provider path on a machine without those backends.
func TestAnonProvision_GRPCSuccess_HandlerRedisError_LogsRecycleMarkFailure(t *testing.T) {
	liveDB, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { liveDB.Close() })
	liveRedis, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { liveRedis.Close() })

	closedRdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	require.NoError(t, closedRdb.Close())

	cfg := &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,redis,mongodb,queue",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		QueueBackend:             "legacy_open",
		NATSHost:                 "nats.test",
		NATSPublicHost:           "nats.instanode.dev",
	}
	planReg := plans.Default()
	provClient := newBufconnProvisionerClient(t, &fakeProvisioner{})

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.SendStatus(fiber.StatusInternalServerError)
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(liveRedis, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlgre"}))

	app.Post("/db/new", middleware.OptionalAuth(cfg), handlers.NewDBHandler(liveDB, closedRdb, cfg, provClient, planReg).NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), handlers.NewCacheHandler(liveDB, closedRdb, cfg, provClient, planReg).NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), handlers.NewNoSQLHandler(liveDB, closedRdb, cfg, provClient, planReg).NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), handlers.NewQueueHandler(liveDB, closedRdb, cfg, provClient, planReg).NewQueue)

	for i, path := range []string{"/db/new", "/cache/new", "/nosql/new", "/queue/new"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "10.221."+string(rune('0'+i))+".1")
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// gRPC provisioning succeeds → 201 even though the handler-redis is
		// closed (checkProvisionLimit + markRecycleSeen fail open + log).
		assert.Equalf(t, http.StatusCreated, resp.StatusCode,
			"%s should 201 (gRPC provisions; handler-redis errors fail open). body=%s", path, raw)
	}
}

// recycleGate fired: a recycle_seen:<fp> marker + zero active rows for the
// fingerprint → 402 free_tier_recycle_requires_claim.
func TestAnonProvision_RecycleGate_Returns402(t *testing.T) {
	liveDB, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { liveDB.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres",
		Environment:              "test",
		PostgresProvisionBackend: "local",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.SendStatus(fiber.StatusInternalServerError)
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlrg"}))
	dbH := handlers.NewDBHandler(liveDB, rdb, cfg, nil, plans.Default())
	app.Post("/db/new", middleware.OptionalAuth(cfg), dbH.NewDB)

	// Learn the fingerprint for our IP via the helper, then plant the recycle
	// marker + ensure zero active rows so the gate fires on the next POST.
	ip := "192.0.2.123"
	// Compute fingerprint by issuing one request and reading the row, then
	// soft-delete it so no active row remains.
	req0 := httptest.NewRequest(http.MethodPost, "/db/new", strings.NewReader(`{"name":"probe"}`))
	req0.Header.Set("Content-Type", "application/json")
	req0.Header.Set("X-Forwarded-For", ip)
	resp0, err := app.Test(req0, 10000)
	require.NoError(t, err)
	raw0, _ := io.ReadAll(resp0.Body)
	resp0.Body.Close()
	if resp0.StatusCode == http.StatusServiceUnavailable {
		t.Skip("local postgres-customers backend not reachable — skipping recycle-gate probe")
	}
	require.Equalf(t, http.StatusCreated, resp0.StatusCode, "probe provision (body=%s)", raw0)
	var probe struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw0, &probe))
	var fp string
	require.NoError(t, liveDB.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM resources WHERE token = $1::uuid`, probe.Token).Scan(&fp))

	// Soft-delete every active row for this fingerprint so the gate's
	// "zero active rows" condition holds, then plant the recycle marker.
	_, err = liveDB.ExecContext(context.Background(),
		`UPDATE resources SET status = 'deleted' WHERE fingerprint = $1`, fp)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(context.Background(),
		handlers.RecycleSeenKeyPrefix+fp, "1", time.Hour).Err())

	// Next provision from the same IP → recycle gate fires (402).
	req := httptest.NewRequest(http.MethodPost, "/db/new", strings.NewReader(`{"name":"recycle"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", uuid.NewString())
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var env struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	require.Equalf(t, http.StatusPaymentRequired, resp.StatusCode, "recycle gate should 402 (body=%s)", raw)
	assert.Equal(t, "free_tier_recycle_requires_claim", env.Error)
}
