package handlers_test

// db_fault_provarms_test.go — drives the team-lookup-failure (503
// team_lookup_failed) branch of every authenticated provisioning handler by
// pointing the handler at a CLOSED *sql.DB. A closed DB makes GetTeamByID
// return an error after the JWT auth middleware has already populated a
// (syntactically valid) team_id, so control reaches the team_lookup_failed
// branch that the happy-path fixtures never exercise.
//
// The JWT itself is validated by middleware against cfg.JWTSecret (no DB), so a
// closed DB only trips once the handler queries it — exactly the branch we want.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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

// testDSN returns the platform test DB DSN (TEST_DATABASE_URL with a default
// matching testhelpers).
func testDSN() string {
	if d := os.Getenv("TEST_DATABASE_URL"); d != "" {
		return d
	}
	return "postgres://postgres:postgres@127.0.0.1:5432/instant_dev_test?sslmode=disable"
}

// closedDBFixture wires the four provisioning handlers against a CLOSED DB so
// the authenticated path's GetTeamByID fails. A live Redis is still needed for
// the rate-limit + auth middleware chain.
type closedDBFixture struct {
	app *fiber.App
	rdb *redis.Client
}

func setupClosedDBFixture(t *testing.T) (closedDBFixture, string) {
	t.Helper()
	// A real DB to mint a valid team+user+JWT, then we CLOSE a SEPARATE handle
	// so the handler's queries fail while the JWT stays valid.
	liveDB, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { liveDB.Close() })
	teamID := testhelpers.MustCreateTeamDB(t, liveDB, "pro")
	jwt := authSessionJWT(t, liveDB, teamID)

	dsn := testDSN()
	closed, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, closed.Close()) // every query now errors

	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

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
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlclosed"}))

	dbH := handlers.NewDBHandler(closed, rdb, cfg, nil, planReg)
	cacheH := handlers.NewCacheHandler(closed, rdb, cfg, nil, planReg)
	nosqlH := handlers.NewNoSQLHandler(closed, rdb, cfg, nil, planReg)
	queueH := handlers.NewQueueHandler(closed, rdb, cfg, nil, planReg)
	storageH := handlers.NewStorageHandler(closed, rdb, cfg, newDOSpacesProvider(t), planReg)

	app.Post("/db/new", middleware.OptionalAuth(cfg), dbH.NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), cacheH.NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), nosqlH.NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), queueH.NewQueue)
	app.Post("/storage/new", middleware.OptionalAuth(cfg), storageH.NewStorage)

	return closedDBFixture{app: app, rdb: rdb}, jwt
}

func postClosed(t *testing.T, fx closedDBFixture, path, jwt string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.200.0.1")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := fx.app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env.Error
}

func TestAuthProvision_TeamLookupFailure_AllHandlers(t *testing.T) {
	fx, jwt := setupClosedDBFixture(t)
	for _, path := range []string{"/db/new", "/cache/new", "/nosql/new", "/queue/new", "/storage/new"} {
		status, errCode := postClosed(t, fx, path, jwt)
		assert.Equalf(t, http.StatusServiceUnavailable, status, "%s should 503 on DB fault", path)
		assert.Equalf(t, "team_lookup_failed", errCode, "%s error code", path)
	}
}

// Anonymous provision against a closed DB: checkProvisionLimit (redis) passes,
// recycleGate's DB lookup fails-open, then CreateResource fails on the closed DB
// → the create_resource_failed branch returns 503 provision_failed. Covers that
// branch in every anonymous handler arm.
func TestAnonProvision_CreateResourceFailure_AllHandlers(t *testing.T) {
	fx, _ := setupClosedDBFixture(t)
	for i, path := range []string{"/db/new", "/cache/new", "/nosql/new", "/queue/new", "/storage/new"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		// Distinct IP per handler so each gets its own fingerprint + cap counter.
		req.Header.Set("X-Forwarded-For", "10.201."+digitStr(i)+".1")
		resp, err := fx.app.Test(req, 10000)
		require.NoError(t, err)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var env struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &env)
		assert.Equalf(t, http.StatusServiceUnavailable, resp.StatusCode, "%s anon create-fail should 503", path)
		assert.Equalf(t, "provision_failed", env.Error, "%s error code", path)
	}
}

func digitStr(i int) string { return string(rune('0' + i)) }

// readOnlyDSN appends a session option that makes the connection reject writes
// (default_transaction_read_only=on). SELECTs succeed; INSERT/UPDATE fail —
// exactly the shape needed to reach the authenticated-path create_resource_failed
// branch (team SELECT ok → CreateResource INSERT fails).
func readOnlyDSN() string {
	d := testDSN()
	sep := "?"
	if strings.Contains(d, "?") {
		sep = "&"
	}
	return d + sep + "options=-c%20default_transaction_read_only%3Don"
}

// Authenticated provision against a READ-ONLY DB: GetTeamByID (SELECT) succeeds
// but CreateResource (INSERT) fails → the create_resource_failed branch returns
// 503 provision_failed in every authenticated handler arm.
func TestAuthProvision_CreateResourceFailure_AllHandlers(t *testing.T) {
	liveDB, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { liveDB.Close() })
	teamID := testhelpers.MustCreateTeamDB(t, liveDB, "pro")
	jwt := authSessionJWT(t, liveDB, teamID)

	roDB, err := sql.Open("postgres", readOnlyDSN())
	require.NoError(t, err)
	t.Cleanup(func() { roDB.Close() })

	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

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
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlro"}))

	app.Post("/db/new", middleware.OptionalAuth(cfg), handlers.NewDBHandler(roDB, rdb, cfg, nil, planReg).NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), handlers.NewCacheHandler(roDB, rdb, cfg, nil, planReg).NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), handlers.NewNoSQLHandler(roDB, rdb, cfg, nil, planReg).NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), handlers.NewQueueHandler(roDB, rdb, cfg, nil, planReg).NewQueue)
	app.Post("/storage/new", middleware.OptionalAuth(cfg), handlers.NewStorageHandler(roDB, rdb, cfg, newDOSpacesProvider(t), planReg).NewStorage)

	for _, path := range []string{"/db/new", "/cache/new", "/nosql/new", "/queue/new", "/storage/new"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "10.202.0.1")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, rerr := app.Test(req, 10000)
		require.NoError(t, rerr)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var env struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &env)
		assert.Equalf(t, http.StatusServiceUnavailable, resp.StatusCode, "%s auth create-fail should 503 (body=%s)", path, raw)
		assert.Equalf(t, "provision_failed", env.Error, "%s error code", path)
	}
}

// invalid team id in JWT → 400 invalid_team across all authenticated handlers.
func TestAuthProvision_InvalidTeamID_AllHandlers(t *testing.T) {
	fx, _ := setupClosedDBFixture(t)
	badJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
	for _, path := range []string{"/db/new", "/cache/new", "/nosql/new", "/queue/new", "/storage/new"} {
		status, errCode := postClosed(t, fx, path, badJWT)
		assert.Equalf(t, http.StatusBadRequest, status, "%s should 400 on bad team id", path)
		assert.Equalf(t, "invalid_team", errCode, "%s error code", path)
	}
}
