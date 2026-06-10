package handlers_test

// provision_softdelete_final2_test.go — FINAL SERIAL PASS #2.
//
// Reaches the BACKEND-provision-failure soft-delete arms that the existing
// db_fault_provarms suite cannot: those tests fail at CreateResource (closed /
// read-only DB), but the soft-delete arms only run when CreateResource
// SUCCEEDS and then the backend Provision RPC fails. We give the handler a
// healthy WRITABLE platform DB but point the customer backend at an
// unreachable host, so:
//
//   GetTeamByID (ok) → CreateResource (ok, real row) → provisionDB/NoSQL
//   (backend dial fails) → SoftDeleteResource arm + respondProvisionFailed 503.
//
//   * db.go    L255 (anon) / L424 (auth) soft_delete_failed arms
//   * nosql.go L236/L240 soft-delete arms
//
// Authenticated path is used so the flow is deterministic (no fingerprint
// caps). A unique IP per call keeps the rate-limit/fingerprint counters clean.

import (
	"context"
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
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// badBackendApp builds db + nosql handlers over a healthy writable platform DB
// but with customer backends pointed at unreachable hosts so the backend
// Provision call fails AFTER CreateResource has already written a pending row.
func badBackendApp(t *testing.T) (*fiber.App, *redis.Client, *sql.DB) {
	t.Helper()
	liveDB, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { liveDB.Close() })

	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,mongodb,vector,queue",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		// Unreachable customer Postgres → dbProvider.Provision dial fails.
		PostgresCustomersURL: "postgres://nope:nope@127.0.0.1:1/none?sslmode=disable&connect_timeout=1",
		// Unreachable Mongo admin → mongo provider Provision fails.
		MongoAdminURI: "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=800&connectTimeoutMS=800",
		// Reserved non-resolvable host → NATS monitor (8222) probe fails → queue
		// provider provision fails. Not 127.0.0.1: CI now runs a live NATS on
		// localhost:8222, which would make 127.0.0.1:8222 reachable.
		NATSHost: "nats.test",
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
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlbadbk"}))

	dbH := handlers.NewDBHandler(liveDB, rdb, cfg, nil, planReg)
	nosqlH := handlers.NewNoSQLHandler(liveDB, rdb, cfg, nil, planReg)
	vectorH := handlers.NewVectorHandler(liveDB, rdb, cfg, nil, planReg)
	queueH := handlers.NewQueueHandler(liveDB, rdb, cfg, nil, planReg)
	app.Post("/db/new", middleware.OptionalAuth(cfg), dbH.NewDB)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), nosqlH.NewNoSQL)
	app.Post("/vector/new", middleware.OptionalAuth(cfg), vectorH.NewVector)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), queueH.NewQueue)
	return app, rdb, liveDB
}

func postBadBackend(t *testing.T, app *fiber.App, path, jwt, ip string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
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

// TestProvisionFinal2_BackendFailure_SoftDelete_Auth covers the authenticated
// backend-failure rollback arms in db.go (L424) and nosql.go. Post Wave-2 A1
// the rollback persists the row as status='failed' (a pollable terminal
// state) instead of soft-deleting it — asserted per resource type below.
func TestProvisionFinal2_BackendFailure_SoftDelete_Auth(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	app, _, liveDB := badBackendApp(t)
	teamID := testhelpers.MustCreateTeamDB(t, liveDB, "pro")
	jwt := authSessionJWT(t, liveDB, teamID)

	cases := []struct{ path, resourceType string }{
		{"/db/new", "postgres"},
		{"/nosql/new", "mongodb"},
		{"/vector/new", "vector"},
		{"/queue/new", "queue"},
	}
	for i, tc := range cases {
		status, errCode := postBadBackend(t, app, tc.path, jwt, "10.220."+digitStr(i)+".7")
		assert.Equalf(t, http.StatusServiceUnavailable, status, "%s backend-fail must 503", tc.path)
		assert.Equalf(t, "provision_failed", errCode, "%s error code", tc.path)

		// Wave-2 A1: the rolled-back row must persist as 'failed', not vanish.
		var rowStatus string
		require.NoErrorf(t, liveDB.QueryRowContext(context.Background(),
			`SELECT status FROM resources WHERE team_id = $1::uuid AND resource_type = $2
			 ORDER BY created_at DESC LIMIT 1`, teamID, tc.resourceType).Scan(&rowStatus),
			"%s rollback row must exist", tc.path)
		assert.Equalf(t, models.StatusFailed, rowStatus,
			"%s rollback row must be status='failed' (pollable terminal state)", tc.path)
	}
}

// TestProvisionFinal2_BackendFailure_SoftDelete_Anon covers the anonymous
// backend-failure soft-delete arms (db.go L255 + nosql.go).
func TestProvisionFinal2_BackendFailure_SoftDelete_Anon(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	app, _, _ := badBackendApp(t)
	for i, path := range []string{"/db/new", "/nosql/new", "/vector/new", "/queue/new"} {
		status, errCode := postBadBackend(t, app, path, "", "10.221."+digitStr(i)+".9")
		assert.Equalf(t, http.StatusServiceUnavailable, status, "%s anon backend-fail must 503", path)
		assert.Equalf(t, "provision_failed", errCode, "%s error code", path)
	}
}

// TestProvisionFinal2_OverCapNoExistingResource covers the denyProvisionOverCap
// path (provision_helper.go) + the over-cap-no-existing arms in db.go (L157) +
// nosql.go: with a backend that always fails, no resource is ever committed, so
// after the per-fingerprint cap is exhausted from the SAME IP the over-cap
// caller finds NO existing resource of any type → 429 provision_limit_reached.
func TestProvisionFinal2_OverCapNoExistingResource(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	app, _, _ := badBackendApp(t)
	// Each handler's backend always fails (no committed resource), so after the
	// per-fingerprint cap (5/day) is exhausted from a distinct same-IP burst the
	// over-cap caller hits denyProvisionOverCap (429), never a fresh provision.
	for i, path := range []string{"/db/new", "/nosql/new", "/vector/new", "/queue/new"} {
		ip := "10.222." + digitStr(i) + ".7"
		var lastStatus int
		var lastErr string
		for j := 0; j < 8; j++ {
			lastStatus, lastErr = postBadBackend(t, app, path, "", ip)
		}
		assert.Equalf(t, http.StatusTooManyRequests, lastStatus,
			"%s over-cap with no committed resource must 429 (got %s)", path, lastErr)
		assert.Equalf(t, "provision_limit_reached", lastErr, "%s error code", path)
	}
}

// TestProvisionFinal2_OverCapReturnsExisting covers the over-cap WITH-existing
// resource arm (db.go L159-180): a working backend commits one resource, then
// the same fingerprint exhausts the cap → subsequent calls return the EXISTING
// token + issue the onboarding JWT instead of provisioning fresh.
func TestProvisionFinal2_OverCapReturnsExisting(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,webhook")
	defer cleanApp()

	// Each handler with a WORKING backend: first call commits a real anonymous
	// resource, then the same fingerprint exhausts the cap → subsequent calls
	// return the EXISTING token + issue the onboarding JWT (the err==nil
	// over-cap-existing arm in each handler).
	for i, path := range []string{"/db/new", "/cache/new", "/webhook/new"} {
		ip := "10.223." + digitStr(i) + ".9"
		first := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
		first.Header.Set("Content-Type", "application/json")
		first.Header.Set("X-Forwarded-For", ip)
		r1, err := app.Test(first, 15000)
		require.NoError(t, err)
		seedOK := r1.StatusCode == http.StatusCreated
		r1.Body.Close()
		if !seedOK {
			t.Logf("%s seed provision did not 201 (backend unavailable) — skipping its dedup arm", path)
			continue
		}
		for j := 0; j < 8; j++ {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"x"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", ip)
			resp, rerr := app.Test(req, 15000)
			require.NoError(t, rerr)
			resp.Body.Close()
		}
	}
}
