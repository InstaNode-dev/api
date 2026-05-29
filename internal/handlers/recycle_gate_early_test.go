package handlers_test

// recycle_gate_early_test.go — coverage pin for API-7 (QA 2026-05-29):
// the recycle gate now fires from the EARLIER position in storage/webhook/
// vector anonymous handlers (before checkProvisionLimit), so the existing
// recycle-gate fired-branch tests at the LATER position are no longer
// reachable for those handlers. This file adds the missing per-handler
// pin so a regression to the old ordering immediately reds.
//
// The cache/nosql/queue pin lives in anon_paths_provarms_test.go
// (TestAnonRecycleGate_Cache/NoSQL/Queue). The db pin lives there too
// (TestAnonRecycleGate_DB). storage/webhook/vector need their own
// fixtures because they're not mounted on the gRPC fixture.

import (
	"context"
	"database/sql"
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

// recycleGateApp mounts a single anonymous-path handler with the minimum
// middleware needed to drive a recycle-gate-fired path: RequestID + Fingerprint
// (for fp computation) + OptionalAuth (no-op for anonymous) + the handler.
// Idempotency middleware intentionally omitted — we want every POST to actually
// reach the handler.
func recycleGateApp(t *testing.T, mount func(app *fiber.App, db *sql.DB, rdb *redis.Client, cfg *config.Config)) (*fiber.App, *sql.DB, *redis.Client) {
	t.Helper()
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := &config.Config{
		Port:            "8080",
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "postgres,redis,mongodb,queue,webhook,storage,vector",
		Environment:     "test",
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())

	mount(app, db, rdb, cfg)
	return app, db, rdb
}

// plantRecycleMarker computes the fingerprint via the middleware's helper
// (X-Forwarded-For + ASN) and writes the recycle-seen Redis marker so the
// gate will fire on the next request from the same IP. The fingerprint for
// an unknown IP comes purely from /24 subnet + ASN, so two calls from the
// same IP produce the same fp deterministically.
func plantRecycleMarker(t *testing.T, app *fiber.App, db *sql.DB, rdb *redis.Client, probePath, ip string, probeBody string) string {
	t.Helper()
	// Issue one cache /probe call (cache is always available + doesn't depend
	// on a real backend) to learn the fp. The handler creates a row whose
	// fingerprint we read back. We use cache because it's the simplest
	// anonymous flow that doesn't need a real provisioner.
	req := httptest.NewRequest(http.MethodPost, probePath, strings.NewReader(probeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", uuid.NewString())
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "probe call body: %s", raw)

	// Extract token then look up the fingerprint from the row.
	var probe struct {
		Token string `json:"token"`
	}
	require.NoError(t, parseProbeJSON(raw, &probe))

	var fp string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM resources WHERE token = $1::uuid`, probe.Token).Scan(&fp))

	// Soft-delete every active row for this fp so the gate's "zero active
	// rows" condition is satisfied. Plant the marker.
	_, err = db.ExecContext(context.Background(),
		`UPDATE resources SET status = 'deleted' WHERE fingerprint = $1`, fp)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(context.Background(),
		handlers.RecycleSeenKeyPrefix+fp, "1", time.Hour).Err())
	return fp
}

// parseProbeJSON is a tiny JSON decoder helper kept in this file so the test
// has zero dependencies on the larger provarms helpers (which need a gRPC
// fixture). We only need the token field.
func parseProbeJSON(raw []byte, out *struct {
	Token string `json:"token"`
}) error {
	return json.Unmarshal(raw, out)
}

// TestRecycleGate_EarlyFire_Storage covers the API-7 reorder: storage's
// recycle gate now fires from the early position in NewStorage. Pin: with
// a planted marker and zero active rows, /storage/new must 402.
func TestRecycleGate_EarlyFire_Storage(t *testing.T) {
	provider := newDOSpacesProvider(t)
	app, db, rdb := recycleGateApp(t, func(app *fiber.App, db *sql.DB, rdb *redis.Client, cfg *config.Config) {
		// Both /cache/new (probe to learn fp) and /storage/new mounted.
		cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, plans.Default())
		storageH := handlers.NewStorageHandler(db, rdb, cfg, provider, plans.Default())
		app.Post("/cache/new", middleware.OptionalAuth(cfg), cacheH.NewCache)
		app.Post("/storage/new", middleware.OptionalAuth(cfg), storageH.NewStorage)
	})
	ip := "10.220.0.1"
	plantRecycleMarker(t, app, db, rdb, "/cache/new", ip, `{"name":"probe"}`)

	// Now /storage/new from the same IP must 402.
	req := httptest.NewRequest(http.MethodPost, "/storage/new", strings.NewReader(`{"name":"recycle"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", uuid.NewString())
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	require.Equalf(t, http.StatusPaymentRequired, resp.StatusCode,
		"/storage/new recycle gate must 402 (body=%s)", raw)
	assert.Contains(t, string(raw), "free_tier_recycle_requires_claim")
}

// TestRecycleGate_EarlyFire_Webhook — same shape for /webhook/new.
func TestRecycleGate_EarlyFire_Webhook(t *testing.T) {
	app, db, rdb := recycleGateApp(t, func(app *fiber.App, db *sql.DB, rdb *redis.Client, cfg *config.Config) {
		cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, plans.Default())
		webhookH := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
		app.Post("/cache/new", middleware.OptionalAuth(cfg), cacheH.NewCache)
		app.Post("/webhook/new", middleware.OptionalAuth(cfg), webhookH.NewWebhook)
	})
	ip := "10.221.0.1"
	plantRecycleMarker(t, app, db, rdb, "/cache/new", ip, `{"name":"probe"}`)

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", strings.NewReader(`{"name":"recycle"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", uuid.NewString())
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	require.Equalf(t, http.StatusPaymentRequired, resp.StatusCode,
		"/webhook/new recycle gate must 402 (body=%s)", raw)
	assert.Contains(t, string(raw), "free_tier_recycle_requires_claim")
}

// TestRecycleGate_EarlyFire_Vector — same shape for /vector/new.
func TestRecycleGate_EarlyFire_Vector(t *testing.T) {
	app, db, rdb := recycleGateApp(t, func(app *fiber.App, db *sql.DB, rdb *redis.Client, cfg *config.Config) {
		cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, plans.Default())
		vectorH := handlers.NewVectorHandler(db, rdb, cfg, nil, plans.Default())
		app.Post("/cache/new", middleware.OptionalAuth(cfg), cacheH.NewCache)
		app.Post("/vector/new", middleware.OptionalAuth(cfg), vectorH.NewVector)
	})
	ip := "10.222.0.1"
	plantRecycleMarker(t, app, db, rdb, "/cache/new", ip, `{"name":"probe"}`)

	req := httptest.NewRequest(http.MethodPost, "/vector/new", strings.NewReader(`{"name":"recycle"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", uuid.NewString())
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	require.Equalf(t, http.StatusPaymentRequired, resp.StatusCode,
		"/vector/new recycle gate must 402 (body=%s)", raw)
	assert.Contains(t, string(raw), "free_tier_recycle_requires_claim")
}
