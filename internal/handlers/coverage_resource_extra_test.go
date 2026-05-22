package handlers_test

// coverage_resource_extra_test.go — drives the remaining low-coverage paths in
// storage.go (full credential-mode provision via a real MinIO backend),
// resource_metrics.go (every tier-gate + window branch), and the rotate /
// pause provider helpers that the existing fixtures only reached at the
// status-flip layer.
//
// The storage app here wires a real per-tenant-credential (PrefixScopedKeys=true)
// MinIO provider against the test-minio container so decideStorageMode returns
// "credential" and the full provisionStorage → buildStorageResponse →
// newStorageAuthenticated / storageAnonymousLimits chain executes end-to-end.
// When MinIO is not reachable the storage tests skip cleanly.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/testhelpers"
)

// ───────────────────────────────────────────────────────────────────────────
// Storage app wired to a real MinIO (PrefixScopedKeys=true) backend.
// ───────────────────────────────────────────────────────────────────────────

func minioEndpoint() string {
	if v := os.Getenv("TEST_MINIO_ENDPOINT"); v != "" {
		return v
	}
	return "127.0.0.1:9100"
}

// newMinioStorageProvider builds a credential-mode storage provider against the
// test-minio container, or returns nil if MinIO can't be reached.
func newMinioStorageProvider(t *testing.T) *storageprovider.Provider {
	t.Helper()
	sp, err := storageprovider.New(minioEndpoint(), "http://"+minioEndpoint(), "minioadmin", "minioadmin", "instant-shared")
	if err != nil {
		t.Skipf("MinIO storage provider unavailable: %v", err)
	}
	// Probe an actual provision so we skip (not fail) when admin API is down.
	if _, perr := sp.Provision(context.Background(), uuid.NewString(), "anonymous"); perr != nil {
		t.Skipf("MinIO storage provider not reachable: %v", perr)
	}
	return sp
}

// storageFixture is an authedFixture whose app has a real credential-mode
// storage backend wired, so /storage/new runs end-to-end.
type storageFixture struct {
	app    *fiber.App
	jwt    string
	teamID string
	rdb    *redis.Client
	db     *sql.DB
}

func storageTestConfig() *config.Config {
	customersURL := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if customersURL == "" {
		customersURL = "postgres://postgres:postgres@127.0.0.1:5432/instant_customers?sslmode=disable"
	}
	return &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "storage",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		PostgresCustomersURL:     customersURL,
		MinioEndpoint:            minioEndpoint(),
		MinioPublicEndpoint:      "http://" + minioEndpoint(),
		MinioRootUser:            "minioadmin",
		MinioRootPassword:        "minioadmin",
		MinioBucketName:          "instant-shared",
	}
}

// storageErrorHandler mirrors the production router's ErrorHandler: it swallows
// the ErrResponseWritten sentinel (the handler already committed the body via
// respondError) so Fiber's default 500 doesn't overwrite it.
func storageErrorHandler(c *fiber.Ctx, err error) error {
	if errors.Is(err, handlers.ErrResponseWritten) {
		return nil
	}
	if c.Response().StatusCode() >= 400 {
		return nil
	}
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	return c.Status(code).JSON(fiber.Map{"error": "internal_error"})
}

func setupStorageFixture(t *testing.T, planTier string) storageFixture {
	t.Helper()
	sp := newMinioStorageProvider(t)
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := storageTestConfig()
	planReg := plans.Default()
	app := fiber.New(fiber.Config{
		ErrorHandler: storageErrorHandler,
		ProxyHeader:  "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())

	storageH := handlers.NewStorageHandler(db, rdb, cfg, sp, planReg)
	app.Post("/storage/new",
		middleware.OptionalAuth(cfg),
		middleware.Idempotency(rdb, "storage.new"),
		storageH.NewStorage,
	)
	t.Cleanup(func() { app.Shutdown() })

	var teamID, jwtTok string
	if planTier != "" {
		teamID = testhelpers.MustCreateTeamDB(t, db, planTier)
		email := testhelpers.UniqueEmail(t)
		var userID string
		require.NoError(t, db.QueryRowContext(context.Background(),
			`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
			teamID, email,
		).Scan(&userID))
		jwtTok = testhelpers.MustSignSessionJWT(t, userID, teamID, email)
	}
	return storageFixture{app: app, jwt: jwtTok, teamID: teamID, rdb: rdb, db: db}
}

func storagePost(t *testing.T, fix storageFixture, body, ip string, authed bool) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/storage/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if authed {
		req.Header.Set("Authorization", "Bearer "+fix.jwt)
	}
	resp, err := fix.app.Test(req, 15000)
	require.NoError(t, err)
	return resp
}

// TestStorageNew_CredentialMode_Authenticated drives newStorageAuthenticated +
// provisionStorage + buildStorageResponse (credential arm) for a paid tier.
func TestStorageNew_CredentialMode_Authenticated(t *testing.T) {
	fix := setupStorageFixture(t, "pro")
	resp := storagePost(t, fix, `{"name":"app-bucket"}`, "10.40.0.1", true)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "pro", body["tier"])
	assert.Equal(t, "app-bucket", body["name"])
	// credential mode → access_key_id present.
	assert.NotEmpty(t, body["access_key_id"], "credential mode must surface access_key_id")
	assert.NotEmpty(t, body["secret_access_key"])
	assert.Equal(t, "prefix-scoped", body["mode"])
	limits, ok := body["limits"].(map[string]any)
	require.True(t, ok)
	assert.NotNil(t, limits["storage_mb"])
}

// TestStorageNew_CredentialMode_Anonymous drives the anonymous arm:
// CreateResource → provisionStorage → buildStorageResponse → storageAnonymousLimits.
func TestStorageNew_CredentialMode_Anonymous(t *testing.T) {
	fix := setupStorageFixture(t, "")
	resp := storagePost(t, fix, `{"name":"anon-bucket"}`, "10.41.0.1", false)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "anonymous", body["tier"])
	assert.NotEmpty(t, body["access_key_id"])
	assert.NotEmpty(t, body["upgrade_jwt"])
	assert.NotEmpty(t, body["expires_at"])
	limits, ok := body["limits"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "24h", limits["expires_in"])
}

// TestStorageNew_AnonymousDedupReturnsExisting drives the over-cap dedup branch:
// the same fingerprint provisioning storage 6+ times trips checkProvisionLimit
// and returns the existing resource (credentials_note path).
func TestStorageNew_AnonymousDedupReturnsExisting(t *testing.T) {
	fix := setupStorageFixture(t, "")
	const ip = "10.42.0.7"
	sawDedup := false
	saw429 := false
	for i := 0; i < 8; i++ {
		// Unique body per iteration so the Idempotency middleware doesn't serve
		// the cached first response — each request must reach the handler to
		// bump the per-fingerprint daily INCR past the cap.
		resp := storagePost(t, fix, fmt.Sprintf(`{"name":"dedup-bucket-%d"}`, i), ip, false)
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		// A dedup hit on storage carries the credentials_note marker; an
		// over-cap caller with no committed row yet gets 429.
		if body["credentials_note"] != nil {
			sawDedup = true
			assert.NotEmpty(t, body["token"])
			break
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			saw429 = true
		}
	}
	assert.True(t, sawDedup || saw429, "expected a storage dedup hit or 429 after exceeding the daily cap")
}

// TestStorageNew_ServiceDisabled returns 503 when storage is not enabled.
func TestStorageNew_ServiceDisabled(t *testing.T) {
	sp := newMinioStorageProvider(t)
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })
	cfg := storageTestConfig()
	cfg.EnabledServices = "redis" // storage disabled
	app := fiber.New(fiber.Config{ErrorHandler: storageErrorHandler, ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	storageH := handlers.NewStorageHandler(db, rdb, cfg, sp, plans.Default())
	app.Post("/storage/new", middleware.OptionalAuth(cfg), storageH.NewStorage)
	t.Cleanup(func() { app.Shutdown() })

	req := httptest.NewRequest(http.MethodPost, "/storage/new", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.43.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestStorageNew_Authenticated_QuotaExceeded seeds a storage row whose
// storage_bytes already exceeds the hobby tier cap, then provisions again as
// that team → 402 storage_limit_reached (newStorageAuthenticated quota gate).
func TestStorageNew_Authenticated_QuotaExceeded(t *testing.T) {
	fix := setupStorageFixture(t, "hobby")
	// hobby storage cap is 512 MB; seed a row at 600 MB so the next provision
	// trips the SumStorageBytesByTeamAndType >= limit gate.
	_, err := fix.db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, name, storage_bytes)
		VALUES ($1::uuid, 'storage', 'hobby', 'active', 'big', $2)
	`, fix.teamID, int64(600)*1024*1024)
	require.NoError(t, err)

	resp := storagePost(t, fix, `{"name":"over-quota"}`, "10.45.0.1", true)
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "storage_limit_reached", body["error"])
	assert.NotEmpty(t, body["agent_action"])
}

// ───────────────────────────────────────────────────────────────────────────
// resource_metrics.go — GET /api/v1/resources/:id/metrics, every branch.
// ───────────────────────────────────────────────────────────────────────────

// insertResource inserts an active resource owned by the fixture team and
// returns its token.
func insertOwnedResource(t *testing.T, fix authedFixture, rtype string) string {
	t.Helper()
	var token string
	require.NoError(t, fix.db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, name)
		VALUES ($1::uuid, $2, 'hobby', 'active', 'metrics-target')
		RETURNING token::text
	`, fix.teamID, rtype).Scan(&token))
	return token
}

func TestResourceMetrics_BadUUID_400(t *testing.T) {
	fix := setupAuthedFixture(t, "pro")
	resp := authedGet(t, fix, "/api/v1/resources/not-a-uuid/metrics")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestResourceMetrics_NotFound_404(t *testing.T) {
	fix := setupAuthedFixture(t, "pro")
	resp := authedGet(t, fix, "/api/v1/resources/"+uuid.NewString()+"/metrics")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestResourceMetrics_CrossTeam_404(t *testing.T) {
	owner := setupAuthedFixture(t, "pro")
	other := setupAuthedFixture(t, "pro")
	token := insertOwnedResource(t, owner, "postgres")
	resp := authedGet(t, other, "/api/v1/resources/"+token+"/metrics")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestResourceMetrics_AnonymousFreeTier_402(t *testing.T) {
	// A "free" plan team hits the upgrade wall (tierCap == 0).
	fix := setupAuthedFixture(t, "free")
	token := insertOwnedResource(t, fix, "postgres")
	resp := authedGet(t, fix, "/api/v1/resources/"+token+"/metrics")
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"])
	assert.NotEmpty(t, body["agent_action"])
}

func TestResourceMetrics_Hobby_DefaultWindow_OK(t *testing.T) {
	fix := setupAuthedFixture(t, "hobby")
	token := insertOwnedResource(t, fix, "postgres")
	resp := authedGet(t, fix, "/api/v1/resources/"+token+"/metrics")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "stub", body["data_source"])
	assert.EqualValues(t, 3600, body["window_seconds"])
	m, ok := body["metrics"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, m, "latency_p50_ms")
	assert.Contains(t, m, "storage_bytes")
}

func TestResourceMetrics_Hobby_WindowTooLarge_402(t *testing.T) {
	fix := setupAuthedFixture(t, "hobby")
	token := insertOwnedResource(t, fix, "redis")
	resp := authedGet(t, fix, "/api/v1/resources/"+token+"/metrics?window=24h")
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"])
	assert.Contains(t, body["agent_action"], "hobby")
}

func TestResourceMetrics_Pro_24h_OK(t *testing.T) {
	fix := setupAuthedFixture(t, "pro")
	token := insertOwnedResource(t, fix, "mongodb")
	resp := authedGet(t, fix, "/api/v1/resources/"+token+"/metrics?window=24h")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.EqualValues(t, 86400, body["window_seconds"])
}

func TestResourceMetrics_Growth_7d_OK(t *testing.T) {
	fix := setupAuthedFixture(t, "growth")
	token := insertOwnedResource(t, fix, "postgres")
	resp := authedGet(t, fix, "/api/v1/resources/"+token+"/metrics?window=604800")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.EqualValues(t, 604800, body["window_seconds"])
}

func TestResourceMetrics_InvalidWindow_400(t *testing.T) {
	fix := setupAuthedFixture(t, "pro")
	token := insertOwnedResource(t, fix, "postgres")
	for _, w := range []string{"banana", "-5m", "0", "8d", "999h"} {
		resp := authedGet(t, fix, "/api/v1/resources/"+token+"/metrics?window="+w)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Equalf(t, http.StatusBadRequest, resp.StatusCode,
			"window=%q should be 400, got %d (%s)", w, resp.StatusCode, body)
	}
}

func TestResourceMetrics_SecondsVariantWindow_OK(t *testing.T) {
	fix := setupAuthedFixture(t, "pro")
	token := insertOwnedResource(t, fix, "postgres")
	// bare-seconds variant in parseMetricsWindow.
	resp := authedGet(t, fix, "/api/v1/resources/"+token+"/metrics?window=1800")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.EqualValues(t, 1800, body["window_seconds"])
}

func TestResourceMetrics_NoAuth_401(t *testing.T) {
	fix := setupAuthedFixture(t, "pro")
	token := insertOwnedResource(t, fix, "postgres")
	// No Authorization header → RequireAuth on the /api/v1 group 401s.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+token+"/metrics", nil)
	resp, err := fix.app.(*fiber.App).Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────────
// Rotate / pause provider-arm coverage that requires a real customer DB conn.
// ───────────────────────────────────────────────────────────────────────────

// TestRotateCredentials_PostgresURL_BestEffort drives RotateCredentials on a
// postgres resource with a properly AES-encrypted connection_url. The
// provider-side rotatePostgresPassword only runs when CustomerDatabaseURL is
// set (it is not in the default fixture), so this exercises the postgres branch
// entry + URL re-encrypt + persist and returns 200 with a fresh URL.
func TestRotateCredentials_PostgresURL_BestEffort(t *testing.T) {
	fix := setupAuthedFixture(t, "pro")
	_, token := insertResourceWithURL(t, fix.db, fix.teamID, "postgres", "pro",
		"postgres://rot_user:oldpw@pg.example.com:5432/db")
	resp := authedPost(t, fix, "/api/v1/resources/"+token+"/rotate-credentials", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	newURL, _ := body["connection_url"].(string)
	assert.NotContains(t, newURL, "oldpw")
}

var _ = fiber.StatusOK
