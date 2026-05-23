package handlers_test

// storage_provarms_test.go — HTTP-level coverage for the POST /storage/new and
// POST /storage/:token/presign handler arms that the existing storage_test.go
// suite skips because it runs with a nil storage provider (503).
//
// THE TECHNIQUE — offline storage providers.
//   - The "do-spaces" backend issues credentials WITHOUT contacting any
//     server (it returns the master key directly) and has PrefixScopedKeys=
//     false, so it drives the BROKER-mode response branch.
//   - The "s3" backend has PrefixScopedKeys=true and an injectable
//     SetAssumeRoleFunc seam, so a stub STS lets it issue prefix-scoped
//     credentials offline — driving the CREDENTIAL-mode response branch.
//
// A real *storage.Provider is built around each impl and injected into a real
// *handlers.StorageHandler, wired into a Fiber app with the production
// middleware chain. This reaches NewStorage / newStorageAuthenticated /
// buildStorageResponse / PresignStorage / signStorageURL on real HTTP traffic.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
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

	"instant.dev/common/storageprovider"
	s3prov "instant.dev/common/storageprovider/s3"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	storageprov "instant.dev/internal/providers/storage"
	"instant.dev/internal/testhelpers"
)

// newDOSpacesProvider builds an offline do-spaces-backed storage provider
// (PrefixScopedKeys=false → broker mode).
func newDOSpacesProvider(t *testing.T) *storageprov.Provider {
	t.Helper()
	p, err := storageprov.NewFromConfig(storageprovider.Config{
		Backend:      "do-spaces",
		Endpoint:     "nyc3.test.local",
		PublicURL:    "https://s3.test.local",
		Bucket:       "instant-shared",
		MasterKey:    "MASTERKEY",
		MasterSecret: "MASTERSECRET",
		Region:       "nyc3",
		UseTLS:       true,
	})
	require.NoError(t, err)
	return p
}

// newS3PrefixScopedProvider builds an offline s3-backed storage provider with
// a stub AssumeRole so IssueTenantCredentials returns prefix-scoped creds
// without touching AWS (PrefixScopedKeys=true → credential mode).
func newS3PrefixScopedProvider(t *testing.T) *storageprov.Provider {
	t.Helper()
	p, err := storageprov.NewFromConfig(storageprovider.Config{
		Backend:      "s3",
		Endpoint:     "s3.us-east-1.amazonaws.com",
		PublicURL:    "https://s3.test.local",
		Bucket:       "instant-shared",
		Region:       "us-east-1",
		MasterKey:    "AKIAEXAMPLE",
		MasterSecret: "SECRETEXAMPLE",
		AWSRoleARN:   "arn:aws:iam::123456789012:role/instant-storage",
	})
	require.NoError(t, err)
	impl, ok := p.Impl().(*s3prov.Provider)
	require.True(t, ok, "expected *s3.Provider impl")
	impl.SetAssumeRoleFunc(func(_ context.Context, in s3prov.AssumeRoleInput) (*s3prov.AssumeRoleOutput, error) {
		return &s3prov.AssumeRoleOutput{
			AccessKeyID:     "ASIASESSION",
			SecretAccessKey: "sessionsecret",
			SessionToken:    "sessiontoken",
			Expiration:      time.Now().Add(time.Hour),
		}, nil
	})
	return p
}

// storageProvFixture is a Fiber app whose storage handler is wired with an injected
// (offline) storage provider plus a queue handler (unused here but mirrors the
// production chain shape). It supports both anonymous and authenticated POSTs.
type storageProvFixture struct {
	app *fiber.App
	db  *sql.DB
	rdb *redis.Client
	cfg *config.Config
}

func storageProvConfig(badAES bool) *config.Config {
	cfg := &config.Config{
		Port:                 "8080",
		JWTSecret:            testhelpers.TestJWTSecret,
		AESKey:               testhelpers.TestAESKeyHex,
		EnabledServices:      "storage",
		Environment:          "test",
		ObjectStoreBucket:    "instant-shared",
		ObjectStoreEndpoint:  "nyc3.test.local",
		ObjectStoreAccessKey: "MASTERKEY",
		ObjectStoreSecretKey: "MASTERSECRET",
		ObjectStoreRegion:    "nyc3",
		ObjectStoreSecure:    true,
	}
	if badAES {
		cfg.AESKey = "not-a-valid-aes-key"
	}
	return cfg
}

func setupStorageProvFixture(t *testing.T, provider *storageprov.Provider, badAES bool) storageProvFixture {
	t.Helper()
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := storageProvConfig(badAES)
	planReg := plans.Default()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			_ = handlers.WriteFiberError(c, code, "internal_error", err.Error())
			return nil
		},
		ProxyHeader: "X-Forwarded-For",
		BodyLimit:   50 * 1024 * 1024,
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlstor"}))

	storageH := handlers.NewStorageHandler(db, rdb, cfg, provider, planReg)
	app.Post("/storage/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "storage.new"), storageH.NewStorage)
	app.Post("/storage/:token/presign",
		middleware.OptionalAuth(cfg),
		middleware.PresignTokenRateLimit(rdb),
		middleware.Idempotency(rdb, "storage.presign"),
		storageH.PresignStorage,
	)

	return storageProvFixture{app: app, db: db, rdb: rdb, cfg: cfg}
}

type storageResp struct {
	OK              bool           `json:"ok"`
	ID              string         `json:"id"`
	Token           string         `json:"token"`
	Name            string         `json:"name"`
	ConnectionURL   string         `json:"connection_url"`
	Mode            string         `json:"mode"`
	AccessKeyID     string         `json:"access_key_id"`
	SecretAccessKey string         `json:"secret_access_key"`
	SessionToken    string         `json:"session_token"`
	PresignURL      string         `json:"presign_url"`
	AgentAction     string         `json:"agent_action"`
	Prefix          string         `json:"prefix"`
	Tier            string         `json:"tier"`
	Env             string         `json:"env"`
	Limits          map[string]any `json:"limits"`
	Error           string         `json:"error"`
	ExpiresAt       string         `json:"expires_at"`
}

func postStorage(t *testing.T, fx storageProvFixture, ip, jwt, idemKey string, body map[string]any) (*http.Response, storageResp) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(http.MethodPost, "/storage/new", reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-For", ip)
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	var parsed storageResp
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

// ── Broker mode (do-spaces) anonymous success ─────────────────────────────

func TestStorage_Anonymous_BrokerMode_Success(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)

	resp, body := postStorage(t, fx, "10.100.0.1", "", "", map[string]any{"name": "anon-broker"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, body.OK)
	assert.NotEmpty(t, body.Token)
	assert.Equal(t, "broker", body.Mode, "do-spaces has PrefixScopedKeys=false → broker mode")
	assert.Empty(t, body.AccessKeyID, "broker mode must NOT return a long-lived credential")
	assert.NotEmpty(t, body.PresignURL)
	assert.Equal(t, "anonymous", body.Tier)
	assert.NotEmpty(t, body.ExpiresAt)
}

// ── Credential mode (s3 + stub STS) anonymous success ─────────────────────

func TestStorage_Anonymous_CredentialMode_Success(t *testing.T) {
	fx := setupStorageProvFixture(t, newS3PrefixScopedProvider(t), false)

	resp, body := postStorage(t, fx, "10.101.0.1", "", "", map[string]any{"name": "anon-cred"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Equal(t, "credential", "credential") // sanity
	assert.NotEmpty(t, body.AccessKeyID, "prefix-scoped backend issues a long-lived/STS credential")
	assert.NotEmpty(t, body.SecretAccessKey)
	assert.NotEmpty(t, body.SessionToken, "STS path returns a session token")
}

// ── Authenticated credential-mode success (tier echo + limits) ─────────────

func TestStorage_Authenticated_CredentialMode_Success(t *testing.T) {
	fx := setupStorageProvFixture(t, newS3PrefixScopedProvider(t), false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := postStorage(t, fx, "10.102.0.1", jwt, "", map[string]any{"name": "auth-cred"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "pro", body.Tier)
	assert.NotEmpty(t, body.AccessKeyID)
	require.NotNil(t, body.Limits)
	assert.Contains(t, body.Limits, "storage_mb")
}

// ── Authenticated broker-mode success ──────────────────────────────────────

func TestStorage_Authenticated_BrokerMode_Success(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "hobby")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := postStorage(t, fx, "10.103.0.1", jwt, "", map[string]any{"name": "auth-broker"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "hobby", body.Tier)
	assert.Equal(t, "broker", body.Mode)
	assert.Empty(t, body.AccessKeyID)
}

// ── Service disabled / provider nil → 503 ──────────────────────────────────

func TestStorage_ServiceDisabled_Returns503(t *testing.T) {
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := storageProvConfig(false)
	cfg.EnabledServices = "redis" // storage NOT enabled
	app := fiber.New(fiber.Config{
		ProxyHeader: "X-Forwarded-For",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// The 503 service_disabled response is written via respondError,
			// which returns ErrResponseWritten — swallow it so Fiber's default
			// 500 doesn't overwrite the already-committed body. Mirrors prod.
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.SendStatus(fiber.StatusInternalServerError)
		},
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	storageH := handlers.NewStorageHandler(db, rdb, cfg, newDOSpacesProvider(t), plans.Default())
	app.Post("/storage/new", middleware.OptionalAuth(cfg), storageH.NewStorage)

	req := httptest.NewRequest(http.MethodPost, "/storage/new", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.104.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// ── name_required negative path ────────────────────────────────────────────

func TestStorage_MissingName_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)

	resp, body := postStorage(t, fx, "10.105.0.1", "", "", map[string]any{})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "name_required", body.Error)
}

// ── invalid env negative path ──────────────────────────────────────────────

func TestStorage_InvalidEnv_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)

	resp, body := postStorage(t, fx, "10.106.0.1", "", "", map[string]any{"name": "x", "env": "BAD ENV!"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_env", body.Error)
}

// ── Anonymous dedup over-cap returns existing (with prefix + presign_url) ───

func TestStorage_AnonymousDedup_ReturnsExisting(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	ip := "10.107.0.1"
	var firstToken string
	for i := 0; i < 6; i++ {
		resp, body := postStorage(t, fx, ip, "", uuid.NewString(), map[string]any{"name": "dedup-storage"})
		resp.Body.Close()
		require.True(t, body.OK)
		if i < 5 {
			require.Equal(t, http.StatusCreated, resp.StatusCode, "call %d provisions fresh", i+1)
			if i == 0 {
				firstToken = body.Token
			}
		} else {
			require.Equal(t, http.StatusOK, resp.StatusCode, "6th call (over cap) dedups with 200")
			assert.NotEmpty(t, body.ConnectionURL)
			assert.NotEmpty(t, body.Prefix, "dedup response surfaces the recoverable prefix")
			assert.NotEmpty(t, body.PresignURL, "broker-mode dedup surfaces the presign endpoint")
		}
	}
	require.NotEmpty(t, firstToken)
}

// ── persist failure (bad AES) → 503 + best-effort backend deprovision ──────

func TestStorage_Anonymous_PersistFailure_Returns503(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), true) // bad AES key

	resp, body := postStorage(t, fx, "10.108.0.1", "", "", map[string]any{"name": "persistfail"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// setProvisionCounterOverCap sets the per-fingerprint daily provision counter
// to the anonymous cap so the NEXT provision from that fingerprint is over-cap.
func setProvisionCounterOverCap(t *testing.T, rdb *redis.Client, fp string) {
	t.Helper()
	cap := plans.Default().ProvisionLimit("anonymous")
	key := fmt.Sprintf("prov:%s:%s", fp, time.Now().UTC().Format("2006-01-02"))
	require.NoError(t, rdb.Set(context.Background(), key, cap, time.Hour).Err())
}

// fingerprintFor provisions once from ip and returns the platform-assigned
// fingerprint for that anonymous row.
func fingerprintFor(t *testing.T, fx storageProvFixture, ip string) string {
	t.Helper()
	resp, body := postStorage(t, fx, ip, "", uuid.NewString(), map[string]any{"name": "fp-probe"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var fp string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM resources WHERE token = $1::uuid`, body.Token).Scan(&fp))
	require.NotEmpty(t, fp)
	return fp
}

// Storage anonymous cross-service daily-cap fallback: over-cap storage POST with
// no storage row but an existing non-storage anon row for the fingerprint → 429.
func TestStorage_Anonymous_CrossServiceCapFallback_Returns429(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	ip := fmt.Sprintf("198.19.%d.%d", rand.Intn(250)+1, rand.Intn(250)+1)
	fp := fingerprintFor(t, fx, ip)

	// Remove the probe's STORAGE row so the over-cap POST finds NO same-type row
	// (forcing the cross-service fallback), then seed a non-storage anon row so
	// GetActiveResourceByFingerprint (any type) DOES find one → 429.
	_, err := fx.db.ExecContext(context.Background(),
		`DELETE FROM resources WHERE fingerprint = $1 AND resource_type = 'storage'`, fp)
	require.NoError(t, err)
	_, err = fx.db.ExecContext(context.Background(), `
		INSERT INTO resources (resource_type, tier, env, status, fingerprint)
		VALUES ('postgres', 'anonymous', 'development', 'active', $1)
	`, fp)
	require.NoError(t, err)
	setProvisionCounterOverCap(t, fx.rdb, fp)

	resp, body := postStorage(t, fx, ip, "", uuid.NewString(), map[string]any{"name": "xservice-storage"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "provision_limit_reached", body.Error)
}

// Storage anonymous dedup decrypt-failure → provisions fresh (not ciphertext).
func TestStorage_Anonymous_DedupDecryptFailure_ProvisionsFresh(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	ip := fmt.Sprintf("198.20.%d.%d", rand.Intn(250)+1, rand.Intn(250)+1)

	resp, body := postStorage(t, fx, ip, "", uuid.NewString(), map[string]any{"name": "decryptfail-storage"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var fp string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM resources WHERE token = $1::uuid`, body.Token).Scan(&fp))

	// Corrupt the stored connection_url so dedup decrypt fails.
	_, err := fx.db.ExecContext(context.Background(), `
		UPDATE resources SET connection_url = 'not-decryptable'
		WHERE resource_type = 'storage' AND status = 'active' AND team_id IS NULL AND fingerprint = $1
	`, fp)
	require.NoError(t, err)
	setProvisionCounterOverCap(t, fx.rdb, fp)

	resp2, body2 := postStorage(t, fx, ip, "", uuid.NewString(), map[string]any{"name": "decryptfail-storage-2"})
	defer resp2.Body.Close()
	require.Equal(t, http.StatusCreated, resp2.StatusCode, "decrypt-fail dedup must provision fresh")
	assert.NotContains(t, body2.ConnectionURL, "not-decryptable")
}

// ── authenticated storage quota exceeded → 402 storage_limit_reached ───────
//
// Seed an active storage row for the team whose storage_bytes already exceeds
// the tier's storage_mb limit, so the SumStorageBytesByTeamAndType gate trips
// before provisioning.
func TestStorage_Authenticated_QuotaExceeded_Returns402(t *testing.T) {
	fx := setupStorageProvFixture(t, newS3PrefixScopedProvider(t), false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "hobby") // hobby storage limit is small
	jwt := authSessionJWT(t, fx.db, teamID)

	limitMB := plans.Default().StorageLimitMB("hobby", "storage")
	require.Positive(t, limitMB, "test assumes a positive hobby storage cap")
	// Seed a row already at/over the cap.
	_, err := fx.db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env, status, storage_bytes)
		VALUES ($1::uuid, 'storage', 'hobby', 'development', 'active', $2)
	`, teamID, int64(limitMB)*1024*1024+1)
	require.NoError(t, err)

	resp, body := postStorage(t, fx, "10.109.0.1", jwt, "", map[string]any{"name": "over-quota"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "storage_limit_reached", body.Error)
}

// ── anonymous storage byte cap exceeded → 402 storage_limit_reached ────────
//
// Seed an anonymous storage row (team_id NULL) over the anon byte cap for the
// EXACT fingerprint the test IP maps to, then provision from that IP so the
// SumStorageBytesByFingerprintAndType gate trips. The fingerprint is computed
// the same way the Fingerprint middleware does, so we read it back from a
// throwaway provision first and clear any pre-existing rows to avoid
// cross-test /24 collisions on the shared DB.
func TestStorage_Anonymous_ByteCapExceeded_Returns402(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	// A per-run random /24 keeps this isolated from every other test's
	// fingerprint on the shared DB, so the seed provision can't be pre-polluted
	// nor over the daily cap.
	ip := fmt.Sprintf("198.18.%d.%d", rand.Intn(250)+1, rand.Intn(250)+1)

	resp, body := postStorage(t, fx, ip, "", uuid.NewString(), map[string]any{"name": "seed-fp"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "seed provision must succeed")

	var fp string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM resources WHERE token = $1::uuid`, body.Token).Scan(&fp))
	require.NotEmpty(t, fp)

	limitMB := plans.Default().StorageLimitMB("anonymous", "storage")
	require.Positive(t, limitMB)
	_, err := fx.db.ExecContext(context.Background(), `
		INSERT INTO resources (resource_type, tier, env, status, fingerprint, storage_bytes)
		VALUES ('storage', 'anonymous', 'development', 'active', $1, $2)
	`, fp, int64(limitMB)*1024*1024+1)
	require.NoError(t, err)

	// Next provision from the SAME ip (same fingerprint) trips the byte cap.
	// A distinct Idempotency-Key defeats the replay cache so the handler runs.
	resp2, body2 := postStorage(t, fx, ip, "", uuid.NewString(), map[string]any{"name": "over-anon-cap"})
	defer resp2.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp2.StatusCode)
	assert.Equal(t, "storage_limit_reached", body2.Error)
}
