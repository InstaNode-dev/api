package handlers_test

// vector_grpc_vecwave_test.go — drives the gRPC-provisioner arm of the
// /vector/new handler that the local-provider fixtures (vector_test.go,
// vector_authenticated_coverage_test.go) cannot reach.
//
// THE TECHNIQUE — bufconn fake provisioner.
// Reuses the in-process fakeProvisioner + newBufconnProvisionerClient helpers
// from coverage_provisioner_grpc_test.go (same handlers_test package). A
// *provisioner.Client dialing the bufconn listener is injected into a
// VectorHandler, so the `if h.provClient != nil` arm of provisionVectorDB
// executes — exercising both ProvisionPostgres-over-gRPC AND the
// createPgvectorExtension no-op stub that only runs on the gRPC path.
//
// vector.provisionVectorDB maps to RESOURCE_TYPE_POSTGRES (pgvector is
// pgvector-on-Postgres), so the fake returns the postgres connection string.
//
// Arms covered here:
//   - anonymous gRPC provision success (201) → provisionVectorDB gRPC branch +
//     createPgvectorExtension stub.
//   - authenticated gRPC provision success (201, tier echo).
//   - gRPC error → 503 provision_failed (soft-delete of the pending row).
//   - persist failure (bad AES key) → 503 + best-effort deprovision.
//   - anonymous over-cap dedup (6th call) → 200 with decrypted connection_url
//     (decryptConnectionURL happy path).

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/testhelpers"
)

func setupVectorGRPCFixture(t *testing.T, fake *fakeProvisioner, badAESKey bool) (*fiber.App, *fakeProvisioner, func()) {
	t.Helper()
	db, _ := testhelpers.SetupTestDB(t)
	rdb, _ := testhelpers.SetupTestRedis(t)

	cfg := &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,vector,redis",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		FamilyBindingsEnabled:    true,
	}
	if badAESKey {
		cfg.AESKey = "not-a-valid-aes-key"
	}

	planReg := plans.Default()
	var provClient *provisioner.Client
	if fake != nil {
		provClient = newBufconnProvisionerClient(t, fake)
	}

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
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 200, KeyPrefix: "rlvecgrpc"}))

	vectorH := handlers.NewVectorHandler(db, rdb, cfg, provClient, planReg)
	app.Post("/vector/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "vector.new"), vectorH.NewVector)

	cleanup := func() { db.Close(); rdb.Close() }
	return app, fake, cleanup
}

type vecRespVecwave struct {
	OK            bool           `json:"ok"`
	ID            string         `json:"id"`
	Token         string         `json:"token"`
	ConnectionURL string         `json:"connection_url"`
	Tier          string         `json:"tier"`
	Env           string         `json:"env"`
	Extension     string         `json:"extension"`
	Dimensions    int            `json:"dimensions"`
	Limits        map[string]any `json:"limits"`
	Error         string         `json:"error"`
}

func postVectorVecwave(t *testing.T, app *fiber.App, ip, jwt, idemKey string, body map[string]any) (*http.Response, vecRespVecwave) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(http.MethodPost, "/vector/new", reader)
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
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	var parsed vecRespVecwave
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

func TestVectorGRPC_Anonymous_Success_Vecwave(t *testing.T) {
	app, _, clean := setupVectorGRPCFixture(t, &fakeProvisioner{}, false)
	defer clean()

	resp, body := postVectorVecwave(t, app, "10.120.0.1", "", "", map[string]any{"name": "grpc-vec", "dimensions": 768})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Contains(t, body.ConnectionURL, "postgres://usr_", "vector maps to the postgres backend")
	assert.Equal(t, "anonymous", body.Tier)
	assert.Equal(t, "pgvector", body.Extension)
	assert.Equal(t, 768, body.Dimensions)
}

func TestVectorGRPC_Authenticated_TierEcho_Vecwave(t *testing.T) {
	app, _, clean := setupVectorGRPCFixture(t, &fakeProvisioner{}, false)
	defer clean()
	// reuse the same db the fixture created via a fresh handle is awkward;
	// instead mint the team against a separate connection.
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := authSessionJWT(t, db, teamID)

	resp, body := postVectorVecwave(t, app, "10.121.0.1", jwt, "", map[string]any{"name": "grpc-vec-auth"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "pro", body.Tier)
	assert.Equal(t, "pgvector", body.Extension)
}

// TestVectorGRPC_Authenticated_GRPCError_Returns503_Vecwave drives the
// newVectorAuthenticated provision-failure arm: gRPC error → soft-delete the
// pending row → 503 provision_failed.
func TestVectorGRPC_Authenticated_GRPCError_Returns503_Vecwave(t *testing.T) {
	app, _, clean := setupVectorGRPCFixture(t, &fakeProvisioner{failProvision: true}, false)
	defer clean()
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := authSessionJWT(t, db, teamID)

	resp, body := postVectorVecwave(t, app, "10.125.0.1", jwt, "", map[string]any{"name": "grpc-vec-auth-fail"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// TestVectorGRPC_Authenticated_PersistFailure_Returns503_Vecwave drives the
// newVectorAuthenticated persist-failure arm: bad AES key → finalizeProvision
// fails → best-effort deprovision + 503.
func TestVectorGRPC_Authenticated_PersistFailure_Returns503_Vecwave(t *testing.T) {
	fake := &fakeProvisioner{}
	app, _, clean := setupVectorGRPCFixture(t, fake, true) // bad AES key
	defer clean()
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := authSessionJWT(t, db, teamID)

	resp, body := postVectorVecwave(t, app, "10.126.0.1", jwt, "", map[string]any{"name": "grpc-vec-auth-persistfail"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

func TestVectorGRPC_GRPCError_Returns503_Vecwave(t *testing.T) {
	app, _, clean := setupVectorGRPCFixture(t, &fakeProvisioner{failProvision: true}, false)
	defer clean()

	resp, body := postVectorVecwave(t, app, "10.122.0.1", "", "", map[string]any{"name": "grpc-vec-fail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestVectorGRPC_PersistFailure_Returns503_Vecwave(t *testing.T) {
	fake := &fakeProvisioner{}
	app, _, clean := setupVectorGRPCFixture(t, fake, true) // bad AES → finalizeProvision persist failure
	defer clean()

	resp, body := postVectorVecwave(t, app, "10.123.0.1", "", "", map[string]any{"name": "grpc-vec-persistfail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1,
		"persist failure must trigger best-effort backend deprovision via the gRPC client")
}

// TestVectorDecryptConnectionURL_Vecwave drives VectorHandler.decryptConnectionURL
// directly (the only caller in production is the anonymous over-cap dedup arm of
// NewVector, which is birthday-collision-flaky to reach end-to-end). All three
// arms: empty input → ("", true); valid ciphertext → (plaintext, true);
// bad AES key → ("", false).
func TestVectorDecryptConnectionURL_Vecwave(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()

	const plain = "postgres://usr_x:pw@postgres-customers:5432/db_x"

	// Happy path: real AES key, real ciphertext round-trips.
	goodCfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, Environment: "test"}
	hGood := handlers.NewVectorHandler(db, rdb, goodCfg, nil, plans.Default())
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, plain)
	require.NoError(t, err)

	got, ok := handlers.VectorDecryptConnectionURLForTest(hGood, enc, "req-1")
	require.True(t, ok, "valid ciphertext must decrypt with ok=true")
	assert.Equal(t, plain, got)

	// Empty input → ("", true) without touching the key.
	got, ok = handlers.VectorDecryptConnectionURLForTest(hGood, "", "req-2")
	assert.True(t, ok)
	assert.Equal(t, "", got)

	// Bad AES key → fail-CLOSED ("", false).
	badCfg := &config.Config{AESKey: "not-a-valid-aes-key", Environment: "test"}
	hBad := handlers.NewVectorHandler(db, rdb, badCfg, nil, plans.Default())
	got, ok = handlers.VectorDecryptConnectionURLForTest(hBad, enc, "req-3")
	assert.False(t, ok, "bad AES key must fail closed (ok=false)")
	assert.Equal(t, "", got)

	// Good key, malformed ciphertext → crypto.Decrypt fails → ("", false).
	got, ok = handlers.VectorDecryptConnectionURLForTest(hGood, "not-valid-ciphertext", "req-4")
	assert.False(t, ok, "undecryptable ciphertext must fail closed (ok=false)")
	assert.Equal(t, "", got)
}
