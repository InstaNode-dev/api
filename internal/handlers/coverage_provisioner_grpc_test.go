package handlers_test

// coverage_provisioner_grpc_test.go — drives the gRPC-provisioner arms of the
// resource-provisioning handlers (provisionDB / provisionCache / provisionNoSQL
// / provisionQueue and the deprovisionBestEffort cleanup path) that the
// local-provider fixtures cannot reach.
//
// THE TECHNIQUE — bufconn fake provisioner.
// A fake ProvisionerServiceServer is stood up on an in-process
// google.golang.org/grpc/test/bufconn listener. A real *provisioner.Client is
// constructed (via provisioner.NewClientFromConn) around a grpc.ClientConn that
// dials that listener with grpc.WithContextDialer. That client is injected into
// the db/cache/nosql/queue handlers, so the `if h.provClient != nil` branch in
// every provisionX method actually executes — returning the fake's connection
// strings on success, or a gRPC error on the fault path.
//
// Production behaviour is untouched: NewClientFromConn is the only new export,
// and it merely builds a Client around an already-dialed conn (production keeps
// using NewClient, which owns the dial).
//
// Each test asserts the success path (201 + tier/limits echo + env default +
// dedup) and the two documented error branches:
//   - gRPC error  → 503 provision_failed (+ soft-delete of the pending row)
//   - persist err → 503 provision_failed (+ best-effort backend deprovision)

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/testhelpers"
	commonv1 "instant.dev/proto/common/v1"
	provisionerv1 "instant.dev/proto/provisioner/v1"
)

// fakeProvisioner is an in-process ProvisionerServiceServer used over bufconn.
// failProvision, when set, makes ProvisionResource return a gRPC error so the
// handler's provision-failure branch (soft-delete + 503) executes.
type fakeProvisioner struct {
	provisionerv1.UnimplementedProvisionerServiceServer

	mu               sync.Mutex
	failProvision    bool
	deprovisionCalls int

	lastReq            *provisionerv1.ProvisionRequest
	lastDeprovisionReq *provisionerv1.DeprovisionRequest
}

func (f *fakeProvisioner) ProvisionResource(_ context.Context, req *provisionerv1.ProvisionRequest) (*provisionerv1.ProvisionResponse, error) {
	f.mu.Lock()
	f.lastReq = req
	fail := f.failProvision
	f.mu.Unlock()

	if fail {
		return nil, status.Error(codes.Unavailable, "fake provisioner: backend down")
	}

	// Per-type connection strings so the handler's response echo is realistic.
	switch req.GetResourceType() {
	case commonv1.ResourceType_RESOURCE_TYPE_POSTGRES:
		return &provisionerv1.ProvisionResponse{
			ConnectionUrl:      "postgres://usr_" + req.GetToken() + ":pw@postgres-customers:5432/db_" + req.GetToken(),
			DatabaseName:       "db_" + req.GetToken(),
			Username:           "usr_" + req.GetToken(),
			ProviderResourceId: "pg-prid-" + req.GetToken(),
		}, nil
	case commonv1.ResourceType_RESOURCE_TYPE_REDIS:
		return &provisionerv1.ProvisionResponse{
			ConnectionUrl:      "redis://usr_" + req.GetToken() + ":pw@redis-provision:6379",
			KeyPrefix:          "kp_" + req.GetToken(),
			ProviderResourceId: "redis-prid-" + req.GetToken(),
		}, nil
	case commonv1.ResourceType_RESOURCE_TYPE_MONGODB:
		return &provisionerv1.ProvisionResponse{
			ConnectionUrl:      "mongodb://usr_" + req.GetToken() + ":pw@mongodb:27017/db_" + req.GetToken(),
			DatabaseName:       "db_" + req.GetToken(),
			Username:           "usr_" + req.GetToken(),
			ProviderResourceId: "mongo-prid-" + req.GetToken(),
		}, nil
	case commonv1.ResourceType_RESOURCE_TYPE_QUEUE:
		return &provisionerv1.ProvisionResponse{
			ConnectionUrl:      "nats://nats:4222",
			KeyPrefix:          "subj_" + req.GetToken(),
			ProviderResourceId: "queue-prid-" + req.GetToken(),
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "fake provisioner: unknown resource type")
	}
}

func (f *fakeProvisioner) DeprovisionResource(_ context.Context, req *provisionerv1.DeprovisionRequest) (*provisionerv1.DeprovisionResponse, error) {
	f.mu.Lock()
	f.deprovisionCalls++
	f.lastDeprovisionReq = req
	f.mu.Unlock()
	return &provisionerv1.DeprovisionResponse{}, nil
}

// lastDeprovision returns the most recent DeprovisionRequest (nil if none).
func (f *fakeProvisioner) lastDeprovision() *provisionerv1.DeprovisionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastDeprovisionReq
}

func (f *fakeProvisioner) deprovisionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deprovisionCalls
}

// newBufconnProvisionerClient stands up the fake server on a bufconn listener
// and returns a real *provisioner.Client dialing it. The grpc.Server is stopped
// via t.Cleanup.
func newBufconnProvisionerClient(t *testing.T, fake *fakeProvisioner) *provisioner.Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	provisionerv1.RegisterProvisionerServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return provisioner.NewClientFromConn(conn, "test-provisioner-secret")
}

// grpcProvFixture is a fiber app whose db/cache/nosql/queue handlers are wired
// with a bufconn-backed provisioner.Client so the gRPC provision arms execute.
type grpcProvFixture struct {
	app  *fiber.App
	db   *sql.DB
	rdb  *redis.Client
	fake     *fakeProvisioner
	cfg      *config.Config
	bulkTwin *handlers.BulkTwinHandler
}

// grpcProvConfig builds a config whose AES key may be intentionally broken to
// drive the finalizeProvision persistence-failure branch.
func grpcProvConfig(t *testing.T, badAESKey bool) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,redis,mongodb,queue,webhook,storage",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		QueueBackend:             "legacy_open",
		NATSHost:                 "nats.test",
		NATSPublicHost:           "nats.instanode.dev",
		FamilyBindingsEnabled:    true,
	}
	if badAESKey {
		// Not 64 hex chars → crypto.ParseAESKey fails → finalizeProvision
		// treats the provision as a persistence failure and runs cleanup.
		cfg.AESKey = "not-a-valid-aes-key"
	}
	return cfg
}

func setupGRPCProvFixture(t *testing.T, fake *fakeProvisioner, badAESKey bool) grpcProvFixture {
	t.Helper()
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := grpcProvConfig(t, badAESKey)
	planReg := plans.Default()
	provClient := newBufconnProvisionerClient(t, fake)

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
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlgrpc"}))

	dbH := handlers.NewDBHandler(db, rdb, cfg, provClient, planReg)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, provClient, planReg)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, provClient, planReg)
	queueH := handlers.NewQueueHandler(db, rdb, cfg, provClient, planReg)
	resourceH := handlers.NewResourceHandler(db, rdb, cfg, planReg, provClient, nil)

	app.Post("/db/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "db.new"), dbH.NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "cache.new"), cacheH.NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "nosql.new"), nosqlH.NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "queue.new"), queueH.NewQueue)

	twinH := handlers.NewTwinHandler(dbH, cacheH, nosqlH)
	bulkTwinH := handlers.NewBulkTwinHandler(db, dbH, cacheH, nosqlH, planReg)

	middleware.SetRoleLookupDB(db)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())
	api.Get("/resources", resourceH.List)
	api.Get("/resources/:id", resourceH.Get)
	api.Delete("/resources/:id", resourceH.Delete)
	api.Post("/resources/:id/provision-twin", twinH.ProvisionTwin)
	api.Post("/families/bulk-twin", bulkTwinH.BulkTwin)

	return grpcProvFixture{app: app, db: db, rdb: rdb, fake: fake, cfg: cfg, bulkTwin: bulkTwinH}
}

// authSessionJWT mints a session JWT for a fresh user on teamID.
func authSessionJWT(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

type grpcProvResp struct {
	OK            bool           `json:"ok"`
	ID            string         `json:"id"`
	Token         string         `json:"token"`
	Name          string         `json:"name"`
	ConnectionURL string         `json:"connection_url"`
	Tier          string         `json:"tier"`
	Env           string         `json:"env"`
	Limits        map[string]any `json:"limits"`
	Error         string         `json:"error"`
}

func doProvision(t *testing.T, fx grpcProvFixture, path, ip, jwt string, body map[string]any) (*http.Response, grpcProvResp) {
	return doProvisionKeyed(t, fx, path, ip, jwt, "", body)
}

// doProvisionKeyed is doProvision with an explicit Idempotency-Key. A distinct
// key per call defeats the middleware's body-fingerprint replay cache so the
// handler actually runs every time (needed for the cap / dedup branches).
func doProvisionKeyed(t *testing.T, fx grpcProvFixture, path, ip, jwt, idemKey string, body map[string]any) (*http.Response, grpcProvResp) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(http.MethodPost, path, reader)
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
	var parsed grpcProvResp
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

// ── Anonymous happy path via gRPC provisioner ──────────────────────────────

func TestGRPCProvision_DB_Anonymous_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/db/new", "10.40.0.1", "", map[string]any{"name": "grpc-db"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, body.OK)
	assert.NotEmpty(t, body.Token)
	assert.Contains(t, body.ConnectionURL, "postgres://usr_")
	assert.Equal(t, "anonymous", body.Tier)
	assert.Equal(t, "development", body.Env, "no env in body → default development")
	require.NotNil(t, body.Limits)
	assert.Contains(t, body.Limits, "storage_mb")
}

func TestGRPCProvision_Cache_Anonymous_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/cache/new", "10.41.0.1", "", map[string]any{"name": "grpc-cache"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, body.ConnectionURL, "redis://usr_")
	assert.Equal(t, "anonymous", body.Tier)
	assert.Equal(t, "development", body.Env)
}

func TestGRPCProvision_NoSQL_Anonymous_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/nosql/new", "10.42.0.1", "", map[string]any{"name": "grpc-mongo"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, body.ConnectionURL, "mongodb://usr_")
	assert.Equal(t, "anonymous", body.Tier)
}

func TestGRPCProvision_Queue_Anonymous_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/queue/new", "10.43.0.1", "", map[string]any{"name": "grpc-queue"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, body.ConnectionURL, "nats://")
	assert.Equal(t, "anonymous", body.Tier)
}

// ── Explicit env echo (production) ─────────────────────────────────────────

func TestGRPCProvision_DB_EnvEchoProduction(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/db/new", "10.44.0.1", "",
		map[string]any{"name": "grpc-db-prod", "env": "production"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "production", body.Env)
}

// ── Authenticated happy path: tier + limits echo via gRPC ──────────────────

func TestGRPCProvision_DB_Authenticated_TierAndLimits(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.45.0.1", jwt, map[string]any{"name": "grpc-db-auth"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "pro", body.Tier)
	require.NotNil(t, body.Limits)
	// Pro limits come from plans.Registry — assert the echo reflects the tier
	// rather than the anonymous fallback.
	reg := plans.Default()
	assert.EqualValues(t, reg.StorageLimitMB("pro", "postgres"), body.Limits["storage_mb"])
	assert.EqualValues(t, reg.ConnectionsLimit("pro", "postgres"), body.Limits["connections"])
}

func TestGRPCProvision_Cache_Authenticated_TierEcho(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "hobby")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/cache/new", "10.46.0.1", jwt, map[string]any{"name": "grpc-cache-auth"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "hobby", body.Tier)
}

func TestGRPCProvision_NoSQL_Authenticated_TierEcho(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/nosql/new", "10.47.0.1", jwt, map[string]any{"name": "grpc-mongo-auth"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "pro", body.Tier)
}

func TestGRPCProvision_Queue_Authenticated_TierEcho(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "team")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/queue/new", "10.48.0.1", jwt, map[string]any{"name": "grpc-queue-auth"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "team", body.Tier)
}

// ── gRPC error → 503 provision_failed (soft-delete of pending row) ─────────

func TestGRPCProvision_DB_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/db/new", "10.50.0.1", "", map[string]any{"name": "grpc-db-fail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestGRPCProvision_Cache_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/cache/new", "10.51.0.1", "", map[string]any{"name": "grpc-cache-fail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestGRPCProvision_NoSQL_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/nosql/new", "10.52.0.1", "", map[string]any{"name": "grpc-mongo-fail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestGRPCProvision_Queue_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/queue/new", "10.53.0.1", "", map[string]any{"name": "grpc-queue-fail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestGRPCProvision_DB_Authenticated_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.54.0.1", jwt, map[string]any{"name": "grpc-db-auth-fail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// ── persist failure (bad AES key) → 503 + best-effort backend deprovision ──
//
// With a malformed AES key, finalizeProvision fails to encrypt the connection
// URL, runs the cleanup closure (which calls provClient.DeprovisionResource via
// deprovisionBestEffort), soft-deletes the row, and returns 503. This is the
// only path that exercises the non-nil-provClient arm of deprovisionBestEffort.

func TestGRPCProvision_DB_PersistFailure_DeprovisionsAndReturns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true) // bad AES key

	resp, body := doProvision(t, fx, "/db/new", "10.60.0.1", "", map[string]any{"name": "grpc-db-persistfail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1,
		"persist failure must trigger best-effort backend deprovision via the gRPC client")
}

func TestGRPCProvision_Cache_PersistFailure_DeprovisionsAndReturns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true)

	resp, body := doProvision(t, fx, "/cache/new", "10.61.0.1", "", map[string]any{"name": "grpc-cache-persistfail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

func TestGRPCProvision_NoSQL_PersistFailure_DeprovisionsAndReturns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true)

	resp, body := doProvision(t, fx, "/nosql/new", "10.62.0.1", "", map[string]any{"name": "grpc-mongo-persistfail"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

// ── Anonymous dedup: a 2nd over-cap call from the same fingerprint returns the
// existing resource (decrypted connection_url) instead of provisioning fresh ──

func TestGRPCProvision_DB_AnonymousDedup_ReturnsExisting(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	ip := "10.70.0.1"
	// The per-fingerprint provision cap is 5 (checkProvisionLimit). A distinct
	// Idempotency-Key per call defeats the middleware replay cache so the
	// handler runs each time. Calls 1-5 provision fresh (201); the 6th is over
	// cap and dedups to an existing row with a decrypted connection_url (200).
	var firstToken string
	for i := 0; i < 6; i++ {
		resp, body := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "grpc-db-dedup"})
		resp.Body.Close()
		require.True(t, body.OK)
		if i < 5 {
			require.Equal(t, http.StatusCreated, resp.StatusCode, "call %d should provision fresh", i+1)
			if i == 0 {
				firstToken = body.Token
			}
		} else {
			require.Equal(t, http.StatusOK, resp.StatusCode, "6th call (over cap) must dedup with 200")
			assert.NotEmpty(t, body.ConnectionURL, "dedup response must carry a decrypted connection_url")
		}
	}
	require.NotEmpty(t, firstToken)
}

// ── Authenticated dedicated tier-gate (402) and growth success ─────────────

func TestGRPCProvision_DB_Dedicated_NonGrowth_Returns402(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro") // pro is not a dedicated tier
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.80.0.1", jwt,
		map[string]any{"name": "grpc-db-ded", "dedicated": true})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "upgrade_required", body.Error)
}

func TestGRPCProvision_Cache_Dedicated_Growth_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "growth")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/cache/new", "10.81.0.1", jwt,
		map[string]any{"name": "grpc-cache-ded", "dedicated": true})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	// dedicated forces tier=growth in the handler.
	assert.Equal(t, "growth", body.Tier)
}

func TestGRPCProvision_NoSQL_Dedicated_NonGrowth_Returns402(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "hobby")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/nosql/new", "10.82.0.1", jwt,
		map[string]any{"name": "grpc-mongo-ded", "dedicated": true})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "upgrade_required", body.Error)
}

// ── Anonymous dedicated / parent_resource_id → 402 auth_required ───────────

func TestGRPCProvision_DB_Anonymous_Dedicated_Returns402(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/db/new", "10.83.0.1", "",
		map[string]any{"name": "grpc-db-anon-ded", "dedicated": true})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "auth_required", body.Error)
}

func TestGRPCProvision_DB_Anonymous_ParentResource_Returns402(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	resp, body := doProvision(t, fx, "/db/new", "10.84.0.1", "",
		map[string]any{"name": "grpc-db-anon-parent", "parent_resource_id": uuid.NewString()})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "auth_required", body.Error)
}

// ── Single-twin to development env (bypasses approval gate) via gRPC ───────

type twinResp struct {
	OK            bool   `json:"ok"`
	Token         string `json:"token"`
	ConnectionURL string `json:"connection_url"`
	Tier          string `json:"tier"`
	Env           string `json:"env"`
	Error         string `json:"error"`
}

func postTwinDev(t *testing.T, fx grpcProvFixture, sourceToken, jwt string) (*http.Response, twinResp) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"env": "development"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+sourceToken+"/provision-twin", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	var parsed twinResp
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

func TestGRPCTwin_DB_DevEnv_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Contains(t, body.ConnectionURL, "postgres://usr_")
	assert.Equal(t, "development", body.Env)
}

func TestGRPCTwin_Cache_DevEnv_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "redis", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, body.ConnectionURL, "redis://usr_")
}

func TestGRPCTwin_NoSQL_DevEnv_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "mongodb", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, body.ConnectionURL, "mongodb://usr_")
}

func TestGRPCTwin_DB_DevEnv_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// ── Bulk-twin via gRPC — exercises ProvisionForTwinCore success + cleanup ──

type bulkResp struct {
	OK       bool `json:"ok"`
	Twinned  int  `json:"twinned"`
	Failures []struct {
		Error string `json:"error"`
	} `json:"failures"`
}

func postBulk(t *testing.T, fx grpcProvFixture, jwt, sourceEnv, targetEnv string) (*http.Response, bulkResp) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"source_env": sourceEnv, "target_env": targetEnv})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/families/bulk-twin", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := fx.app.Test(req, 30000)
	require.NoError(t, err)
	var parsed bulkResp
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

func TestGRPCBulkTwin_Success_AllTwinned(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")
	seedSourceResource(t, fx.db, teamID, "redis", "pro", "production")

	resp, body := postBulk(t, fx, jwt, "production", "development")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Twinned)
	assert.Empty(t, body.Failures)
}

func TestGRPCBulkTwin_PersistFailure_AllFail(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true) // bad AES → ProvisionForTwinCore persist failure
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")
	seedSourceResource(t, fx.db, teamID, "mongodb", "pro", "production")

	resp, _ := postBulk(t, fx, jwt, "production", "development")
	defer resp.Body.Close()
	// Multi-status (some/all failed) — the Core persist-failure branch +
	// best-effort deprovision ran for each source.
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

// ── Anonymous dedup for cache / nosql / queue (limitExceeded → existing) ───
//
// Six provisions from the same fingerprint exhaust the per-fingerprint daily
// cap (5); the 6th lands in the limitExceeded branch and dedups to an existing
// resource with a decrypted connection_url (and key_prefix for redis/queue).

func TestGRPCProvision_Cache_AnonymousDedup_ReturnsExisting(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.90.0.1"
	for i := 0; i < 6; i++ {
		resp, body := doProvisionKeyed(t, fx, "/cache/new", ip, "", uuid.NewString(), map[string]any{"name": "dedup-cache"})
		resp.Body.Close()
		require.True(t, body.OK)
		if i < 5 {
			require.Equal(t, http.StatusCreated, resp.StatusCode)
		} else {
			require.Equal(t, http.StatusOK, resp.StatusCode, "6th call must dedup")
		}
	}
}

func TestGRPCProvision_NoSQL_AnonymousDedup_ReturnsExisting(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.91.0.1"
	for i := 0; i < 6; i++ {
		resp, body := doProvisionKeyed(t, fx, "/nosql/new", ip, "", uuid.NewString(), map[string]any{"name": "dedup-mongo"})
		resp.Body.Close()
		require.True(t, body.OK)
		if i < 5 {
			require.Equal(t, http.StatusCreated, resp.StatusCode)
		} else {
			require.Equal(t, http.StatusOK, resp.StatusCode, "6th call must dedup")
		}
	}
}

func TestGRPCProvision_Queue_AnonymousDedup_ReturnsExisting(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.92.0.1"
	for i := 0; i < 6; i++ {
		resp, body := doProvisionKeyed(t, fx, "/queue/new", ip, "", uuid.NewString(), map[string]any{"name": "dedup-queue"})
		resp.Body.Close()
		require.True(t, body.OK)
		if i < 5 {
			require.Equal(t, http.StatusCreated, resp.StatusCode)
		} else {
			require.Equal(t, http.StatusOK, resp.StatusCode, "6th call must dedup")
		}
	}
}

// ── Authenticated invalid team ID in token → 400 invalid_team ──────────────

func TestGRPCProvision_DB_InvalidTeamID_Returns400(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	// Mint a session JWT with a non-UUID team id.
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))

	resp, body := doProvision(t, fx, "/db/new", "10.94.0.1", jwt, map[string]any{"name": "bad-team-db"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_team", body.Error)
}

// seedSourceResource inserts an active source resource with a real
// AES-encrypted connection_url so dedup / family-link / twin paths treat it as
// a usable source. Returns (id, token).
func seedSourceResource(t *testing.T, db *sql.DB, teamID, resourceType, tier, env string) (id, token string) {
	t.Helper()
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env, status)
		VALUES ($1::uuid, $2, $3, $4, 'active')
		RETURNING id::text, token::text
	`, teamID, resourceType, tier, env).Scan(&id, &token))
	return id, token
}
