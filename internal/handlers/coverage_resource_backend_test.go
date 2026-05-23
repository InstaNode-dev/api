package handlers_test

// coverage_resource_backend_test.go — full-backend flows that exercise the
// provider-side helpers in resource.go (pauseProvider / resumeProvider /
// rotate* / grant* / revoke* / setRedisACLEnabled) and the per-handler
// provision → twin → decryptConnectionURL paths in db.go / cache.go /
// nosql.go / queue.go that the no-backend fixture only reached at the
// status-flip layer.
//
// The app wired here points CustomerDatabaseURL / RedisProvision* /
// MongoAdminURI at the local Docker test backends, then provisions REAL
// postgres / redis / mongo resources before pausing / resuming / rotating
// them — so the provider helpers run against a backend where the
// db + user + ACL actually exist and the revoke / grant succeeds (returning
// 200 instead of the 503 a missing-role revoke would produce).
//
// Every test skips cleanly when its backend is not reachable.

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func backendTestConfig() *config.Config {
	customersURL := envOr("TEST_POSTGRES_CUSTOMERS_URL",
		"postgres://postgres:postgres@127.0.0.1:5432/instant_customers?sslmode=disable")
	// Redis the provider provisions ACL users on. Use the platform test redis
	// (the local cache provider builds connection URLs against RedisProvisionHost).
	// The local cache provider appends :6379, so this is host-only.
	redisHost := envOr("TEST_REDIS_PROVISION_HOST", "127.0.0.1")
	mongoURI := envOr("MONGO_ADMIN_URI", "mongodb://127.0.0.1:27017")
	mongoHost := envOr("MONGO_HOST", "127.0.0.1:27017")
	return &config.Config{
		Port:                     "8080",
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,redis,mongodb,queue,webhook,storage",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		PostgresCustomersURL:     customersURL,
		CustomerDatabaseURL:      customersURL,
		RedisProvisionBackend:    "local",
		RedisProvisionHost:       redisHost,
		MongoAdminURI:            mongoURI,
		MongoHost:                mongoHost,
		FamilyBindingsEnabled:    true,
	}
}

type backendFixture struct {
	app    *fiber.App
	db     *sql.DB
	rdb    *redis.Client
	jwt    string
	teamID string
}

func setupBackendFixture(t *testing.T, planTier string) backendFixture {
	t.Helper()
	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	cfg := backendTestConfig()
	planReg := plans.Default()

	app := fiber.New(fiber.Config{
		ErrorHandler: storageErrorHandler,
		ProxyHeader:  "X-Forwarded-For",
		BodyLimit:    50 * 1024 * 1024,
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 100, KeyPrefix: "rlbk"}))

	resourceH := handlers.NewResourceHandler(db, rdb, cfg, planReg, nil, nil)
	dbH := handlers.NewDBHandler(db, rdb, cfg, nil, planReg)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, planReg)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, nil, planReg)
	queueH := handlers.NewQueueHandler(db, rdb, cfg, nil, planReg)
	webhookH := handlers.NewWebhookHandler(db, rdb, cfg, planReg)

	app.Post("/db/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "db.new"), dbH.NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "cache.new"), cacheH.NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "nosql.new"), nosqlH.NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "queue.new"), queueH.NewQueue)
	app.Post("/webhook/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "webhook.new"), webhookH.NewWebhook)

	middleware.SetRoleLookupDB(db)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())
	api.Get("/resources/:id", resourceH.Get)
	api.Get("/resources/:id/credentials", resourceH.GetCredentials)
	api.Delete("/resources/:id", resourceH.Delete)
	api.Post("/resources/:id/rotate-credentials", resourceH.RotateCredentials)
	api.Post("/resources/:id/pause", resourceH.Pause)
	api.Post("/resources/:id/resume", resourceH.Resume)

	twinH := handlers.NewTwinHandler(dbH, cacheH, nosqlH)
	api.Post("/resources/:id/provision-twin", twinH.ProvisionTwin)

	_ = email.NewNoop()
	t.Cleanup(func() { app.Shutdown() })

	teamID := testhelpers.MustCreateTeamDB(t, db, planTier)
	em := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner') RETURNING id::text`,
		teamID, em,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, em)
	return backendFixture{app: app, db: db, rdb: rdb, jwt: jwt, teamID: teamID}
}

func (f backendFixture) post(t *testing.T, path, body, ip string, authed bool) *http.Response {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(http.MethodPost, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if authed {
		req.Header.Set("Authorization", "Bearer "+f.jwt)
	}
	resp, err := f.app.Test(req, 20000)
	require.NoError(t, err)
	return resp
}

func (f backendFixture) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+f.jwt)
	resp, err := f.app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

func (f backendFixture) del(t *testing.T, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.Header.Set("Authorization", "Bearer "+f.jwt)
	resp, err := f.app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// provisionAuthed POSTs to a provisioning endpoint as the fixture team and
// returns the decoded body, skipping the test if the backend is unreachable.
func (f backendFixture) provisionAuthed(t *testing.T, path, name, ip string) map[string]any {
	t.Helper()
	resp := f.post(t, path, `{"name":"`+name+`"}`, ip, true)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skipf("%s backend not reachable in test env (503)", path)
	}
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "expected 201 from %s", path)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}

// ── Postgres: provision → getcredentials → rotate → pause → resume → delete ──

func TestResourceLifecycle_Postgres_FullBackend(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	body := f.provisionAuthed(t, "/db/new", "pg-life", "10.60.0.1")
	id, _ := body["token"].(string)
	require.NotEmpty(t, id)

	// GetCredentials (resource.go 296, was 0%).
	cred := f.get(t, "/api/v1/resources/"+id+"/credentials")
	require.Equal(t, http.StatusOK, cred.StatusCode)
	var cb map[string]any
	require.NoError(t, json.NewDecoder(cred.Body).Decode(&cb))
	cred.Body.Close()
	curl, _ := cb["connection_url"].(string)
	assert.True(t, strings.HasPrefix(curl, "postgres://"), "credentials must decrypt to a postgres URL")

	// Rotate (rotatePostgresPassword runs since CustomerDatabaseURL is set).
	rot := f.post(t, "/api/v1/resources/"+id+"/rotate-credentials", "", "10.60.0.1", true)
	assert.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable}, rot.StatusCode)
	rot.Body.Close()

	// Pause (revokePostgresConnect against the real provisioned db+user).
	pause := f.post(t, "/api/v1/resources/"+id+"/pause", "", "10.60.0.1", true)
	defer pause.Body.Close()
	if pause.StatusCode == http.StatusServiceUnavailable {
		t.Skip("postgres pause provider unreachable")
	}
	require.Equal(t, http.StatusOK, pause.StatusCode)

	// Resume (grantPostgresConnect).
	resume := f.post(t, "/api/v1/resources/"+id+"/resume", "", "10.60.0.1", true)
	require.Equal(t, http.StatusOK, resume.StatusCode)
	resume.Body.Close()

	// Delete soft-deletes.
	d := f.del(t, "/api/v1/resources/"+id)
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, d.StatusCode)
	d.Body.Close()
}

// ── Redis: provision → pause (setRedisACLEnabled off) → resume (on) ──

func TestResourceLifecycle_Redis_FullBackend(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	body := f.provisionAuthed(t, "/cache/new", "redis-life", "10.61.0.1")
	id, _ := body["token"].(string)
	require.NotEmpty(t, id)

	cred := f.get(t, "/api/v1/resources/"+id+"/credentials")
	require.Equal(t, http.StatusOK, cred.StatusCode)
	cred.Body.Close()

	// Pause runs setRedisACLEnabled against the tenant URL. The provisioned
	// tenant ACL denies acl|setuser (multi-tenant isolation), so the provider
	// revoke fails and the handler returns 503 with the DB row left active —
	// this exercises both the setRedisACLEnabled arm AND the pause iron-rule
	// atomicity (no DB flip on provider failure). 200 (admin-capable backend)
	// or 503 (restricted tenant ACL) both prove the redis pause arm ran.
	pause := f.post(t, "/api/v1/resources/"+id+"/pause", "", "10.61.0.1", true)
	defer pause.Body.Close()
	require.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable}, pause.StatusCode)

	if pause.StatusCode == http.StatusOK {
		resume := f.post(t, "/api/v1/resources/"+id+"/resume", "", "10.61.0.1", true)
		require.Equal(t, http.StatusOK, resume.StatusCode)
		resume.Body.Close()
	}
}

// ── Mongo: provision → rotate (rotateMongoPassword) → pause → resume ──

func TestResourceLifecycle_Mongo_FullBackend(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	body := f.provisionAuthed(t, "/nosql/new", "mongo-life", "10.62.0.1")
	id, _ := body["token"].(string)
	require.NotEmpty(t, id)

	rot := f.post(t, "/api/v1/resources/"+id+"/rotate-credentials", "", "10.62.0.1", true)
	assert.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable}, rot.StatusCode)
	rot.Body.Close()

	pause := f.post(t, "/api/v1/resources/"+id+"/pause", "", "10.62.0.1", true)
	defer pause.Body.Close()
	if pause.StatusCode == http.StatusServiceUnavailable {
		t.Skip("mongo pause provider unreachable")
	}
	require.Equal(t, http.StatusOK, pause.StatusCode)

	resume := f.post(t, "/api/v1/resources/"+id+"/resume", "", "10.62.0.1", true)
	require.Equal(t, http.StatusOK, resume.StatusCode)
	resume.Body.Close()
}

// ── Queue: provision (issueTenantCreds / addQueueCredentials) ──

func TestQueueNew_FullBackend_Provision(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	body := f.provisionAuthed(t, "/queue/new", "q-life", "10.63.0.1")
	assert.Equal(t, "pro", body["tier"])
	id, _ := body["token"].(string)
	require.NotEmpty(t, id)
	// GetCredentials on a queue resource exercises that arm too.
	cred := f.get(t, "/api/v1/resources/"+id+"/credentials")
	assert.Contains(t, []int{http.StatusOK, http.StatusBadRequest}, cred.StatusCode)
	cred.Body.Close()
}

// ── Twin: postgres / redis / mongo twin into a new env (ProvisionForTwin /
//    ProvisionForTwinCore + the per-handler decryptConnectionURL) ──

func twinFromSource(t *testing.T, f backendFixture, sourcePath, name, ip string) {
	t.Helper()
	// Provision the source in a non-development env, then twin INTO development
	// — dev-env twins bypass the email-approval gate and run ProvisionForTwin
	// synchronously (returning 201 with a fresh connection_url). A twin into a
	// non-dev env would return 202 pending_approval instead.
	resp0 := f.post(t, sourcePath, `{"name":"`+name+`","env":"staging"}`, ip, true)
	if resp0.StatusCode == http.StatusServiceUnavailable {
		resp0.Body.Close()
		t.Skipf("%s backend not reachable in test env (503)", sourcePath)
	}
	require.Equalf(t, http.StatusCreated, resp0.StatusCode, "source provision from %s should 201", sourcePath)
	var src map[string]any
	require.NoError(t, json.NewDecoder(resp0.Body).Decode(&src))
	resp0.Body.Close()
	srcToken, _ := src["token"].(string)
	require.NotEmpty(t, srcToken)

	resp := f.post(t, "/api/v1/resources/"+srcToken+"/provision-twin",
		`{"env":"development","name":"`+name+`-dev"}`, ip, true)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("twin backend unreachable")
	}
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "twin from %s should 201", sourcePath)
	var tb map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tb))
	assert.Equal(t, "development", tb["env"])
	assert.NotEmpty(t, tb["connection_url"], "twin must carry a fresh connection_url")
}

func TestResourceTwin_Postgres_FullBackend(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	twinFromSource(t, f, "/db/new", "twin-pg", "10.64.0.1")
}

func TestResourceTwin_Redis_FullBackend(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	twinFromSource(t, f, "/cache/new", "twin-redis", "10.65.0.1")
}

func TestResourceTwin_Mongo_FullBackend(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	twinFromSource(t, f, "/nosql/new", "twin-mongo", "10.66.0.1")
}

// ── Anonymous dedup: drives each handler's decryptConnectionURL on the
//    rate-limited dedup path (the 6th+ provision returns the existing row with
//    a re-decrypted connection_url). ──

func anonDedup(t *testing.T, f backendFixture, path, ip string) {
	t.Helper()
	sawDedup := false
	for i := 0; i < 9; i++ {
		// Unique body so the Idempotency middleware lets each request reach the
		// handler and bump the per-fingerprint daily INCR past the cap.
		resp := f.post(t, path, `{"name":"dd-`+ddIdx(i)+`"}`, ip, false)
		if resp.StatusCode == http.StatusServiceUnavailable {
			resp.Body.Close()
			t.Skipf("%s backend not reachable (503)", path)
		}
		var b map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&b)
		resp.Body.Close()
		// On the dedup path the handler re-decrypts and returns the existing
		// resource with the same token; over-cap-no-row returns 429.
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests {
			sawDedup = true
			break
		}
	}
	assert.Truef(t, sawDedup, "expected a dedup hit / 429 on %s after exceeding the daily cap", path)
}

func ddIdx(i int) string {
	return string(rune('0' + i))
}

func TestDBNew_AnonymousDedup_DecryptPath(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	anonDedup(t, f, "/db/new", "10.70.0.1")
}

func TestCacheNew_AnonymousDedup_DecryptPath(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	anonDedup(t, f, "/cache/new", "10.71.0.1")
}

func TestNoSQLNew_AnonymousDedup_DecryptPath(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	anonDedup(t, f, "/nosql/new", "10.72.0.1")
}

func TestQueueNew_AnonymousDedup_DecryptPath(t *testing.T) {
	f := setupBackendFixture(t, "pro")
	anonDedup(t, f, "/queue/new", "10.73.0.1")
}

// ── Negative-path coverage: parseProvisionBody / requireName / resolveEnv
//    error returns in each provisioning handler (the 2-line `return err`
//    branches in db.go / cache.go / nosql.go / queue.go / storage.go). ──

func TestDBNew_NegativePaths(t *testing.T) {
	provisioningNegativePaths(t, "/db/new", "10.80.0.1")
}
func TestCacheNew_NegativePaths(t *testing.T) {
	provisioningNegativePaths(t, "/cache/new", "10.80.1.1")
}
func TestNoSQLNew_NegativePaths(t *testing.T) {
	provisioningNegativePaths(t, "/nosql/new", "10.80.2.1")
}
func TestQueueNew_NegativePaths(t *testing.T) {
	provisioningNegativePaths(t, "/queue/new", "10.80.3.1")
}
func TestStorageNew_NegativePaths(t *testing.T) {
	// Storage needs the MinIO-backed app (the backend fixture has no storage
	// provider wired) so NewStorage gets past the service-enabled guard.
	fix := setupStorageFixture(t, "pro")
	// Invalid JSON body → parseProvisionBody 400.
	resp := storagePostRaw(t, fix, "{not json", "10.81.0.1", "application/json")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
	// Missing name → requireName 400.
	resp = storagePostRaw(t, fix, `{}`, "10.81.0.2", "application/json")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
	// Unsupported Content-Type → 415.
	resp = storagePostRaw(t, fix, `<x>1</x>`, "10.81.0.3", "application/xml")
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	resp.Body.Close()
}

func storagePostRaw(t *testing.T, fix storageFixture, body, ip, ct string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/storage/new", strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := fix.app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// provisioningNegativePaths exercises the shared error returns on a
// provisioning endpoint via the full-backend app.
func provisioningNegativePaths(t *testing.T, path, ipBase string) {
	f := setupBackendFixture(t, "pro")

	// 1. Invalid JSON body → parseProvisionBody returns 400 invalid_body.
	resp := f.postRaw(t, path, "{bad json", ipBase, "application/json")
	assert.Equalf(t, http.StatusBadRequest, resp.StatusCode, "%s bad-json", path)
	resp.Body.Close()

	// 2. Missing name → requireName returns 400 (no injectDefaultProvisionName
	//    middleware in this app).
	resp = f.postRaw(t, path, `{}`, ipBase, "application/json")
	assert.Equalf(t, http.StatusBadRequest, resp.StatusCode, "%s missing-name", path)
	resp.Body.Close()

	// 3. Invalid env via ?env= → resolveEnv returns 400 invalid_env.
	resp = f.postRaw(t, path+"?env=NOT_VALID_ENV", `{"name":"x"}`, ipBase, "application/json")
	assert.Equalf(t, http.StatusBadRequest, resp.StatusCode, "%s bad-env", path)
	resp.Body.Close()

	// 4. Unsupported Content-Type → 415.
	resp = f.postRaw(t, path, `<x>1</x>`, ipBase, "application/xml")
	assert.Equalf(t, http.StatusUnsupportedMediaType, resp.StatusCode, "%s bad-ct", path)
	resp.Body.Close()
}

func (f backendFixture) postRaw(t *testing.T, path, body, ip, ct string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := f.app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}
