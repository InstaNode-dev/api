package handlers_test

// resource_provider_happy_vecwave_test.go — residual coverage for resource.go
// (the _vecwave wave). Drives the SUCCESS (nil-return) arms of the pause/resume
// provider helpers against the real local Postgres / Redis / Mongo containers
// (CI's service matrix). The existing resource_residual_test.go +
// resource_providers_rbw_test.go reach the validation / connect-error /
// command-error arms but skip the happy returns of:
//
//   pauseProvider  → revokePostgresConnect / setRedisACLEnabled(false) /
//                    revokeMongoRoles  (success returns)
//   resumeProvider → grantPostgresConnect / setRedisACLEnabled(true)  /
//                    grantMongoRoles   (success returns)
//
// Each test creates the real backend object (db+role / ACL user / mongo user)
// the helper expects, calls the exported Call{Pause,Resume}ProviderForTest
// wrappers, and asserts the helper returns nil.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/redis/go-redis/v9"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// TestPauseResumeProvider_Postgres_HappyPath_Vecwave drives the postgres
// REVOKE/GRANT CONNECT success returns of pauseProvider/resumeProvider.
func TestPauseResumeProvider_Postgres_HappyPath_Vecwave(t *testing.T) {
	customersDSN := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if customersDSN == "" {
		customersDSN = os.Getenv("TEST_DATABASE_URL")
	}
	if customersDSN == "" {
		t.Skip("no customer DSN — skipping postgres provider happy path")
	}

	adminDB, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()

	// Token drives db_<token> + usr_<token>. validateSQLIdent only allows
	// [a-z0-9_-], and a UUID (lowercase hex + dashes) satisfies that.
	token := uuid.NewString()
	dbName := "db_" + token
	role := "usr_" + token

	// Open an admin connection to the customers backend to create the db+role.
	ctx := context.Background()
	customerAdmin, err := sql.Open("postgres", customersDSN)
	require.NoError(t, err)
	require.NoError(t, customerAdmin.Ping())
	defer customerAdmin.Close()

	// Role first, then a database owned by it. Quote identifiers (tokens carry
	// dashes). Drop on cleanup.
	_, err = customerAdmin.ExecContext(ctx, fmt.Sprintf(`CREATE ROLE %q LOGIN PASSWORD 'pw'`, role))
	require.NoError(t, err)
	_, err = customerAdmin.ExecContext(ctx, fmt.Sprintf(`CREATE DATABASE %q OWNER %q`, dbName, role))
	require.NoError(t, err)
	t.Cleanup(func() {
		customerAdmin.ExecContext(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, dbName))
		customerAdmin.ExecContext(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %q`, role))
	})

	// connection_url must encrypt a URL whose username == usr_<token> so
	// extractURLUsername recovers it.
	aesKey, keyErr := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, keyErr)
	plain := fmt.Sprintf("postgres://%s:pw@postgres-customers:5432/%s", role, dbName)
	enc, encErr := crypto.Encrypt(aesKey, plain)
	require.NoError(t, encErr)

	cfg := &config.Config{
		Environment:         "test",
		AESKey:              testhelpers.TestAESKeyHex,
		CustomerDatabaseURL: customersDSN,
	}
	h := handlers.NewResourceHandlerWithBackendsForTest(adminDB, cfg, plans.Default())

	// Pause → REVOKE CONNECT success (+ pg_terminate_backend follow-up).
	require.NoError(t, handlers.CallPauseProviderForTest(h, ctx, "postgres", token, enc),
		"revokePostgresConnect success arm must return nil")
	// Resume → GRANT CONNECT success.
	require.NoError(t, handlers.CallResumeProviderForTest(h, ctx, "postgres", token, enc),
		"grantPostgresConnect success arm must return nil")
}

// TestPauseResumeProvider_Redis_HappyPath_Vecwave drives setRedisACLEnabled
// (false then true) success returns. We connect to redis as the default user
// (the test URL has admin rights on the local container) and create the ACL
// user the helper then toggles.
func TestPauseResumeProvider_Redis_HappyPath_Vecwave(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("no redis URL — skipping redis provider happy path")
	}
	adminDB, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()

	ctx := context.Background()
	opts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	admin := redis.NewClient(opts)
	defer admin.Close()

	user := "usr_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	// Create the ACL user the helper toggles. on/allkeys/allcommands with a pw.
	require.NoError(t, admin.Do(ctx, "ACL", "SETUSER", user, "on", ">pw", "~*", "+@all").Err())
	t.Cleanup(func() { admin.Do(context.Background(), "ACL", "DELUSER", user) })

	// The helper opens its own client from the connection_url; that URL must
	// authenticate as a user allowed to run ACL SETUSER. The local test redis
	// default user has full perms, so use the admin URL's credentials but the
	// per-tenant username embedded in the path is what setRedisACLEnabled
	// toggles — the helper extracts username from the URL userinfo. We embed
	// the admin (default) credentials so the ACL SETUSER is authorised, and
	// the username it toggles is read from the same userinfo, so create the
	// ACL user matching the admin user is unnecessary — instead encrypt a URL
	// whose userinfo is the per-tenant `user` but authenticate via default.
	//
	// Simpler + correct: the local test redis default user is unauthenticated
	// (no password). setRedisACLEnabled connects with redis.ParseURL(url) then
	// runs ACL SETUSER <username> on/off. ParseURL on the admin URL connects as
	// default (full perms). The username arg comes from urlUsername(url). So we
	// encrypt a URL that carries `user` in the userinfo but points at the same
	// host/db — connecting as `user:pw` which we just created with +@all.
	plain := fmt.Sprintf("redis://%s:pw@%s/%d", user, opts.Addr, opts.DB)
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, plain)
	require.NoError(t, err)

	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewResourceHandlerWithBackendsForTest(adminDB, cfg, plans.Default())

	token := uuid.NewString()
	// pauseProvider redis arm: setRedisACLEnabled(false) — but disabling our own
	// user mid-connection still returns nil from the command. Run pause then
	// resume; both must succeed. Re-enable via a separate admin call between if
	// needed is not required because the command itself returns OK.
	require.NoError(t, handlers.CallResumeProviderForTest(h, ctx, "redis", token, enc),
		"setRedisACLEnabled(on) success arm must return nil")
	require.NoError(t, handlers.CallPauseProviderForTest(h, ctx, "redis", token, enc),
		"setRedisACLEnabled(off) success arm must return nil")
}

// TestPauseResumeProvider_Mongo_HappyPath_Vecwave drives revokeMongoRoles /
// grantMongoRoles success returns. The helper derives username usr_<token> and
// db db_<token>; we create that user in the admin DB with the readWrite role so
// revoke (drop role) and grant (add role) both succeed.
func TestPauseResumeProvider_Mongo_HappyPath_Vecwave(t *testing.T) {
	mongoURI := os.Getenv("TEST_MONGO_URI")
	if mongoURI == "" {
		t.Skip("no TEST_MONGO_URI — skipping mongo provider happy path")
	}
	adminDB, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()

	ctx := context.Background()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	require.NoError(t, err)
	defer client.Disconnect(ctx)
	require.NoError(t, client.Ping(ctx, nil))

	token := uuid.NewString()
	user := "usr_" + token
	dbN := "db_" + token

	// Create the user in admin with readWrite on db_<token>.
	createRes := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "createUser", Value: user},
		{Key: "pwd", Value: "pw"},
		{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: "readWrite"}, {Key: "db", Value: dbN}}}},
	})
	require.NoError(t, createRes.Err())
	t.Cleanup(func() {
		client.Database("admin").RunCommand(context.Background(), bson.D{{Key: "dropUser", Value: user}})
	})

	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex, MongoAdminURI: mongoURI}
	h := handlers.NewResourceHandlerWithBackendsForTest(adminDB, cfg, plans.Default())

	// Pause → revokeRolesFromUser success.
	require.NoError(t, handlers.CallPauseProviderForTest(h, ctx, "mongodb", token, ""),
		"revokeMongoRoles success arm must return nil")
	// Resume → grantRolesToUser success.
	require.NoError(t, handlers.CallResumeProviderForTest(h, ctx, "mongodb", token, ""),
		"grantMongoRoles success arm must return nil")
}

// TestRotateCredentials_Postgres_HappyPath_Vecwave drives the RotateCredentials
// handler's postgres ALTER ROLE arm (lines 451-463) end-to-end against a real
// customer DB: decrypt → new password → url substitution → ALTER ROLE success →
// re-encrypt + persist → connection_url.decrypted audit emit. Returns the new
// plaintext URL (the one place connection_url is exposed).
func TestRotateCredentials_Postgres_HappyPath_Vecwave(t *testing.T) {
	customersDSN := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if customersDSN == "" {
		customersDSN = os.Getenv("TEST_DATABASE_URL")
	}
	if customersDSN == "" {
		t.Skip("no customer DSN — skipping rotate postgres happy path")
	}

	platformDB, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()

	ctx := context.Background()
	customerAdmin, err := sql.Open("postgres", customersDSN)
	require.NoError(t, err)
	require.NoError(t, customerAdmin.Ping())
	defer customerAdmin.Close()

	token := uuid.NewString()
	role := "usr_" + token
	_, err = customerAdmin.ExecContext(ctx, fmt.Sprintf(`CREATE ROLE %q LOGIN PASSWORD 'pw'`, role))
	require.NoError(t, err)
	t.Cleanup(func() { customerAdmin.ExecContext(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %q`, role)) })

	aesKey, kErr := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, kErr)
	plain := fmt.Sprintf("postgres://%s:pw@postgres-customers:5432/db_%s", role, token)
	enc, eErr := crypto.Encrypt(aesKey, plain)
	require.NoError(t, eErr)

	teamID := testhelpers.MustCreateTeamDB(t, platformDB, "pro")
	userID := uuid.NewString()
	_, err = platformDB.ExecContext(ctx, `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, connection_url)
		VALUES ($1::uuid, $2, 'postgres', 'pro', 'production', 'active', $3)`,
		teamID, token, enc)
	require.NoError(t, err)
	t.Cleanup(func() { platformDB.Exec(`DELETE FROM resources WHERE token = $1`, token) })

	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex, CustomerDatabaseURL: customersDSN}
	h := handlers.NewResourceHandler(platformDB, rdb, cfg, plans.Default(), nil, nil)
	app := newRotateApp(t, h, teamID, userID)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/rotate-credentials", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		OK            bool   `json:"ok"`
		ConnectionURL string `json:"connection_url"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.True(t, out.OK)
	assert.Contains(t, out.ConnectionURL, role, "rotated URL keeps the same username")
	assert.NotContains(t, out.ConnectionURL, ":pw@", "password must have been rotated")
}

// TestRotateCredentials_Redis_HappyPath_Vecwave drives the RotateCredentials
// handler's redis ACL-resetpass arm (lines 466-476): a redis resource whose
// encrypted connection_url carries a user with ACL perms. rotateRedisPassword
// runs ACL SETUSER <user> resetpass against the live test redis and succeeds.
func TestRotateCredentials_Redis_HappyPath_Vecwave(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("no redis URL — skipping rotate redis happy path")
	}
	platformDB, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()

	ctx := context.Background()
	opts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	admin := redis.NewClient(opts)
	defer admin.Close()

	user := "usr_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	require.NoError(t, admin.Do(ctx, "ACL", "SETUSER", user, "on", ">pw", "~*", "+@all").Err())
	t.Cleanup(func() { admin.Do(context.Background(), "ACL", "DELUSER", user) })

	aesKey, kErr := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, kErr)
	plain := fmt.Sprintf("redis://%s:pw@%s/%d", user, opts.Addr, opts.DB)
	enc, eErr := crypto.Encrypt(aesKey, plain)
	require.NoError(t, eErr)

	teamID := testhelpers.MustCreateTeamDB(t, platformDB, "pro")
	token := uuid.NewString()
	_, err = platformDB.ExecContext(ctx, `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, connection_url)
		VALUES ($1::uuid, $2, 'redis', 'pro', 'production', 'active', $3)`,
		teamID, token, enc)
	require.NoError(t, err)
	t.Cleanup(func() { platformDB.Exec(`DELETE FROM resources WHERE token = $1`, token) })

	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewResourceHandler(platformDB, rdb, cfg, plans.Default(), nil, nil)
	app := newRotateApp(t, h, teamID, uuid.NewString())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/rotate-credentials", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		OK            bool   `json:"ok"`
		ConnectionURL string `json:"connection_url"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.True(t, out.OK)
	assert.Contains(t, out.ConnectionURL, user)
}

// newRotateApp wires a fiber app with a fake-auth shim pinning team/user and
// the rotate-credentials route.
func newRotateApp(t *testing.T, h *handlers.ResourceHandler, teamID, userID string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		c.Locals(middleware.LocalKeyUserID, userID)
		return c.Next()
	})
	app.Post("/api/v1/resources/:id/rotate-credentials", h.RotateCredentials)
	return app
}
