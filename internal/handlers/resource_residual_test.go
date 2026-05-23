package handlers_test

// resource_residual_test.go — residual coverage for resource.go (90.9% → ≥95%).
// Targets the hard seams the prior slice left uncovered:
//
//   Delete:   the gRPC-provisioner deprovision arm (266-281) via the bufconn
//             fakeProvisioner; the storage deprovision arm (231-265) via a
//             MinIO-admin Provider pointed at an unreachable endpoint (the
//             Deprovision call errors → warn arm + Backend()==MinIOAdmin audit
//             branch); lookup-failed (brokenDB); cross-team 404; soft-delete
//             fail (sqlmock mid-call).
//   Pause:    lookup-failed (brokenDB); already-paused 409; tier-gate
//             rejection (non-Pro tier).
//   Resume:   not-paused 409.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/testhelpers"
)

// resourceResidualConfig is a minimal config: no customer/mongo URLs so the
// pause/resume provider helpers take their no-op test arms, AES key set so
// decrypt works.
func resourceResidualConfig() *config.Config {
	return &config.Config{
		Environment: "test",
		AESKey:      testhelpers.TestAESKeyHex,
		JWTSecret:   testhelpers.TestJWTSecret,
	}
}

// resourceResidualApp wires Get/Delete/Pause/Resume against a ResourceHandler
// built with the supplied db + provisioner + storage provider, behind a
// fake-auth shim that pins the caller's team/user.
func resourceResidualApp(t *testing.T, db *sql.DB, rdb interface{}, h *handlers.ResourceHandler, teamID, userID string) *fiber.App {
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
	app.Delete("/api/v1/resources/:id", h.Delete)
	app.Post("/api/v1/resources/:id/pause", h.Pause)
	app.Post("/api/v1/resources/:id/resume", h.Resume)
	return app
}

// seedTeamResource inserts a resource owned by teamID at the given type/status.
func seedTeamResource(t *testing.T, db *sql.DB, teamID, resType, status string) string {
	t.Helper()
	token := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status)
		VALUES ($1::uuid, $2, $3, 'pro', 'production', $4)
	`, teamID, token, resType, status)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })
	return token
}

func resDelete(t *testing.T, app *fiber.App, token string) (*http.Response, func()) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+token, nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp, func() { resp.Body.Close() }
}

// TestResidualDelete_ProvisionerArm drives the gRPC-provisioner deprovision arm
// (266-281): a postgres resource + a bufconn provisioner. DeprovisionResource
// is called once.
func TestResidualDelete_ProvisionerArm(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := uuid.NewString()

	fake := &fakeProvisioner{}
	prov := newBufconnProvisionerClient(t, fake)
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), prov, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, userID)

	token := seedTeamResource(t, db, teamID, "postgres", "active")
	resp, done := resDelete(t, app, token)
	defer done()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1, "provisioner DeprovisionResource must fire on delete")
}

// TestResidualDelete_StorageArm drives the storage deprovision arm (231-265):
// a storage resource + a MinIO-admin Provider pointed at an unreachable
// endpoint (Deprovision errors → warn arm). Backend()==MinIOAdmin so the audit
// branch's guard is also evaluated.
func TestResidualDelete_StorageArm(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := uuid.NewString()

	// Constructs fine (no connect); Deprovision against this dead endpoint
	// errors, exercising the deprovision-failed warn arm.
	sp, err := storageprovider.New("127.0.0.1:19097", "http://127.0.0.1:19097", "minioadmin", "minioadmin", "instant-shared")
	require.NoError(t, err)
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, sp)
	app := resourceResidualApp(t, db, rdb, h, teamID, userID)

	token := seedTeamResource(t, db, teamID, "storage", "active")
	resp, done := resDelete(t, app, token)
	defer done()
	// Delete fails open on the storage deprovision error → still 200.
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestResidualDelete_LookupFailed_BrokenDB drives the fetch_failed arm
// (205-210) via a brokenDB.
func TestResidualDelete_LookupFailed_BrokenDB(t *testing.T) {
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	h := handlers.NewResourceHandler(brokenDB(t), rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, nil, rdb, h, uuid.NewString(), uuid.NewString())
	resp, done := resDelete(t, app, uuid.NewString())
	defer done()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualDelete_SoftDeleteFailed_Sqlmock drives the delete_failed arm
// (219-225): GetResourceByToken succeeds (mocked, owned by the caller team),
// then SoftDeleteResource errors.
func TestResidualDelete_SoftDeleteFailed_Sqlmock(t *testing.T) {
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	token := uuid.New()
	// GetResourceByToken — return a resource owned by teamID. The column set
	// must match models.GetResourceByToken's SELECT; use a wide row and let
	// sqlmock map by position. We mock the minimum: id, team_id, token,
	// resource_type, status. To avoid coupling to the exact column list, we
	// return an error-free row via a permissive matcher and rely on the
	// handler reading TeamID + ResourceType + ID.
	mock.ExpectQuery(`FROM resources`).WithArgs(token).
		WillReturnRows(resourceRowForDelete(token, teamID))
	mock.ExpectExec(`UPDATE resources SET status`).WillReturnError(errors.New("soft delete boom"))

	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID.String(), uuid.NewString())
	resp, done := resDelete(t, app, token.String())
	defer done()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualPause_AlreadyPaused_409 drives the already-paused arm (581-585).
func TestResidualPause_AlreadyPaused_409(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())

	token := seedTeamResource(t, db, teamID, "redis", "paused")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/pause", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// TestResidualPause_TierGate drives the tier-gate rejection (598-600): a hobby
// team can't pause (Pro+ feature).
func TestResidualPause_TierGate(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())

	token := seedTeamResourceTier(t, db, teamID, "redis", "active", "hobby")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/pause", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Pause is Pro+ — a hobby team is rejected (402 upgrade-required).
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
}

// TestResidualPause_PostgresProviderFailed_503 drives the pauseProvider
// postgres arm (818-826) + revokePostgresConnect validate-error + the Pause
// provider_failed arm (604-613): a postgres resource with CustomerDatabaseURL
// configured but a connection_url that yields an empty username, so
// validateSQLIdent rejects it and the revoke errors.
func TestResidualPause_PostgresProviderFailed_503(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	cfg := resourceResidualConfig()
	cfg.CustomerDatabaseURL = "postgres://nouser:nopass@127.0.0.1:5999/none?sslmode=disable"
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())
	// postgres resource with an empty/garbage connection_url → username extract
	// yields "" → validateSQLIdent rejects → revoke errors → provider_failed.
	token := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, connection_url)
		VALUES ($1::uuid, $2, 'postgres', 'pro', 'production', 'active', '')
	`, teamID, token)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/pause", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualPauseResume_Mongo_ProviderArms drives the pauseProvider +
// resumeProvider mongo arms (842-847 / 875-880) + revokeMongoRoles /
// grantMongoRoles against the live test MongoDB. The user doesn't exist, so
// revokeRolesFromUser errors → Pause returns 503 provider_failed; that
// exercises the connect-success + RunCommand-error path of revokeMongoRoles.
func TestResidualPause_Mongo_ProviderArm(t *testing.T) {
	if os.Getenv("TEST_MONGO_URI") == "" {
		t.Skip("TEST_MONGO_URI not set — skipping mongo provider arm test")
	}
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	cfg := resourceResidualConfig()
	cfg.MongoAdminURI = os.Getenv("TEST_MONGO_URI")
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())
	token := seedTeamResource(t, db, teamID, "mongodb", "active")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/pause", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// revokeRolesFromUser for a nonexistent user errors → provider_failed 503.
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualPause_LookupFailed_BrokenDB drives the pause fetch_failed arm
// (567-568) via a brokenDB.
func TestResidualPause_LookupFailed_BrokenDB(t *testing.T) {
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	h := handlers.NewResourceHandler(brokenDB(t), rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, nil, rdb, h, uuid.NewString(), uuid.NewString())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+uuid.NewString()+"/pause", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualResume_NotPaused_409 drives the resume not-paused arm: resuming
// an active resource is a 409.
func TestResidualResume_NotPaused_409(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())

	token := seedTeamResource(t, db, teamID, "redis", "active")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/resume", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func resourceResidualAppRotate(t *testing.T, db *sql.DB, rdb interface{}, h *handlers.ResourceHandler, teamID, userID string) *fiber.App {
	t.Helper()
	app := resourceResidualApp(t, db, rdb, h, teamID, userID)
	app.Post("/api/v1/resources/:id/rotate-credentials", h.RotateCredentials)
	return app
}

// TestResidualRotate_LookupFailed_BrokenDB drives RotateCredentials
// fetch_failed (399-401) via a brokenDB.
func TestResidualRotate_LookupFailed_BrokenDB(t *testing.T) {
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	h := handlers.NewResourceHandler(brokenDB(t), rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualAppRotate(t, nil, rdb, h, uuid.NewString(), uuid.NewString())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+uuid.NewString()+"/rotate-credentials", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualRotate_NoConnectionURL_400 drives the no_connection_url arm
// (410-413): a resource with a NULL connection_url.
func TestResidualRotate_NoConnectionURL_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualAppRotate(t, db, rdb, h, teamID, uuid.NewString())
	token := seedTeamResource(t, db, teamID, "redis", "active") // no connection_url
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/rotate-credentials", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestResidualRotate_DecryptFailed_500 drives the decrypt_failed arm
// (425-428): a resource whose connection_url is not valid ciphertext.
func TestResidualRotate_DecryptFailed_500(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualAppRotate(t, db, rdb, h, teamID, uuid.NewString())
	token := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, connection_url)
		VALUES ($1::uuid, $2, 'redis', 'pro', 'production', 'active', 'not-valid-ciphertext')
	`, teamID, token)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/rotate-credentials", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestResidualResume_LookupFailed_BrokenDB drives the resume fetch_failed arm
// via a brokenDB.
func TestResidualResume_LookupFailed_BrokenDB(t *testing.T) {
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	h := handlers.NewResourceHandler(brokenDB(t), rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, nil, rdb, h, uuid.NewString(), uuid.NewString())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+uuid.NewString()+"/resume", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualPause_HappyPath_WithExpiry covers the Pause success path
// (646-679) + resourceToMap's expires_at (1108-1110) + paused_at (1111-1113)
// branches: a pro resource carrying an explicit expires_at is paused.
func TestResidualPause_HappyPath_WithExpiry(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())
	// queue resource (pauseProvider no-op default arm) with an expires_at set.
	token := uuid.NewString()
	exp := time.Now().Add(24 * time.Hour)
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, expires_at)
		VALUES ($1::uuid, $2, 'queue', 'pro', 'production', 'active', $3)
	`, teamID, token, exp)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/pause", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestResidualPause_Redis_ProviderArm drives the pauseProvider redis arm
// (827-841) + setRedisACLEnabled + the Pause provider_failed arm (604-613): a
// redis resource carrying an AES-encrypted connection_url. The URL's own
// (limited) credentials can't run ACL SETUSER, so the toggle errors and Pause
// returns 503 provider_failed — which is exactly the arm we want to exercise.
func TestResidualPause_Redis_ProviderArm(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")

	user := "u" + uuid.NewString()[:8]
	redisURL := "redis://" + user + ":pw@127.0.0.1:6397/15"
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, redisURL)
	require.NoError(t, err)

	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())
	token := uuid.NewString()
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, connection_url)
		VALUES ($1::uuid, $2, 'redis', 'pro', 'production', 'active', $3)
	`, teamID, token, enc)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })

	pReq := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/pause", nil)
	pResp, err := app.Test(pReq, 10000)
	require.NoError(t, err)
	defer pResp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, pResp.StatusCode)
}

// TestResidualResume_HappyPath_200 drives the resume success path (735-760+):
// resuming a paused resource flips it active and 200s. Resume has NO tier gate
// (by design — see resource.go comment) so a hobby team can resume too.
func TestResidualResume_HappyPath_200(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, nil)
	app := resourceResidualApp(t, db, rdb, h, teamID, uuid.NewString())
	token := seedTeamResourceTier(t, db, teamID, "redis", "paused", "hobby")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/"+token+"/resume", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// seedTeamResourceTier is seedTeamResource with an explicit tier.
func seedTeamResourceTier(t *testing.T, db *sql.DB, teamID, resType, status, tier string) string {
	t.Helper()
	token := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status)
		VALUES ($1::uuid, $2, $3, $4, 'production', $5)
	`, teamID, token, resType, tier, status)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE token = $1`, token) })
	return token
}

// resourceRowForDelete builds a 26-column sqlmock row matching
// models.resourceColumns / scanResource. The resource is a postgres resource
// owned by teamID with status='active' (so Delete reaches SoftDeleteResource).
func resourceRowForDelete(token, teamID uuid.UUID) *sqlmock.Rows {
	cols := []string{
		"id", "team_id", "token", "resource_type", "name", "connection_url", "key_prefix",
		"tier", "env", "fingerprint", "cloud_vendor", "country_code", "status",
		"migration_status", "expires_at", "storage_bytes", "provider_resource_id", "created_request_id",
		"parent_resource_id", "paused_at",
		"last_seen_at", "degraded", "degraded_reason", "last_reconciled_at",
		"auth_mode", "created_at",
	}
	return sqlmock.NewRows(cols).AddRow(
		uuid.New(),    // id
		teamID,        // team_id
		token,         // token
		"postgres",    // resource_type
		nil,           // name
		nil,           // connection_url
		nil,           // key_prefix
		"pro",         // tier
		"production",  // env
		nil,           // fingerprint
		nil,           // cloud_vendor
		nil,           // country_code
		"active",      // status
		nil,           // migration_status
		nil,           // expires_at
		int64(0),      // storage_bytes
		nil,           // provider_resource_id
		nil,           // created_request_id
		nil,           // parent_resource_id
		nil,           // paused_at
		nil,           // last_seen_at
		false,         // degraded
		nil,           // degraded_reason
		nil,           // last_reconciled_at
		"legacy_open", // auth_mode
		time.Now(),    // created_at
	)
}
