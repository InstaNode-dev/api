package handlers_test

// resource_handlers_rbw_test.go — error-branch coverage for the resource
// lifecycle handler methods (List/Get/Delete/GetCredentials/RotateCredentials/
// Pause/Resume). The happy paths are covered by the full-backend lifecycle
// tests; this file drives the unauthorized / invalid-id / not-found /
// cross-team / DB-error arms that those flows don't reach.
//
// Auth is injected via a Locals-shim middleware (not RequireAuth) so we can
// set an empty / malformed team_id to hit the handler's own parseTeamID arm,
// which RequireAuth would otherwise short-circuit before the handler runs.

import (
	"context"
	"database/sql"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// mustEncryptForTest encrypts plaintext with the shared test AES key.
func mustEncryptForTest(t *testing.T, plain string) string {
	t.Helper()
	key, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(key, plain)
	require.NoError(t, err)
	return enc
}

// mustInsertResourceWithURLStatus inserts a resource with both an (encrypted)
// connection_url and an explicit status.
func mustInsertResourceWithURLStatus(t *testing.T, db *sql.DB, teamID, resType, encURL, status string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status, connection_url)
		 VALUES ($1::uuid, $2, 'pro', $3, $4) RETURNING token::text`,
		teamID, resType, status, encURL,
	).Scan(&token))
	return token
}

// mustInsertResource inserts an active resource for a team and returns its
// token (UUID string).
func mustInsertResource(t *testing.T, db *sql.DB, teamID, resType string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status)
		 VALUES ($1::uuid, $2, 'pro', 'active') RETURNING token::text`,
		teamID, resType,
	).Scan(&token))
	return token
}

// localsApp mounts the resource routes behind a shim that sets team_id/user_id
// Locals to the given values (empty string = "no auth").
func localsApp(t *testing.T, h *handlers.ResourceHandler, teamID, userID string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{ErrorHandler: rbwErrorHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		if userID != "" {
			c.Locals(middleware.LocalKeyUserID, userID)
		}
		return c.Next()
	})
	app.Get("/r/:id", h.Get)
	app.Get("/r", h.List)
	app.Delete("/r/:id", h.Delete)
	app.Get("/r/:id/creds", h.GetCredentials)
	app.Post("/r/:id/rotate", h.RotateCredentials)
	app.Post("/r/:id/pause", h.Pause)
	app.Post("/r/:id/resume", h.Resume)
	return app
}

func rbwErrorHandler(c *fiber.Ctx, err error) error {
	if errors.Is(err, handlers.ErrResponseWritten) {
		return nil
	}
	return fiber.DefaultErrorHandler(c, err)
}

func doReqRBW(t *testing.T, app *fiber.App, method, path string) int {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(method, path, nil), 10000)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func newResourceHandlerForTest(t *testing.T) (*handlers.ResourceHandler, func()) {
	t.Helper()
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	return h, func() { dbClean(); rClean() }
}

// mustInsertResourceWithURL inserts an active resource with a connection_url
// (already-encrypted ciphertext supplied by the caller).
func mustInsertResourceWithURL(t *testing.T, db *sql.DB, teamID, resType, encURL string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status, connection_url)
		 VALUES ($1::uuid, $2, 'pro', 'active', $3) RETURNING token::text`,
		teamID, resType, encURL,
	).Scan(&token))
	return token
}

// TestGetCredentials_NoConnectionURL covers the no_connection_url 400 arm.
func TestGetCredentials_NoConnectionURL(t *testing.T) {
	h, clean := newResourceHandlerForTest(t)
	defer clean()
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := mustInsertResource(t, db, team, "postgres") // null connection_url
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusBadRequest, doReqRBW(t, app, "GET", "/r/"+token+"/creds"))
	require.Equal(t, fiber.StatusBadRequest, doReqRBW(t, app, "POST", "/r/"+token+"/rotate"))
}

// TestGetCredentials_AESKeyInvalid covers the aes_key_invalid 500 arm of both
// GetCredentials and RotateCredentials (handler configured with a junk key).
func TestGetCredentials_AESKeyInvalid(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: "not-a-valid-hex-key"}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)

	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := mustInsertResourceWithURL(t, db, team, "postgres", "ciphertext-doesnt-matter")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusInternalServerError, doReqRBW(t, app, "GET", "/r/"+token+"/creds"))
	require.Equal(t, fiber.StatusInternalServerError, doReqRBW(t, app, "POST", "/r/"+token+"/rotate"))
}

// TestGetCredentials_DecryptFailed covers the decrypt_failed 500 arm: a valid
// AES key but ciphertext that wasn't produced by it.
func TestGetCredentials_DecryptFailed(t *testing.T) {
	h, clean := newResourceHandlerForTest(t) // uses TestAESKeyHex
	defer clean()
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := mustInsertResourceWithURL(t, db, team, "postgres", "deadbeefnotcipher")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusInternalServerError, doReqRBW(t, app, "GET", "/r/"+token+"/creds"))
	require.Equal(t, fiber.StatusInternalServerError, doReqRBW(t, app, "POST", "/r/"+token+"/rotate"))
}

// mustInsertResourceWithStatus inserts a resource with a specific status.
func mustInsertResourceWithStatus(t *testing.T, db *sql.DB, teamID, resType, status string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status)
		 VALUES ($1::uuid, $2, 'pro', $3) RETURNING token::text`,
		teamID, resType, status,
	).Scan(&token))
	return token
}

// pauseResumeFixture wires a handler whose CustomerDatabaseURL/MongoAdminURI
// are empty, so pauseProvider/resumeProvider no-op for postgres — letting the
// DB-flip success path run without a live backend.
func pauseResumeFixture(t *testing.T, planTier string) (*handlers.ResourceHandler, *sql.DB, string) {
	t.Helper()
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { dbClean(); rClean() })
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex} // no CustomerDatabaseURL
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	team := testhelpers.MustCreateTeamDB(t, db, planTier)
	return h, db, team
}

// TestPause_Success covers the Pause happy path (provider no-op for postgres
// with no CustomerDatabaseURL → DB flip → 200).
func TestPause_Success(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "pro")
	token := mustInsertResourceWithStatus(t, db, team, "postgres", "active")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+token+"/pause"))
}

// TestResume_Success covers the Resume happy path (paused → active).
func TestResume_Success(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "pro")
	token := mustInsertResourceWithStatus(t, db, team, "postgres", "paused")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+token+"/resume"))
}

// TestPause_AlreadyPaused covers the already_paused 409 arm.
func TestPause_AlreadyPaused(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "pro")
	token := mustInsertResourceWithStatus(t, db, team, "postgres", "paused")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusConflict, doReqRBW(t, app, "POST", "/r/"+token+"/pause"))
}

// TestPause_InvalidState covers the invalid_state 409 arm (deleted resource).
func TestPause_InvalidState(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "pro")
	token := mustInsertResourceWithStatus(t, db, team, "postgres", "deleted")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusConflict, doReqRBW(t, app, "POST", "/r/"+token+"/pause"))
}

// TestPause_TierGate covers the pause upgrade-required arm for a hobby team.
func TestPause_TierGate(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "hobby")
	token := mustInsertResourceWithStatus(t, db, team, "postgres", "active")
	app := localsApp(t, h, team, uuid.NewString())
	code := doReqRBW(t, app, "POST", "/r/"+token+"/pause")
	require.Equal(t, fiber.StatusPaymentRequired, code, "hobby pause should require upgrade")
}

// TestPauseResume_RedisMongo_NoOpArms covers pauseProvider/resumeProvider's
// redis (empty-URL no-op) and mongo (empty-MongoAdminURI no-op) branches via
// the no-backend fixture. Redis resources have no connection_url here so
// decryptOrEmpty returns "" → the no-op return; mongo has MongoAdminURI=="".
func TestPauseResume_RedisMongo_NoOpArms(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "pro")
	app := localsApp(t, h, team, uuid.NewString())

	// redis active → pause (decryptOrEmpty=="" no-op) → 200
	rtok := mustInsertResourceWithStatus(t, db, team, "redis", "active")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+rtok+"/pause"))

	// mongodb active → pause (MongoAdminURI=="" no-op) → 200
	mtok := mustInsertResourceWithStatus(t, db, team, "mongodb", "active")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+mtok+"/pause"))

	// redis/mongo paused → resume → 200 (inverse no-op arms)
	rtok2 := mustInsertResourceWithStatus(t, db, team, "redis", "paused")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+rtok2+"/resume"))
	mtok2 := mustInsertResourceWithStatus(t, db, team, "mongodb", "paused")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+mtok2+"/resume"))

	// storage/queue/webhook → default no-op arm
	stok := mustInsertResourceWithStatus(t, db, team, "storage", "active")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+stok+"/pause"))
}

// TestRotate_ProviderWarnArms covers RotateCredentials' non-fatal provider
// rotate arms for postgres/redis/mongo: the backend rotate fails (unreachable)
// but the handler still persists the new URL and returns 200.
func TestRotate_ProviderWarnArms(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { dbClean(); rClean() })
	cfg := &config.Config{
		Environment:         "test",
		AESKey:              testhelpers.TestAESKeyHex,
		CustomerDatabaseURL: "postgres://nobody@127.0.0.1:1/x?sslmode=disable&connect_timeout=1",
		MongoAdminURI:       "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=300",
	}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	app := localsApp(t, h, team, uuid.NewString())

	// postgres: rotatePostgresPassword warns (unreachable) → still 200
	pgEnc := mustEncryptForTest(t, "postgres://usr_x:pw@127.0.0.1:1/db_x")
	pgTok := mustInsertResourceWithURLStatus(t, db, team, "postgres", pgEnc, "active")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+pgTok+"/rotate"))

	// redis: rotateRedisPassword warns (unreachable host) → still 200
	rEnc := mustEncryptForTest(t, "redis://usr_x:pw@127.0.0.1:1/0")
	rTok := mustInsertResourceWithURLStatus(t, db, team, "redis", rEnc, "active")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+rTok+"/rotate"))

	// mongodb: rotateMongoPassword warns (unreachable) → still 200
	mEnc := mustEncryptForTest(t, "mongodb://usr_x:pw@127.0.0.1:1/db_x")
	mTok := mustInsertResourceWithURLStatus(t, db, team, "mongodb", mEnc, "active")
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "POST", "/r/"+mTok+"/rotate"))
}

// TestResume_NotPaused covers the not_paused 409 arm (active resource).
func TestResume_NotPaused(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "pro")
	token := mustInsertResourceWithStatus(t, db, team, "postgres", "active")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusConflict, doReqRBW(t, app, "POST", "/r/"+token+"/resume"))
}

// TestDelete_Success covers the Delete happy path (soft-delete, nil provisioner
// → deprovision skipped, 200).
func TestDelete_Success(t *testing.T) {
	h, db, team := pauseResumeFixture(t, "pro")
	token := mustInsertResourceWithStatus(t, db, team, "postgres", "active")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusOK, doReqRBW(t, app, "DELETE", "/r/"+token))
}

// TestPause_ProviderFailed covers the provider_failed 503 arm: a postgres
// resource with a CustomerDatabaseURL pointing at a closed port makes
// pauseProvider's revokePostgresConnect fail, so the DB row stays active and
// the caller gets 503 (the iron-rule atomicity guarantee).
func TestPause_ProviderFailed(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { dbClean(); rClean() })
	cfg := &config.Config{
		Environment:         "test",
		AESKey:              testhelpers.TestAESKeyHex,
		CustomerDatabaseURL: "postgres://nobody@127.0.0.1:1/x?sslmode=disable&connect_timeout=1",
	}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	// Needs a decryptable connection_url so pauseProvider extracts a username
	// and reaches revokePostgresConnect against the unreachable customer DB.
	enc := mustEncryptForTest(t, "postgres://usr_x:pw@host:5432/db_x")
	token := mustInsertResourceWithURLStatus(t, db, team, "postgres", enc, "active")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "POST", "/r/"+token+"/pause"))
}

// TestResume_ProviderFailed mirrors TestPause_ProviderFailed for resume.
func TestResume_ProviderFailed(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { dbClean(); rClean() })
	cfg := &config.Config{
		Environment:         "test",
		AESKey:              testhelpers.TestAESKeyHex,
		CustomerDatabaseURL: "postgres://nobody@127.0.0.1:1/x?sslmode=disable&connect_timeout=1",
	}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	enc := mustEncryptForTest(t, "postgres://usr_x:pw@host:5432/db_x")
	token := mustInsertResourceWithURLStatus(t, db, team, "postgres", enc, "paused")
	app := localsApp(t, h, team, uuid.NewString())
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "POST", "/r/"+token+"/resume"))
}

// TestResourceMethods_Unauthorized covers the parseTeamID unauthorized arm of
// every method (empty team_id Local).
func TestResourceMethods_Unauthorized(t *testing.T) {
	h, clean := newResourceHandlerForTest(t)
	defer clean()
	app := localsApp(t, h, "", "")
	id := uuid.NewString()
	cases := []struct {
		method, path string
	}{
		{"GET", "/r"},
		{"GET", "/r/" + id},
		{"DELETE", "/r/" + id},
		{"GET", "/r/" + id + "/creds"},
		{"POST", "/r/" + id + "/rotate"},
		{"POST", "/r/" + id + "/pause"},
		{"POST", "/r/" + id + "/resume"},
	}
	for _, tc := range cases {
		require.Equal(t, fiber.StatusUnauthorized, doReqRBW(t, app, tc.method, tc.path),
			"%s %s should be 401 with no team_id", tc.method, tc.path)
	}
}

// TestResourceMethods_InvalidUUID covers the uuid.Parse invalid_id arm.
func TestResourceMethods_InvalidUUID(t *testing.T) {
	h, clean := newResourceHandlerForTest(t)
	defer clean()
	app := localsApp(t, h, uuid.NewString(), uuid.NewString())
	for _, p := range []string{"/r/not-a-uuid", "/r/not-a-uuid/creds"} {
		require.Equal(t, fiber.StatusBadRequest, doReqRBW(t, app, "GET", p), "GET %s", p)
	}
	for _, p := range []string{"/r/not-a-uuid", "/r/not-a-uuid/rotate", "/r/not-a-uuid/pause", "/r/not-a-uuid/resume"} {
		m := "POST"
		if p == "/r/not-a-uuid" {
			m = "DELETE"
		}
		require.Equal(t, fiber.StatusBadRequest, doReqRBW(t, app, m, p), "%s %s", m, p)
	}
}

// TestResourceMethods_NotFound covers the not_found arm (valid UUID, no row).
func TestResourceMethods_NotFound(t *testing.T) {
	h, clean := newResourceHandlerForTest(t)
	defer clean()
	app := localsApp(t, h, uuid.NewString(), uuid.NewString())
	id := uuid.NewString()
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "GET", "/r/"+id))
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "DELETE", "/r/"+id))
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "GET", "/r/"+id+"/creds"))
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "POST", "/r/"+id+"/rotate"))
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "POST", "/r/"+id+"/pause"))
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "POST", "/r/"+id+"/resume"))
}

// TestResourceMethods_DBError covers the fetch_failed / list_failed arms by
// closing the platform DB pool so every query errors.
func TestResourceMethods_DBError(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	dbClean() // close the pool — every query now errors

	app := localsApp(t, h, uuid.NewString(), uuid.NewString())
	id := uuid.NewString()
	// List → list_failed (503)
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "GET", "/r"))
	// Get/Delete/GetCredentials → fetch_failed (503)
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "GET", "/r/"+id))
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "DELETE", "/r/"+id))
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "GET", "/r/"+id+"/creds"))
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "POST", "/r/"+id+"/rotate"))
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "POST", "/r/"+id+"/pause"))
	require.Equal(t, fiber.StatusServiceUnavailable, doReqRBW(t, app, "POST", "/r/"+id+"/resume"))
}

// TestResourceMethods_CrossTeam covers the cross-team 404 arm: a resource that
// belongs to a different team must 404 (never 403) for the requesting team.
func TestResourceMethods_CrossTeam(t *testing.T) {
	h, clean := newResourceHandlerForTest(t)
	defer clean()
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()

	ownerTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	token := mustInsertResource(t, db, ownerTeam, "postgres")

	// Request as a DIFFERENT team.
	otherTeam := uuid.NewString()
	app := localsApp(t, h, otherTeam, uuid.NewString())
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "GET", "/r/"+token))
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "DELETE", "/r/"+token))
	require.Equal(t, fiber.StatusNotFound, doReqRBW(t, app, "GET", "/r/"+token+"/creds"))
}
