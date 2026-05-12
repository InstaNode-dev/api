package handlers_test

// stack_test.go — Integration tests for StackHandler.
//
// These tests use NoopStackProvider + a real test database (TEST_DATABASE_URL).
// If the DB is unavailable the test is skipped via testhelpers.SetupTestDB's
// built-in skip path.
//
// Run:
//   TEST_DATABASE_URL=postgres://instant:instant@localhost:5432/instant_platform?sslmode=disable \
//   go test ./internal/handlers/... -run TestStack -v -count=1

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// requireTestDB skips the test if TEST_DATABASE_URL is not set.
// This prevents t.Fatalf (from testhelpers.SetupTestDB) in environments
// where Postgres is not available (e.g. CI without a DB sidecar).
func requireTestDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping DB integration test")
	}
}

// ── stack-specific DB migrations ──────────────────────────────────────────────

// ensureStackTables creates the stacks + stack_services tables in the test DB if
// they do not already exist. Called at the top of each stack test so the suite
// works even when testhelpers.runMigrations does not yet include these tables.
func ensureStackTables(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS stacks (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id         UUID REFERENCES teams(id) ON DELETE CASCADE,
			name            TEXT,
			slug            TEXT UNIQUE NOT NULL,
			namespace       TEXT UNIQUE NOT NULL,
			status          TEXT NOT NULL DEFAULT 'building',
			tier            TEXT NOT NULL DEFAULT 'hobby',
			env             TEXT NOT NULL DEFAULT 'production',
			parent_stack_id UUID,
			expires_at      TIMESTAMPTZ,
			fingerprint     TEXT,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// Idempotent ALTERs for environments where the table already existed
		// before this migration (matches the production migration sequence).
		`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production'`,
		`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS parent_stack_id UUID`,
		`CREATE TABLE IF NOT EXISTS stack_services (
			id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			stack_id    UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
			name        TEXT NOT NULL,
			image_tag   TEXT,
			status      TEXT NOT NULL DEFAULT 'building',
			expose      BOOLEAN NOT NULL DEFAULT FALSE,
			port        INT NOT NULL DEFAULT 8080,
			app_url     TEXT,
			error_msg   TEXT,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(stack_id, name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_stacks_team_id     ON stacks(team_id)`,
		`CREATE INDEX IF NOT EXISTS idx_stacks_slug        ON stacks(slug)`,
		`CREATE INDEX IF NOT EXISTS idx_stack_services_stack ON stack_services(stack_id)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("ensureStackTables: %v\n  SQL: %.120s", err, s)
		}
	}
}

// ── test app helpers ──────────────────────────────────────────────────────────

// newStackTestApp creates a minimal Fiber app with all stack routes registered,
// backed by the provided test DB and using NoopStackProvider.
// rdb may be nil since StackHandler does not use Redis directly.
func newStackTestApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
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
			return c.Status(code).JSON(fiber.Map{
				"ok":      false,
				"error":   "internal_error",
				"message": err.Error(),
			})
		},
	})

	stackH := handlers.NewStackHandler(db, nil, cfg, plans.Default())

	// Mirror router.go: OptionalAuth for anonymous-capable routes, RequireAuth for mutations.
	app.Post("/stacks/new", middleware.OptionalAuth(cfg), stackH.New)
	app.Get("/stacks/:slug", middleware.OptionalAuth(cfg), stackH.Get)
	app.Get("/stacks/:slug/logs/:svc", middleware.OptionalAuth(cfg), stackH.Logs)
	app.Delete("/stacks/:slug", middleware.OptionalAuth(cfg), stackH.Delete)
	app.Patch("/stacks/:slug/env", middleware.RequireAuth(cfg), stackH.UpdateEnv)
	app.Post("/stacks/:slug/redeploy", middleware.RequireAuth(cfg), stackH.Redeploy)

	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/stacks", stackH.List)
	api.Post("/stacks/:slug/promote", stackH.Promote)

	return app
}

// ── tarball + multipart helpers ───────────────────────────────────────────────

// createMinimalTarball returns a minimal valid gzipped tarball containing a
// placeholder Dockerfile. The noop provider never inspects tarball contents.
func createMinimalTarball(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("FROM scratch\n")
	hdr := &tar.Header{
		Name: "Dockerfile",
		Mode: 0o644,
		Size: int64(len(content)),
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// multipartBody builds a multipart/form-data body from the given manifest YAML
// and per-service tarball map. Also accepts optional plain string fields via
// extraFields (e.g. {"name": "my-stack"}).
func multipartBody(t *testing.T, manifestYAML string, tarballs map[string][]byte, extraFields map[string]string) (body *bytes.Buffer, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Write manifest field.
	fw, err := mw.CreateFormField("manifest")
	require.NoError(t, err)
	_, err = io.WriteString(fw, manifestYAML)
	require.NoError(t, err)

	// Write extra string fields.
	for k, v := range extraFields {
		fw, err = mw.CreateFormField(k)
		require.NoError(t, err)
		_, err = io.WriteString(fw, v)
		require.NoError(t, err)
	}

	// Write per-service tarballs.
	for svcName, tarball := range tarballs {
		ff, err := mw.CreateFormFile(svcName, svcName+".tar.gz")
		require.NoError(t, err)
		_, err = ff.Write(tarball)
		require.NoError(t, err)
	}

	require.NoError(t, mw.Close())
	return &buf, mw.FormDataContentType()
}

// postStackNew is a convenience helper that posts to /stacks/new with an auth
// header and the provided manifest + tarballs.
func postStackNew(t *testing.T, app *fiber.App, authToken, manifestYAML string, tarballs map[string][]byte) *http.Response {
	t.Helper()
	body, ct := multipartBody(t, manifestYAML, tarballs, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	req.Header.Set("X-Forwarded-For", "10.10.10.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	return resp
}

// ── test manifests ────────────────────────────────────────────────────────────

const testManifest = `
services:
  api:
    build: ./api
    port: 8080
    expose: true
  worker:
    build: ./worker
    port: 8080
    expose: false
    env:
      LOG_LEVEL: debug
`

const testManifestSingleService = `
services:
  web:
    build: ./web
    port: 3000
    expose: true
`

// ── tests ─────────────────────────────────────────────────────────────────────

// TestStackNew_ValidManifest verifies that POST /stacks/new with a valid 2-service
// manifest + tarballs returns 202 and creates DB rows.
func TestStackNew_ValidManifest(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-1", teamID, "stack1@example.com")

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	tarballs := map[string][]byte{
		"api":    tarball,
		"worker": tarball,
	}
	resp := postStackNew(t, app, sessionJWT, testManifest, tarballs)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body struct {
		OK      bool   `json:"ok"`
		StackID string `json:"stack_id"`
		Status  string `json:"status"`
		Note    string `json:"note"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.NotEmpty(t, body.StackID, "stack_id must be set")
	assert.Equal(t, "building", body.Status)
	assert.NotEmpty(t, body.Note)

	// Verify DB: stack row exists.
	var stackCount int
	require.NoError(t,
		db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM stacks WHERE slug = $1`, body.StackID,
		).Scan(&stackCount),
	)
	assert.Equal(t, 1, stackCount, "stack row must exist in DB")

	// Verify DB: service rows exist.
	var svcCount int
	require.NoError(t,
		db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM stack_services ss
			JOIN stacks s ON s.id = ss.stack_id
			WHERE s.slug = $1
		`, body.StackID).Scan(&svcCount),
	)
	assert.Equal(t, 2, svcCount, "two service rows must be created")
}

// TestStackNew_MissingManifest verifies that POST /stacks/new with no manifest
// field returns 400.
func TestStackNew_MissingManifest(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-2", teamID, "stack2@example.com")

	app := newStackTestApp(t, db)

	// Send a multipart form with NO manifest field.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	require.NoError(t, mw.Close())

	req := httptest.NewRequest(http.MethodPost, "/stacks/new", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.False(t, errBody.OK)
	assert.Contains(t, errBody.Message+errBody.Error, "manifest")
}

// TestStackNew_InvalidYAML verifies that an invalid YAML manifest returns 400
// with error="invalid_manifest".
func TestStackNew_InvalidYAML(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-3", teamID, "stack3@example.com")

	app := newStackTestApp(t, db)

	resp := postStackNew(t, app, sessionJWT, ":::not valid yaml:::", nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "invalid_manifest", errBody.Error)
}

// TestStackNew_MissingTarball verifies that a valid 2-service manifest with only
// 1 tarball returns 400 with error="missing_tarball".
func TestStackNew_MissingTarball(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-4", teamID, "stack4@example.com")

	app := newStackTestApp(t, db)

	// Manifest declares "api" and "worker" but we only supply "api".
	tarballs := map[string][]byte{
		"api": createMinimalTarball(t),
		// "worker" intentionally omitted
	}
	resp := postStackNew(t, app, sessionJWT, testManifest, tarballs)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "missing_tarball", errBody.Error)
}

// TestStackNew_UnknownServiceRef verifies that a manifest with a service:// env
// reference pointing to an undeclared service returns 400 with error="invalid_manifest".
func TestStackNew_UnknownServiceRef(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-5", teamID, "stack5@example.com")

	app := newStackTestApp(t, db)

	badManifest := `
services:
  web:
    build: ./web
    port: 3000
    expose: true
    env:
      BACKEND_URL: service://unknown-service
`
	tarball := createMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	resp := postStackNew(t, app, sessionJWT, badManifest, tarballs)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "invalid_manifest", errBody.Error)
	assert.Contains(t, errBody.Message, "unknown")
}

// TestStackNew_Anonymous_Returns202 verifies that POST /stacks/new without auth
// returns 202 with tier=anonymous and expires_in=24h — same model as /db/new, /cache/new.
func TestStackNew_Anonymous_Returns202(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	resp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{"web": tarball})
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("POST /stacks/new: service unavailable")
	}
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body struct {
		OK        bool   `json:"ok"`
		StackID   string `json:"stack_id"`
		Status    string `json:"status"`
		Tier      string `json:"tier"`
		ExpiresIn string `json:"expires_in"`
		Note      string `json:"note"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.NotEmpty(t, body.StackID)
	assert.Equal(t, "anonymous", body.Tier)
	assert.Equal(t, "24h", body.ExpiresIn)
	assert.Contains(t, body.Note, "instanode.dev/start", "upgrade URL must appear in note")

	// Verify DB: stack has nil team_id and non-nil expires_at.
	var teamIDNull sql.NullString
	var expiresAtNull sql.NullTime
	require.NoError(t,
		db.QueryRowContext(context.Background(),
			`SELECT team_id::text, expires_at FROM stacks WHERE slug = $1`, body.StackID,
		).Scan(&teamIDNull, &expiresAtNull),
	)
	assert.False(t, teamIDNull.Valid, "anonymous stack must have NULL team_id")
	assert.True(t, expiresAtNull.Valid, "anonymous stack must have non-NULL expires_at")
}

// TestStackGet_NotFound verifies that GET /stacks/nonexistent returns 404.
func TestStackGet_NotFound(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-6", teamID, "stack6@example.com")

	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodGet, "/stacks/stk-notexist", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestStackGet_WrongTeam verifies that a stack owned by team A is invisible
// to team B (returns 404, not 403 — avoids leaking existence).
func TestStackGet_WrongTeam(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	// Team A creates a stack.
	teamAID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWTA := testhelpers.MustSignSessionJWT(t, "user-a", teamAID, "a@example.com")

	// Team B will try to read it.
	teamBID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWTB := testhelpers.MustSignSessionJWT(t, "user-b", teamBID, "b@example.com")

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}
	resp := postStackNew(t, app, sessionJWTA, testManifestSingleService, tarballs)
	defer resp.Body.Close()

	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var createBody struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&createBody))
	slug := createBody.StackID

	// Team B tries to GET the stack.
	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWTB)

	getResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()

	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

// TestStackGet_HappyPath verifies that a stack owner can retrieve status + services.
func TestStackGet_HappyPath(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-get", teamID, "stackget@example.com")

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}
	createResp := postStackNew(t, app, sessionJWT, testManifestSingleService, tarballs)
	defer createResp.Body.Close()

	require.Equal(t, http.StatusAccepted, createResp.StatusCode)

	var createBody struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	slug := createBody.StackID
	require.NotEmpty(t, slug)

	// GET the stack.
	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	getResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer getResp.Body.Close()

	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	var getBody struct {
		OK       bool        `json:"ok"`
		StackID  string      `json:"stack_id"`
		Status   string      `json:"status"`
		Services []fiber.Map `json:"services"`
	}
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&getBody))
	assert.True(t, getBody.OK)
	assert.Equal(t, slug, getBody.StackID)
	assert.NotEmpty(t, getBody.Status)
	assert.Len(t, getBody.Services, 1, "one service declared in manifest")
}

// TestStackDelete_HappyPath verifies that a stack can be deleted by its owner
// and is subsequently absent from the DB.
func TestStackDelete_HappyPath(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-del", teamID, "stackdel@example.com")

	app := newStackTestApp(t, db)

	// Create a stack.
	tarball := createMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}
	createResp := postStackNew(t, app, sessionJWT, testManifestSingleService, tarballs)
	defer createResp.Body.Close()

	require.Equal(t, http.StatusAccepted, createResp.StatusCode)

	var createBody struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	slug := createBody.StackID
	require.NotEmpty(t, slug)

	// Delete the stack.
	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	delResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer delResp.Body.Close()

	assert.Equal(t, http.StatusOK, delResp.StatusCode)

	var delBody struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, json.NewDecoder(delResp.Body).Decode(&delBody))
	assert.True(t, delBody.OK)

	// Verify DB: stack row is gone.
	var count int
	require.NoError(t,
		db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM stacks WHERE slug = $1`, slug,
		).Scan(&count),
	)
	assert.Equal(t, 0, count, "stack row must be deleted from DB")
}

// TestStackList verifies that GET /api/v1/stacks returns all stacks for a team.
func TestStackList(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-list", teamID, "stacklist@example.com")

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)

	// Create first stack.
	tarballs1 := map[string][]byte{"web": tarball}
	r1 := postStackNew(t, app, sessionJWT, testManifestSingleService, tarballs1)
	require.Equal(t, http.StatusAccepted, r1.StatusCode)
	io.Copy(io.Discard, r1.Body)
	r1.Body.Close()

	// Create second stack (also single-service).
	tarballs2 := map[string][]byte{"web": tarball}
	r2 := postStackNew(t, app, sessionJWT, testManifestSingleService, tarballs2)
	require.Equal(t, http.StatusAccepted, r2.StatusCode)
	io.Copy(io.Discard, r2.Body)
	r2.Body.Close()

	// List stacks.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	listResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer listResp.Body.Close()

	assert.Equal(t, http.StatusOK, listResp.StatusCode)

	var listBody struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listBody))
	assert.True(t, listBody.OK)
	assert.Equal(t, 2, listBody.Total)
	assert.Len(t, listBody.Items, 2)

	// Verify structure of each item.
	for _, item := range listBody.Items {
		assert.NotEmpty(t, item["stack_id"], "stack_id must be set")
		assert.NotEmpty(t, item["status"], "status must be set")
		assert.NotEmpty(t, item["tier"], "tier must be set")
	}
}

// TestStackList_RequiresAuth verifies that GET /api/v1/stacks without token returns 401.
func TestStackList_RequiresAuth(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestStackList_Empty verifies that a team with no stacks gets an empty slice (not 404/500).
func TestStackList_Empty(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-empty", teamID, "stackempty@example.com")

	app := newStackTestApp(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var listBody struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listBody))
	assert.True(t, listBody.OK)
	assert.Equal(t, 0, listBody.Total)
	assert.NotNil(t, listBody.Items, "items must be an array, not null")
}

// TestStackNew_NameOptional verifies the optional 'name' field is accepted.
func TestStackNew_NameOptional(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-stack-named", teamID, "stacknamed@example.com")

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	body, ct := multipartBody(t, testManifestSingleService, tarballs, map[string]string{
		"name": "my-awesome-stack",
	})
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var respBody struct {
		OK      bool   `json:"ok"`
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))
	assert.True(t, respBody.OK)
	assert.NotEmpty(t, respBody.StackID)

	// Verify name was saved in DB.
	var savedName sql.NullString
	require.NoError(t,
		db.QueryRowContext(context.Background(),
			`SELECT name FROM stacks WHERE slug = $1`, respBody.StackID,
		).Scan(&savedName),
	)
	assert.True(t, savedName.Valid)
	assert.Equal(t, "my-awesome-stack", savedName.String)
}

// TestStackGet_AnonymousStack verifies that an anonymous caller can GET their own
// anonymous stack using the slug (which acts as the secret).
func TestStackGet_AnonymousStack(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	createResp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{"web": tarball})
	defer createResp.Body.Close()

	if createResp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("stack service unavailable")
	}
	require.Equal(t, http.StatusAccepted, createResp.StatusCode)

	var createBody struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	slug := createBody.StackID
	require.NotEmpty(t, slug)

	// Anonymous GET — no auth header.
	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug, nil)
	req.Header.Set("X-Forwarded-For", "10.10.10.1")

	getResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer getResp.Body.Close()

	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	var getBody struct {
		OK      bool   `json:"ok"`
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&getBody))
	assert.True(t, getBody.OK)
	assert.Equal(t, slug, getBody.StackID)
}

// TestStackDelete_AnonymousStack verifies that an anonymous caller can delete
// their own anonymous stack without authentication.
func TestStackDelete_AnonymousStack(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	createResp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{"web": tarball})
	defer createResp.Body.Close()

	if createResp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("stack service unavailable")
	}
	require.Equal(t, http.StatusAccepted, createResp.StatusCode)

	var createBody struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	slug := createBody.StackID
	require.NotEmpty(t, slug)

	// Anonymous DELETE — no auth header.
	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	req.Header.Set("X-Forwarded-For", "10.10.10.1")

	delResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer delResp.Body.Close()

	assert.Equal(t, http.StatusOK, delResp.StatusCode)

	var delBody struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, json.NewDecoder(delResp.Body).Decode(&delBody))
	assert.True(t, delBody.OK)

	// Verify DB: stack row is gone.
	var count int
	require.NoError(t,
		db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM stacks WHERE slug = $1`, slug,
		).Scan(&count),
	)
	assert.Equal(t, 0, count, "anonymous stack row must be deleted from DB")
}

// TestStackGet_AuthCannotAccessAnonStack verifies that an authenticated team member
// cannot access an anonymous (team-less) stack — prevents existence disclosure.
func TestStackGet_AuthCannotAccessAnonStack(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app := newStackTestApp(t, db)

	// Create an anonymous stack (no auth).
	tarball := createMinimalTarball(t)
	createResp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{"web": tarball})
	defer createResp.Body.Close()

	if createResp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("stack service unavailable")
	}
	require.Equal(t, http.StatusAccepted, createResp.StatusCode)

	var createBody struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	slug := createBody.StackID
	require.NotEmpty(t, slug)

	// Authenticated team tries to GET the anonymous stack — must get 404.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-cross", teamID, "cross@example.com")

	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	getResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()

	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}
