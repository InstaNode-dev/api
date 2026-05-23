package handlers_test

// multipart_new_final3_test.go — FINAL serial pass #3. Drives the remaining
// reachable error arms of the deploy.New and stack.New multipart mega-handlers
// that the existing happy-path tests leave open:
//
//   deploy.New: service_disabled, invalid_form, missing_tarball, tarball
//     open-error (seam), tarball read-error (seam), name-required error,
//     appID rand-error (seam), invalid_port, invalid_env_vars.
//   stack.New:  invalid_form, invalid_manifest (resolve), AES-key-parse error.

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// multipartDeployNoTarball builds a /deploy/new multipart body with a name
// field but NO tarball part, to drive the missing_tarball arm.
func multipartDeployNoTarball(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	require.NoError(t, w.WriteField("name", "no-tarball-deploy"))
	require.NoError(t, w.WriteField("port", "8080"))
	require.NoError(t, w.Close())
	return buf, w.FormDataContentType()
}

// deployNewApp wires POST /deploy/new against an arbitrary *sql.DB with a
// configurable enabled-services + AES key, so the error arms can be driven
// independently of the full router.
func deployNewApp(t *testing.T, enabledServices, aesKey string) (*fiber.App, string) {
	t.Helper()
	db, clean := testhelpers.SetupTestDB(t)
	t.Cleanup(clean)
	if aesKey == "" {
		aesKey = testhelpers.TestAESKeyHex
	}
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          aesKey,
		ComputeProvider: "noop",
		EnabledServices: enabledServices,
	}
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, testhelpers.UniqueEmail(t))
	app := fiber.New(fiber.Config{
		BodyLimit: 60 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Post("/deploy/new", middleware.RequireAuth(cfg), dh.New)
	return app, jwt
}

func postDeployNewMultipart(t *testing.T, app *fiber.App, jwt string, fields map[string]string) *http.Response {
	t.Helper()
	body, ct := multipartDeployBody(t, fields)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.222.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// TestDeployNewFinal3_ServiceDisabled — deploy not in enabled-services →
// service_disabled 503 (deploy.New first guard).
func TestDeployNewFinal3_ServiceDisabled(t *testing.T) {
	app, jwt := deployNewApp(t, "postgres,redis", "")
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{"port": "8080"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "service_disabled", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_InvalidForm — a non-multipart body → invalid_form 400.
func TestDeployNewFinal3_InvalidForm(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", strings.NewReader("not-multipart"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_form", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_MissingTarball — multipart with no tarball field →
// missing_tarball 400.
func TestDeployNewFinal3_MissingTarball(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	// Build a multipart body with only a name field, no tarball.
	body, ct := multipartDeployNoTarball(t)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "missing_tarball", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_TarballOpenFailed — openMultipartFile errors →
// tarball_open_failed 400.
func TestDeployNewFinal3_TarballOpenFailed(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	restore := handlers.SetOpenMultipartFileForTest(func(*multipart.FileHeader) (multipart.File, error) {
		return nil, errors.New("forced open error")
	})
	defer restore()
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{"port": "8080"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "tarball_open_failed", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_TarballReadFailed — openMultipartFile returns a file whose
// Read errors → tarball_read_failed 400.
func TestDeployNewFinal3_TarballReadFailed(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	restore := handlers.SetOpenMultipartFileForTest(func(*multipart.FileHeader) (multipart.File, error) {
		return errReadFile{}, nil
	})
	defer restore()
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{"port": "8080"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "tarball_read_failed", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_NameRequired — empty name → requireName error.
func TestDeployNewFinal3_NameRequired(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{"port": "8080", "name": ""})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestDeployNewFinal3_AppIDRandError — randRead errors → generateAppID error →
// internal_error 500 (deploy.New appID arm).
func TestDeployNewFinal3_AppIDRandError(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	restore := handlers.SetRandReadForTest(func([]byte) (int, error) {
		return 0, errors.New("forced rand error")
	})
	defer restore()
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{"port": "8080"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "internal_error", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_InvalidPort — non-numeric port → invalid_port 400.
func TestDeployNewFinal3_InvalidPort(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{"port": "abc"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_port", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_PortOutOfRange — port 0 → invalid_port 400 (range arm).
func TestDeployNewFinal3_PortOutOfRange(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{"port": "0"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_port", decodeErrCode(t, resp))
}

// TestDeployNewFinal3_InvalidEnvVarsJSON — malformed env_vars JSON →
// invalid_env_vars 400.
func TestDeployNewFinal3_InvalidEnvVarsJSON(t *testing.T) {
	app, jwt := deployNewApp(t, "deploy", "")
	resp := postDeployNewMultipart(t, app, jwt, map[string]string{
		"port":     "8080",
		"env_vars": "{not-json",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_env_vars", decodeErrCode(t, resp))
}

// ── stack.New error arms ──────────────────────────────────────────────────────

// TestStackNewFinal3_InvalidForm — a non-multipart body → invalid_form 400.
func TestStackNewFinal3_InvalidForm(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackNewApp(t, db, nil)
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", strings.NewReader("not-multipart"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.223.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_form", decodeErrCode(t, resp))
}

// TestStackNewFinal3_MissingManifest — multipart with a tarball but no manifest
// field → missing_manifest 400.
func TestStackNewFinal3_MissingManifest(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackNewApp(t, db, nil)
	resp := postStackNew(t, app, "", "", map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "missing_manifest", decodeErrCode(t, resp))
}

// TestStackNewFinal3_AESKeyParseError — a config with a non-hex AES key makes
// crypto.ParseAESKey fail inside stack.New (after the tarball read) →
// internal_error 500.
func TestStackNewFinal3_AESKeyParseError(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          "not-a-valid-hex-aes-key",
		ComputeProvider: "noop",
	}
	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	app.Post("/stacks/new", middleware.OptionalAuth(cfg), h.New)

	resp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "internal_error", decodeErrCode(t, resp))
}
