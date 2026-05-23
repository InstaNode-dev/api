package handlers_test

// storage_hermetic_coverage_test.go — drives the storage handler (storage.go)
// and the broker-mode presign path (storage_presign.go) with a REAL but fully
// hermetic do-spaces-backed provider. The do-spaces backend computes
// prefix-scoped credentials + presigned URLs without any network call (verified
// by inspecting common/storageprovider/dospaces), so the entire handler flow —
// anonymous provision, authenticated provision, and presign — runs under CI's
// postgres+redis matrix with no MinIO / S3 / DO Spaces reachable.
//
// The pre-existing storage_test.go skips every assertion when the provider is
// nil (NewTestAppWithServices wires nil), leaving newStorageAuthenticated and
// the credential/broker response arms uncovered under CI.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
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

// hermeticStorageProvider builds a do-spaces-backed provider with dummy master
// credentials. No network call is made at provision or presign time.
func hermeticStorageProvider(t *testing.T) *storageprovider.Provider {
	t.Helper()
	p, err := storageprovider.NewWithBackend(
		storageprovider.BackendDOSpaces,
		"nyc3.example-spaces.invalid",       // endpoint
		"https://s3.example.invalid",        // public endpoint
		"DUMMYACCESSKEYFORTESTSONLY",        // master access key
		"dummysecretkeyfortestsonly0000000", // master secret
		"instant-shared-test",               // bucket
		true,                                // secure
	)
	require.NoError(t, err)
	return p
}

// storageHermeticApp wires /storage/new + /storage/:token/presign with the
// hermetic provider, mirroring the production middleware chain.
func storageHermeticApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "storage",
		Environment:     "test",
		// Master-key config for broker-mode presign signing. minio-go's
		// PresignedGetObject computes the V4 signature locally (no network),
		// so an unreachable .invalid endpoint is fine for a hermetic test.
		ObjectStoreEndpoint:  "nyc3.example-spaces.invalid",
		ObjectStoreAccessKey: "DUMMYACCESSKEYFORTESTSONLY",
		ObjectStoreSecretKey: "dummysecretkeyfortestsonly0000000",
		ObjectStoreBucket:    "instant-shared-test",
		ObjectStoreRegion:    "nyc3",
		ObjectStoreSecure:    true,
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
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	h := handlers.NewStorageHandler(db, rdb, cfg, hermeticStorageProvider(t), plans.Default())
	app.Post("/storage/new", middleware.OptionalAuth(cfg), h.NewStorage)
	app.Post("/storage/:token/presign", middleware.OptionalAuth(cfg), h.PresignStorage)
	return app
}

func shStoragePost(t *testing.T, app *fiber.App, path, ip, authJWT, body string) *http.Response {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader(`{"name":"assets"}`)
	}
	req := httptest.NewRequest(http.MethodPost, path, r)
	req.Header.Set("Content-Type", "application/json")
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	if authJWT != "" {
		req.Header.Set("Authorization", "Bearer "+authJWT)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func TestStorageHermetic_Anonymous_BrokerMode(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storageHermeticApp(t, db, rdb)

	resp := shStoragePost(t, app, "/storage/new", "10.50.0.1", "", `{"name":"assets"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body struct {
		OK          bool   `json:"ok"`
		Token       string `json:"token"`
		Mode        string `json:"mode"`
		PresignURL  string `json:"presign_url"`
		AgentAction string `json:"agent_action"`
		Tier        string `json:"tier"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	assert.True(t, body.OK)
	assert.Equal(t, "anonymous", body.Tier)
	// DO Spaces has PrefixScopedKeys=false → anonymous lands in broker mode.
	assert.Equal(t, "broker", body.Mode)
	assert.NotEmpty(t, body.PresignURL)

	// Presign the broker-mode resource: GET op should mint a signed URL.
	presign := shStoragePost(t, app, "/storage/"+body.Token+"/presign", "10.50.0.1", "",
		`{"operation":"GET","key":"photos/cat.png","expires_in":600}`)
	require.Equal(t, http.StatusOK, presign.StatusCode)
	var pbody struct {
		OK     bool   `json:"ok"`
		URL    string `json:"url"`
		Method string `json:"method"`
	}
	require.NoError(t, json.NewDecoder(presign.Body).Decode(&pbody))
	presign.Body.Close()
	assert.True(t, pbody.OK)
	assert.NotEmpty(t, pbody.URL)
}

func TestStorageHermetic_Authenticated(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storageHermeticApp(t, db, rdb)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "user-storage", teamID, "s@example.com")

	resp := shStoragePost(t, app, "/storage/new", "10.50.0.2", jwt, `{"name":"team-assets"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
		Tier  string `json:"tier"`
		Mode  string `json:"mode"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	assert.True(t, body.OK)
	assert.Equal(t, "pro", body.Tier)

	// Persisted as a storage resource owned by the team.
	var rtype, tier string
	require.NoError(t, db.QueryRow(
		`SELECT resource_type, tier FROM resources WHERE token=$1::uuid`, body.Token,
	).Scan(&rtype, &tier))
	assert.Equal(t, "storage", rtype)
	assert.Equal(t, "pro", tier)
}

func TestStorageHermetic_Presign_Arms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storageHermeticApp(t, db, rdb)

	// Provision a token to presign against.
	resp := shStoragePost(t, app, "/storage/new", "10.50.0.3", "", `{"name":"a"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	tok := body.Token

	t.Run("invalid_operation", func(t *testing.T) {
		r := shStoragePost(t, app, "/storage/"+tok+"/presign", "10.50.0.3", "", `{"operation":"DELETE","key":"x"}`)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode)
		r.Body.Close()
	})
	t.Run("path_unsafe", func(t *testing.T) {
		r := shStoragePost(t, app, "/storage/"+tok+"/presign", "10.50.0.3", "", `{"operation":"GET","key":"../etc/passwd"}`)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode)
		r.Body.Close()
	})
	t.Run("missing_key", func(t *testing.T) {
		r := shStoragePost(t, app, "/storage/"+tok+"/presign", "10.50.0.3", "", `{"operation":"PUT","key":""}`)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode)
		r.Body.Close()
	})
	t.Run("ttl_capped_put", func(t *testing.T) {
		r := shStoragePost(t, app, "/storage/"+tok+"/presign", "10.50.0.3", "", `{"operation":"PUT","key":"ok.txt","expires_in":999999}`)
		assert.Equal(t, http.StatusOK, r.StatusCode)
		r.Body.Close()
	})
	t.Run("invalid_token", func(t *testing.T) {
		r := shStoragePost(t, app, "/storage/not-a-uuid/presign", "10.50.0.3", "", `{"operation":"GET","key":"x"}`)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode)
		r.Body.Close()
	})
	t.Run("token_not_found", func(t *testing.T) {
		r := shStoragePost(t, app, "/storage/11111111-1111-1111-1111-111111111111/presign", "10.50.0.3", "", `{"operation":"GET","key":"x"}`)
		assert.Equal(t, http.StatusNotFound, r.StatusCode)
		r.Body.Close()
	})
}

func TestStorageHermetic_ServiceDisabled(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	// Provider present but service not enabled → 503.
	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex,
		EnabledServices: "redis", Environment: "test",
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
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(middleware.RequestID(), middleware.Fingerprint())
	h := handlers.NewStorageHandler(db, rdb, cfg, hermeticStorageProvider(t), plans.Default())
	app.Post("/storage/new", middleware.OptionalAuth(cfg), h.NewStorage)
	resp := shStoragePost(t, app, "/storage/new", "10.50.0.9", "", `{"name":"x"}`)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
}
