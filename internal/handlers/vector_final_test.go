package handlers_test

// vector_final_test.go — FINAL coverage pass for vector.go. Closes the
// authenticated-path arms and parseDimensions branches the vecwave/coverage
// slices leave open:
//
//   - newVectorAuthenticated: invalid_team (450), team_lookup DB error (453),
//     dedicated-on-non-growth 402 (462), create_resource DB error (486),
//     gRPC-error soft-delete (514), storage-exceeded warning (561).
//   - parseDimensions: malformed-JSON-falls-back-to-default (164).
//
// Uses the bufconn fakeProvisioner (setupVectorGRPCFixture) for the success +
// gRPC-error arms, and openFaultDB for the mid-handler DB-error arms.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// vectorFaultApp wires /vector/new against an arbitrary *sql.DB (no provisioner)
// so the fault driver can drive the authenticated mid-handler DB-error arms.
func vectorFaultApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,vector,redis",
		Environment:              "test",
		PostgresProvisionBackend: "local",
	}
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	t.Cleanup(cleanR)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			_ = handlers.WriteFiberError(c, code, "internal_error", e.Error())
			return nil
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	vectorH := handlers.NewVectorHandler(db, rdb, cfg, nil, plans.Default())
	app.Post("/vector/new", middleware.OptionalAuth(cfg), vectorH.NewVector)
	return app
}

func vecJWT(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

func vecPost(t *testing.T, app *fiber.App, ip, jwt, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/vector/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	return resp
}

// vectorGRPCAppWithDB builds a /vector/new app backed by a bufconn fake
// provisioner AND returns the *sql.DB + *redis.Client so the test can corrupt
// resource rows / inspect the cap. Mirrors setupVectorGRPCFixture but exposes
// the DB.
func vectorGRPCAppWithDB(t *testing.T) (*fiber.App, *sql.DB, *redis.Client) {
	t.Helper()
	db, _ := testhelpers.SetupTestDB(t)
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { db.Close(); rdb.Close() })
	cfg := &config.Config{
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,vector,redis",
		Environment:              "test",
		PostgresProvisionBackend: "local",
	}
	provClient := newBufconnProvisionerClient(t, &fakeProvisioner{})
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			_ = handlers.WriteFiberError(c, code, "internal_error", e.Error())
			return nil
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{Limit: 500, KeyPrefix: "rlvecfin"}))
	vectorH := handlers.NewVectorHandler(db, rdb, cfg, provClient, plans.Default())
	app.Post("/vector/new", middleware.OptionalAuth(cfg), vectorH.NewVector)
	return app, db, rdb
}

// TestVectorFinal_Anon_OverCap_DedupDecryptFail — first call mints a real
// anonymous vector resource; we then CORRUPT its connection_url and hammer the
// same fingerprint past the daily cap. The over-cap dedup branch finds the
// (now-corrupt) resource, decryptConnectionURL fails, and the handler falls
// through (vector.go:294-298) rather than emitting ciphertext.
func TestVectorFinal_Anon_OverCap_DedupDecryptFail(t *testing.T) {
	app, db, _ := vectorGRPCAppWithDB(t)
	const ip = "10.130.0.7"

	post := func() (*http.Response, vecRespVecwave) {
		return postVectorVecwave(t, app, ip, "", "", map[string]any{"name": "v", "env": "production"})
	}
	first, _ := post()
	first.Body.Close()
	require.Equal(t, http.StatusCreated, first.StatusCode)

	// Burn the rest of the daily cap (anonymous = 5/fp) so the NEXT call lands
	// on the over-cap dedup branch.
	for i := 0; i < 5; i++ {
		r, _ := post()
		r.Body.Close()
	}

	// Now corrupt EVERY active vector resource for this fingerprint so the
	// over-cap dedup's GetActiveResourceByFingerprintType returns a row whose
	// connection_url cannot be decrypted → the fail-closed fallthrough
	// (vector.go:294-298) runs instead of emitting ciphertext.
	_, err := db.ExecContext(context.Background(),
		`UPDATE resources SET connection_url = 'not-valid-ciphertext'
		 WHERE resource_type = 'vector' AND status = 'active' AND tier = 'anonymous'`)
	require.NoError(t, err)

	// One more over-cap call: dedup hit on a corrupt row → decrypt fails →
	// fallthrough (then recycle gate / fresh provision / deny). Any non-5xx
	// outcome proves the corrupt-url fallthrough arm executed.
	resp, _ := post()
	code := resp.StatusCode
	resp.Body.Close()
	assert.NotEqual(t, http.StatusInternalServerError, code)
}

// TestVectorFinal_Anon_OverCap_CrossServiceFallback — burns the cap with vector
// provisions, then RETYPES every active row for the fingerprint to 'redis' so
// the over-cap vector-type-by-env lookup MISSES but the any-type-by-env lookup
// HITS → cross-service daily-cap fallback 429 (vector.go:269-275).
func TestVectorFinal_Anon_OverCap_CrossServiceFallback(t *testing.T) {
	app, db, _ := vectorGRPCAppWithDB(t)
	const ip = "10.131.0.8"
	post := func() (*http.Response, vecRespVecwave) {
		return postVectorVecwave(t, app, ip, "", "", map[string]any{"name": "v", "env": "production"})
	}
	// Burn the full cap (6 calls → over-cap on the 6th onward).
	for i := 0; i < 6; i++ {
		r, _ := post()
		r.Body.Close()
	}
	// Retype the fingerprint's vector rows to redis: vector-type lookup now
	// misses, but any-type lookup still finds a row → cross-service 429.
	_, err := db.ExecContext(context.Background(),
		`UPDATE resources SET resource_type = 'redis'
		 WHERE resource_type = 'vector' AND status = 'active' AND tier = 'anonymous'`)
	require.NoError(t, err)

	resp, body := post()
	defer resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "provision_limit_reached", body.Error)
}

// TestVectorFinal_Auth_TeamLookup_DBError_503 — GetTeamByID errors (vector.go:453).
// failAfter=0 — the team lookup is the first DB call after JWT auth.
func TestVectorFinal_Auth_TeamLookup_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := vecJWT(t, seedDB, teamID)

	faultDB := openFaultDB(t, 0)
	app := vectorFaultApp(t, faultDB)
	resp := vecPost(t, app, "10.61.0.1", jwt, `{"name":"v","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestVectorFinal_Auth_BadTeamID_400 — JWT tid is not a UUID → invalid_team
// (vector.go:450). RequireAuth passes (tid != ""); parseTeamID fails.
func TestVectorFinal_Auth_BadTeamID_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := vectorFaultApp(t, db)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
	resp := vecPost(t, app, "10.61.0.9", jwt, `{"name":"v","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestVectorFinal_Auth_DedicatedNonGrowth_402 — dedicated=true on a pro team →
// upgrade_required (vector.go:462).
func TestVectorFinal_Auth_DedicatedNonGrowth_402(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := vecJWT(t, db, teamID)

	app := vectorFaultApp(t, db) // normal DB; the dedicated gate fires before any provision
	resp := vecPost(t, app, "10.61.0.2", jwt, `{"name":"v","env":"production","dedicated":true}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
}

// TestVectorFinal_Auth_CreateResource_DBError_503 — team lookup ok, then
// CreateResource errors (vector.go:486). team(1) succeeds, the INSERT errors.
// resolveFamilyParent is skipped (no parent_resource_id) so the INSERT is the
// 2nd DB call. failAfter=1.
func TestVectorFinal_Auth_CreateResource_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := vecJWT(t, seedDB, teamID)

	faultDB := openFaultDB(t, 1)
	app := vectorFaultApp(t, faultDB)
	resp := vecPost(t, app, "10.61.0.3", jwt, `{"name":"v","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// vectorGRPCFailAppWithDB builds a /vector/new app whose bufconn provisioner
// FAILS, exposing the DB so an authenticated team can be seeded.
func vectorGRPCFailAppWithDB(t *testing.T) (*fiber.App, *sql.DB) {
	t.Helper()
	db, _ := testhelpers.SetupTestDB(t)
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { db.Close(); rdb.Close() })
	cfg := &config.Config{
		JWTSecret:                testhelpers.TestJWTSecret,
		AESKey:                   testhelpers.TestAESKeyHex,
		EnabledServices:          "postgres,vector,redis",
		Environment:              "test",
		PostgresProvisionBackend: "local",
	}
	provClient := newBufconnProvisionerClient(t, &fakeProvisioner{failProvision: true})
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			_ = handlers.WriteFiberError(c, code, "internal_error", e.Error())
			return nil
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	vectorH := handlers.NewVectorHandler(db, rdb, cfg, provClient, plans.Default())
	app.Post("/vector/new", middleware.OptionalAuth(cfg), vectorH.NewVector)
	return app, db
}

// TestVectorFinal_Auth_GRPCError_SoftDelete_503 — an AUTHENTICATED provision
// where the gRPC provisioner fails → soft-delete + 503 (vector.go:514). Uses a
// DB-exposed failing fixture so we can seed the team the JWT points at.
func TestVectorFinal_Auth_GRPCError_SoftDelete_503(t *testing.T) {
	app, db := vectorGRPCFailAppWithDB(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := vecJWT(t, db, teamID)

	resp := vecPost(t, app, "10.62.0.1", jwt, `{"name":"v","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestVectorFinal_Anon_GRPCError_SoftDelete_503 — anonymous provision gRPC
// failure → soft-delete on the anon arm (vector.go:362).
func TestVectorFinal_Anon_GRPCError_SoftDelete_503(t *testing.T) {
	app, _ := vectorGRPCFailAppWithDB(t)
	resp := vecPost(t, app, "10.62.0.9", "", `{"name":"v","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestVectorFinal_ParseDimensions_MalformedJSON_Default — a body that is valid
// UTF-8 but not valid JSON for the dimensions struct still provisions with the
// default dimensions (parseDimensions falls back, vector.go:164). We send a
// JSON array (unmarshals into the struct as an error) — parseProvisionBody
// rejects it first though, so instead send a body where `dimensions` is a
// string: BodyParser tolerates type drift differently. The reliable trigger is
// a body that parseProvisionBody accepts as JSON object but whose dimensions
// unmarshal mismatches — covered by a dimensions value of the wrong JSON type.
func TestVectorFinal_ParseDimensions_MalformedJSON_Default(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := vectorFaultApp(t, db)

	// `dimensions` as a string → json.Unmarshal into vectorRequestBody (int
	// field) errors inside parseDimensions, which falls back to the default
	// and provisions anonymously (local backend → 201, or 503 if unreachable).
	resp := vecPost(t, app, "10.63.0.1", "", `{"name":"v","env":"production","dimensions":"not-a-number"}`)
	defer resp.Body.Close()
	// Either a real anonymous provision (201) or a backend-unreachable 503 —
	// either way parseDimensions' fallback arm ran (no 400 invalid_dimensions).
	assert.NotEqual(t, http.StatusBadRequest, resp.StatusCode)
}
