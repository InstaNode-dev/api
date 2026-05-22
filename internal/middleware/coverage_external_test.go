package middleware_test

// coverage_external_test.go — black-box tests for the exported middleware
// surface: GeoEnrich (fail-open when MaxMind absent), SecurityHeaders,
// Telemetry, RequestID, NewRelic no-op, JTI revocation (miniredis),
// env-policy / role-lookup / api-key DB paths (sqlmock), and presign
// per-token rate limiting (miniredis). Covers the fail-open branches the
// brief calls out for geo + rate-limit.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

func newMiniRedis(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return rdb, func() { rdb.Close(); mr.Close() }
}

// ---------------------------------------------------------------------------
// geo.go — fail-open path (MaxMind absent) and getters
// ---------------------------------------------------------------------------

func TestGeoEnrich_NilDBs_FailsOpenWithDefaults(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.GeoEnrich(nil)) // MaxMind absent — fail-open
	app.Get("/g", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"country": middleware.GetGeoCountry(c),
			"asn":     middleware.GetGeoASN(c),
			"org":     middleware.GetGeoOrgName(c),
			"vendor":  middleware.GetCloudVendor(c),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/g", nil)
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"GeoEnrich must fail open (200) when MaxMind DB is missing")
}

func TestGeoEnrich_WithEmptyDBs(t *testing.T) {
	// Non-nil GeoDBs with nil readers exercises enrichFromIP's nil-reader
	// guards while still parsing the IP.
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.GeoEnrich(&middleware.GeoDBs{}))
	app.Get("/g", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/g", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestGeoGetters_DefaultsWhenLocalsMissing(t *testing.T) {
	app := fiber.New()
	app.Get("/x", func(c *fiber.Ctx) error {
		assert.Equal(t, "XX", middleware.GetGeoCountry(c))
		assert.EqualValues(t, 0, middleware.GetGeoASN(c))
		assert.Equal(t, "unknown", middleware.GetGeoOrgName(c))
		assert.Equal(t, "unknown", middleware.GetCloudVendor(c))
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestLoadGeoLite2_MissingFileReturnsNil(t *testing.T) {
	dbs := middleware.LoadGeoLite2("/nonexistent/GeoLite2-City.mmdb")
	assert.Nil(t, dbs, "LoadGeoLite2 must return nil (not panic) when the file is absent")
}

// TestGeoEnrich_RealMMDBPopulatesLocals loads a hand-built combined
// City+ASN MaxMind fixture (testdata/geo-combined-test.mmdb: 8.8.8.0/24 →
// US, ASN 16509 = AMAZON-02 = "aws") and asserts enrichFromIP populates
// every geo local — the success path the nil-DB fail-open test can't reach.
func TestGeoEnrich_RealMMDBPopulatesLocals(t *testing.T) {
	dbs := middleware.LoadGeoLite2("testdata/geo-combined-test.mmdb")
	require.NotNil(t, dbs, "fixture mmdb must load")

	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.GeoEnrich(dbs))
	app.Get("/g", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"country": middleware.GetGeoCountry(c),
			"asn":     middleware.GetGeoASN(c),
			"org":     middleware.GetGeoOrgName(c),
			"vendor":  middleware.GetCloudVendor(c),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/g", nil)
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body struct {
		Country string `json:"country"`
		ASN     uint   `json:"asn"`
		Org     string `json:"org"`
		Vendor  string `json:"vendor"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "US", body.Country)
	assert.EqualValues(t, 16509, body.ASN)
	assert.Equal(t, "AMAZON-02", body.Org)
	assert.Equal(t, "aws", body.Vendor, "ASN 16509 maps to the aws cloud vendor")
}

// ---------------------------------------------------------------------------
// admin.go — AdminEmailAllowlist / IsAdminEmail
// ---------------------------------------------------------------------------

func TestAdminEmailAllowlist_AndIsAdminEmail(t *testing.T) {
	// Unset → nil allowlist, nobody is admin.
	t.Setenv("ADMIN_EMAILS", "")
	assert.Nil(t, middleware.AdminEmailAllowlist())
	assert.False(t, middleware.IsAdminEmail("a@b.com"))
	assert.False(t, middleware.IsAdminEmail(""), "empty email is never admin")

	// Only-commas / blanks → still nil.
	t.Setenv("ADMIN_EMAILS", " , ,  ")
	assert.Nil(t, middleware.AdminEmailAllowlist())

	// Populated, case-insensitive, whitespace-trimmed.
	t.Setenv("ADMIN_EMAILS", "Root@Example.com, ops@x.io ")
	allow := middleware.AdminEmailAllowlist()
	require.NotNil(t, allow)
	assert.True(t, allow["root@example.com"])
	assert.True(t, allow["ops@x.io"])
	assert.True(t, middleware.IsAdminEmail("ROOT@example.com"))
	assert.True(t, middleware.IsAdminEmail("  ops@x.io  "))
	assert.False(t, middleware.IsAdminEmail("intruder@evil.com"))
}

// ---------------------------------------------------------------------------
// env_policy.go — loadEnvPolicy branches via RequireEnvAccess (no-rows, error,
// malformed JSON all fail-open to allow)
// ---------------------------------------------------------------------------

func envPolicyApp(t *testing.T, tid uuid.UUID) (*fiber.App, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	middleware.SetEnvPolicyDB(db)
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, tid.String())
		c.Locals(middleware.LocalKeyTeamRole, "developer")
		return c.Next()
	})
	app.Post("/deploy",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	return app, mock, func() { middleware.SetEnvPolicyDB(nil); db.Close() }
}

func TestRequireEnvAccess_LoadEnvPolicyBranches(t *testing.T) {
	tid := uuid.New()

	cases := []struct {
		name string
		set  func(m sqlmock.Sqlmock)
	}{
		{"no_rows", func(m sqlmock.Sqlmock) {
			m.ExpectQuery("SELECT env_policy FROM teams").WithArgs(tid).WillReturnError(sql.ErrNoRows)
		}},
		{"db_error", func(m sqlmock.Sqlmock) {
			m.ExpectQuery("SELECT env_policy FROM teams").WithArgs(tid).WillReturnError(sql.ErrConnDone)
		}},
		{"malformed_json", func(m sqlmock.Sqlmock) {
			m.ExpectQuery("SELECT env_policy FROM teams").WithArgs(tid).
				WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(`{not json`)))
		}},
		{"nil_bytes", func(m sqlmock.Sqlmock) {
			m.ExpectQuery("SELECT env_policy FROM teams").WithArgs(tid).
				WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(nil)))
		}},
		{"env_missing_in_policy", func(m sqlmock.Sqlmock) {
			m.ExpectQuery("SELECT env_policy FROM teams").WithArgs(tid).
				WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(`{"staging":{"deploy":["owner"]}}`)))
		}},
		{"action_missing_for_env", func(m sqlmock.Sqlmock) {
			m.ExpectQuery("SELECT env_policy FROM teams").WithArgs(tid).
				WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(`{"production":{"vault_write":["owner"]}}`)))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, mock, clean := envPolicyApp(t, tid)
			defer clean()
			tc.set(mock)
			// env=production so the lookup resolves; all of these branches
			// must FAIL OPEN to 200 (never lock the team out).
			resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/deploy?env=production", nil), 3000)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "branch %s must fail open to allow", tc.name)
			resp.Body.Close()
		})
	}
}

// ---------------------------------------------------------------------------
// fingerprint.go — production XFF (rightmost hop) + E2E bypass override
// ---------------------------------------------------------------------------

func TestFingerprintMiddleware_ProductionUsesRightmostXFF(t *testing.T) {
	var fpA, fpB string
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.FingerprintMiddleware(middleware.FingerprintConfig{Production: true}))
	app.Get("/p", func(c *fiber.Ctx) error {
		c.Set("X-FP", middleware.GetFingerprint(c))
		return c.SendStatus(fiber.StatusOK)
	})

	get := func(xff string) string {
		req := httptest.NewRequest(http.MethodGet, "/p", nil)
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.Header.Get("X-FP")
	}
	// Production uses the LAST (trusted edge) hop. Both XFF lists end in the
	// same trusted hop → identical fingerprints despite different client IPs.
	fpA = get("1.1.1.1, 9.9.9.9")
	fpB = get("2.2.2.2, 9.9.9.9")
	assert.NotEmpty(t, fpA)
	assert.Equal(t, fpA, fpB, "production fingerprint keys on the rightmost (edge) hop")
}

func TestFingerprintMiddleware_E2EBypassOverridesIP(t *testing.T) {
	t.Setenv("E2E_TEST_TOKEN", "shared-e2e-secret-value")

	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.FingerprintMiddleware(middleware.FingerprintConfig{Production: true}))
	app.Get("/p", func(c *fiber.Ctx) error {
		c.Set("X-FP", middleware.GetFingerprint(c))
		return c.SendStatus(fiber.StatusOK)
	})

	get := func(token, sourceIP string) string {
		req := httptest.NewRequest(http.MethodGet, "/p", nil)
		req.Header.Set("X-Forwarded-For", "9.9.9.9") // same edge hop for all
		if token != "" {
			req.Header.Set("X-E2E-Test-Token", token)
		}
		if sourceIP != "" {
			req.Header.Set("X-E2E-Source-IP", sourceIP)
		}
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.Header.Get("X-FP")
	}

	// With a valid token the source-IP header drives the fingerprint, so two
	// different override IPs (same XFF edge) yield DIFFERENT fingerprints.
	fp1 := get("shared-e2e-secret-value", "10.0.0.1")
	fp2 := get("shared-e2e-secret-value", "10.1.0.1")
	assert.NotEqual(t, fp1, fp2, "valid E2E token must let X-E2E-Source-IP drive the fingerprint")

	// A wrong token is ignored → falls back to the (shared) edge hop.
	fpBad := get("wrong-token", "10.0.0.1")
	fpNoTok := get("", "")
	assert.Equal(t, fpBad, fpNoTok, "invalid/absent E2E token → fall back to XFF edge hop")
}

// ---------------------------------------------------------------------------
// idempotency.go — explicit Idempotency-Key replay + empty-key 400 reject
// ---------------------------------------------------------------------------

func TestIdempotency_ExplicitKeyReplay(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()

	calls := 0
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.Status(fiber.StatusCreated).JSON(fiber.Map{"n": calls})
		},
	)
	key := "explicit-" + uuid.NewString()
	send := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"name":"a"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	r1 := send()
	r1.Body.Close()
	r2 := send()
	r2.Body.Close()
	assert.Equal(t, 1, calls, "explicit-key replay must run the handler once")
}

func TestIdempotency_ExplicitKeyConflict(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error { return c.Status(fiber.StatusCreated).SendString("ok") },
	)
	key := "conflict-" + uuid.NewString()
	send := func(body string) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	r1 := send(`{"name":"a"}`)
	r1.Body.Close()
	// Same key, DIFFERENT body → 409 idempotency_key_conflict.
	r2 := send(`{"name":"b"}`)
	defer r2.Body.Close()
	assert.Equal(t, http.StatusConflict, r2.StatusCode,
		"same Idempotency-Key with a different body must 409")
}

func TestIdempotency_5xxNotCached(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	calls := 0
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.SendStatus(fiber.StatusInternalServerError) // 5xx → not cached
		},
	)
	key := "fivexx-" + uuid.NewString()
	send := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"n":1}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	send().Body.Close()
	send().Body.Close()
	assert.Equal(t, 2, calls, "5xx responses must NOT be cached — handler runs each time")
}

// ---------------------------------------------------------------------------
// security_headers.go
// ---------------------------------------------------------------------------

func TestSecurityHeaders_ProdEmitsHSTS(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.SecurityHeaders(true))
	app.Get("/h", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/h", nil), 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, middleware.HSTSValue, resp.Header.Get("Strict-Transport-Security"))
	assert.Equal(t, middleware.XContentTypeOptionsValue, resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, middleware.XFrameOptionsValue, resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, middleware.ReferrerPolicyValue, resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, middleware.PermissionsPolicyValue, resp.Header.Get("Permissions-Policy"))
	assert.Equal(t, middleware.CrossOriginResourcePolicyValue, resp.Header.Get("Cross-Origin-Resource-Policy"))
}

func TestSecurityHeaders_DevOmitsHSTS(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.SecurityHeaders(false))
	app.Get("/h", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/h", nil), 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Empty(t, resp.Header.Get("Strict-Transport-Security"),
		"dev/non-prod must NOT advertise HSTS")
	assert.Equal(t, middleware.XContentTypeOptionsValue, resp.Header.Get("X-Content-Type-Options"))
}

// ---------------------------------------------------------------------------
// telemetry.go
// ---------------------------------------------------------------------------

func TestTelemetry_RecordsAndPassesThrough(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.Telemetry())
	app.Get("/ok", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	app.Get("/boom", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusInternalServerError) })

	for path, want := range map[string]int{"/ok": 200, "/boom": 500} {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), 3000)
		require.NoError(t, err)
		assert.Equal(t, want, resp.StatusCode)
		resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// request_id.go
// ---------------------------------------------------------------------------

func TestRequestID_GeneratesAndPropagates(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/r", func(c *fiber.Ctx) error {
		// In-handler the locals + Go context both carry the id.
		assert.NotEmpty(t, middleware.GetRequestID(c))
		assert.Equal(t, middleware.GetRequestID(c),
			middleware.RequestIDFromContext(c.UserContext()))
		return c.SendStatus(fiber.StatusOK)
	})

	// Generated when absent.
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/r", nil), 3000)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Header.Get(middleware.HeaderRequestID))
	resp.Body.Close()

	// Propagated when supplied.
	req := httptest.NewRequest(http.MethodGet, "/r", nil)
	req.Header.Set(middleware.HeaderRequestID, "supplied-id-123")
	resp2, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, "supplied-id-123", resp2.Header.Get(middleware.HeaderRequestID))
	resp2.Body.Close()
}

func TestRequestIDFromContext_Empty(t *testing.T) {
	assert.Empty(t, middleware.RequestIDFromContext(context.Background()))
}

func TestGetRequestID_EmptyWhenUnset(t *testing.T) {
	app := fiber.New()
	app.Get("/n", func(c *fiber.Ctx) error {
		assert.Empty(t, middleware.GetRequestID(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/n", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// newrelic.go — nil agent degrades to no-op
// ---------------------------------------------------------------------------

func TestNewRelic_NilAppNoOp(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.NewRelic(nil))
	app.Get("/nr", func(c *fiber.Ctx) error {
		assert.Nil(t, middleware.GetNRTxn(c), "no txn when agent disabled")
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/nr", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

// newrelic_metrics.go emit helpers no-op when the global app is nil (default
// in tests). Calling them must not panic and exercises the nil-guard branch.
func TestNewRelicMetrics_NoOpWhenNilApp(t *testing.T) {
	middleware.SetNRApp(nil)
	middleware.RecordProvisionSuccess("postgres")
	middleware.RecordProvisionFail("redis", "quota")
	middleware.RecordProvisionFail("redis", "") // empty reason branch
	middleware.RecordResourceExpired("mongodb")
}

// ---------------------------------------------------------------------------
// revocation.go — fail-open on Redis error, hit/miss on live miniredis
// ---------------------------------------------------------------------------

func TestIsJTIRevoked_NilClientAndEmptyJTI(t *testing.T) {
	middleware.SetRevocationDB(nil)
	revoked, err := middleware.IsJTIRevoked(context.Background(), "jti")
	require.NoError(t, err)
	assert.False(t, revoked, "nil client → not revoked (fail-open)")
}

func TestIsJTIRevoked_HitAndMiss(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	middleware.SetRevocationDB(rdb)
	defer middleware.SetRevocationDB(nil)

	ctx := context.Background()
	// Empty jti short-circuits.
	revoked, err := middleware.IsJTIRevoked(ctx, "")
	require.NoError(t, err)
	assert.False(t, revoked)

	// Not present → not revoked.
	revoked, err = middleware.IsJTIRevoked(ctx, "abc")
	require.NoError(t, err)
	assert.False(t, revoked)

	// Present → revoked.
	require.NoError(t, rdb.Set(ctx, "session.revoked:abc", "1", 0).Err())
	revoked, err = middleware.IsJTIRevoked(ctx, "abc")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestIsJTIRevoked_RedisErrorFailsOpen(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	clean() // close immediately → every op errors
	middleware.SetRevocationDB(rdb)
	defer middleware.SetRevocationDB(nil)

	revoked, err := middleware.IsJTIRevoked(context.Background(), "abc")
	assert.Error(t, err, "a Redis error must surface")
	assert.False(t, revoked, "but the request still treats it as not-revoked (fail-open)")
}

// ---------------------------------------------------------------------------
// presign_token_rate_limit.go — nil rdb no-op, allow under cap, 429 over cap
// ---------------------------------------------------------------------------

func presignApp(rdb *redis.Client) *fiber.App {
	app := fiber.New()
	// Register the limiter as a route-level handler (NOT app.Use) so the
	// :token route param is bound — matching the production router wiring.
	app.Post("/storage/:token/presign",
		middleware.PresignTokenRateLimit(rdb),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	return app
}

func TestPresignRateLimit_NilRedisNoOp(t *testing.T) {
	app := presignApp(nil)
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/storage/tok123/presign", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestPresignRateLimit_AllowsUnderCapThen429(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	app := presignApp(rdb)

	tok := uuid.NewString()
	url := "/storage/" + tok + "/presign"
	// The first request is always allowed; once the rolling-window count
	// reaches the cap a subsequent request returns 429 with a Retry-After.
	// Send a burst well past the cap and assert the limit eventually trips.
	var firstStatus, last429 int
	for i := 0; i < middleware.PresignPerTokenPerMinute+5; i++ {
		resp, err := app.Test(httptest.NewRequest(http.MethodPost, url, nil), 3000)
		require.NoError(t, err)
		if i == 0 {
			firstStatus = resp.StatusCode
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			last429 = resp.StatusCode
			assert.NotEmpty(t, resp.Header.Get(fiber.HeaderRetryAfter),
				"429 must carry a Retry-After header")
		}
		resp.Body.Close()
	}
	assert.Equal(t, http.StatusOK, firstStatus, "first request must be allowed")
	assert.Equal(t, http.StatusTooManyRequests, last429,
		"a burst past the cap must eventually trip the per-token limit")
}

func TestPresignRateLimit_RedisErrorFailsOpen(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	clean() // closed → pipeline errors
	app := presignApp(rdb)
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/storage/tok/presign", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Redis error must fail open (200, request proceeds)")
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// role_lookup.go — sqlmock-backed PopulateTeamRole
// ---------------------------------------------------------------------------

func TestPopulateTeamRole_NoIDsPassesThrough(t *testing.T) {
	middleware.SetRoleLookupDB(nil)
	defer middleware.SetRoleLookupDB(nil)
	app := fiber.New()
	app.Use(middleware.PopulateTeamRole())
	app.Get("/role", func(c *fiber.Ctx) error {
		assert.Empty(t, middleware.GetTeamRole(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/role", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestPopulateTeamRole_ResolvesRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetRoleLookupDB(db)
	defer middleware.SetRoleLookupDB(nil)

	uid := uuid.NewString()
	tid := uuid.NewString()
	mock.ExpectQuery("SELECT role FROM users").
		WithArgs(uid, tid).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))

	app := fiber.New()
	// Inject locals to simulate RequireAuth having populated them.
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyUserID, uid)
		c.Locals(middleware.LocalKeyTeamID, tid)
		return c.Next()
	})
	app.Use(middleware.PopulateTeamRole())
	app.Get("/role", func(c *fiber.Ctx) error {
		assert.Equal(t, "owner", middleware.GetTeamRole(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/role", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestPopulateTeamRole_NoRowsIsTolerated(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetRoleLookupDB(db)
	defer middleware.SetRoleLookupDB(nil)

	uid := uuid.NewString()
	tid := uuid.NewString()
	mock.ExpectQuery("SELECT role FROM users").
		WithArgs(uid, tid).
		WillReturnError(sql.ErrNoRows)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyUserID, uid)
		c.Locals(middleware.LocalKeyTeamID, tid)
		return c.Next()
	})
	app.Use(middleware.PopulateTeamRole())
	app.Get("/role", func(c *fiber.Ctx) error {
		assert.Empty(t, middleware.GetTeamRole(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/role", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// env_policy.go — RequireEnvAccess DB paths via sqlmock
// ---------------------------------------------------------------------------

func TestRequireEnvAccess_NilDBAllows(t *testing.T) {
	middleware.SetEnvPolicyDB(nil)
	defer middleware.SetEnvPolicyDB(nil)
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	})
	app.Use(middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy))
	app.Post("/deploy", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/deploy", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "no policy DB → allow (fail-open)")
	resp.Body.Close()
}

func TestRequireEnvAccess_EmptyPolicyAllows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetEnvPolicyDB(db)
	defer middleware.SetEnvPolicyDB(nil)

	tid := uuid.New()
	mock.ExpectQuery("SELECT env_policy FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(`{}`)))

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, tid.String())
		return c.Next()
	})
	app.Use(middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy))
	app.Post("/deploy", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/deploy", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "empty policy → allow")
	resp.Body.Close()
}

func TestRequireEnvAccess_RoleAllowedAndDenied(t *testing.T) {
	tid := uuid.New()
	// Policy: production/deploy allows owner only.
	policy := `{"production":{"deploy":["owner"]}}`

	run := func(role string, wantStatus int) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer db.Close()
		middleware.SetEnvPolicyDB(db)
		defer middleware.SetEnvPolicyDB(nil)

		mock.ExpectQuery("SELECT env_policy FROM teams").
			WithArgs(tid).
			WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(policy)))

		app := fiber.New()
		app.Use(func(c *fiber.Ctx) error {
			c.Locals(middleware.LocalKeyTeamID, tid.String())
			c.Locals(middleware.LocalKeyTeamRole, role)
			return c.Next()
		})
		app.Use(middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy))
		app.Post("/deploy", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

		// env=production via query string so defaultEnvLookup resolves it.
		resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/deploy?env=production", nil), 3000)
		require.NoError(t, err)
		assert.Equal(t, wantStatus, resp.StatusCode, "role=%s", role)
		resp.Body.Close()
	}

	run("owner", http.StatusOK)         // allowed
	run("developer", http.StatusForbidden) // denied → 403 env_policy_denied
}

func TestRequireEnvAccess_BadTeamIDPassesThrough(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetEnvPolicyDB(db)
	defer middleware.SetEnvPolicyDB(nil)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, "not-a-uuid")
		return c.Next()
	})
	app.Use(middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy))
	app.Post("/deploy", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/deploy", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "unparseable team id → pass through")
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// api_key.go — IsAPIKey / AuthenticateAPIKey nil-DB path / scope getters
// ---------------------------------------------------------------------------

func TestIsAPIKey(t *testing.T) {
	assert.True(t, middleware.IsAPIKey("ink_abc123"))
	assert.False(t, middleware.IsAPIKey("not-a-pat"))
}

func TestAuthenticateAPIKey_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetAPIKeyDB(db)
	defer middleware.SetAPIKeyDB(nil)

	keyID := uuid.New()
	teamID := uuid.New()
	creator := uuid.New()
	rows := sqlmock.NewRows([]string{
		"id", "team_id", "created_by", "name", "key_hash",
		"scopes", "last_used_at", "revoked_at", "created_at",
	}).AddRow(
		keyID, teamID, creator, "ci-key", "deadbeef",
		"{admin,deploy}", nil, nil, time.Now(),
	)
	mock.ExpectQuery("SELECT .* FROM api_keys").WillReturnRows(rows)
	// Best-effort async TouchAPIKey may or may not run before assertions; be
	// lenient about its UPDATE.
	mock.ExpectExec("UPDATE api_keys").WillReturnResult(sqlmock.NewResult(0, 1))

	app := fiber.New()
	app.Get("/k", func(c *fiber.Ctx) error {
		ok, aerr := middleware.AuthenticateAPIKey(c, "ink_secret")
		require.NoError(t, aerr)
		assert.True(t, ok)
		assert.True(t, middleware.IsAuthedViaAPIKey(c))
		assert.Equal(t, []string{"admin", "deploy"}, middleware.GetAPIKeyScopes(c))
		assert.Equal(t, teamID.String(), middleware.GetTeamID(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/k", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestAuthenticateAPIKey_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetAPIKeyDB(db)
	defer middleware.SetAPIKeyDB(nil)
	mock.ExpectQuery("SELECT .* FROM api_keys").WillReturnError(sql.ErrNoRows)

	app := fiber.New()
	app.Get("/k", func(c *fiber.Ctx) error {
		ok, aerr := middleware.AuthenticateAPIKey(c, "ink_missing")
		assert.NoError(t, aerr, "not-found is (false, nil)")
		assert.False(t, ok)
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/k", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestAuthenticateAPIKey_NilDB(t *testing.T) {
	middleware.SetAPIKeyDB(nil)
	app := fiber.New()
	app.Get("/k", func(c *fiber.Ctx) error {
		ok, err := middleware.AuthenticateAPIKey(c, "ink_whatever")
		assert.False(t, ok)
		assert.Error(t, err, "nil DB → error")
		assert.False(t, middleware.IsAuthedViaAPIKey(c))
		assert.Nil(t, middleware.GetAPIKeyScopes(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/k", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}
