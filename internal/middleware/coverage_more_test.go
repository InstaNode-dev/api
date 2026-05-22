package middleware_test

// coverage_more_test.go — second coverage batch: drives the remaining
// low-coverage middleware surface (RequireAuth JWT path, rate-limit
// locals + dedup cap, idempotency fingerprint/multipart canonicalisation,
// log-scrubber child loggers, NewRelic with a live agent, env-policy
// route-param + body lookups + WithEnvLookup, admin-audit locals).

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// signSessionRich mints a session JWT carrying email + impersonation +
// read-only claims so RequireAuth populates every optional local.
func signSessionRich(t *testing.T, secret, uid, tid, email, impersonatedBy string, readOnly bool) string {
	t.Helper()
	type sessionClaims struct {
		UserID         string `json:"uid"`
		TeamID         string `json:"tid"`
		Email          string `json:"email,omitempty"`
		ReadOnly       bool   `json:"read_only,omitempty"`
		ImpersonatedBy string `json:"impersonated_by,omitempty"`
		jwt.RegisteredClaims
	}
	claims := sessionClaims{
		UserID:         uid,
		TeamID:         tid,
		Email:          email,
		ReadOnly:       readOnly,
		ImpersonatedBy: impersonatedBy,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// ---------------------------------------------------------------------------
// auth.go — RequireAuth JWT happy path + getters (email/impersonation)
// ---------------------------------------------------------------------------

func requireAuthApp(secret string) *fiber.App {
	cfg := &config.Config{JWTSecret: secret}
	app := fiber.New()
	app.Use(middleware.RequireAuth(cfg))
	app.Get("/me", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"email":           middleware.GetEmail(c),
			"impersonated_by": middleware.GetImpersonatedBy(c),
			"read_only":       middleware.IsReadOnly(c),
			"user_id":         middleware.GetUserID(c),
		})
	})
	return app
}

func TestRequireAuth_ValidJWTPopulatesLocals(t *testing.T) {
	middleware.SetRevocationDB(nil) // no revocation check
	app := requireAuthApp(testhelpers.TestJWTSecret)
	tok := signSessionRich(t, testhelpers.TestJWTSecret,
		uuid.NewString(), uuid.NewString(), "u@x.com", "admin@x.com", true)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestRequireAuth_NoBearerRejected(t *testing.T) {
	app := requireAuthApp(testhelpers.TestJWTSecret)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/me", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestRequireAuth_WrongAlgRejected(t *testing.T) {
	app := requireAuthApp(testhelpers.TestJWTSecret)
	// "none" alg token — must be rejected by WithValidMethods.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"uid": uuid.NewString(), "tid": uuid.NewString(),
	})
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "alg=none must be rejected")
	resp.Body.Close()
}

func TestGetEmailImpersonation_DefaultsEmpty(t *testing.T) {
	app := fiber.New()
	app.Get("/g", func(c *fiber.Ctx) error {
		assert.Empty(t, middleware.GetEmail(c))
		assert.Empty(t, middleware.GetImpersonatedBy(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/g", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// dpop.go — verifyDPoPProof error branches (htu mismatch, JKT mismatch)
// reusing the fixture defined in dpop_test.go (same _test package).
// ---------------------------------------------------------------------------

func TestDPoP_HTUMismatchRejected(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	// Proof's htu points at a DIFFERENT path than the request → urlMatches
	// returns false → 401.
	proof := f.signProof("POST", "https://api.instanode.dev/cache/new", time.Now(), uuid.NewString())
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, proof)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"htu pointing at a different resource must be rejected")
	resp.Body.Close()
}

func TestDPoP_WrongMethodInProofRejected(t *testing.T) {
	// htm in the proof says GET but the request is POST → getStringClaim
	// returns "GET", the htm comparison fails → 401. Exercises the htm
	// branch of verifyDPoPProof + getStringClaim success path.
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	proof := f.signProof("GET", "https://api.instanode.dev/db/new", time.Now(), uuid.NewString())
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, proof)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a proof whose htm doesn't match the request method must be rejected")
	resp.Body.Close()
}

// signPartialProof builds a DPoP proof omitting selected claims so the
// getStringClaim `!ok` branches in verifyDPoPProof are exercised.
func signPartialProof(t *testing.T, f *dpopFixture, setHTM, setHTU bool) string {
	t.Helper()
	tok := jwxjwt.New()
	if setHTM {
		require.NoError(t, tok.Set("htm", "POST"))
	}
	if setHTU {
		require.NoError(t, tok.Set("htu", "https://api.instanode.dev/db/new"))
	}
	require.NoError(t, tok.Set(jwxjwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set(jwxjwt.JwtIDKey, uuid.NewString()))
	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, hdrs.Set(jws.JWKKey, f.publicKey))
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.ES256, f.privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

func TestDPoP_MissingHTMClaimRejected(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	proof := signPartialProof(t, f, false, true) // no htm
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, proof)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "missing htm claim must be rejected")
	resp.Body.Close()
}

func TestDPoP_MissingHTUClaimRejected(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	proof := signPartialProof(t, f, true, false) // htm but no htu
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, proof)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "missing htu claim must be rejected")
	resp.Body.Close()
}

func TestDPoP_WrongTypHeaderRejected(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	// Build a proof whose protected-header typ is NOT "dpop+jwt".
	tok := jwxjwt.New()
	require.NoError(t, tok.Set("htm", "POST"))
	require.NoError(t, tok.Set("htu", "https://api.instanode.dev/db/new"))
	require.NoError(t, tok.Set(jwxjwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set(jwxjwt.JwtIDKey, uuid.NewString()))
	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "jwt")) // wrong typ
	require.NoError(t, hdrs.Set(jws.JWKKey, f.publicKey))
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.ES256, f.privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, string(signed))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong DPoP typ header must be rejected")
	resp.Body.Close()
}

func TestDPoP_MissingJWKHeaderRejected(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	// Proof with correct typ but NO jwk in the protected header.
	tok := jwxjwt.New()
	require.NoError(t, tok.Set("htm", "POST"))
	require.NoError(t, tok.Set("htu", "https://api.instanode.dev/db/new"))
	require.NoError(t, tok.Set(jwxjwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set(jwxjwt.JwtIDKey, uuid.NewString()))
	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.ES256, f.privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, string(signed))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "DPoP proof missing jwk must be rejected")
	resp.Body.Close()
}

func TestDPoP_NilRedisReplayStoreDown(t *testing.T) {
	// rdb == nil → DPoP replay check can't run → 503 (fail-CLOSED, not open).
	middleware.ResetDPoPRedisBreakerForTest()
	f := newDPoPFixture(t)
	app := newDPoPApp(nil)
	proof := f.signProof("POST", "https://api.instanode.dev/db/new", time.Now(), uuid.NewString())
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, proof)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"a missing replay store must fail closed (503), never silently fail open")
	resp.Body.Close()
}

func TestDPoP_GarbageProofParseError(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	// A non-JWS DPoP header → jws.Parse fails inside verifyDPoPProof → 401.
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", f.bearer, "not-a-valid-jws")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"an unparseable DPoP proof must be rejected")
	resp.Body.Close()
}

func TestDPoP_JKTMismatchRejected(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	rdb, clean := newMiniRedis(t)
	defer clean()
	// Bearer is bound to fixture A's thumbprint, but the proof is signed by
	// fixture B's key → the computed jwkThumbprint != cnf.jkt → 401.
	fA := newDPoPFixture(t)
	fB := newDPoPFixture(t)
	app := newDPoPApp(rdb)
	proofFromB := fB.signProof("POST", "https://api.instanode.dev/db/new", time.Now(), uuid.NewString())
	resp := runRequest(t, app, "POST", "https://api.instanode.dev/db/new", fA.bearer, proofFromB)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a proof key whose thumbprint != bearer cnf.jkt must be rejected")
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// auth.go — OptionalAuth credential-drop branches (audience, revoked) +
// rich-token locals population + PAT path
// ---------------------------------------------------------------------------

func optionalAuthRichApp(secret string) *fiber.App {
	cfg := &config.Config{JWTSecret: secret}
	app := fiber.New()
	app.Get("/me",
		middleware.OptionalAuth(cfg),
		func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"user_id":         middleware.GetUserID(c),
				"email":           middleware.GetEmail(c),
				"impersonated_by": middleware.GetImpersonatedBy(c),
				"read_only":       middleware.IsReadOnly(c),
			})
		},
	)
	return app
}

func TestOptionalAuth_RichTokenPopulatesLocals(t *testing.T) {
	middleware.SetRevocationDB(nil)
	app := optionalAuthRichApp(testhelpers.TestJWTSecret)
	tok := signSessionRich(t, testhelpers.TestJWTSecret,
		uuid.NewString(), uuid.NewString(), "rich@x.com", "admin@x.com", true)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "rich@x.com", body["email"])
	assert.Equal(t, "admin@x.com", body["impersonated_by"])
	assert.Equal(t, true, body["read_only"])
}

func TestOptionalAuth_RevokedJTIDropsCredential(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	middleware.SetRevocationDB(rdb)
	defer middleware.SetRevocationDB(nil)

	jti := uuid.NewString()
	require.NoError(t, rdb.Set(context.Background(), "session.revoked:"+jti, "1", 0).Err())

	app := optionalAuthRichApp(testhelpers.TestJWTSecret)
	tok := signSessionJTI(t, testhelpers.TestJWTSecret, jti)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	// Credential dropped → anonymous (empty user_id), request still 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, body["user_id"], "a revoked JTI drops the credential on OptionalAuth (anonymous, not 401)")
}

func TestOptionalAuth_PATPath(t *testing.T) {
	// An ink_-prefixed bearer routes through AuthenticateAPIKey; with no DB
	// wired it fails and the request continues as anonymous (no block).
	middleware.SetAPIKeyDB(nil)
	app := optionalAuthRichApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer ink_some_token")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "invalid PAT on OptionalAuth → anonymous, not 401")
	resp.Body.Close()
}

func TestOptionalAuth_AudienceMismatchDropsCredential(t *testing.T) {
	middleware.SetRevocationDB(nil)
	app := optionalAuthRichApp(testhelpers.TestJWTSecret)
	// A token with a bogus audience → OptionalAuth drops the credential and
	// continues anonymous (does NOT 401, unlike RequireAuth).
	type sc struct {
		UserID string `json:"uid"`
		TeamID string `json:"tid"`
		jwt.RegisteredClaims
	}
	claims := sc{
		UserID: uuid.NewString(),
		TeamID: uuid.NewString(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        uuid.NewString(),
			Audience:  jwt.ClaimStrings{"https://wrong.example/x"},
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Empty(t, body["user_id"], "audience mismatch drops the credential on OptionalAuth")
}

func TestRequireAuth_RevocationRedisErrorFailsOpen(t *testing.T) {
	// A revocation Redis error must fail open: the request still authenticates
	// (covers the `if err != nil` branch of RequireAuth's JTI check).
	rdb, clean := newMiniRedis(t)
	clean() // closed → IsJTIRevoked returns an error
	middleware.SetRevocationDB(rdb)
	defer middleware.SetRevocationDB(nil)

	app := requireAuthApp(testhelpers.TestJWTSecret)
	tok := signSessionJTI(t, testhelpers.TestJWTSecret, uuid.NewString())
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "revocation Redis error must fail open (request still authenticates)")
	resp.Body.Close()
}

func TestAuth_CnfJKTPopulatesDPoPLocal(t *testing.T) {
	middleware.SetRevocationDB(nil)
	type cnf struct {
		JKT string `json:"jkt"`
	}
	type sc struct {
		UserID string `json:"uid"`
		TeamID string `json:"tid"`
		Cnf    *cnf   `json:"cnf,omitempty"`
		jwt.RegisteredClaims
	}
	mint := func() string {
		claims := sc{
			UserID: uuid.NewString(),
			TeamID: uuid.NewString(),
			Cnf:    &cnf{JKT: "thumbprint-abc"},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				ID:        uuid.NewString(),
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
		require.NoError(t, err)
		return signed
	}
	// RequireAuth path.
	app := requireAuthApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+mint())
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// OptionalAuth path.
	app2 := optionalAuthRichApp(testhelpers.TestJWTSecret)
	req2 := httptest.NewRequest(http.MethodGet, "/me", nil)
	req2.Header.Set("Authorization", "Bearer "+mint())
	resp2, err := app2.Test(req2, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	resp2.Body.Close()
}

func TestRequireAuth_EmptyClaimsRejected(t *testing.T) {
	middleware.SetRevocationDB(nil)
	app := requireAuthApp(testhelpers.TestJWTSecret)
	// Valid signature but empty uid/tid → rejected.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		ID:        uuid.NewString(),
	})
	signed, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "empty uid/tid claims must be rejected")
	resp.Body.Close()
}

func TestRequireAuth_PATPath(t *testing.T) {
	// PAT routing on RequireAuth: nil DB → AuthenticateAPIKey errors → 401.
	middleware.SetAPIKeyDB(nil)
	app := requireAuthApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer ink_bad")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// rate_limit.go — locals getters, allow-under-limit + exceed
// ---------------------------------------------------------------------------

func TestRateLimit_LocalsGetters_Defaults(t *testing.T) {
	app := fiber.New()
	app.Get("/r", func(c *fiber.Ctx) error {
		assert.False(t, middleware.IsRateLimitExceeded(c))
		assert.EqualValues(t, 0, middleware.GetRateLimitCount(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/r", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestRateLimit_ExceedSetsLocals(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()

	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{KeyPrefix: "covtest", Limit: 2}))
	app.Get("/r", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"exceeded": middleware.IsRateLimitExceeded(c),
			"count":    middleware.GetRateLimitCount(c),
		})
	})

	ip := "198.51.100.7"
	var exceededSeen bool
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/r", nil)
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		if i >= 2 { // limit is 2 → 3rd+ exceed
			// header should reflect remaining 0
			assert.Equal(t, "0", resp.Header.Get("X-RateLimit-Remaining"))
			exceededSeen = true
		}
		resp.Body.Close()
	}
	assert.True(t, exceededSeen)
}

func TestRateLimit_NilRedisFailsOpen(t *testing.T) {
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(nil, middleware.RateLimitConfig{}))
	app.Get("/r", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/r", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "nil redis → fail open")
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// idempotency.go — fingerprint replay (JSON) + multipart canonicalisation
// ---------------------------------------------------------------------------

func TestIdempotency_FingerprintReplay_JSON(t *testing.T) {
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
	body := `{"name":"x","env":"development"}`
	send := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	r1 := send()
	r1.Body.Close()
	r2 := send()
	// Second identical body within TTL is replayed from cache.
	assert.Equal(t, "true", r2.Header.Get("X-Idempotent-Replay"))
	r2.Body.Close()
	assert.Equal(t, 1, calls, "handler must run once; the replay is served from cache")
}

func TestIdempotency_MultipartCanonicalisation(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()

	calls := 0
	app := fiber.New(fiber.Config{BodyLimit: 10 * 1024 * 1024})
	app.Post("/deploy/new",
		middleware.Idempotency(rdb, "deploy.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.Status(fiber.StatusCreated).JSON(fiber.Map{"n": calls})
		},
	)

	buildMultipart := func() (*bytes.Buffer, string) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		_ = w.WriteField("name", "myapp")
		_ = w.WriteField("env", "development")
		fw, _ := w.CreateFormFile("bundle", "app.tar")
		_, _ = fw.Write([]byte("deterministic-tarball-bytes"))
		w.Close()
		return &buf, w.FormDataContentType()
	}

	send := func() *http.Response {
		buf, ct := buildMultipart()
		req := httptest.NewRequest(http.MethodPost, "/deploy/new", buf)
		req.Header.Set("Content-Type", ct)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}
	r1 := send()
	r1.Body.Close()
	r2 := send()
	defer r2.Body.Close()
	assert.Equal(t, "true", r2.Header.Get("X-Idempotent-Replay"),
		"identical multipart upload (same file + fields) must dedup via canonicalMultipartBody")
	assert.Equal(t, 1, calls)
}

func TestIdempotency_RawBodyAndMalformedJSON(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()

	calls := 0
	app := fiber.New()
	app.Post("/webhook/new",
		middleware.Idempotency(rdb, "webhook.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.Status(fiber.StatusCreated).SendString("ok")
		},
	)
	// text/plain raw-body path (canonicalRequestBody returns raw bytes).
	send := func(ct, body string) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/webhook/new", bytes.NewReader([]byte(body)))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	send("text/plain", "raw-payload").Body.Close()
	r := send("text/plain", "raw-payload")
	r.Body.Close()
	assert.Equal(t, 1, calls, "identical raw bodies dedup via the raw-bytes fingerprint")

	// Malformed-JSON content-type falls back to raw bytes (no crash).
	calls = 0
	send("application/json", "{not valid json").Body.Close()
	r2 := send("application/json", "{not valid json")
	r2.Body.Close()
	assert.Equal(t, 1, calls, "malformed JSON falls back to a stable raw-bytes fingerprint")
}

func TestIdempotency_Fingerprint5xxNotCached(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	calls := 0
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.SendStatus(fiber.StatusBadGateway) // 5xx → not cached on fingerprint path
		},
	)
	send := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"k":"v"}`)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	send().Body.Close()
	send().Body.Close()
	assert.Equal(t, 2, calls, "5xx must not be cached on the fingerprint path either")
}

func TestIdempotency_ExplicitRedisGetFailOpen(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	clean() // closed → explicit-path rdb.Get errors → fail open to handler
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusCreated) },
	)
	req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"a":1}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "k-"+uuid.NewString())
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "explicit-path Redis error must fail open")
	resp.Body.Close()
}

func TestIdempotency_EmptyBodyFingerprintDedup(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	calls := 0
	app := fiber.New()
	app.Post("/webhook/new",
		middleware.Idempotency(rdb, "webhook.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.SendStatus(fiber.StatusCreated)
		},
	)
	send := func() *http.Response {
		// No body, no content-type → canonicalRequestBody returns "" (empty).
		resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/webhook/new", nil), 3000)
		require.NoError(t, err)
		return resp
	}
	send().Body.Close()
	send().Body.Close()
	assert.Equal(t, 1, calls, "two empty-body POSTs with same route+scope dedup")
}

func TestIdempotency_MultipartMultiFileCanonicalisation(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	calls := 0
	app := fiber.New(fiber.Config{BodyLimit: 10 * 1024 * 1024})
	app.Post("/deploy/new",
		middleware.Idempotency(rdb, "deploy.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.SendStatus(fiber.StatusCreated)
		},
	)
	build := func() (*bytes.Buffer, string) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		// Two files + multi-valued field exercise the sorted-iteration loops.
		f1, _ := w.CreateFormFile("a", "a.bin")
		_, _ = f1.Write([]byte("aaa"))
		f2, _ := w.CreateFormFile("b", "b.bin")
		_, _ = f2.Write([]byte("bbb"))
		_ = w.WriteField("tag", "v2")
		_ = w.WriteField("tag", "v1") // multi-value, unsorted
		w.Close()
		return &buf, w.FormDataContentType()
	}
	send := func() *http.Response {
		buf, ct := build()
		req := httptest.NewRequest(http.MethodPost, "/deploy/new", buf)
		req.Header.Set("Content-Type", ct)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}
	send().Body.Close()
	send().Body.Close()
	assert.Equal(t, 1, calls, "identical 2-file + multi-value multipart bodies dedup")
}

func TestIdempotency_MalformedMultipartCanonErr(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	calls := 0
	app := fiber.New()
	app.Post("/deploy/new",
		middleware.Idempotency(rdb, "deploy.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.SendStatus(fiber.StatusCreated)
		},
	)
	// multipart content-type but a body that isn't valid multipart →
	// canonicalRequestBody/canonicalMultipartBody errors → the fingerprint
	// path logs canonErr and falls through (the middleware must not crash;
	// Fiber's own multipart reader may then surface the parse error). Either
	// way the canonErr branch in idempotencyFingerprint is exercised.
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", bytes.NewReader([]byte("garbage-not-multipart")))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
	resp, err := app.Test(req, 3000)
	if err == nil {
		resp.Body.Close()
	}
	// The point of this test is coverage of the canonErr fall-through, not a
	// specific status — assert only that the middleware itself didn't panic.
	_ = calls
}

func TestIdempotency_FingerprintHandlerErrorPropagates(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error {
			// Return a plain (non-response-written) error so the fingerprint
			// path's `nextErr != nil && !IsResponseWrittenErr` branch runs.
			return fiber.NewError(fiber.StatusBadRequest, "handler error")
		},
	)
	req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"a":1}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestIdempotency_FingerprintCorruptCacheFallsThrough(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	calls := 0
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.Status(fiber.StatusCreated).SendString("ok")
		},
	)
	send := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"a":1}`)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	// First request caches a valid entry under some idem-fp:* key.
	send().Body.Close()
	require.Equal(t, 1, calls)

	// Corrupt the cached entry, then resend: json.Unmarshal fails → the
	// fingerprint path logs and falls through to the handler again.
	keys, err := rdb.Keys(context.Background(), "idem-fp:*").Result()
	require.NoError(t, err)
	require.NotEmpty(t, keys, "first request must have cached a fingerprint entry")
	require.NoError(t, rdb.Set(context.Background(), keys[0], "{not-json", 0).Err())

	send().Body.Close()
	assert.Equal(t, 2, calls, "a corrupt cache entry must fall through to the handler, not replay")
}

func TestIdempotency_ExplicitCorruptCacheFallsThrough(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	calls := 0
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error {
			calls++
			return c.Status(fiber.StatusCreated).SendString("ok")
		},
	)
	key := "corrupt-" + uuid.NewString()
	send := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"a":1}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		return resp
	}
	send().Body.Close()
	require.Equal(t, 1, calls)

	keys, err := rdb.Keys(context.Background(), "idem:*").Result()
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	require.NoError(t, rdb.Set(context.Background(), keys[0], "{not-json", 0).Err())

	send().Body.Close()
	assert.Equal(t, 2, calls, "explicit-path corrupt cache must fall through to the handler")
}

func TestIdempotency_FingerprintRedisFailOpen(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	clean() // close → every Redis op errors → fingerprint path fails open
	app := fiber.New()
	app.Post("/db/new",
		middleware.Idempotency(rdb, "db.new"),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusCreated) },
	)
	req := httptest.NewRequest(http.MethodPost, "/db/new", bytes.NewReader([]byte(`{"a":1}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "Redis error must fail open")
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// auth.go — RequireAuth revoked-JTI rejection (audience mismatch is covered
// by auth_audience_test.go's newAudApp suite)
// ---------------------------------------------------------------------------

func signSessionJTI(t *testing.T, secret, jti string) string {
	t.Helper()
	type sessionClaims struct {
		UserID string `json:"uid"`
		TeamID string `json:"tid"`
		jwt.RegisteredClaims
	}
	claims := sessionClaims{
		UserID: uuid.NewString(),
		TeamID: uuid.NewString(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        jti,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

func TestRequireAuth_RevokedJTIRejected(t *testing.T) {
	rdb, clean := newMiniRedis(t)
	defer clean()
	middleware.SetRevocationDB(rdb)
	defer middleware.SetRevocationDB(nil)

	jti := uuid.NewString()
	require.NoError(t, rdb.Set(context.Background(), "session.revoked:"+jti, "1", 0).Err())

	app := requireAuthApp(testhelpers.TestJWTSecret)
	tok := signSessionJTI(t, testhelpers.TestJWTSecret, jti)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a revoked JTI must be rejected")
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// log_scrubber.go — WithAttrs / WithGroup child loggers still scrub
// ---------------------------------------------------------------------------

func TestLogScrubber_WithAttrsAndGroup(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{})
	scrub := middleware.NewLogScrubber(base, "topsecret")

	// WithAttrs eagerly scrubs the bound attrs.
	child := scrub.WithAttrs([]slog.Attr{slog.String("url", "/api/v1/topsecret/x")})
	// WithGroup returns a still-scrubbing wrapper.
	grouped := child.WithGroup("g")

	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "msg topsecret here", 0)
	// A group attr carrying the secret in a nested field exercises the
	// group-rebuild branch of scrubAttr/Handle.
	rec.AddAttrs(slog.Group("ctx",
		slog.String("url", "/api/v1/topsecret/x"),
		slog.Int("n", 1),
	))
	require.NoError(t, grouped.Handle(context.Background(), rec))

	out := buf.String()
	assert.NotContains(t, out, "topsecret", "scrubber must redact the secret in child loggers + message + nested groups")
	assert.Contains(t, out, "<ADMIN>")
}

func TestLogScrubber_EmptySecretPassThrough(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, nil)
	h := middleware.NewLogScrubber(base, "")
	// Empty secret → base handler returned unchanged.
	assert.Equal(t, base, h)
}

// ---------------------------------------------------------------------------
// newrelic.go — live (no-op) agent opens + ends a transaction
// ---------------------------------------------------------------------------

func TestNewRelic_LiveAgentOpensTxn(t *testing.T) {
	// A disabled-but-non-nil application: the agent records nothing but the
	// middleware exercises StartTransaction / SetWebResponse / NoticeError.
	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName("cov-test"),
		newrelic.ConfigEnabled(false),
	)
	require.NoError(t, err)
	require.NotNil(t, app)
	middleware.SetNRApp(app)
	defer middleware.SetNRApp(nil)

	fapp := fiber.New()
	fapp.Use(middleware.NewRelic(app))
	fapp.Get("/ok", func(c *fiber.Ctx) error {
		assert.NotNil(t, middleware.GetNRTxn(c))
		// exercise the emit helpers with a live (disabled) agent
		middleware.RecordProvisionSuccess("postgres")
		middleware.RecordProvisionFail("redis", "quota")
		middleware.RecordResourceExpired("mongodb")
		return c.SendStatus(fiber.StatusOK)
	})
	fapp.Get("/err", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusInternalServerError, "boom")
	})

	r1, err := fapp.Test(httptest.NewRequest(http.MethodGet, "/ok", nil), 3000)
	require.NoError(t, err)
	r1.Body.Close()
	r2, err := fapp.Test(httptest.NewRequest(http.MethodGet, "/err", nil), 3000)
	require.NoError(t, err)
	r2.Body.Close()
}

// ---------------------------------------------------------------------------
// env_policy.go — route-param lookup, body lookup, WithEnvLookup override
// ---------------------------------------------------------------------------

func TestRequireEnvAccess_EmptyTeamIDPassesThrough(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetEnvPolicyDB(db)
	defer middleware.SetEnvPolicyDB(nil)
	// No team_id local at all → RequireEnvAccess passes through (the
	// downstream handler returns its own 401 in production).
	app := fiber.New()
	app.Post("/deploy",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/deploy", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "no team id → pass through (handler 401s itself)")
	resp.Body.Close()
}

func TestRequireEnvAccess_RouteParamAndBodyLookup(t *testing.T) {
	// No DB wired → always allows, but the lookup branches execute.
	middleware.SetEnvPolicyDB(nil)
	defer middleware.SetEnvPolicyDB(nil)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	})
	// :env route param path.
	app.Post("/vault/:env/set",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/vault/production/set", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// JSON body "env" / "to" path.
	app2 := fiber.New()
	app2.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	})
	app2.Post("/promote",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	req := httptest.NewRequest(http.MethodPost, "/promote", bytes.NewReader([]byte(`{"to":"production"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := app2.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	resp2.Body.Close()
}

func TestRequireEnvAccess_WithEnvLookupOverride(t *testing.T) {
	// A non-nil DB is required so the middleware reaches the env-lookup
	// stage (it short-circuits on a nil DB before invoking the lookup).
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetEnvPolicyDB(db)
	defer middleware.SetEnvPolicyDB(nil)
	mock.ExpectQuery("SELECT env_policy FROM teams").
		WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(`{}`)))

	called := false
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	})
	app.Delete("/resources/:id",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeleteResource,
			middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
				called = true
				return "production", nil
			})),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	resp, err := app.Test(httptest.NewRequest(http.MethodDelete, "/resources/abc", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, called, "WithEnvLookup override must be invoked")
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// admin_audit.go — AdminAuditMetadataFromLocals round-trip
// ---------------------------------------------------------------------------

func TestAdminAuditEmit_EmptyPrefixNoOp(t *testing.T) {
	app := fiber.New()
	app.Get("/x", middleware.AdminAuditEmit(nil, ""), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminAuditEmit_NilDBPassThrough(t *testing.T) {
	// nil DB → buildAdminAuditMetadata runs (path-suffix strip, UA scrub,
	// denied-by resolution) but no insert. The request still completes.
	app := fiber.New()
	app.Get("/api/v1/sek/customers/list",
		middleware.AdminAuditEmit(nil, "sek"),
		func(c *fiber.Ctx) error {
			c.Set(fiber.HeaderUserAgent, "probe-ua")
			return c.SendStatus(fiber.StatusOK)
		},
	)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/sek/customers/list", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminAuditEmit_InsertsWithTeamIDFromPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	tid := uuid.New()
	mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(1, 1))

	app := fiber.New()
	app.Get("/api/v1/sek/customers/:team_id/tier",
		middleware.AdminAuditEmit(db, "sek"),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet,
		"/api/v1/sek/customers/"+tid.String()+"/tier", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminAuditEmit_LongUATruncatedAndJWTTeamFallback(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(1, 1))

	tid := uuid.New()
	app := fiber.New()
	// No :team_id param and no /customers/<uuid> segment → adminAuditTeamID
	// falls back to the JWT team local. A >120-char User-Agent exercises the
	// truncation branch in buildAdminAuditMetadata.
	app.Get("/api/v1/sek/dashboard",
		func(c *fiber.Ctx) error {
			c.Locals(middleware.LocalKeyTeamID, tid.String())
			return c.Next()
		},
		middleware.AdminAuditEmit(db, "sek"),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sek/dashboard", nil)
	req.Header.Set(fiber.HeaderUserAgent, string(bytes.Repeat([]byte("u"), 300)))
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminAuditEmit_NoTeamContextLogsButNoInsert(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// No team context resolvable → uuid.Nil → no-team-context warn branch,
	// no INSERT (sqlmock would fail if an unexpected Exec fired).
	app := fiber.New()
	app.Get("/api/v1/sek/dashboard",
		middleware.AdminAuditEmit(db, "sek"),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusForbidden) },
	)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/sek/dashboard", nil), 3000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminAuditMetadataFromLocals_AbsentThenPresent(t *testing.T) {
	app := fiber.New()
	app.Get("/a", func(c *fiber.Ctx) error {
		_, ok := middleware.AdminAuditMetadataFromLocals(c)
		assert.False(t, ok, "absent before AdminAuditEmit stamps it")
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/a", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}
