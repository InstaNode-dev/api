package handlers

// auth_logout_coverage_test.go — exercises the Logout handler's
// HTTP-level branches so the previously-uncovered Logout() body is
// driven end-to-end. The constant-only tests live in auth_logout_test.go;
// these tests mount Logout onto a Fiber app and validate every path.
//
//   * Missing/invalid Authorization header  → 401
//   * Wrong-secret JWT                       → 401
//   * Token without `jti`                    → 200 (no-op for legacy tokens)
//   * Happy path                             → 200 + Redis key written
//   * Redis SET failure                      → 503 (fail-closed contract)

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
)

const logoutTestSecret = "test-secret-that-is-at-least-32-bytes-long!!"

// newLogoutApp wires Logout onto a Fiber app with the production-shaped
// error handler so respondError sentinel returns surface as the
// caller-visible status (401/503), not Fiber's default 500.
func newLogoutApp(t *testing.T, rdb *redis.Client) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: logoutTestSecret}
	h := NewLogoutHandler(cfg, rdb)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Post("/auth/logout", h.Logout)
	return app
}

// mintLogoutJWT produces a signed JWT with the supplied jti and exp
// shift. expDelta>0 → future, <0 → already expired, ==0 → no exp claim.
func mintLogoutJWT(t *testing.T, jti string, expDelta time.Duration) string {
	t.Helper()
	rc := jwt.RegisteredClaims{
		ID:       jti,
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	if expDelta != 0 {
		rc.ExpiresAt = jwt.NewNumericDate(time.Now().Add(expDelta))
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, rc)
	s, err := tok.SignedString([]byte(logoutTestSecret))
	require.NoError(t, err)
	return s
}

// BUG-AUTH-005: /auth/logout is idempotent per the OpenAPI contract —
// "safe to call without a valid token." Missing / non-Bearer / wrong-secret
// credentials must return 200 {ok:true} (the local token is already
// useless, so the dashboard's logout-on-expiry path can't surface a
// confusing 401). Pre-fix all three returned 401.
func TestLogout_MissingAuthorizationHeader(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "BUG-AUTH-005: idempotent on missing auth")
}

func TestLogout_NonBearerAuthorization(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "BUG-AUTH-005: idempotent on non-Bearer scheme")
}

func TestLogout_WrongSecretJWT(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	// Sign with a different secret so verification fails inside Logout.
	rc := jwt.RegisteredClaims{
		ID:        "jti-rejected",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, rc)
	bad, err := tok.SignedString([]byte("a-completely-different-secret-32-bytes!"))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "BUG-AUTH-005: idempotent on wrong-secret JWT (parse fail)")
}

func TestLogout_NoJTIIsNoOp(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	// jti="" — the empty branch in Logout returns 200 without writing.
	tokenStr := mintLogoutJWT(t, "", time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
}

func TestLogout_HappyPath_WritesRedisRevocationKey(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	jti := uuid.New().String()
	tokenStr := mintLogoutJWT(t, jti, 2*time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify Redis key was set with a finite TTL ≤ token's remaining lifetime.
	key := RevokedJTIKey(jti)
	val, err := rdb.Get(context.Background(), key).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", val)

	ttl, err := rdb.TTL(context.Background(), key).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, 2*time.Hour+time.Second)
}

// BUG-AUTH-005: an expired-but-validly-signed token is a no-op. The
// underlying jwt library refuses to parse it (exp in the past), so the
// handler treats it as "nothing to revoke" and returns 200 {ok:true}.
// Pre-fix this returned 401 — which broke the dashboard's
// logout-on-expiry path because the local token was already useless.
func TestLogout_ExpiredButValidlySignedTokenIsIdempotent(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	tokenStr := mintLogoutJWT(t, uuid.New().String(), -time.Minute)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"BUG-AUTH-005: expired token = no-op, returns 200 (idempotent)")
}

func TestLogout_RedisFailureReturns503(t *testing.T) {
	// Use a Redis client pointed at an unreachable port so Set errors.
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // reserved invalid port
		DialTimeout: 50 * time.Millisecond,
		ReadTimeout: 50 * time.Millisecond,
	})
	defer rdb.Close()

	cfg := &config.Config{JWTSecret: logoutTestSecret}
	h := NewLogoutHandler(cfg, rdb)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	app.Post("/auth/logout", h.Logout)

	tokenStr := mintLogoutJWT(t, uuid.New().String(), time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Fail-closed contract: a Redis outage MUST surface as a 503 so the
	// client can retry rather than silently leaving the JWT live.
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestLogout_TokenWithoutExpDefaultsTo24h(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	// expDelta=0 → no exp claim. The handler falls back to 24h TTL.
	jti := uuid.New().String()
	tokenStr := mintLogoutJWT(t, jti, 0)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	key := RevokedJTIKey(jti)
	ttl, err := rdb.TTL(context.Background(), key).Result()
	require.NoError(t, err)
	// 24h fallback ± a few seconds.
	assert.Greater(t, ttl, 23*time.Hour+59*time.Minute)
	assert.LessOrEqual(t, ttl, 24*time.Hour+time.Second)
}

// BUG-AUTH-005 + T10 P2-1: an HS384-signed token still fails the
// jwt.WithValidMethods(["HS256"]) gate at parse-time, so the handler
// treats it as "nothing to revoke" and returns 200 (idempotent contract).
// The alg pin is still enforced — a wrong-alg JWT never lands in the
// revocation set. Pre-AUTH-005 fix this returned 401.
func TestLogout_HS384TokenIsIdempotent(t *testing.T) {
	rdb, clean := setupCoverageRedis(t)
	defer clean()
	app := newLogoutApp(t, rdb)

	// HS384 is HMAC, but Logout pins HS256 via jwt.WithValidMethods.
	rc := jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS384, rc)
	signed, err := tok.SignedString([]byte(logoutTestSecret))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"BUG-AUTH-005: HS384 won't parse → idempotent 200, jti never revoked")

	// Verify the alg-pin still bars the jti from landing in Redis.
	key := RevokedJTIKey(rc.ID)
	exists, err := rdb.Exists(context.Background(), key).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists,
		"HS384 token must NOT result in a Redis revocation row (alg pin honoured)")
}
