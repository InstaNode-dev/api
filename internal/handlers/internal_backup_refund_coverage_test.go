package handlers_test

// internal_backup_refund_coverage_test.go — hermetic coverage for
// POST /internal/teams/:id/backup-quota/refund (internal_backup_refund.go).
// DB + Redis only (both in CI's service matrix). Before this file the handler
// measured 0% under CI — the route was never wired into a test app.

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

const testBackupRefundSecret = "worker-refund-secret-32-bytes!!!"

func backupRefundTestApp(t *testing.T, db *sql.DB, rdb *redis.Client, secret string) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		WorkerInternalJWTSecret: secret,
		JWTSecret:               testhelpers.TestJWTSecret,
		AESKey:                  testhelpers.TestAESKeyHex,
		Environment:             "test",
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
	h := handlers.NewInternalBackupRefundHandler(db, rdb, cfg)
	app.Post("/internal/teams/:id/backup-quota/refund", h.Refund)
	return app
}

func mintBackupRefundJWT(t *testing.T, secret, purpose, teamID string, iatOffset time.Duration) string {
	t.Helper()
	claims := jwt.MapClaims{
		"purpose": purpose,
		"team_id": teamID,
		"iat":     jwt.NewNumericDate(time.Now().Add(iatOffset)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

func backupRefundPost(t *testing.T, app *fiber.App, jwt, teamID, body string) *http.Response {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader("")
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/teams/"+teamID+"/backup-quota/refund", r)
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func TestBackupRefund_AuthArms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := backupRefundTestApp(t, db, rdb, testBackupRefundSecret)
	teamID := uuid.NewString()
	backupID := uuid.NewString()

	t.Run("invalid_team_id", func(t *testing.T) {
		// API-28 (QA 2026-05-29): auth-first ordering means an unauth
		// caller with a malformed :id 401s on the auth check before the
		// path parse. The invalid_team_id arm is only reachable by an
		// authenticated caller (worker emitted a bad URL) — we exercise
		// it with a valid JWT here so the path-parse arm stays covered.
		validJWT := mintBackupRefundJWT(t, testBackupRefundSecret, "internal_backup_refund", uuid.NewString(), 0)
		resp := backupRefundPost(t, app, validJWT, "not-a-uuid", `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("missing_bearer", func(t *testing.T) {
		resp := backupRefundPost(t, app, "", teamID, `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("wrong_purpose", func(t *testing.T) {
		jwt := mintBackupRefundJWT(t, testBackupRefundSecret, "terminate", teamID, 0)
		resp := backupRefundPost(t, app, jwt, teamID, `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("stale_iat", func(t *testing.T) {
		jwt := mintBackupRefundJWT(t, testBackupRefundSecret, "internal_backup_refund", teamID, -5*time.Minute)
		resp := backupRefundPost(t, app, jwt, teamID, `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("team_mismatch", func(t *testing.T) {
		jwt := mintBackupRefundJWT(t, testBackupRefundSecret, "internal_backup_refund", uuid.NewString(), 0)
		resp := backupRefundPost(t, app, jwt, teamID, `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestBackupRefund_SecretUnset_401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := backupRefundTestApp(t, db, rdb, "")
	teamID := uuid.NewString()
	jwt := mintBackupRefundJWT(t, "anything", "internal_backup_refund", teamID, 0)
	resp := backupRefundPost(t, app, jwt, teamID, `{"backup_id":"`+uuid.NewString()+`"}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestBackupRefund_BodyValidationArms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := backupRefundTestApp(t, db, rdb, testBackupRefundSecret)
	teamID := uuid.NewString()
	jwt := mintBackupRefundJWT(t, testBackupRefundSecret, "internal_backup_refund", teamID, 0)

	t.Run("invalid_json", func(t *testing.T) {
		resp := backupRefundPost(t, app, jwt, teamID, `{not json`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("missing_backup_id", func(t *testing.T) {
		resp := backupRefundPost(t, app, jwt, teamID, `{}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("invalid_backup_id", func(t *testing.T) {
		resp := backupRefundPost(t, app, jwt, teamID, `{"backup_id":"nope"}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestBackupRefund_HappyPathAndIdempotent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := backupRefundTestApp(t, db, rdb, testBackupRefundSecret)
	teamID := uuid.NewString()
	backupID := uuid.NewString()
	jwt := mintBackupRefundJWT(t, testBackupRefundSecret, "internal_backup_refund", teamID, 0)

	// First call → refunded=true.
	resp := backupRefundPost(t, app, jwt, teamID, `{"backup_id":"`+backupID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Second call (same backup_id) → idempotent no-op, still 200.
	jwt2 := mintBackupRefundJWT(t, testBackupRefundSecret, "internal_backup_refund", teamID, 0)
	resp = backupRefundPost(t, app, jwt2, teamID, `{"backup_id":"`+backupID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestBackupRefund_RedisDisabled_FailOpen(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := backupRefundTestApp(t, db, nil, testBackupRefundSecret) // rdb=nil
	teamID := uuid.NewString()
	jwt := mintBackupRefundJWT(t, testBackupRefundSecret, "internal_backup_refund", teamID, 0)
	resp := backupRefundPost(t, app, jwt, teamID, `{"backup_id":"`+uuid.NewString()+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}
