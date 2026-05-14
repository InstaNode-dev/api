package handlers_test

// vault_rotate_idempotency_test.go — FOLLOWUP-6 (2026-05-14).
//
// BB2-CHROME-3: double-clicking the dashboard "Rotate" button created
// two new versioned rows in vault_secrets. RotateSecret →
// models.CreateVaultSecret inserts a new row on every call. FOLLOWUP-4
// (PR #112) skipped this route — these tests pin the fix.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
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

// rotateIdemApp wires the production middleware chain for the rotate
// route: Fingerprint + RequireAuth + Idempotency, scope "vault.rotate"
// (must match router.go exactly or the dedup cache key diverges).
func rotateIdemApp(t *testing.T) (*fiber.App, *sql.DB, string, uuid.UUID, func()) {
	t.Helper()
	db, cleanDB := vaultIntegrationDB(t) // skips if no TEST_DATABASE_URL
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	app := fiber.New()
	app.Use(middleware.RequestID(), middleware.Fingerprint())
	h := handlers.NewVaultHandler(db, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Put("/vault/:env/:key", h.PutSecret)
	api.Post("/vault/:env/:key/rotate", middleware.Idempotency(rdb, "vault.rotate"), h.RotateSecret)
	teamIDStr, _, jwt := makeTeamUser(t, db)
	return app, db, jwt, uuid.MustParse(teamIDStr), func() { rdb.Close(); mr.Close(); cleanDB() }
}

// rotateReq builds a POST /api/v1/vault/{env}/{key}/rotate with the
// given JWT, body, and optional Idempotency-Key header.
func rotateReq(t *testing.T, jwt, env, key, value, idemKey string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(map[string]string{"value": value}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vault/"+env+"/"+key+"/rotate", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	return req
}

// countVersions returns the row count for (teamID, env, key) in vault_secrets.
func countVersions(t *testing.T, db *sql.DB, env, key string, teamID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM vault_secrets WHERE team_id = $1::uuid AND env = $2 AND key = $3`,
		teamID, env, key).Scan(&n))
	return n
}

// TestVaultRotate_DoubleClick_DedupViaFingerprint — BB2-CHROME-3 repro.
// Two POSTs, same JWT + body, NO Idempotency-Key → fingerprint fallback
// dedups the second. Exactly ONE new versioned row lands.
func TestVaultRotate_DoubleClick_DedupViaFingerprint(t *testing.T) {
	app, db, jwt, teamID, clean := rotateIdemApp(t)
	defer clean()
	const env, key = "production", "DOUBLE_CLICK_KEY"

	// Seed v1 so rotate has something to bump.
	seed, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt, map[string]string{"value": "v1"}), 5000)
	require.NoError(t, err)
	seed.Body.Close()

	resp1, err := app.Test(rotateReq(t, jwt, env, key, "v2", ""), 5000)
	require.NoError(t, err)
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	assert.Equal(t, "miss", resp1.Header.Get("X-Idempotency-Source"))
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"))

	resp2, err := app.Test(rotateReq(t, jwt, env, key, "v2", ""), 5000)
	require.NoError(t, err)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"))
	assert.Equal(t, "fingerprint", resp2.Header.Get("X-Idempotency-Source"))
	assert.Equal(t, string(body1), string(body2), "replayed body must equal cached body verbatim")

	// CRITICAL: 2 rows (v1 + v2). Without the middleware we'd see 3.
	assert.Equal(t, 2, countVersions(t, db, env, key, teamID),
		"exactly ONE new version row must land across two identical rotate POSTs")
}

// TestVaultRotate_ExplicitKey_Caches — Stripe-shape path. Same key on
// both calls → second replays via the 24h cache. Row count = 2.
func TestVaultRotate_ExplicitKey_Caches(t *testing.T) {
	app, db, jwt, teamID, clean := rotateIdemApp(t)
	defer clean()
	const env, key, idemKey = "production", "EXPLICIT_KEY_K", "abc123-vault-rotate"

	seed, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt, map[string]string{"value": "seed"}), 5000)
	require.NoError(t, err)
	seed.Body.Close()

	resp1, err := app.Test(rotateReq(t, jwt, env, key, "rotated", idemKey), 5000)
	require.NoError(t, err)
	resp1.Body.Close()
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	assert.Equal(t, "explicit", resp1.Header.Get("X-Idempotency-Source"))
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"))

	resp2, err := app.Test(rotateReq(t, jwt, env, key, "rotated", idemKey), 5000)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)
	assert.Equal(t, "explicit", resp2.Header.Get("X-Idempotency-Source"))
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"))

	assert.Equal(t, 2, countVersions(t, db, env, key, teamID),
		"explicit Idempotency-Key replay must NOT insert a v3")
}
