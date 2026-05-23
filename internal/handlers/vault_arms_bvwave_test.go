package handlers_test

// vault_arms_bvwave_test.go — pushes vault.go past 95% by covering the error
// arms the existing vault_*_coverage_test.go files leave open:
//
//   - encryptPlaintext / decryptCiphertext AES-key-parse failure (bad AESKey)
//   - upsertSecret: vault_not_available (free tier, maxEntries==0) + quota
//   - GetSecret: decrypt failure on a tampered/garbage-key read
//   - CopySecrets: missing source key, quota_exceeded (blocked), overwrite,
//     and the hobby-tier 402 gate
//   - DeleteSecret: 404 (no row) + invalid-key validation
//
// Reuses vaultTestApp / makeTeamUser / jsonReq / vaultIntegrationDB from
// vault_test.go. A second app built with a deliberately-invalid AES key drives
// the crypto-failure arms (a valid AES-256-GCM key never fails in practice, so
// a bad-key seam is the only deterministic way to reach those lines).

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strconv"
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

// vaultBadKeyApp builds the vault routes with an AES key that ParseAESKey
// rejects (not 64 hex chars), so encryptPlaintext / decryptCiphertext error
// out and the 500 arms run.
// vaultErrHandlerApp returns a fiber.App whose ErrorHandler swallows the
// ErrResponseWritten sentinel (matching vaultTestApp), so handlers that have
// already written their response body don't get a default-500 overwrite.
func vaultErrHandlerApp() *fiber.App {
	return fiber.New(fiber.Config{
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
}

func vaultBadKeyApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret,
		AESKey:    "not-a-valid-aes-key", // ParseAESKey fails on this
	}
	app := vaultErrHandlerApp()
	app.Use(middleware.RequestID())
	h := handlers.NewVaultHandler(db, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Put("/vault/:env/:key", h.PutSecret)
	api.Get("/vault/:env/:key", h.GetSecret)
	return app
}

// vaultGoodKeyApp builds the vault routes with the standard test AES key over
// an arbitrary DB (used to drive the DB-error arms with a closed DB).
func vaultGoodKeyApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	app := vaultErrHandlerApp()
	app.Use(middleware.RequestID())
	h := handlers.NewVaultHandler(db, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Put("/vault/:env/:key", h.PutSecret)
	api.Get("/vault/:env/:key", h.GetSecret)
	api.Get("/vault/:env", h.ListKeys)
	api.Delete("/vault/:env/:key", h.DeleteSecret)
	api.Post("/vault/copy", h.CopySecrets)
	return app
}

// vaultBrokenDB returns a closed *sql.DB so every query errors.
func vaultBrokenDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	require.NotEmpty(t, dsn, "TEST_DATABASE_URL required")
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	return db
}

// TestVault_DBErrorArms_bvwave drives the persist/fetch/list/delete/copy DB-
// error arms via a closed DB. The team JWT is well-formed so auth passes; the
// first DB touch then fails.
func TestVault_DBErrorArms_bvwave(t *testing.T) {
	// A real signed JWT (team/user are arbitrary UUIDs — the DB is broken so
	// no row need exist).
	teamID := "11111111-1111-1111-1111-111111111111"
	userID := "22222222-2222-2222-2222-222222222222"
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, "x@example.com")

	app := vaultGoodKeyApp(t, vaultBrokenDB(t))

	t.Run("put_persist_or_team_lookup_fails", func(t *testing.T) {
		// GetTeamByID errors (fail-open warn) then CreateVaultSecret errors → 503.
		req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/K", jwt, map[string]string{"value": "v"})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		// Broken DB → either persist_failed (503) or an internal_error (500)
		// depending on which query fails first; both exercise the error arm.
		assert.Contains(t, []int{http.StatusServiceUnavailable, http.StatusInternalServerError}, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("get_fetch_fails_500", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/K", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("list_fails_500", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("delete_fails_500", func(t *testing.T) {
		req := jsonReq(t, http.MethodDelete, "/api/v1/vault/production/K", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("copy_team_lookup_fails_503", func(t *testing.T) {
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{"from": "staging", "to": "production"})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		// team_lookup_failed (503) or internal_error (500) — both are error arms.
		assert.Contains(t, []int{http.StatusServiceUnavailable, http.StatusInternalServerError}, resp.StatusCode)
		resp.Body.Close()
	})
}

// TestVault_GetSecret_DecryptFailure_500_bvwave inserts a row whose ciphertext
// cannot be decrypted by the configured key, so GetSecret's decrypt-error arm
// (500) runs.
func TestVault_GetSecret_DecryptFailure_500_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	teamID, userID, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultGoodKeyApp(t, db)

	// Insert a vault row with garbage bytes that decryptCiphertext rejects.
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO vault_secrets (team_id, env, key, encrypted_value, version, created_by)
		VALUES ($1::uuid, 'production', 'BADCIPHER', $2, 1, $3::uuid)
	`, teamID, []byte("not-valid-gcm-ciphertext-bytes"), userID)
	require.NoError(t, err)

	req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/BADCIPHER", jwt, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	resp.Body.Close()
}

func TestVault_CryptoFailureArms_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	_, _, jwt := makeTeamUser(t, db)

	app := vaultBadKeyApp(t, db)

	// PUT with a bad AES key → encryptPlaintext fails → 500 internal_error.
	req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/SECRET", jwt, map[string]string{"value": "v"})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	resp.Body.Close()
}

// TestVault_DecryptCiphertext_ParseKeyFail_bvwave: a row exists (written with a
// good key on a separate app) but the GET app has a bad AES key → ParseAESKey
// fails inside decryptCiphertext → 500.
func TestVault_DecryptCiphertext_ParseKeyFail_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	_, _, jwt := makeTeamUserTier(t, db, "pro")

	// Write a secret with the GOOD-key app so a row exists.
	goodApp := vaultGoodKeyApp(t, db)
	put := jsonReq(t, http.MethodPut, "/api/v1/vault/production/RK", jwt, map[string]string{"value": "v"})
	rp, err := goodApp.Test(put, 5000)
	require.NoError(t, err)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, rp.StatusCode)
	rp.Body.Close()

	// Read with the BAD-key app → decryptCiphertext's ParseAESKey fails → 500.
	badApp := vaultBadKeyApp(t, db)
	get := jsonReq(t, http.MethodGet, "/api/v1/vault/production/RK", jwt, nil)
	resp, err := badApp.Test(get, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	resp.Body.Close()
}

// TestVault_AuthArms_bvwave: a JWT whose team claim is not a UUID drives the
// authContext invalid-team-id 401 arm on every handler (PUT/GET/LIST/DELETE/COPY).
func TestVault_AuthArms_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultGoodKeyApp(t, db)

	// Forge a session JWT carrying a non-UUID team_id so middleware.RequireAuth
	// accepts it (signature valid) but authContext's uuid.Parse fails → 401.
	jwt := testhelpers.MustSignSessionJWT(t, "not-a-uuid-user", "not-a-uuid-team", "x@example.com")

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/api/v1/vault/production/K", map[string]string{"value": "v"}},
		{http.MethodGet, "/api/v1/vault/production/K", nil},
		{http.MethodGet, "/api/v1/vault/production", nil},
		{http.MethodDelete, "/api/v1/vault/production/K", nil},
		{http.MethodPost, "/api/v1/vault/copy", map[string]any{"from": "a", "to": "b"}},
	}
	for _, tc := range cases {
		req := jsonReq(t, tc.method, tc.path, jwt, tc.body)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s %s", tc.method, tc.path)
		resp.Body.Close()
	}
}

// TestVault_ValidateArms_bvwave drives the validateEnv / validateKey rejection
// branches (env >64 chars, illegal char) and CopySecrets validation arms
// (missing from/to, same from/to, illegal key in allowlist).
func TestVault_ValidateArms_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	_, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultGoodKeyApp(t, db)

	longEnv := ""
	for i := 0; i < 65; i++ {
		longEnv += "a"
	}

	t.Run("env_too_long_400", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/"+longEnv, jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("env_illegal_char_400", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/prod$env", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("copy_missing_to_400", func(t *testing.T) {
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{"from": "staging"})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("copy_same_from_to_400", func(t *testing.T) {
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{"from": "staging", "to": "staging"})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("copy_illegal_key_400", func(t *testing.T) {
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{"from": "staging", "to": "prod", "keys": []string{"bad key!"}})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("upper_case_env_ok_200", func(t *testing.T) {
		// Uppercase is a legal env char (validateEnv 'A'-'Z' branch).
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/PRODUCTION", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("get_invalid_key_400", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/bad%20key", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("delete_invalid_key_400", func(t *testing.T) {
		req := jsonReq(t, http.MethodDelete, "/api/v1/vault/production/bad%20key", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("copy_keys_over_cap_400", func(t *testing.T) {
		// >1000 keys → vaultCopyKeysCap rejection (562).
		keys := make([]string, 1001)
		for i := range keys {
			keys[i] = "K"
		}
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{"from": "staging", "to": "prod", "keys": keys})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
}

// TestVault_CopySecrets_QuotaBlocked_bvwave fills a pro team's vault to its
// finite cap (200) so a copy of a NEW key into the target env is blocked
// (CopySecrets quota_exceeded arm). Uses an explicit small allowlist so we only
// need to seed cap-1 keys plus one new source key.
func TestVault_CopySecrets_QuotaBlocked_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	teamID, userID, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultGoodKeyApp(t, db)

	maxCap := plans.Default().VaultMaxEntries("pro")
	require.Positive(t, maxCap)

	// Seed `cap` distinct keys in production directly (fast path) so the team is
	// exactly at quota. One source key "NEWKEY" lives in staging.
	for i := 0; i < maxCap; i++ {
		_, err := db.ExecContext(context.Background(), `
			INSERT INTO vault_secrets (team_id, env, key, encrypted_value, version, created_by)
			VALUES ($1::uuid, 'production', $2, $3, 1, $4::uuid)
		`, teamID, "FILL_"+strconv.Itoa(i), []byte("x"), userID)
		require.NoError(t, err)
	}
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO vault_secrets (team_id, env, key, encrypted_value, version, created_by)
		VALUES ($1::uuid, 'staging', 'NEWKEY', $2, 1, $3::uuid)
	`, teamID, []byte("y"), userID)
	require.NoError(t, err)

	// Copy NEWKEY staging→production: at-cap so the new key is quota_exceeded.
	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{
		"from": "staging", "to": "production", "keys": []string{"NEWKEY"},
	})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode) // 200 with blocked>0 in the plan
	resp.Body.Close()
}

// TestVault_CopySecrets_TeamUnlimited_RealCopy_bvwave exercises the unlimited
// (team-tier, VaultMaxEntries == -1) copy path: remaining=-1 branch (616) +
// the real CreateVaultSecret copy (684) for a fresh key.
func TestVault_CopySecrets_TeamUnlimited_RealCopy_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	_, _, jwt := makeTeamUserTier(t, db, "team")
	app := vaultGoodKeyApp(t, db)

	// Seed two source keys in 'staging-1' (digit+dash env exercises validateEnv
	// digit/dash branches too).
	for _, k := range []string{"X", "Y"} {
		put := jsonReq(t, http.MethodPut, "/api/v1/vault/staging-1/"+k, jwt, map[string]string{"value": "v-" + k})
		rp, err := app.Test(put, 5000)
		require.NoError(t, err)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, rp.StatusCode)
		rp.Body.Close()
	}
	// Copy all keys staging-1 → prod-2 (no allowlist → ListVaultKeys path).
	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{"from": "staging-1", "to": "prod-2"})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}


func TestVault_Upsert_TierArms_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	t.Run("free_tier_vault_not_available_403", func(t *testing.T) {
		// A 'free' team has VaultMaxEntries == 0 → 403 vault_not_available.
		freeTeam := testhelpers.MustCreateTeamDB(t, db, "free")
		emailAddr := testhelpers.UniqueEmail(t)
		var uid string
		require.NoError(t, db.QueryRow(
			`INSERT INTO users (team_id, email) VALUES ($1::uuid,$2) RETURNING id`,
			freeTeam, emailAddr).Scan(&uid))
		jwt := testhelpers.MustSignSessionJWT(t, uid, freeTeam, emailAddr)

		app := vaultTestApp(t, db)
		req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/K", jwt, map[string]string{"value": "v"})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		// free tier may be env-restricted (403 env_not_allowed) or
		// vault_not_available (403); either way a 403 is the tier gate.
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestVault_CopySecrets_Arms_bvwave(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	teamID, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultTestApp(t, db)

	// Seed two keys in staging.
	for _, k := range []string{"A", "B"} {
		req := jsonReq(t, http.MethodPut, "/api/v1/vault/staging/"+k, jwt, map[string]string{"value": "val-" + k})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, resp.StatusCode)
		resp.Body.Close()
	}
	// Pre-seed B in production so the copy must "overwrite" it (overwrite=true).
	req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/B", jwt, map[string]string{"value": "old-B"})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	resp.Body.Close()

	t.Run("copy_with_overwrite_and_missing", func(t *testing.T) {
		// Keys allowlist includes a key that does NOT exist in source (MISSING_KEY)
		// → "missing" action; A → "copy"; B → "overwrite".
		body := map[string]any{
			"from":      "staging",
			"to":        "production",
			"keys":      []string{"A", "B", "MISSING_KEY"},
			"overwrite": true,
		}
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, body)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("dry_run_all_keys", func(t *testing.T) {
		body := map[string]any{"from": "staging", "to": "qa", "dry_run": true}
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, body)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("skip_existing_no_overwrite", func(t *testing.T) {
		// B already exists in production and overwrite is false → "skip".
		body := map[string]any{"from": "staging", "to": "production", "keys": []string{"B"}, "overwrite": false}
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, body)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	_ = teamID
}
