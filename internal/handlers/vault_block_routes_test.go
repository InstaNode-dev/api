package handlers_test

// vault_block_routes_test.go — W3 vault-block integration suite.
//
// Covers the per-team encrypted-secret vault user-flow block from
// USER-FLOW-INVENTORY-AND-TEST-MATRIX.md (2026-06-04) §W3. Each route below
// was, in internal/router/route_donebar_guard_test.go, either pointing at the
// shallow TestMerged_Vault_RequiresAuth requires-auth probe (GET list, GET
// key, PUT key) or listed in routeCoverageExemptions with a "TODO: matrix W3
// …" pointer and NO mapped test (rotate, delete, copy). This suite supplies
// the DB-backed integration coverage the done-bar guard's routeTestMap now
// points at, so all six routes move (shallow|exempt) → mapped.
//
// Routes covered here (by route key):
//
//	GET    /api/v1/vault/:env              ListKeys     → TestVaultBlock_ListKeys
//	GET    /api/v1/vault/:env/:key         GetSecret    → TestVaultBlock_GetSecret
//	PUT    /api/v1/vault/:env/:key         PutSecret    → TestVaultBlock_PutSecret
//	POST   /api/v1/vault/:env/:key/rotate  RotateSecret → TestVaultBlock_RotateSecret
//	DELETE /api/v1/vault/:env/:key         DeleteSecret → TestVaultBlock_DeleteSecret
//	POST   /api/v1/vault/copy              CopySecrets  → TestVaultBlock_CopySecrets
//
// Every test runs against a real migrated Postgres (testhelpers.SetupTestDB)
// through the PRODUCTION RequireAuth + PopulateTeamRole + RequireEnvAccess
// chain (vaultBlockApp mirrors internal/router/router.go), asserting where
// applicable:
//   - happy path (correct 2xx + persisted versioned row / response contract),
//   - authz (owner / member / env-policy-gated role → 200 / 403),
//   - cross-team isolation (another team's secret → 404, never 403),
//   - the encrypt/decrypt-at-rest contract (ciphertext at rest ≠ plaintext;
//     GET decrypts to the original; the list path never returns values),
//   - rotate / copy semantics (new version, dry-run, overwrite, skip, missing,
//     Pro+ tier gate),
//   - input validation (invalid env / key / body → 400).
//
// Skips loudly when TEST_DATABASE_URL is unset (vaultBlockSkipNoDB).

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// ─────────────────────────────────────────────────────────────────────────
// PUT /api/v1/vault/:env/:key — VaultHandler.PutSecret  (write)
// ─────────────────────────────────────────────────────────────────────────

func TestVaultBlock_PutSecret(t *testing.T) {
	vaultBlockSkipNoDB(t)
	db, cleanup := vaultBlockDB(t)
	defer cleanup()

	t.Run("hobby member writes a secret to production: 201 + v1 + encrypt-at-rest", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "hobby", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))

		status, body := vaultBlockReq(t, app, jwt, http.MethodPut,
			"/api/v1/vault/production/DATABASE_URL", map[string]any{"value": "postgres://secret-conn"})
		require.Equal(t, http.StatusCreated, status, "body=%v", body)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, "DATABASE_URL", body["key"])
		assert.Equal(t, "production", body["env"])
		assert.EqualValues(t, 1, body["version"])

		// Encrypt-at-rest contract: the stored bytes must NOT contain the
		// plaintext, and must decrypt back to the original via GET.
		raw := vaultBlockRawCiphertext(t, db, teamID, "production", "DATABASE_URL")
		assert.NotContains(t, string(raw), "postgres://secret-conn",
			"value must be encrypted at rest, never stored as plaintext")

		gs, gb := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/DATABASE_URL", nil)
		require.Equal(t, http.StatusOK, gs)
		assert.Equal(t, "postgres://secret-conn", gb["value"], "ciphertext decrypts to the original plaintext")
	})

	t.Run("re-PUT same key bumps to v2 (versioned write)", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "hobby", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))

		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/API_KEY",
			map[string]any{"value": "v1-value"})
		status, body := vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/API_KEY",
			map[string]any{"value": "v2-value"})
		require.Equal(t, http.StatusCreated, status, "body=%v", body)
		assert.EqualValues(t, 2, body["version"], "second write to same key is v2")

		gs, gb := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/API_KEY", nil)
		require.Equal(t, http.StatusOK, gs)
		assert.Equal(t, "v2-value", gb["value"], "GET returns the latest version by default")
	})

	t.Run("free tier: vault not available → 403", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "free", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/X",
			map[string]any{"value": "v"})
		require.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "vault_not_available", body["error"])
	})

	t.Run("hobby tier: non-production env not allowed → 403", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "hobby", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/staging/X",
			map[string]any{"value": "v"})
		require.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "vault_env_not_allowed", body["error"],
			"hobby vault_envs_allowed is production-only")
	})

	t.Run("env_policy locks production vault_write to owner → developer member 403 env_policy_denied", func(t *testing.T) {
		teamID, _, _ := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		// Add a developer member to the SAME team and lock the env policy.
		dev, err := models.CreateUser(context.Background(), db, teamID, "vbdev-"+uuid.NewString()[:8]+"@example.com", "", "", "developer")
		require.NoError(t, err)
		require.NoError(t, models.SetEmailVerified(context.Background(), db, dev.ID))
		devJWT := signVaultBlockJWT(t, dev.ID, teamID)
		vaultBlockSetEnvPolicy(t, db, teamID, `{"production":{"vault_write":["owner"]}}`)

		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, devJWT, http.MethodPut, "/api/v1/vault/production/SECRET",
			map[string]any{"value": "v"})
		require.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "env_policy_denied", body["error"],
			"RequireEnvAccess(vault_write) gates the mutating route on env_policy")
	})

	t.Run("invalid key → 400", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "hobby", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/bad%20key",
			map[string]any{"value": "v"})
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_key", body["error"])
	})

	t.Run("missing bearer → 401", func(t *testing.T) {
		app := vaultBlockApp(t, db, miniRedis(t))
		status, _ := vaultBlockReq(t, app, "", http.MethodPut, "/api/v1/vault/production/X",
			map[string]any{"value": "v"})
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/vault/:env/:key — VaultHandler.GetSecret  (read)
// ─────────────────────────────────────────────────────────────────────────

func TestVaultBlock_GetSecret(t *testing.T) {
	vaultBlockSkipNoDB(t)
	db, cleanup := vaultBlockDB(t)
	defer cleanup()

	t.Run("happy path returns decrypted value + version", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/TOKEN",
			map[string]any{"value": "tok-123"})

		status, body := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/TOKEN", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, "tok-123", body["value"])
		assert.EqualValues(t, 1, body["version"])
	})

	t.Run("explicit ?version=1 returns that version after a v2 write", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/ROT",
			map[string]any{"value": "first"})
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/ROT",
			map[string]any{"value": "second"})

		status, body := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/ROT?version=1", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "first", body["value"])
		assert.EqualValues(t, 1, body["version"])
	})

	t.Run("missing key → 404", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/NOPE", nil)
		require.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "not_found", body["error"])
	})

	t.Run("cross-team isolation: team B cannot read team A's secret → 404", func(t *testing.T) {
		teamA, _, jwtA := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		_, _, jwtB := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))

		_, _ = vaultBlockReq(t, app, jwtA, http.MethodPut, "/api/v1/vault/production/ISOLATED",
			map[string]any{"value": "team-a-only"})

		status, body := vaultBlockReq(t, app, jwtB, http.MethodGet, "/api/v1/vault/production/ISOLATED", nil)
		require.True(t, vaultBlockCrossTeamRefused(status),
			"cross-team read must be refused (404, never 403); got %d", status)
		assert.Equal(t, "not_found", body["error"], "existence of another team's secret must be unobservable")
		_ = teamA
	})

	t.Run("invalid version → 400", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, _ := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/X?version=abc", nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/vault/:env — VaultHandler.ListKeys  (list, never values)
// ─────────────────────────────────────────────────────────────────────────

func TestVaultBlock_ListKeys(t *testing.T) {
	vaultBlockSkipNoDB(t)
	db, cleanup := vaultBlockDB(t)
	defer cleanup()

	t.Run("lists key names only — never values", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/AAA",
			map[string]any{"value": "secret-aaa"})
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/BBB",
			map[string]any{"value": "secret-bbb"})

		status, body := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, "production", body["env"])
		keys, ok := body["keys"].([]any)
		require.True(t, ok, "keys array present")
		assert.ElementsMatch(t, []any{"AAA", "BBB"}, keys)

		// The list path must never leak ciphertext or plaintext values.
		_, hasValue := body["value"]
		assert.False(t, hasValue, "list response must not carry any value field")
	})

	t.Run("cross-team isolation: team B sees an empty list for an env team A populated", func(t *testing.T) {
		_, _, jwtA := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		_, _, jwtB := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwtA, http.MethodPut, "/api/v1/vault/production/ONLY_A",
			map[string]any{"value": "v"})

		status, body := vaultBlockReq(t, app, jwtB, http.MethodGet, "/api/v1/vault/production", nil)
		require.Equal(t, http.StatusOK, status)
		keys, _ := body["keys"].([]any)
		assert.Empty(t, keys, "team B's vault must not enumerate team A's keys")
	})

	t.Run("invalid env → 400", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/bad$env", nil)
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_env", body["error"])
	})
}

// ─────────────────────────────────────────────────────────────────────────
// POST /api/v1/vault/:env/:key/rotate — VaultHandler.RotateSecret
// ─────────────────────────────────────────────────────────────────────────

func TestVaultBlock_RotateSecret(t *testing.T) {
	vaultBlockSkipNoDB(t)
	db, cleanup := vaultBlockDB(t)
	defer cleanup()

	t.Run("rotate creates a new version + audits as 'rotate'", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/ROTKEY",
			map[string]any{"value": "old"})

		status, body := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/production/ROTKEY/rotate",
			map[string]any{"value": "new"})
		require.Equal(t, http.StatusCreated, status, "body=%v", body)
		assert.EqualValues(t, 2, body["version"], "rotate bumps to a new version")

		gs, gb := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/ROTKEY", nil)
		require.Equal(t, http.StatusOK, gs)
		assert.Equal(t, "new", gb["value"], "rotate replaces the latest value")

		n, err := models.CountVaultAudit(context.Background(), db, teamID, "rotate", "production", "ROTKEY")
		require.NoError(t, err)
		assert.Equal(t, 1, n, "rotate writes a distinct 'rotate' audit action")
	})

	t.Run("rotate is idempotent under a repeated Idempotency-Key (no duplicate version)", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/IDEM",
			map[string]any{"value": "base"})

		idemKey := "idem-" + uuid.NewString()
		body := map[string]any{"value": "rotated"}
		h := map[string]string{"Authorization": "Bearer " + jwt, "Idempotency-Key": idemKey}
		r1 := doJSON(t, app, http.MethodPost, "/api/v1/vault/production/IDEM/rotate", body, h)
		_ = decodeBody(t, r1)
		r2 := doJSON(t, app, http.MethodPost, "/api/v1/vault/production/IDEM/rotate", body, h)
		_ = decodeBody(t, r2)

		var maxVersion int
		require.NoError(t, db.QueryRow(`
			SELECT COALESCE(MAX(version),0) FROM vault_secrets
			WHERE team_id=$1 AND env='production' AND key='IDEM'
		`, teamID).Scan(&maxVersion))
		assert.Equal(t, 2, maxVersion, "replayed rotate under one Idempotency-Key must not create a 3rd version")
	})

	t.Run("missing bearer → 401", func(t *testing.T) {
		app := vaultBlockApp(t, db, miniRedis(t))
		status, _ := vaultBlockReq(t, app, "", http.MethodPost, "/api/v1/vault/production/X/rotate",
			map[string]any{"value": "v"})
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// DELETE /api/v1/vault/:env/:key — VaultHandler.DeleteSecret  (hard delete)
// ─────────────────────────────────────────────────────────────────────────

func TestVaultBlock_DeleteSecret(t *testing.T) {
	vaultBlockSkipNoDB(t)
	db, cleanup := vaultBlockDB(t)
	defer cleanup()

	t.Run("delete removes ALL versions → 204; subsequent GET 404", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/DELME",
			map[string]any{"value": "v1"})
		_, _ = vaultBlockReq(t, app, jwt, http.MethodPut, "/api/v1/vault/production/DELME",
			map[string]any{"value": "v2"})

		resp := doJSON(t, app, http.MethodDelete, "/api/v1/vault/production/DELME", nil,
			map[string]string{"Authorization": "Bearer " + jwt})
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		var n int
		require.NoError(t, db.QueryRow(`
			SELECT COUNT(*) FROM vault_secrets WHERE team_id=$1 AND env='production' AND key='DELME'
		`, teamID).Scan(&n))
		assert.Equal(t, 0, n, "hard delete removes every version")

		gs, _ := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/DELME", nil)
		assert.Equal(t, http.StatusNotFound, gs)
	})

	t.Run("delete of a non-existent key → 404 (non-leaking)", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		resp := doJSON(t, app, http.MethodDelete, "/api/v1/vault/production/GHOST", nil,
			map[string]string{"Authorization": "Bearer " + jwt})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("cross-team isolation: team B cannot delete team A's secret → 404 + secret survives", func(t *testing.T) {
		teamA, _, jwtA := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		_, _, jwtB := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		_, _ = vaultBlockReq(t, app, jwtA, http.MethodPut, "/api/v1/vault/production/KEEP",
			map[string]any{"value": "team-a"})

		resp := doJSON(t, app, http.MethodDelete, "/api/v1/vault/production/KEEP", nil,
			map[string]string{"Authorization": "Bearer " + jwtB})
		require.True(t, vaultBlockCrossTeamRefused(resp.StatusCode),
			"cross-team delete must be refused (404); got %d", resp.StatusCode)

		var n int
		require.NoError(t, db.QueryRow(`
			SELECT COUNT(*) FROM vault_secrets WHERE team_id=$1 AND env='production' AND key='KEEP'
		`, teamA).Scan(&n))
		assert.Equal(t, 1, n, "team A's secret must survive team B's delete attempt")
	})
}

// ─────────────────────────────────────────────────────────────────────────
// POST /api/v1/vault/copy — VaultHandler.CopySecrets  (Pro+ bulk copy)
// ─────────────────────────────────────────────────────────────────────────

func TestVaultBlock_CopySecrets(t *testing.T) {
	vaultBlockSkipNoDB(t)
	db, cleanup := vaultBlockDB(t)
	defer cleanup()

	t.Run("pro tier copies staging→production with encrypted bytes preserved", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		// Seed two keys in staging directly (bypasses hobby env restriction;
		// pro vault_envs_allowed is production-only but CopySecrets reads from
		// any source env — it gates on multiEnvTierAllowed, not the env list).
		seedVaultSecret(t, db, teamID, "staging", "ALPHA", "alpha-secret")
		seedVaultSecret(t, db, teamID, "staging", "BETA", "beta-secret")

		status, body := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "staging", "to": "production"})
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		assert.EqualValues(t, 2, body["copied"])
		assert.EqualValues(t, 0, body["skipped"])

		// Copied secrets decrypt to the originals in the target env.
		gs, gb := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/ALPHA", nil)
		require.Equal(t, http.StatusOK, gs)
		assert.Equal(t, "alpha-secret", gb["value"])
	})

	t.Run("dry_run reports the plan but persists nothing", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		seedVaultSecret(t, db, teamID, "staging", "DRY", "dry-secret")

		status, body := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "staging", "to": "production", "dry_run": true})
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		assert.Equal(t, true, body["dry_run"])
		assert.EqualValues(t, 1, body["copied"])

		var n int
		require.NoError(t, db.QueryRow(`
			SELECT COUNT(*) FROM vault_secrets WHERE team_id=$1 AND env='production' AND key='DRY'
		`, teamID).Scan(&n))
		assert.Equal(t, 0, n, "dry_run must not write any target rows")
	})

	t.Run("existing target key skipped by default; overwrite=true bumps version", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		seedVaultSecret(t, db, teamID, "staging", "DUP", "from-staging")
		seedVaultSecret(t, db, teamID, "production", "DUP", "already-in-prod")

		// Default: existing target key is skipped.
		_, sb := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "staging", "to": "production"})
		assert.EqualValues(t, 0, sb["copied"])
		assert.EqualValues(t, 1, sb["skipped"])

		// overwrite=true: existing key is bumped to a new version.
		_, ob := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "staging", "to": "production", "overwrite": true})
		assert.EqualValues(t, 1, ob["copied"])

		gs, gb := vaultBlockReq(t, app, jwt, http.MethodGet, "/api/v1/vault/production/DUP", nil)
		require.Equal(t, http.StatusOK, gs)
		assert.Equal(t, "from-staging", gb["value"], "overwrite copies the source value over the target")
		_ = teamID
	})

	t.Run("missing source key reported as 'missing'", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "staging", "to": "production", "keys": []string{"ABSENT"}})
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		assert.EqualValues(t, 1, body["missing"])
		assert.EqualValues(t, 0, body["copied"])
	})

	t.Run("hobby tier: not multi-env → 402 upgrade required", func(t *testing.T) {
		teamID, _, jwt := vaultBlockSeedTeamMember(t, db, "hobby", "owner")
		seedVaultSecret(t, db, teamID, "staging", "X", "v")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "staging", "to": "production"})
		require.Equal(t, http.StatusPaymentRequired, status)
		assert.Contains(t, body, "agent_action", "402 carries the canonical upgrade agent_action")
	})

	t.Run("from == to → 400", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "production", "to": "production"})
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_target", body["error"])
	})

	t.Run("missing 'from' → 400 invalid_env", func(t *testing.T) {
		_, _, jwt := vaultBlockSeedTeamMember(t, db, "pro", "owner")
		app := vaultBlockApp(t, db, miniRedis(t))
		status, body := vaultBlockReq(t, app, jwt, http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"to": "production"})
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_env", body["error"])
	})

	t.Run("missing bearer → 401", func(t *testing.T) {
		app := vaultBlockApp(t, db, miniRedis(t))
		status, _ := vaultBlockReq(t, app, "", http.MethodPost, "/api/v1/vault/copy",
			map[string]any{"from": "staging", "to": "production"})
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// Local seam helpers (defined here to keep this suite self-contained without
// redefining package-shared helpers).
// ─────────────────────────────────────────────────────────────────────────

// signVaultBlockJWT mints a real session JWT for an arbitrary (userID, teamID)
// pair — used for the second member in the env_policy authz test, where
// vaultBlockSeedTeamMember (which seeds its own team) doesn't fit. Thin wrapper
// over the package testhelpers signer — does NOT redefine it.
func signVaultBlockJWT(t *testing.T, userID, teamID uuid.UUID) string {
	t.Helper()
	return testhelpers.MustSignSessionJWT(t, userID.String(), teamID.String(), testhelpers.UniqueEmail(t))
}

// seedVaultSecret inserts an AES-256-GCM-encrypted secret straight into
// vault_secrets at the next version for (team,env,key), using the same test
// AES key the app is wired with so a later GET decrypts it. Used to stage
// source secrets for copy tests in envs the tier's write path would reject
// (e.g. staging on hobby/pro), keeping the copy assertions focused on the
// copy contract rather than the write path. Mirrors VaultHandler.encryptPlaintext:
// crypto.Encrypt returns a base64url string; the at-rest representation is the
// decoded raw bytes (opaque BYTEA).
func seedVaultSecret(t *testing.T, db *sql.DB, teamID uuid.UUID, env, key, plaintext string) {
	t.Helper()
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	encoded, err := crypto.Encrypt(aesKey, plaintext)
	require.NoError(t, err)
	raw, err := base64.URLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	_, err = models.CreateVaultSecret(context.Background(), db, teamID, env, key, raw, uuid.NullUUID{})
	require.NoError(t, err, "seed vault secret %s/%s", env, key)
}
