package handlers_test

// vault_test.go — coverage for /api/v1/vault/* endpoints.
//
// Layered tests:
//   - TestVault_AESRoundtrip       : crypto contract used by the handler
//   - TestVault_TeamIsolation      : team A's JWT cannot read team B's secret (404, never 403)
//   - TestVault_AuditLog           : every mutation + read writes a vault_audit_log row
//   - TestVault_Versioning         : rotate creates v2; v1 still queryable via ?version=1
//   - TestVault_DeleteSemantics    : DELETE removes ALL versions (hard delete) and is idempotent
//   - TestVault_E2E_KeyList        : list returns keys but never values
//
// Integration tests skip when TEST_DATABASE_URL is empty (no DB available).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// vaultMigration mirrors db/migrations/008_vault.sql; embedded inline so the
// test does not depend on testhelpers.runMigrations being updated. Idempotent
// (IF NOT EXISTS) so safe to run on every test setup.
const vaultMigration = `
CREATE TABLE IF NOT EXISTS vault_secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    env             TEXT NOT NULL DEFAULT 'production',
    key             TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    version         INT NOT NULL DEFAULT 1,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, env, key, version)
);
CREATE INDEX IF NOT EXISTS idx_vault_secrets_lookup ON vault_secrets (team_id, env, key);
CREATE TABLE IF NOT EXISTS vault_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    team_id     UUID NOT NULL,
    user_id     UUID,
    action      TEXT NOT NULL,
    env         TEXT NOT NULL,
    secret_key  TEXT NOT NULL,
    ip          TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vault_audit_team_ts ON vault_audit_log (team_id, ts DESC);
`

// applyVaultMigration ensures the vault schema exists in the test DB.
func applyVaultMigration(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(vaultMigration); err != nil {
		t.Fatalf("applyVaultMigration: %v", err)
	}
}

// vaultIntegrationDB returns a test DB and cleanup, or skips when none configured
// or when the DB is unreachable. Integration tests must skip cleanly in CI when
// no postgres is running — never fatal.
func vaultIntegrationDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
	// Probe the connection ourselves so a refused/auth-failed connection skips
	// rather than fataling out via testhelpers.SetupTestDB.
	probe, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("integration DB open failed: %v", err)
	}
	if err := probe.Ping(); err != nil {
		probe.Close()
		t.Skipf("integration DB ping failed (no test postgres available): %v", err)
	}
	probe.Close()

	db, clean := testhelpers.SetupTestDB(t)
	applyVaultMigration(t, db)
	return db, clean
}

// vaultTestApp builds a minimal Fiber app exposing only the vault routes.
// Auth is gated by RequireAuth using the standard test JWT secret.
func vaultTestApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret,
		AESKey:    testhelpers.TestAESKeyHex,
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
	h := handlers.NewVaultHandler(db, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Put("/vault/:env/:key", h.PutSecret)
	api.Get("/vault/:env/:key", h.GetSecret)
	api.Get("/vault/:env", h.ListKeys)
	api.Delete("/vault/:env/:key", h.DeleteSecret)
	api.Post("/vault/:env/:key/rotate", h.RotateSecret)
	return app
}

// jsonReq builds a JSON request with the given JWT.
func jsonReq(t *testing.T, method, path, jwt string, body any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	return req
}

// makeTeamUser inserts a team and one user, and returns (teamID, userID, jwt).
func makeTeamUser(t *testing.T, db *sql.DB) (string, string, string) {
	t.Helper()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	emailAddr := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamID, emailAddr,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, emailAddr)
	return teamID, userID, jwt
}

// ── 1. AES roundtrip + tamper detection ──────────────────────────────────────

func TestVault_AESRoundtrip(t *testing.T) {
	keyHex := testhelpers.TestAESKeyHex
	key, err := crypto.ParseAESKey(keyHex)
	require.NoError(t, err)

	plaintext := "supersecret-postgres://user:pass@host/db"
	encoded, err := crypto.Encrypt(key, plaintext)
	require.NoError(t, err)

	raw, err := base64.URLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Greater(t, len(raw), len(plaintext), "ciphertext must include nonce + tag overhead")

	// Roundtrip: re-encode and decrypt.
	got, err := crypto.Decrypt(key, base64.URLEncoding.EncodeToString(raw))
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// Tamper: flip a byte in the middle. GCM auth tag must reject.
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	tampered[len(tampered)/2] ^= 0xFF
	_, err = crypto.Decrypt(key, base64.URLEncoding.EncodeToString(tampered))
	assert.Error(t, err, "tampered ciphertext must fail GCM auth")

	// Wrong key: decryption must fail.
	otherKey, _ := crypto.ParseAESKey("ffeeddccbbaa00112233445566778899aabbccddeeff00112233445566778899")
	_, err = crypto.Decrypt(otherKey, encoded)
	assert.Error(t, err, "wrong AES key must fail decryption")
}

// ── 2. Cross-team isolation: foreign reads return 404, never 403 ─────────────

func TestVault_TeamIsolation(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	_, _, jwtA := makeTeamUser(t, db)
	_, _, jwtB := makeTeamUser(t, db)

	const env, key = "production", "DATABASE_URL"

	// Team A writes a secret.
	resp, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwtA, map[string]string{"value": "team-a-secret"}), 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Team B GET → must be 404 (never 403, never 200).
	resp, err = app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key, jwtB, nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "cross-team read must return 404")

	// Team B DELETE → must also be 404.
	resp2, err := app.Test(jsonReq(t, http.MethodDelete, "/api/v1/vault/"+env+"/"+key, jwtB, nil), 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "cross-team delete must return 404")

	// Team B LIST → must be empty (no leak via the list endpoint).
	resp3, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env, jwtB, nil), 5000)
	require.NoError(t, err)
	defer resp3.Body.Close()
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	var lb struct {
		Keys []string `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp3.Body).Decode(&lb))
	assert.Empty(t, lb.Keys, "team B must not see team A's keys")

	// Sanity: team A still sees its key.
	resp4, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key, jwtA, nil), 5000)
	require.NoError(t, err)
	defer resp4.Body.Close()
	assert.Equal(t, http.StatusOK, resp4.StatusCode)
}

// ── 3. Audit log: every mutation + read writes one row ───────────────────────

func TestVault_AuditLog(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	teamIDStr, _, jwt := makeTeamUser(t, db)
	teamID := uuid.MustParse(teamIDStr)
	// Use production env: tier-restricted envs are validated separately in
	// TestVault_TierEnvRestriction. Hobby tier (the default for makeTeamUser)
	// only permits "production".
	const env, key = "production", "API_TOKEN"

	// PUT
	resp, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt, map[string]string{"value": "v1"}), 5000)
	require.NoError(t, err)
	resp.Body.Close()

	n, err := models.CountVaultAudit(context.Background(), db, teamID, "set", env, key)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "PUT must write one 'set' audit row")

	// GET
	resp, err = app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	resp.Body.Close()

	n, err = models.CountVaultAudit(context.Background(), db, teamID, "get", env, key)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "GET must write one 'get' audit row")

	// DELETE
	resp, err = app.Test(jsonReq(t, http.MethodDelete, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	resp.Body.Close()

	n, err = models.CountVaultAudit(context.Background(), db, teamID, "delete", env, key)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "DELETE must write one 'delete' audit row")
}

// ── 4. Versioning: rotate creates v2; v1 still queryable ─────────────────────

func TestVault_Versioning(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	_, _, jwt := makeTeamUser(t, db)
	const env, key = "production", "OPENAI_KEY"

	// PUT v1
	resp, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt, map[string]string{"value": "sk-v1"}), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var b1 struct{ Version int `json:"version"` }
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&b1))
	assert.Equal(t, 1, b1.Version)

	// Rotate → v2
	resp2, err := app.Test(jsonReq(t, http.MethodPost, "/api/v1/vault/"+env+"/"+key+"/rotate", jwt, map[string]string{"value": "sk-v2"}), 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusCreated, resp2.StatusCode)
	var b2 struct{ Version int `json:"version"` }
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&b2))
	assert.Equal(t, 2, b2.Version, "rotate must produce v2")

	// GET (latest) → must return v2 value
	resp3, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	defer resp3.Body.Close()
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	var b3 struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	require.NoError(t, json.NewDecoder(resp3.Body).Decode(&b3))
	assert.Equal(t, "sk-v2", b3.Value)
	assert.Equal(t, 2, b3.Version)

	// GET ?version=1 → must return v1 value (history queryable)
	resp4, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key+"?version=1", jwt, nil), 5000)
	require.NoError(t, err)
	defer resp4.Body.Close()
	require.Equal(t, http.StatusOK, resp4.StatusCode)
	var b4 struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	require.NoError(t, json.NewDecoder(resp4.Body).Decode(&b4))
	assert.Equal(t, "sk-v1", b4.Value)
	assert.Equal(t, 1, b4.Version)

	// GET ?version=99 → 404
	resp5, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key+"?version=99", jwt, nil), 5000)
	require.NoError(t, err)
	defer resp5.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp5.StatusCode)
}

// ── 5. Delete semantics: hard delete of all versions, idempotent on missing ──

func TestVault_DeleteSemantics(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	teamIDStr, _, jwt := makeTeamUser(t, db)
	teamID := uuid.MustParse(teamIDStr)
	const env, key = "production", "DOC_DELETE"

	// Create v1 + v2.
	for _, v := range []string{"a", "b"} {
		resp, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt, map[string]string{"value": v}), 5000)
		require.NoError(t, err)
		resp.Body.Close()
	}

	// Confirm 2 rows exist.
	var pre int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM vault_secrets WHERE team_id = $1::uuid AND env = $2 AND key = $3`, teamID, env, key).Scan(&pre))
	assert.Equal(t, 2, pre)

	// DELETE → 204
	resp, err := app.Test(jsonReq(t, http.MethodDelete, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Both versions are gone (hard delete).
	var post int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM vault_secrets WHERE team_id = $1::uuid AND env = $2 AND key = $3`, teamID, env, key).Scan(&post))
	assert.Equal(t, 0, post, "DELETE must hard-remove every version (chosen MVP semantics)")

	// GET after delete → 404 for latest AND for ?version=1
	resp2, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

	resp3, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env+"/"+key+"?version=1", jwt, nil), 5000)
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp3.StatusCode)

	// Second DELETE → 404 (idempotent, never leaks "this never existed" vs. "we just deleted it")
	resp4, err := app.Test(jsonReq(t, http.MethodDelete, "/api/v1/vault/"+env+"/"+key, jwt, nil), 5000)
	require.NoError(t, err)
	defer resp4.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp4.StatusCode)
}

// ── 6. Key list returns key names but never values ───────────────────────────

func TestVault_E2E_KeyList(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	_, _, jwt := makeTeamUser(t, db)
	const env = "production"

	// Insert three keys with distinct values that must NEVER appear in the list response.
	for _, kv := range [][2]string{
		{"DB_URL", "value-must-not-leak-1"},
		{"REDIS_URL", "value-must-not-leak-2"},
		{"API_TOKEN", "value-must-not-leak-3"},
	} {
		resp, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+kv[0], jwt, map[string]string{"value": kv[1]}), 5000)
		require.NoError(t, err)
		resp.Body.Close()
	}

	// GET list
	resp, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/"+env, jwt, nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rawBody, err := readAll(resp.Body)
	require.NoError(t, err)

	var lb struct {
		OK   bool     `json:"ok"`
		Env  string   `json:"env"`
		Keys []string `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(rawBody, &lb))
	assert.True(t, lb.OK)
	assert.Equal(t, env, lb.Env)
	assert.ElementsMatch(t, []string{"DB_URL", "REDIS_URL", "API_TOKEN"}, lb.Keys)

	// Body must NOT contain any plaintext value.
	for _, leak := range []string{"value-must-not-leak-1", "value-must-not-leak-2", "value-must-not-leak-3"} {
		assert.NotContains(t, string(rawBody), leak,
			"list response must never include plaintext values (leak=%s)", leak)
	}
}

// ── 7. Auth gate: missing JWT yields 401 (not 404) so external callers know auth is required ──

func TestVault_RequiresAuth(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	resp, err := app.Test(jsonReq(t, http.MethodGet, "/api/v1/vault/production/SOMETHING", "", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ── 8. Invalid env / key validation ──────────────────────────────────────────

func TestVault_Validation(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)
	_, _, jwt := makeTeamUser(t, db)

	cases := []struct {
		name string
		path string
		want int
	}{
		// Path params can't be empty in fiber routes; use illegal characters instead.
		// Pre-encode the space (%20) so httptest.NewRequest accepts the URL —
		// Go 1.26+ panics on unescaped spaces (older Go silently encoded them).
		// The fiber handler decodes back to "foo bar" and the validator rejects
		// the space — exactly what we want to assert.
		{"bad-key-with-space", "/api/v1/vault/production/foo%20bar", http.StatusBadRequest},
		{"bad-key-too-long", "/api/v1/vault/production/" + longString(300), http.StatusBadRequest},
		{"bad-env-with-special", "/api/v1/vault/prod!ction/X", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := app.Test(jsonReq(t, http.MethodPut, tc.path, jwt, map[string]string{"value": "x"}), 5000)
			require.NoError(t, err)
			defer resp.Body.Close()
			// Some illegal chars (e.g. space) get URL-encoded by httptest into %20 which is also rejected;
			// we just assert non-2xx + non-5xx.
			assert.True(t, resp.StatusCode == tc.want || resp.StatusCode == http.StatusNotFound,
				"expected %d (got %d) for path=%s", tc.want, resp.StatusCode, tc.path)
		})
	}
}

// ── 9. Per-tier vault quota + env restriction ────────────────────────────────
//
// Hobby tier (default for makeTeamUser): vault_max_entries=20,
// vault_envs_allowed=["production"]. Verifies:
//   - 20 distinct keys succeed
//   - 21st key returns 402 vault_quota_exceeded
//   - rotating an existing key after the cap still works (count doesn't grow)
//   - PUT to a non-allowed env returns 403 vault_env_not_allowed
func TestVault_TierQuotaAndEnv(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)

	_, _, jwt := makeTeamUser(t, db) // hobby tier

	// 20 PUTs on production should succeed.
	for i := 0; i < 20; i++ {
		path := fmt.Sprintf("/api/v1/vault/production/KEY_%02d", i)
		resp, err := app.Test(jsonReq(t, http.MethodPut, path, jwt, map[string]string{"value": "v"}), 5000)
		require.NoError(t, err)
		body, _ := readAll(resp.Body)
		resp.Body.Close()
		require.Equalf(t, http.StatusCreated, resp.StatusCode,
			"PUT %d/20 expected 201, got %d body=%s", i+1, resp.StatusCode, string(body))
	}

	// 21st distinct key → 402 vault_quota_exceeded.
	resp, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/production/KEY_21", jwt, map[string]string{"value": "v"}), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := readAll(resp.Body)
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"21st key must return 402; got %d body=%s", resp.StatusCode, string(body))
	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "vault_quota_exceeded", errResp.Error)

	// Updating an existing key (KEY_00) must still succeed — no quota burn.
	resp2, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/production/KEY_00", jwt, map[string]string{"value": "v2"}), 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusCreated, resp2.StatusCode,
		"updating an existing key when at quota must still succeed (no count growth)")

	// PUT to non-allowed env → 403 vault_env_not_allowed.
	resp3, err := app.Test(jsonReq(t, http.MethodPut, "/api/v1/vault/staging/SOMETHING", jwt, map[string]string{"value": "v"}), 5000)
	require.NoError(t, err)
	defer resp3.Body.Close()
	body3, _ := readAll(resp3.Body)
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode,
		"hobby tier PUT to staging must return 403; got %d body=%s", resp3.StatusCode, string(body3))
	var errResp3 struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body3, &errResp3)
	assert.Equal(t, "vault_env_not_allowed", errResp3.Error)
}

func longString(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += "a"
	}
	return s
}

// readAll is a small helper so we can introspect the raw body for leak checks.
func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, nil // tolerate; fiber test bodies sometimes return non-io.EOF
		}
	}
}

// Sanity: ensure fmt remains imported even if a debug Sprintf is removed.
var _ = fmt.Sprint
