package handlers_test

// vault_block_helpers_test.go — shared helpers for the W3 vault-block
// integration suite (vault_block_routes_test.go). These cover the per-team
// encrypted-secret vault user-flow block from
// USER-FLOW-INVENTORY-AND-TEST-MATRIX.md (2026-06-04) §W3: the vault
// read/list/write/rotate/delete/copy surfaces that, prior to this suite, were
// carried in internal/router/route_donebar_guard_test.go either pointing at
// the shallow TestMerged_Vault_RequiresAuth probe (GET/GET/PUT) or sitting in
// routeCoverageExemptions with a "TODO: matrix W3 …" pointer and NO mapped
// test (rotate / delete / copy).
//
// Mirrors the established W3 team-block convention
// (team_block_helpers_test.go): a thin SetupTestDB wrapper + a loud
// skip-when-no-DB guard + DB-backed seed helpers. Helpers here are prefixed
// vaultBlock* so they do NOT collide with — and do NOT redefine — the existing
// seedVerifiedTeamUser / teamBlock* / miniRedis / doJSON / decodeBody helpers,
// which this suite reuses verbatim.
//
// Why a dedicated app builder rather than NewTestAppWithServices: that shared
// test app does NOT register the vault routes. vaultBlockApp registers EVERY
// vault route through the SAME production middleware chain
// internal/router/router.go installs — middleware.RequireAuth (real JWT
// validation, no synthetic shim) + PopulateTeamRole + RequireEnvAccess
// (VaultWrite, :env-param lookup) + Idempotency on rotate — against the real
// migrated test DB. The role/env-policy lookups are wired with the live
// SetRoleLookupDB / SetEnvPolicyDB handles exactly as router.go does, so the
// suite exercises the authz + env-policy + tier + encrypt/decrypt-at-rest
// contracts the done-bar guard's routeTestMap rows now point at.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// vaultBlockSkipNoDB skips a W3 vault-block test when no test Postgres is
// configured. The vault block is a real-backend integration surface — these
// tests assert on actual rows in vault_secrets / vault_audit_log and on the
// AES-256-GCM ciphertext stored at rest, so a missing DB is a loud skip, never
// a false green. Mirrors teamBlockSkipNoDB.
func vaultBlockSkipNoDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("W3 vault-block integration: TEST_DATABASE_URL not set")
	}
}

// vaultBlockDB opens a fresh migrated test DB and returns it with its cleanup.
// Thin wrapper over testhelpers.SetupTestDB so every W3 vault-block test reads
// the same way.
func vaultBlockDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	return testhelpers.SetupTestDB(t)
}

// vaultBlockApp builds a Fiber app that registers every vault route through the
// SAME middleware chain production uses (internal/router/router.go): the real
// middleware.RequireAuth(cfg) validates the session JWT (NO synthetic shim —
// callers mint real JWTs via testhelpers.MustSignSessionJWT), PopulateTeamRole
// resolves the caller's role from the DB, RequireEnvAccess(VaultWrite) gates
// the mutating routes on the team's env_policy keyed by the :env param, and
// the rotate route carries Idempotency exactly as the live router does.
//
// The role + env-policy lookups are wired with the live package-level handles
// (SetRoleLookupDB / SetEnvPolicyDB) pointed at the test DB — mirror of
// router.go. cfg.AESKey is the test key so encrypt/decrypt-at-rest round-trips.
func vaultBlockApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()

	cfg := &config.Config{
		JWTSecret:        testhelpers.TestJWTSecret,
		AESKey:           testhelpers.TestAESKeyHex,
		DashboardBaseURL: "http://localhost:5173",
	}
	planReg := plans.Default()

	app := fiber.New(fiber.Config{
		ProxyHeader: "X-Forwarded-For",
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

	// Wire the live role + env-policy lookup handles, exactly as router.go
	// does at startup. RequireEnvAccess reads env_policy through this handle;
	// PopulateTeamRole reads auth_team_role through SetRoleLookupDB.
	middleware.SetRoleLookupDB(db)
	middleware.SetEnvPolicyDB(db)

	vaultH := handlers.NewVaultHandler(db, cfg, planReg)
	vaultEnvLookup := middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
		return c.Params("env"), nil
	})

	api := app.Group("/api/v1", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())
	api.Put("/vault/:env/:key",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite, vaultEnvLookup),
		vaultH.PutSecret,
	)
	api.Get("/vault/:env/:key", vaultH.GetSecret)
	api.Get("/vault/:env", vaultH.ListKeys)
	api.Delete("/vault/:env/:key",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite, vaultEnvLookup),
		vaultH.DeleteSecret,
	)
	api.Post("/vault/:env/:key/rotate",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite, vaultEnvLookup),
		middleware.Idempotency(rdb, "vault.rotate"),
		vaultH.RotateSecret,
	)
	api.Post("/vault/copy",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite),
		vaultH.CopySecrets,
	)

	return app
}

// vaultBlockSeedTeamMember inserts a team at the given tier plus a member with
// the given role, returning (teamID, userID, jwt). The JWT is a real session
// token the RequireAuth chain validates. Registers cleanup. Built on the
// package testhelpers seeders — does NOT redefine seedVerifiedTeamUser.
func vaultBlockSeedTeamMember(t *testing.T, db *sql.DB, tier, role string) (uuid.UUID, uuid.UUID, string) {
	t.Helper()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, tier))
	u, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", role)
	require.NoError(t, err)
	require.NoError(t, models.SetEmailVerified(context.Background(), db, u.ID))
	t.Cleanup(func() {
		db.Exec(`DELETE FROM vault_secrets WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM vault_audit_log WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM users WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})
	jwt := testhelpers.MustSignSessionJWT(t, u.ID.String(), teamID.String(), testhelpers.UniqueEmail(t))
	return teamID, u.ID, jwt
}

// vaultBlockReq issues a JSON request to the test app carrying the supplied
// bearer JWT and returns (status, decoded JSON body). Body may be nil. Built
// on the existing doJSON helper (which takes a headers map) so it does NOT
// redefine it.
func vaultBlockReq(t *testing.T, app *fiber.App, jwt, method, path string, body any) (int, map[string]any) {
	t.Helper()
	headers := map[string]string{}
	if jwt != "" {
		headers["Authorization"] = "Bearer " + jwt
	}
	resp := doJSON(t, app, method, path, body, headers)
	return resp.StatusCode, decodeBody(t, resp)
}

// vaultBlockRawCiphertext reads the encrypted_value bytes stored at rest for
// the latest version of (team,env,key). Used to assert the value is NOT stored
// as plaintext (encrypt-at-rest contract) and that it decrypts to the original.
func vaultBlockRawCiphertext(t *testing.T, db *sql.DB, teamID uuid.UUID, env, key string) []byte {
	t.Helper()
	var raw []byte
	err := db.QueryRow(`
		SELECT encrypted_value FROM vault_secrets
		WHERE team_id = $1 AND env = $2 AND key = $3
		ORDER BY version DESC LIMIT 1
	`, teamID, env, key).Scan(&raw)
	require.NoError(t, err, "read encrypted_value at rest")
	return raw
}

// vaultBlockSetEnvPolicy writes the team's env_policy JSONB so the
// RequireEnvAccess gate can be exercised (e.g. lock production vault_write to
// owners only). Passing an empty string clears it back to the default-allow {}.
func vaultBlockSetEnvPolicy(t *testing.T, db *sql.DB, teamID uuid.UUID, policyJSON string) {
	t.Helper()
	if policyJSON == "" {
		policyJSON = "{}"
	}
	_, err := db.Exec(`UPDATE teams SET env_policy = $2::jsonb WHERE id = $1`, teamID, policyJSON)
	require.NoError(t, err, "set env_policy")
}

// vaultBlockCrossTeamRefused is satisfied for the cross-team-isolation
// assertions: acting on another team's secret must NEVER succeed. Vault's
// contract refuses with 404 (never 403) so existence is unobservable — we
// accept 404 and reject any 2xx.
func vaultBlockCrossTeamRefused(status int) bool {
	return status == http.StatusNotFound
}
