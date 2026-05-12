package handlers_test

// vault_copy_test.go — Integration tests for POST /api/v1/vault/copy.
//
// Coverage:
//   - Hobby tier returns 402 with agent_action (the contract the spec mandates).
//   - Pro tier copy succeeds; secrets land in target env.
//   - dry_run=true returns the plan but writes nothing.
//   - Existing keys in target are skipped by default; overwrite=true bumps them.
//   - Per-key allowlist limits scope.
//   - Validation: missing from/to, from==to, bad env name, bad key name.
//
// Shares setup helpers (applyVaultMigration, makeTeamUser, vaultTestApp,
// jsonReq) with vault_test.go via the same Go package.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// makeTeamUserTier is like makeTeamUser but with a configurable plan tier.
// We can't simply reuse makeTeamUser because it hardcodes the hobby tier;
// the copy endpoint's tier gate is the thing we need to exercise.
func makeTeamUserTier(t *testing.T, db *sql.DB, tier string) (string, string, string) {
	t.Helper()
	teamID := testhelpers.MustCreateTeamDB(t, db, tier)
	emailAddr := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamID, emailAddr,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, emailAddr)
	return teamID, userID, jwt
}

// putSecret is a request helper that PUTs a vault secret via the live handler.
func putSecret(t *testing.T, app interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}, jwt, env, key, value string) {
	t.Helper()
	req := jsonReq(t, http.MethodPut, "/api/v1/vault/"+env+"/"+key, jwt,
		map[string]string{"value": value})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"PUT /vault must return 201 (got %d)", resp.StatusCode)
}

// TestVaultCopy_HobbyTier_402 verifies the tier gate. The agent_action string
// must be present in the response so MCP agents tell the user to upgrade.
func TestVaultCopy_HobbyTier_402(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	_, _, jwt := makeTeamUserTier(t, db, "hobby")
	app := vaultTestApp(t, db)

	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{
		"from": "staging",
		"to":   "production",
	})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"])
	assert.Contains(t, body, "agent_action",
		"402 response must include agent_action so MCP agents can tell the user to upgrade")
	if a, ok := body["agent_action"].(string); ok {
		assert.Contains(t, a, "Pro")
		assert.Contains(t, a, "multi-env")
	}
}

// TestVaultCopy_ProTier_CopiesAllKeys verifies the happy path. Seed two
// secrets in staging, copy to production, assert both are readable there.
func TestVaultCopy_ProTier_CopiesAllKeys(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	teamID, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultTestApp(t, db)

	putSecret(t, app, jwt, "staging", "DATABASE_URL", "postgres://stg")
	putSecret(t, app, jwt, "staging", "API_KEY", "stg-key-123")

	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{
		"from": "staging",
		"to":   "production",
	})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK      bool `json:"ok"`
		Copied  int  `json:"copied"`
		Skipped int  `json:"skipped"`
		Missing int  `json:"missing"`
		Plan    []struct {
			Key    string `json:"key"`
			Action string `json:"action"`
		} `json:"plan"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Copied)
	assert.Equal(t, 0, body.Skipped)
	assert.Equal(t, 0, body.Missing)
	assert.Len(t, body.Plan, 2)

	// Verify DB: both keys exist in production for this team.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT COUNT(DISTINCT key) FROM vault_secrets
		WHERE team_id = $1::uuid AND env = 'production'
		  AND key IN ('DATABASE_URL', 'API_KEY')
	`, teamID).Scan(&n))
	assert.Equal(t, 2, n, "both keys must be present in the production env")
}

// TestVaultCopy_DryRun verifies that dry_run=true returns the same plan
// shape but persists nothing.
func TestVaultCopy_DryRun(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	teamID, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultTestApp(t, db)

	putSecret(t, app, jwt, "staging", "K1", "v1")
	putSecret(t, app, jwt, "staging", "K2", "v2")

	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{
		"from":    "staging",
		"to":     "production",
		"dry_run": true,
	})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Copied int  `json:"copied"`
		DryRun bool `json:"dry_run"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.DryRun)
	assert.Equal(t, 2, body.Copied, "dry_run still reports the plan count for both keys")

	// Verify DB: production has no rows for this team.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM vault_secrets
		WHERE team_id = $1::uuid AND env = 'production'
	`, teamID).Scan(&n))
	assert.Equal(t, 0, n, "dry_run must NOT write to the target env")
}

// TestVaultCopy_SkipsExisting verifies the default behaviour: existing keys
// in the target env are skipped, not overwritten.
func TestVaultCopy_SkipsExisting(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	teamID, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultTestApp(t, db)

	putSecret(t, app, jwt, "staging", "SHARED", "from-staging")
	putSecret(t, app, jwt, "production", "SHARED", "from-prod")

	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{
		"from": "staging",
		"to":   "production",
	})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body struct {
		Copied  int `json:"copied"`
		Skipped int `json:"skipped"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, 0, body.Copied)
	assert.Equal(t, 1, body.Skipped, "existing key must be reported as skipped")

	// Verify DB: production "SHARED" still has the original value (version 1).
	var version int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT MAX(version) FROM vault_secrets
		WHERE team_id = $1::uuid AND env = 'production' AND key = 'SHARED'
	`, teamID).Scan(&version))
	assert.Equal(t, 1, version, "skipped key must not be bumped to v2")
}

// TestVaultCopy_OverwriteBumpsVersion verifies overwrite=true bumps the
// version of an existing key in the target env.
func TestVaultCopy_OverwriteBumpsVersion(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	teamID, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultTestApp(t, db)

	putSecret(t, app, jwt, "staging", "SHARED", "from-staging")
	putSecret(t, app, jwt, "production", "SHARED", "from-prod")

	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{
		"from":      "staging",
		"to":        "production",
		"overwrite": true,
	})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body struct {
		Copied  int `json:"copied"`
		Skipped int `json:"skipped"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, 1, body.Copied)
	assert.Equal(t, 0, body.Skipped)

	// Verify DB: production "SHARED" is now at v2.
	var version int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT MAX(version) FROM vault_secrets
		WHERE team_id = $1::uuid AND env = 'production' AND key = 'SHARED'
	`, teamID).Scan(&version))
	assert.Equal(t, 2, version, "overwrite must bump version to 2")
}

// TestVaultCopy_KeyAllowlist verifies that only the keys in the allowlist
// are considered; everything else stays in the source env only.
func TestVaultCopy_KeyAllowlist(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	teamID, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultTestApp(t, db)

	putSecret(t, app, jwt, "staging", "WANTED", "1")
	putSecret(t, app, jwt, "staging", "OTHER", "2")
	putSecret(t, app, jwt, "staging", "ALSO_NOT", "3")

	req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, map[string]any{
		"from": "staging",
		"to":   "production",
		"keys": []string{"WANTED"},
	})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body struct {
		Copied int `json:"copied"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, 1, body.Copied)

	// Verify DB: only WANTED is in production.
	rows, err := db.QueryContext(context.Background(), `
		SELECT key FROM vault_secrets
		WHERE team_id = $1::uuid AND env = 'production'
		ORDER BY key
	`, teamID)
	require.NoError(t, err)
	defer rows.Close()
	var got []string
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		got = append(got, k)
	}
	assert.Equal(t, []string{"WANTED"}, got, "only WANTED must be copied")
}

// TestVaultCopy_InvalidBody covers the 400 paths: missing 'to', same
// from/to, bogus env / key names.
func TestVaultCopy_InvalidBody(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()

	_, _, jwt := makeTeamUserTier(t, db, "pro")
	app := vaultTestApp(t, db)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing to", map[string]any{"from": "staging"}},
		{"missing from", map[string]any{"to": "production"}},
		{"from equals to", map[string]any{"from": "production", "to": "production"}},
		{"bogus env", map[string]any{"from": "staging", "to": "prod ;;DROP"}},
		{"bogus key", map[string]any{"from": "staging", "to": "production", "keys": []string{"bad key with spaces"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, tc.body)
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"%s must 400, got %d", tc.name, resp.StatusCode)
		})
	}
}
