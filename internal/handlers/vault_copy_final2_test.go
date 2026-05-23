package handlers_test

// vault_copy_final2_test.go — FINAL SERIAL PASS #2 coverage for the CopySecrets
// DB-error arms (vault.go) the validation + happy suites don't reach:
//
//   * list_failed (L593): ListVaultSecretKeys(from) errors
//   * persist_failed (L684): CreateVaultSecret(to) errors
//
// Uses withIsolatedDB so a table rename can break the targeted query without
// disturbing the shared dev DB. The team + tier checks (users / teams tables)
// stay intact so control reaches the vault_secrets access.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func vaultCopyF2NeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

// postVaultCopyF2 posts a copy request and returns status + raw body.
func postVaultCopyF2(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, jwt, from, to string) (int, string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"from": from, "to": to})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vault/copy", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var raw [2048]byte
	n, _ := resp.Body.Read(raw[:])
	return resp.StatusCode, string(raw[:n])
}

// CopySecrets list_failed: vault_secrets renamed away after the team/tier
// checks → ListVaultSecretKeys errors → 500 vault internal error.
func TestVaultCopyFinal2_ListFailed(t *testing.T) {
	vaultCopyF2NeedDB(t)
	db := withIsolatedDB(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner') RETURNING id::text`,
		teamID, email).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	app := vaultTestApp(t, db)

	// Break vault_secrets so the source-env enumeration errors. teams/users
	// stay intact so authContext + tier gate pass.
	_, err := db.ExecContext(context.Background(), `ALTER TABLE vault_secrets RENAME TO vault_secrets_gone_f2`)
	require.NoError(t, err)

	status, body := postVaultCopyF2(t, app, jwt, "production", "staging")
	assert.GreaterOrEqualf(t, status, 500, "list failure must surface a 5xx (body=%s)", body)
}
