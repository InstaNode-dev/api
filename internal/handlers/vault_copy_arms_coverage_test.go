package handlers_test

// vault_copy_arms_coverage_test.go — covers the CopySecrets validation arms
// (invalid from/to env, same-env, invalid key in allowlist) the existing
// vault_copy_test.go (happy + dry-run + overwrite + skip) doesn't reach.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultCopy_ValidationArms(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)
	_, _, jwt := makeTeamUserTier(t, db, "pro")

	post := func(body any) *http.Response {
		req := jsonReq(t, http.MethodPost, "/api/v1/vault/copy", jwt, body)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}

	cases := []struct {
		name string
		body any
		code int
	}{
		{"missing_from", map[string]any{"to": "production"}, http.StatusBadRequest},
		{"missing_to", map[string]any{"from": "staging"}, http.StatusBadRequest},
		{"invalid_from_env", map[string]any{"from": "bad env!", "to": "production"}, http.StatusBadRequest},
		{"invalid_to_env", map[string]any{"from": "staging", "to": "bad env!"}, http.StatusBadRequest},
		{"same_env", map[string]any{"from": "production", "to": "production"}, http.StatusBadRequest},
		{"invalid_key_in_allowlist", map[string]any{"from": "staging", "to": "production", "keys": []string{"bad key!"}}, http.StatusBadRequest},
		{"invalid_body", "not-an-object", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(tc.body)
			assert.Equal(t, tc.code, resp.StatusCode)
			resp.Body.Close()
		})
	}
}
