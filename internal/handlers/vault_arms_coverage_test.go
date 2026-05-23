package handlers_test

// vault_arms_coverage_test.go — covers the GetSecret version arms, ListKeys,
// DeleteSecret arms, and the env/key/version validation branches of the vault
// handler (vault.go) that the existing vault_test.go integration suite leaves
// partially covered. DB-only; uses the existing vaultTestApp + makeTeamUser
// helpers from vault_test.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVault_GetSecret_VersionArms(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)
	_, _, jwt := makeTeamUser(t, db)

	// Put a secret twice → two versions.
	put := func(val string) {
		req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/API_KEY", jwt, map[string]string{"value": val})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, resp.StatusCode)
		resp.Body.Close()
	}
	put("v1")
	put("v2")

	t.Run("latest", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/API_KEY", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("specific_version", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/API_KEY?version=1", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("bad_version", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/API_KEY?version=abc", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("zero_version", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/API_KEY?version=0", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("not_found", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production/NO_SUCH_KEY", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("invalid_env", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/bad%20env/KEY", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestVault_ListKeys_Arms(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)
	_, _, jwt := makeTeamUser(t, db)

	// Seed two keys.
	for _, k := range []string{"A", "B"} {
		req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/"+k, jwt, map[string]string{"value": "x"})
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, resp.StatusCode)
		resp.Body.Close()
	}

	t.Run("list_ok", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/production", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("list_invalid_env", func(t *testing.T) {
		req := jsonReq(t, http.MethodGet, "/api/v1/vault/bad%20env", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("list_unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/vault/production", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestVault_DeleteSecret_Arms(t *testing.T) {
	db, clean := vaultIntegrationDB(t)
	defer clean()
	app := vaultTestApp(t, db)
	_, _, jwt := makeTeamUser(t, db)

	// Seed a key to delete.
	req := jsonReq(t, http.MethodPut, "/api/v1/vault/production/DELME", jwt, map[string]string{"value": "v"})
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, resp.StatusCode)
	resp.Body.Close()

	t.Run("delete_ok", func(t *testing.T) {
		req := jsonReq(t, http.MethodDelete, "/api/v1/vault/production/DELME", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("delete_not_found", func(t *testing.T) {
		req := jsonReq(t, http.MethodDelete, "/api/v1/vault/production/NEVER_EXISTED", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("delete_invalid_key", func(t *testing.T) {
		req := jsonReq(t, http.MethodDelete, "/api/v1/vault/production/bad%20key", jwt, nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
}
