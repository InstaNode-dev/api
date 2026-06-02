package handlers_test

// stack_env_persist_test.go — round-trip integration test for
// PATCH /stacks/:slug/env (B7-P0-1, 2026-05-20).
//
// Before this fix the handler logged stack.env.noted, returned 200, and
// dropped the body on the floor — the next redeploy rebuilt with stale
// env. The fix is migration 062 + stacks.env_vars JSONB + a real persist
// path. This test exercises:
//
//   * 401 unauthenticated (RequireAuth gate still works)
//   * 404 on a missing slug
//   * 200 happy path — body persisted, response carries the full merged set
//   * PATCH semantics — second call merges (does not replace), empty-string
//     value deletes a key
//   * 400 invalid_env_key — POSIX shape enforced at PATCH time
//   * 400 missing_env — empty body still rejected
//   * DB round-trip — direct SQL read of stacks.env_vars sees the change

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestStack_PatchEnv_PersistsAndReturns is the rule-17 round-trip guard for
// B7-P0-1. The handler must:
//   - return 200 with the full merged env in the response, AND
//   - have actually written that env to stacks.env_vars.
//
// Both halves matter — pre-fix the handler returned 200 but persisted
// nothing, which is exactly what this test would now fail on.
func TestStack_PatchEnv_PersistsAndReturns(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-patch-env", teamID, "patchenv@example.com")

	app := newStackTestApp(t, db)

	// Create a stack via /stacks/new so we have a real owned slug.
	tarball := createMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}
	createResp := postStackNew(t, app, sessionJWT, testManifestSingleService, tarballs)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusAccepted, createResp.StatusCode)

	var createBody struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	slug := createBody.StackID
	require.NotEmpty(t, slug)

	// Helper to PATCH /stacks/:slug/env.
	patchEnv := func(t *testing.T, env map[string]string, auth string) *http.Response {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"env": env})
		req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}

	// Helper to read stacks.env_vars directly out of the DB so the round-trip
	// half of the assertion lands on real persistence, not handler-level lying.
	readEnvFromDB := func(t *testing.T) map[string]string {
		t.Helper()
		var raw sql.NullString
		err := db.QueryRowContext(context.Background(),
			`SELECT env_vars::text FROM stacks WHERE slug = $1`, slug,
		).Scan(&raw)
		require.NoError(t, err, "direct stacks.env_vars read")
		if !raw.Valid || raw.String == "" {
			return map[string]string{}
		}
		out := map[string]string{}
		require.NoError(t, json.Unmarshal([]byte(raw.String), &out))
		return out
	}

	// 1) Unauthenticated → 401.
	t.Run("requires auth", func(t *testing.T) {
		resp := patchEnv(t, map[string]string{"DATABASE_URL": "postgres://x"}, "")
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// 2) Happy path — first PATCH writes two keys.
	t.Run("first patch persists", func(t *testing.T) {
		resp := patchEnv(t, map[string]string{
			"DATABASE_URL": "postgres://example",
			"NODE_ENV":     "production",
		}, sessionJWT)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body struct {
			OK  bool              `json:"ok"`
			Env map[string]string `json:"env"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.True(t, body.OK)
		// The RESPONSE redacts secret-bearing values (bug bash #1): DATABASE_URL
		// (key contains "URL") is masked to "***", while a non-secret key like
		// NODE_ENV passes through. The STORED value stays unredacted — asserted
		// against the DB below. This mirrors DeployHandler.UpdateEnv.
		assert.Equal(t, map[string]string{
			"DATABASE_URL": "***",
			"NODE_ENV":     "production",
		}, body.Env, "response masks secret values but keeps non-secret keys")

		// DB round-trip — pre-fix this would still be `{}` because the
		// handler dropped the payload. With migration 062 + UpdateStackEnvVars
		// it must reflect the keys we just set.
		got := readEnvFromDB(t)
		assert.Equal(t, "postgres://example", got["DATABASE_URL"], "DATABASE_URL persisted to stacks.env_vars")
		assert.Equal(t, "production", got["NODE_ENV"], "NODE_ENV persisted to stacks.env_vars")
	})

	// 3) PATCH semantics — second call adds a key + overwrites a key + the
	// previously-set key that we did NOT mention survives.
	t.Run("second patch merges", func(t *testing.T) {
		resp := patchEnv(t, map[string]string{
			"NODE_ENV": "staging",     // overwrite
			"FEATURE":  "experiment1", // new
		}, sessionJWT)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		got := readEnvFromDB(t)
		assert.Equal(t, "postgres://example", got["DATABASE_URL"], "unmentioned key survives")
		assert.Equal(t, "staging", got["NODE_ENV"], "value overwritten")
		assert.Equal(t, "experiment1", got["FEATURE"], "new key added")
		assert.Len(t, got, 3, "exactly three keys in env_vars")
	})

	// 4) Empty-string value deletes a key.
	t.Run("empty-string deletes", func(t *testing.T) {
		resp := patchEnv(t, map[string]string{
			"FEATURE": "", // delete
		}, sessionJWT)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		got := readEnvFromDB(t)
		_, hasFeature := got["FEATURE"]
		assert.False(t, hasFeature, "empty-string value should delete the key")
		assert.Equal(t, "postgres://example", got["DATABASE_URL"])
		assert.Equal(t, "staging", got["NODE_ENV"])
		assert.Len(t, got, 2, "two keys remain after the delete")
	})

	// 5) Invalid key shape → 400 invalid_env_key. The handler must reject
	// at PATCH time (mirrors deploy.go / stacks/new), not punt the failure
	// to the next async redeploy.
	t.Run("invalid_env_key rejected", func(t *testing.T) {
		resp := patchEnv(t, map[string]string{
			"db-url": "postgres://x", // lowercase + hyphen
		}, sessionJWT)
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var body struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.False(t, body.OK)
		assert.Equal(t, "invalid_env_key", body.Error)

		// DB state must be unchanged by the rejected request.
		got := readEnvFromDB(t)
		assert.Len(t, got, 2, "rejected patch must not touch env_vars")
	})

	// 6) Empty body still rejected with missing_env.
	t.Run("missing_env on empty body", func(t *testing.T) {
		resp := patchEnv(t, map[string]string{}, sessionJWT)
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var body struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.False(t, body.OK)
		assert.Equal(t, "missing_env", body.Error)
	})

	// 7) 404 for a slug that doesn't exist.
	t.Run("missing slug returns 404", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"env": map[string]string{"FOO": "BAR"}})
		req := httptest.NewRequest(http.MethodPatch, "/stacks/stk-does-not-exist/env", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sessionJWT)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}
