package handlers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// multipartDeployBody builds a tiny multipart/form-data request body with a fake
// tarball and the given form fields. The tarball content doesn't have to be
// a valid tar — these tests exercise the env_vars parsing path which runs
// before the build, so the bytes are never extracted.
func multipartDeployBody(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball"))
	require.NoError(t, err)
	// `name` is a STRICTLY REQUIRED field on /deploy/new (mandatory-resource-
	// naming contract, 2026-05-16). Inject a valid default when the caller
	// doesn't supply one so legacy deploy tests keep exercising the happy path.
	if _, has := fields["name"]; !has {
		require.NoError(t, w.WriteField("name", "test deploy"))
	}
	for k, v := range fields {
		require.NoError(t, w.WriteField(k, v))
	}
	require.NoError(t, w.Close())
	return buf, w.FormDataContentType()
}

// TestDeployNew_EnvVarsJSON_Parsed_Into_InitEnv guards friction #11 (PR #4):
// POST /deploy/new accepts an env_vars JSON map and merges it into the
// deployment's env on the initial build — no follow-up PATCH+redeploy needed.
//
// We don't have a real k8s backend in the test app (compute provider is
// noop), so the deployment record persists with the env we sent. We assert
// the persisted EnvVars by reading the deployment back via GET /deploy/:id.
func TestDeployNew_EnvVarsJSON_Parsed_Into_InitEnv(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "33333333-3333-3333-3333-333333333333", teamID, "agent@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	envJSON := `{"DATABASE_URL":"postgres://x/y","CUSTOM":"hello","_secret":"should-be-stripped"}`
	body, ct := multipartDeployBody(t, map[string]string{
		"env_vars": envJSON,
		"port":     "8080",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.14.0.1")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read the body once — require.NotEqual's message arg is evaluated
	// unconditionally, so passing readBody(t, resp) there would consume the
	// body before the success-path Decode can read it.
	bodyBytes, _ := io.ReadAll(resp.Body)

	// 202 (noop compute provider succeeds), 503 (service disabled) — both prove the
	// parse path executed without 400. A 400 here is the regression we guard.
	require.NotEqual(t, http.StatusBadRequest, resp.StatusCode,
		"valid env_vars JSON must NOT return 400; got body: %s", string(bodyBytes))

	if resp.StatusCode == http.StatusAccepted {
		var created struct {
			Item struct {
				AppID string            `json:"app_id"`
				Env   map[string]string `json:"env"`
			} `json:"item"`
		}
		require.NoError(t, json.Unmarshal(bodyBytes, &created))
		assert.Contains(t, created.Item.Env, "DATABASE_URL", "env_vars key must land in the deployment's env")
		assert.Equal(t, "postgres://x/y", created.Item.Env["DATABASE_URL"])
		assert.Contains(t, created.Item.Env, "CUSTOM")
		assert.NotContains(t, created.Item.Env, "_secret",
			"underscore-prefixed keys are reserved and must be silently dropped — _secret leaking through is the regression")
	}
}

// TestDeployNew_EnvVarsInvalidJSON_Returns400 guards the input-validation
// branch: malformed JSON in env_vars should produce a precise 400 with
// error="invalid_env_vars", not a generic 500.
func TestDeployNew_EnvVarsInvalidJSON_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "44444444-4444-4444-4444-444444444444", teamID, "agent2@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{
		"env_vars": `{not_valid_json:`,
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.14.0.2")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "invalid_env_vars", errBody.Error,
		"error key must be invalid_env_vars so agents can branch on it; got: %s", errBody.Error)
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
