package handlers_test

// body_validation_test.go — Wave FIX-D regression tests (#125 / #S18 / #Q67 /
// #Q70 / #Q71 / #Q15).
//
// Before this wave every provisioning handler did
//
//	_ = c.BodyParser(&body)
//
// which silently ate parse errors. BOM-prefixed JSON, comments, trailing
// commas, and wrong-type fields all yielded 201 with empty body fields. The
// fix wraps body parsing in parseProvisionBody, which returns a structured
// 400 invalid_body response. These tests lock that behaviour in across every
// affected endpoint.
//
// Coverage:
//   - POST /db/new       (#125)
//   - POST /cache/new    (#125)
//   - POST /nosql/new    (#125)
//   - POST /queue/new    (#125)
//   - POST /storage/new  (#125)
//   - POST /webhook/new  (#125)
//   - POST /vector/new   (#125)
//   - POST /auth/cli     (#125)
//   - sanitizeName UTF-8 rejection            (#Q70)
//   - sanitizeName control-char strip         (#Q71)
//   - resolveEnv override-reason signal       (#Q15)

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// bomJSON is `\xef\xbb\xbf{}` — a valid JSON object preceded by the UTF-8
// byte-order mark. encoding/json rejects this. Before Wave FIX-D the four
// /{service}/new handlers swallowed the rejection silently.
const bomJSON = "\xef\xbb\xbf{}"

// errorEnvelope is the canonical { ok, error, message } shape every
// respondError emits. Same shape used by the existing agent_action_test.go.
type errorEnvelope struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error"`
	Message     string `json:"message"`
	AgentAction string `json:"agent_action"`
}

// provisioningEndpoint enumerates the seven /{service}/new endpoints that
// participate in this wave. Each row also names the enabled-services CSV the
// test app needs and a unique source IP so fingerprint dedup never crosses
// table-driven cases.
type provisioningEndpoint struct {
	name   string
	path   string
	enable string
	ip     string
}

var provisioningEndpoints = []provisioningEndpoint{
	{"db", "/db/new", "postgres,redis,mongodb,queue,webhook,storage,vector", "10.99.1.1"},
	{"cache", "/cache/new", "postgres,redis,mongodb,queue,webhook,storage,vector", "10.99.2.1"},
	{"nosql", "/nosql/new", "postgres,redis,mongodb,queue,webhook,storage,vector", "10.99.3.1"},
	{"queue", "/queue/new", "postgres,redis,mongodb,queue,webhook,storage,vector", "10.99.4.1"},
	// storage skipped from BOM/wrong-type tests: the handler returns
	// 503 service_disabled when storageProvider is nil (test env has no
	// MinIO), short-circuiting BEFORE body parsing fires. The
	// empty-body / empty-{} tolerance tests still cover storage via
	// their NotEqual(400) assertion. Re-add to BOM coverage once
	// storage gets an in-test stub provider.
	{"webhook", "/webhook/new", "postgres,redis,mongodb,queue,webhook,storage,vector", "10.99.6.1"},
	{"vector", "/vector/new", "postgres,redis,mongodb,queue,webhook,storage,vector", "10.99.7.1"},
}

// allProvisioningEndpoints includes storage — used only by the empty-body
// tolerance tests which accept any non-400 status (so the 503 for storage
// is fine).
var allProvisioningEndpoints = append([]provisioningEndpoint{
	{"storage", "/storage/new", "postgres,redis,mongodb,queue,webhook,storage,vector", "10.99.5.1"},
}, provisioningEndpoints...)

// TestProvisioningBodyValidation_BOMJSON_Rejected covers Wave FIX-D #125 /
// #S18. A BOM-prefixed body is malformed JSON; every provisioning handler
// must now surface that as 400 invalid_body instead of silently treating
// it as an empty body and 201-provisioning a nameless resource.
func TestProvisioningBodyValidation_BOMJSON_Rejected(t *testing.T) {
	for _, ep := range provisioningEndpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			rdb, cleanRedis := testhelpers.SetupTestRedis(t)
			defer cleanRedis()

			app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ep.enable)
			defer cleanApp()

			req := httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(bomJSON))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", ep.ip)

			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"%s must reject BOM-prefixed body with 400 (was 201 before Wave FIX-D)", ep.path)

			var env errorEnvelope
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
			assert.False(t, env.OK)
			assert.Equal(t, "invalid_body", env.Error,
				"%s 400 envelope must carry stable code 'invalid_body'", ep.path)
		})
	}
}

// TestProvisioningBodyValidation_WrongTypeField_Rejected covers Wave FIX-D
// #Q67. `{"name": 12345}` is structurally valid JSON but `name` is the
// wrong type. Before this wave Fiber's BodyParser silently coerced it to
// "" and returned 201 with an empty name; now it must 400 invalid_body.
func TestProvisioningBodyValidation_WrongTypeField_Rejected(t *testing.T) {
	// Body with a numeric `name` — JSON-parses but cannot decode into the
	// `Name string` field of provisionRequestBody.
	wrongType := `{"name": 12345}`

	for _, ep := range provisioningEndpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			rdb, cleanRedis := testhelpers.SetupTestRedis(t)
			defer cleanRedis()

			app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ep.enable)
			defer cleanApp()

			req := httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(wrongType))
			req.Header.Set("Content-Type", "application/json")
			// Distinct IP to avoid colliding with the BOM test on the same fp.
			req.Header.Set("X-Forwarded-For", strings.Replace(ep.ip, "10.99.", "10.98.", 1))

			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"%s must reject wrong-type body field with 400 (was 201 + empty name before Wave FIX-D)", ep.path)

			var env errorEnvelope
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
			assert.False(t, env.OK)
			assert.Equal(t, "invalid_body", env.Error)
		})
	}
}

// TestProvisioningBodyValidation_EmptyBody_StillWorks pins the documented
// behaviour: a POST with no body (Content-Length 0) is fine — the body is
// optional. Wave FIX-D only rejects MALFORMED bodies; an absent body keeps
// the wedge intact.
//
// Endpoints that need real downstream infra (NATS for queue, MongoDB user
// admin for nosql, MinIO/S3 for storage, pgvector for vector) return 503
// in the test environment because the provider backends aren't wired.
// That 503 is fine for our purpose — what we're proving here is that the
// EMPTY body itself does NOT fail with 400 invalid_body. We accept any
// non-400 status as proof body parsing didn't fire on an empty body.
func TestProvisioningBodyValidation_EmptyBody_StillWorks(t *testing.T) {
	for _, ep := range allProvisioningEndpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			rdb, cleanRedis := testhelpers.SetupTestRedis(t)
			defer cleanRedis()

			app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ep.enable)
			defer cleanApp()

			req := httptest.NewRequest(http.MethodPost, ep.path, nil)
			req.Header.Set("X-Forwarded-For", strings.Replace(ep.ip, "10.99.", "10.97.", 1))

			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			assert.NotEqual(t, http.StatusBadRequest, resp.StatusCode,
				"%s must NOT 400 on empty body (the wedge: no body is fine)", ep.path)
		})
	}
}

// TestProvisioningBodyValidation_EmptyJSONObject_StillWorks pins the other
// documented happy path: `{}` is valid JSON and must not change behaviour
// vs no body at all. Same 503-tolerance as TestProvisioningBodyValidation_EmptyBody.
func TestProvisioningBodyValidation_EmptyJSONObject_StillWorks(t *testing.T) {
	for _, ep := range allProvisioningEndpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			rdb, cleanRedis := testhelpers.SetupTestRedis(t)
			defer cleanRedis()

			app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ep.enable)
			defer cleanApp()

			req := httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", strings.Replace(ep.ip, "10.99.", "10.96.", 1))

			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			assert.NotEqual(t, http.StatusBadRequest, resp.StatusCode,
				"%s must NOT 400 on empty JSON object {}", ep.path)
		})
	}
}

// TestCLIAuth_BOMJSON_Rejected covers the cli_auth.go arm of #125. The
// session-create endpoint accepts an optional body but, like the
// provisioning handlers, must surface a malformed body as 400 rather than
// silently dropping the anon_tokens field.
func TestCLIAuth_BOMJSON_Rejected(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/auth/cli", strings.NewReader(bomJSON))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"/auth/cli must reject BOM-prefixed body with 400")

	var env errorEnvelope
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.False(t, env.OK)
	assert.Equal(t, "invalid_body", env.Error)
}

// TestProvisioning_NoEnv_SurfacesOverrideReason covers Wave FIX-D #Q15.
// When the caller sends no env (neither query nor body), the API defaults
// to "development" per migration 026. The response now carries
// env_override_reason="default_no_env_specified" so the agent can tell
// the difference between "I asked for dev" and "I sent nothing and got
// dev." When the caller IS explicit, the field is absent.
func TestProvisioning_NoEnv_SurfacesOverrideReason(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanApp()

	// Case 1: no env supplied — override reason MUST be set.
	t.Run("no_env_signals_override", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
		req.Header.Set("X-Forwarded-For", "10.95.1.1")

		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "development", body["env"], "default env is development")
		assert.Equal(t, "default_no_env_specified", body["env_override_reason"],
			"no-env response must carry override reason for the agent")
	})

	// Case 2: explicit env — override reason MUST be absent.
	t.Run("explicit_env_no_override_field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/cache/new",
			strings.NewReader(`{"env":"production"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "10.95.2.1")

		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "production", body["env"])
		_, hasOverride := body["env_override_reason"]
		assert.False(t, hasOverride,
			"explicit env response must NOT include env_override_reason")
	})
}

// TestProvisioning_InvalidUTF8Name_Rejected covers Wave FIX-D #Q70. A name
// containing invalid UTF-8 bytes (which Go's JSON decoder would silently
// rewrite as U+FFFD before this wave) must now be rejected with 400
// invalid_name. The body itself is valid JSON — only the embedded string
// is malformed UTF-8.
func TestProvisioning_InvalidUTF8Name_Rejected(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanApp()

	// Manually construct a JSON body whose string contains a raw 0xff byte.
	// We hand-build the bytes so json.Marshal doesn't rewrite them on the
	// way in — the goal is precisely to exercise the U+FFFD-replacement
	// path that Go's decoder produces for invalid UTF-8 strings.
	rawBody := []byte(`{"name":"hi`)
	rawBody = append(rawBody, 0xff, 0xfe)
	rawBody = append(rawBody, []byte(`"}`)...)

	req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(string(rawBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.94.1.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Either the body parser rejects the malformed JSON with 400 invalid_body
	// (Fiber's parser may surface invalid-UTF-8 strings as parse errors), or
	// our explicit sanitizeName UTF-8 check fires with 400 invalid_name. Both
	// are acceptable — both are 400, both name a stable error code. The
	// regression we're blocking is "201 with a name field full of U+FFFD".
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"invalid-UTF-8 name must be rejected (was 201 with U+FFFD before Wave FIX-D)")

	var env errorEnvelope
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.False(t, env.OK)
	assert.Contains(t, []string{"invalid_body", "invalid_name"}, env.Error,
		"400 envelope must carry a stable error code")
}

// TestProvisioning_ControlCharsInName_Stripped covers Wave FIX-D #Q71.
// CRLF in a name silently passed through before and corrupted audit log
// summaries. Stripped (not rejected) so a stray \r from a paste doesn't
// 400 the caller — but it must NOT make it into the persisted name.
func TestProvisioning_ControlCharsInName_Stripped(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanApp()

	// `users\r\ndb` should become `usersdb` (CRLF stripped).
	body := `{"name":"users\r\ndb"}`
	req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.93.1.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.Equal(t, "usersdb", result.Name,
		"CRLF in name must be silently stripped (Wave FIX-D #Q71)")
	assert.NotContains(t, result.Name, "\r",
		"response name must not contain CR")
	assert.NotContains(t, result.Name, "\n",
		"response name must not contain LF")
}

// provisioningJSONEndpoints is the set of JSON provisioning endpoints where
// `name` is a STRICTLY REQUIRED field (mandatory-resource-naming contract,
// 2026-05-16). The mandatory-name tests below iterate this list so a future
// JSON provisioning endpoint can't silently skip the contract.
//
// /storage/new is intentionally omitted: the storage handler returns 503
// service_disabled when storageProvider is nil (test env has no MinIO),
// short-circuiting BEFORE the name gate fires — the same reason
// provisioningEndpoints excludes it from the BOM/wrong-type tests above.
var provisioningJSONEndpoints = []string{
	"/db/new", "/cache/new", "/nosql/new",
	"/queue/new", "/webhook/new",
}

// TestProvisioning_NameRequired_MissingOrEmpty_Returns400 verifies that every
// JSON provisioning endpoint rejects a request whose `name` is missing or
// empty-after-trim with 400 name_required. This is a BREAKING contract change:
// before 2026-05-16 a name-less POST returned 201 and the dashboard showed a
// raw hash like `db_fcb890cde09d`.
func TestProvisioning_NameRequired_MissingOrEmpty_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanApp()

	// Each case carries an explicit `name` key so the testhelpers
	// inject-default-name middleware leaves it untouched.
	cases := map[string]string{
		"missing":         `{"env":"development"}`,
		"empty_string":    `{"name":""}`,
		"whitespace_only": `{"name":"   "}`,
	}
	octet := 10
	for _, path := range provisioningJSONEndpoints {
		for label, jsonBody := range cases {
			octet++
			t.Run(strings.TrimPrefix(path, "/")+"_"+label, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(jsonBody))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.96.%d.1", octet))
				// Opt out of the testhelpers default-name injection so the
				// name-less body reaches the handler verbatim.
				req.Header.Set(testhelpers.NoNameDefaultHeader, "1")

				resp, err := app.Test(req, 5000)
				require.NoError(t, err)
				defer resp.Body.Close()

				require.Equal(t, http.StatusBadRequest, resp.StatusCode,
					"%s with %s name must be 400", path, label)

				var env errorEnvelope
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
				assert.False(t, env.OK)
				assert.Equal(t, "name_required", env.Error,
					"%s must return error code name_required", path)
			})
		}
	}
}

// TestProvisioning_InvalidName_BadFormat_Returns400 verifies that a `name`
// which is present but fails the length / character contract is rejected
// with 400 invalid_name.
func TestProvisioning_InvalidName_BadFormat_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanApp()

	// 65-char name (one over the 64-char cap).
	tooLong := strings.Repeat("a", 65)
	cases := map[string]string{
		"leading_symbol": `{"name":"-bad-start"}`,
		"illegal_char":   `{"name":"bad@name"}`,
		"too_long":       `{"name":"` + tooLong + `"}`,
	}
	octet := 50
	for label, jsonBody := range cases {
		octet++
		t.Run(label, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.97.%d.1", octet))

			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"name %q must be rejected", label)

			var env errorEnvelope
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
			assert.False(t, env.OK)
			assert.Equal(t, "invalid_name", env.Error,
				"bad-format name must return error code invalid_name")
			assert.NotEmpty(t, env.AgentAction,
				"invalid_name envelope must carry an agent_action")
		})
	}
}

// TestProvisioning_ValidName_TrimmedAndAccepted verifies that a valid name
// with surrounding whitespace is trimmed and the resource provisions 201.
func TestProvisioning_ValidName_TrimmedAndAccepted(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,vector")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/cache/new",
		strings.NewReader(`{"name":"  My App Cache  "}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.98.1.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, "My App Cache", result.Name,
		"surrounding whitespace must be trimmed before persistence")
}
