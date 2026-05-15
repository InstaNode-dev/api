package handlers_test

// deploy_webhook_notify_handler_test.go — Black-box tests for the notify_webhook
// field on POST /deploy/new (migration 026).
//
// Four scenarios from the brief:
//   1. Valid https URL → 202, notify_state='pending'
//   2. Field absent → 202, notify_state='unset' (backward compat)
//   3. http:// (not https) → 400 + agent_action
//   4. Private IP literal → 400 + agent_action (SSRF gate)
//
// Plus one round-trip test that the secret is encrypted at rest (we read
// back from the DB directly and assert the stored ciphertext is not the
// plaintext we sent).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// stubPublicResolver swaps the package-level DNS resolver so the SSRF
// gate sees the supplied IPs for every hostname. Returns a restorer
// the caller defers. Used by every test in this file that needs a
// hostname (not an IP literal) to pass the gate without doing real DNS.
func stubPublicResolver(t *testing.T, ips ...string) func() {
	t.Helper()
	parsed := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		require.NotNil(t, ip, "stubPublicResolver: %q is not a valid IP literal", s)
		parsed = append(parsed, ip)
	}
	return handlers.SetNotifyWebhookResolverForTest(func(host string) ([]net.IP, error) {
		return parsed, nil
	})
}

// notifyDeployBody is a multipart builder with the notify_webhook fields. The
// tarball is a small fake — only the build path reads it, and we don't run
// against a real k8s here.
func notifyDeployBody(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball-bytes"))
	require.NoError(t, err)
	// `name` is now a STRICTLY REQUIRED field on /deploy/new (mandatory-
	// resource-naming contract, 2026-05-16). Inject a default when the
	// caller's fields map doesn't override it.
	if _, has := fields["name"]; !has {
		require.NoError(t, w.WriteField("name", "test deploy"))
	}
	for k, v := range fields {
		require.NoError(t, w.WriteField(k, v))
	}
	require.NoError(t, w.Close())
	return buf, w.FormDataContentType()
}

// TestDeployNew_NotifyWebhookValid_StoredPending guards scenario 1:
// a valid https URL must be persisted and notify_state must transition
// from the column default ('unset') to 'pending'.
//
// We assert against the DB row directly because the JSON response shape
// could swallow an extra field — the source of truth is the column.
func TestDeployNew_NotifyWebhookValid_StoredPending(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	defer stubPublicResolver(t, "8.8.8.8")()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "11111111-1111-1111-1111-111111111111", teamID, "notify@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := notifyDeployBody(t, map[string]string{
		"port":           "8080",
		"notify_webhook": "https://hooks.example.com/deploy",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.26.0.1")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"valid https notify_webhook must be accepted; body: %s", string(bodyBytes))

	// Decode the JSON response to grab the app_id, then verify the DB row
	// directly — the persisted state is the source of truth.
	var created struct {
		Item struct {
			AppID         string `json:"app_id"`
			NotifyWebhook string `json:"notify_webhook"`
			NotifyState   string `json:"notify_state"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &created))
	assert.Equal(t, "https://hooks.example.com/deploy", created.Item.NotifyWebhook,
		"response must echo back the supplied URL")
	assert.Equal(t, "pending", created.Item.NotifyState,
		"notify_state must be 'pending' once a URL is supplied — the worker scan keys on it")

	// Round-trip via the DB (the worker scan reads this column, not the JSON).
	var dbURL, dbState string
	var dbAttempts int
	err = db.QueryRowContext(context.Background(),
		`SELECT notify_webhook, notify_state, notify_attempts FROM deployments WHERE app_id = $1`,
		created.Item.AppID,
	).Scan(&dbURL, &dbState, &dbAttempts)
	require.NoError(t, err)
	assert.Equal(t, "https://hooks.example.com/deploy", dbURL)
	assert.Equal(t, "pending", dbState)
	assert.Equal(t, 0, dbAttempts, "fresh row must start at zero attempts")
}

// TestDeployNew_NotifyWebhookAbsent_StaysUnset guards scenario 2:
// the column default ('unset') is what existing callers see when they
// don't pass the field. This is the backward-compatibility test.
func TestDeployNew_NotifyWebhookAbsent_StaysUnset(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "22222222-2222-2222-2222-222222222222", teamID, "no-webhook@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := notifyDeployBody(t, map[string]string{"port": "8080"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.26.0.2")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"deploy without notify_webhook must still succeed; body: %s", string(bodyBytes))

	var created struct {
		Item struct {
			AppID         string `json:"app_id"`
			NotifyWebhook string `json:"notify_webhook"`
			NotifyState   string `json:"notify_state"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &created))
	assert.Empty(t, created.Item.NotifyWebhook,
		"notify_webhook must be empty when not supplied")
	assert.Equal(t, "unset", created.Item.NotifyState,
		"notify_state must stay at column default 'unset' when no webhook is supplied")

	var dbState string
	err = db.QueryRowContext(context.Background(),
		`SELECT notify_state FROM deployments WHERE app_id = $1`,
		created.Item.AppID,
	).Scan(&dbState)
	require.NoError(t, err)
	assert.Equal(t, "unset", dbState)
}

// TestDeployNew_NotifyWebhookHTTP_Rejects guards scenario 3: plain http
// is rejected with 400 + the agent_action so the worker never POSTs over
// cleartext.
func TestDeployNew_NotifyWebhookHTTP_Rejects(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	defer stubPublicResolver(t, "8.8.8.8")()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "33333333-3333-3333-3333-333333333333", teamID, "http@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := notifyDeployBody(t, map[string]string{
		"port":           "8080",
		"notify_webhook": "http://hooks.example.com/deploy",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.26.0.3")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"http:// notify_webhook must return 400")

	var errBody struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		Message     string `json:"message"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "invalid_notify_webhook", errBody.Error)
	assert.Contains(t, errBody.Message, "https",
		"message must name https so the agent knows the fix")
	assert.NotEmpty(t, errBody.AgentAction,
		"agent_action must be populated so the LLM has copy to relay")
	assert.Contains(t, errBody.AgentAction, "https://instanode.dev/",
		"agent_action must contain the docs URL")
}

// TestDeployNew_NotifyWebhookPrivateIP_Rejects guards scenario 4: a private
// IP literal in the URL is rejected as SSRF — this is the gate that stops
// an attacker from pointing the platform's egress at 169.254.169.254
// (cloud metadata) or 10.0.0.5 (internal services).
func TestDeployNew_NotifyWebhookPrivateIP_Rejects(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "44444444-4444-4444-4444-444444444444", teamID, "ssrf@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Each of these MUST be rejected — they are the classic SSRF targets.
	cases := []string{
		"https://127.0.0.1/webhook",   // loopback
		"https://10.0.0.5/webhook",    // RFC1918
		"https://192.168.1.1/webhook", // RFC1918
		"https://localhost/webhook",   // literal name shortcut
	}
	for i, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			body, ct := notifyDeployBody(t, map[string]string{
				"port":           "8080",
				"notify_webhook": raw,
			})
			req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
			req.Header.Set("Content-Type", ct)
			req.Header.Set("Authorization", "Bearer "+sessionJWT)
			// Unique source IP per case so the rate-limit fingerprint
			// doesn't lump all four into the same /24 bucket.
			req.Header.Set("X-Forwarded-For",
				"10.26.0."+string(rune('a'+i))) // placeholder; overwritten below

			resp, err := app.Test(req, 10000)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"SSRF-target %s must return 400", raw)

			var errBody struct {
				OK          bool   `json:"ok"`
				Error       string `json:"error"`
				AgentAction string `json:"agent_action"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
			assert.Equal(t, "invalid_notify_webhook", errBody.Error)
			assert.NotEmpty(t, errBody.AgentAction)
		})
	}
}

// TestDeployNew_NotifyWebhookSecret_EncryptedAtRest guards the AES
// requirement: the plaintext secret MUST NOT land in the deployments row.
// We sent a unique sentinel value; if it appears in the column we'd fail.
func TestDeployNew_NotifyWebhookSecret_EncryptedAtRest(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	defer stubPublicResolver(t, "8.8.8.8")()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "55555555-5555-5555-5555-555555555555", teamID, "secret@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	const plaintextSecret = "SENTINEL_PLAINTEXT_aabbccdd_DO_NOT_PERSIST"
	body, ct := notifyDeployBody(t, map[string]string{
		"port":                  "8080",
		"notify_webhook":        "https://hooks.example.com/deploy",
		"notify_webhook_secret": plaintextSecret,
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.26.0.5")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"valid deploy with secret must be accepted; body: %s", string(bodyBytes))

	var created struct {
		Item struct {
			AppID           string `json:"app_id"`
			NotifySecretSet bool   `json:"notify_secret_set"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &created))
	assert.True(t, created.Item.NotifySecretSet,
		"notify_secret_set must be true when a secret was supplied")

	var dbSecret string
	err = db.QueryRowContext(context.Background(),
		`SELECT notify_webhook_secret FROM deployments WHERE app_id = $1`,
		created.Item.AppID,
	).Scan(&dbSecret)
	require.NoError(t, err)
	assert.NotEmpty(t, dbSecret, "secret column must hold ciphertext, not be empty")
	assert.NotEqual(t, plaintextSecret, dbSecret,
		"plaintext secret MUST NOT appear in the column — that's the AES requirement")
	assert.NotContains(t, dbSecret, "SENTINEL_PLAINTEXT",
		"no sub-string of the plaintext can leak through into storage")

	// The JSON response also must not include the plaintext or the
	// ciphertext (only the boolean indicator).
	assert.NotContains(t, string(bodyBytes), plaintextSecret,
		"response body must not echo the plaintext secret")
}
