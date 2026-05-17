package handlers_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// webhookNewResponse mirrors the JSON body returned by POST /webhook/new.
type webhookNewResponse struct {
	OK         bool   `json:"ok"`
	ID         string `json:"id"`
	Token      string `json:"token"`
	ReceiveURL string `json:"receive_url"`
	Tier       string `json:"tier"`
	Limits     any    `json:"limits"`
	Note       string `json:"note"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// webhookReceiveResponse mirrors the JSON body returned by POST /webhook/receive/:token.
type webhookReceiveResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

// TestWebhookNew_ServiceDisabled_Returns503 verifies that POST /webhook/new returns 503
// when the webhook service is not listed in EnabledServices.
func TestWebhookNew_ServiceDisabled_Returns503(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Default test app has EnabledServices="redis" — webhook is not enabled.
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	req.Header.Set("X-Forwarded-For", "10.11.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestWebhookNew_Returns201WithRequiredFields verifies the happy path for POST /webhook/new.
func TestWebhookNew_Returns201WithRequiredFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	req.Header.Set("X-Forwarded-For", "10.11.0.2")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body webhookNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.True(t, body.OK)
	assert.NotEmpty(t, body.ID, "response must include resource id")
	assert.NotEmpty(t, body.Token, "response must include token")
	assert.NotEmpty(t, body.ReceiveURL, "response must include receive_url")
	assert.Equal(t, "anonymous", body.Tier, "unauthenticated request must get anonymous tier")
	assert.NotNil(t, body.Limits, "response must include limits")
	assert.NotEmpty(t, body.Note, "response must include note")
}

// TestWebhookNew_ReceiveURLContainsToken verifies that receive_url ends with the token.
func TestWebhookNew_ReceiveURLContainsToken(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	req.Header.Set("X-Forwarded-For", "10.11.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body webhookNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.True(t, strings.HasSuffix(body.ReceiveURL, body.Token),
		"receive_url must end with the token; got receive_url=%q token=%q", body.ReceiveURL, body.Token)
	assert.True(t, strings.HasPrefix(body.ReceiveURL, "http://") || strings.HasPrefix(body.ReceiveURL, "https://"),
		"receive_url must use http(s)://; got %q", body.ReceiveURL)
}

// TestWebhookNew_StoresResourceInDB verifies the webhook resource is written to the DB.
func TestWebhookNew_StoresResourceInDB(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	req.Header.Set("X-Forwarded-For", "10.11.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body webhookNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	var resourceType, tier string
	err = db.QueryRow(
		`SELECT resource_type, tier FROM resources WHERE token = $1::uuid`, body.Token,
	).Scan(&resourceType, &tier)
	require.NoError(t, err)
	assert.Equal(t, "webhook", resourceType, "resource_type must be 'webhook'")
	assert.Equal(t, "anonymous", tier, "anonymous provision must have tier='anonymous'")
}

// TestWebhookNew_XInstantUpgradeHeaderPresent verifies the upgrade CTA header is set.
func TestWebhookNew_XInstantUpgradeHeaderPresent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	req.Header.Set("X-Forwarded-For", "10.11.0.5")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.NotEmpty(t, resp.Header.Get("X-Instant-Upgrade"),
		"POST /webhook/new must include X-Instant-Upgrade header")
}

// TestWebhookNew_AnonymousHasExpiresAt verifies anonymous webhooks include expires_at.
func TestWebhookNew_AnonymousHasExpiresAt(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	req.Header.Set("X-Forwarded-For", "10.11.0.6")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body webhookNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.NotEmpty(t, body.ExpiresAt, "anonymous webhook must include expires_at")
}

// TestWebhookReceive_Returns200AndStoresRequest verifies POST /webhook/receive/:token
// accepts a payload and returns ok=true with a valid request ID.
func TestWebhookReceive_Returns200AndStoresRequest(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	// First provision a webhook.
	provReq := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	provReq.Header.Set("X-Forwarded-For", "10.11.0.7")
	provResp, err := app.Test(provReq, 5000)
	require.NoError(t, err)
	defer provResp.Body.Close()
	require.Equal(t, http.StatusCreated, provResp.StatusCode)

	var prov webhookNewResponse
	require.NoError(t, json.NewDecoder(provResp.Body).Decode(&prov))

	// Send a payload to the receive endpoint.
	payload := strings.NewReader(`{"event":"order.created","order_id":42}`)
	recvPath := "/webhook/receive/" + prov.Token
	recvReq := httptest.NewRequest(http.MethodPost, recvPath, payload)
	recvReq.Header.Set("Content-Type", "application/json")

	recvResp, err := app.Test(recvReq, 5000)
	require.NoError(t, err)
	defer recvResp.Body.Close()

	assert.Equal(t, http.StatusOK, recvResp.StatusCode)

	var recvBody webhookReceiveResponse
	require.NoError(t, json.NewDecoder(recvResp.Body).Decode(&recvBody))

	assert.True(t, recvBody.OK, "receive response must have ok=true")
	assert.NotEmpty(t, recvBody.ID, "receive response must include request id")
}

// TestWebhookReceive_WrongResourceType_Returns404 is P2 bug-hunt coverage
// (Fix #8, 2026-05-17 round 3). GetResourceByToken selects by token only —
// before the fix a postgres/redis/etc token would pass the webhook receive +
// list-requests handlers. Both must reject any non-webhook resource token
// with 404 (same as a genuinely missing token — never confirm the token
// belongs to a different resource type).
func TestWebhookReceive_WrongResourceType_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	// Create a POSTGRES resource directly — its token is a valid UUID but
	// the resource is not a webhook.
	pgRes, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
		ResourceType: models.ResourceTypePostgres,
		Name:         "wrong-type-pg",
		Tier:         "anonymous",
		Fingerprint:  "fp-wrong-type-" + uuid.NewString(),
	})
	require.NoError(t, err)
	token := pgRes.Token.String()

	// POST /webhook/receive/:token with a postgres token must 404.
	recvReq := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+token,
		strings.NewReader(`{"x":1}`))
	recvReq.Header.Set("Content-Type", "application/json")
	recvResp, err := app.Test(recvReq, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, recvResp.Body)
	recvResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, recvResp.StatusCode,
		"receive must reject a non-webhook token with 404")

	// GET /api/v1/webhooks/:token/requests with a postgres token must 404.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+token+"/requests", nil)
	listResp, err := app.Test(listReq, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, listResp.Body)
	listResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, listResp.StatusCode,
		"list-requests must reject a non-webhook token with 404")
}

// TestWebhookReceive_UnknownToken_Returns404 verifies that posting to an unknown token
// returns 404, not a 500.
func TestWebhookReceive_UnknownToken_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/00000000-0000-0000-0000-000000000099", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestWebhookReceive_InvalidToken_Returns400 verifies that a non-UUID token is rejected.
func TestWebhookReceive_InvalidToken_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/not-a-uuid", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Wave FIX-C: webhook receiver hardening ─────────────────────────────────
// Tests cover: header redaction (#119/#S7), query-string capture (#123/#Q33),
// all-method support (#Q29), HMAC verification (#122), ring-buffer rotation
// header (#Q34), idempotency-key replay (#Q28), 1 MiB body cap (#Q30).

// provisionWebhookForTest provisions a fresh anonymous webhook against the
// given test app and returns the parsed response. Centralises the
// "boilerplate to get a usable token" setup the receive-hardening tests
// all share.
func provisionWebhookForTest(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, sourceIP string) webhookNewResponse {
	t.Helper()
	provReq := httptest.NewRequest(http.MethodPost, "/webhook/new", nil)
	provReq.Header.Set("X-Forwarded-For", sourceIP)
	provResp, err := app.Test(provReq, 5000)
	require.NoError(t, err)
	defer provResp.Body.Close()
	require.Equal(t, http.StatusCreated, provResp.StatusCode)

	var prov webhookNewResponse
	require.NoError(t, json.NewDecoder(provResp.Body).Decode(&prov))
	return prov
}

// storedRequests reads the ring buffer for a webhook token directly from
// Redis (head-first: newest payload at index 0). Avoids needing the GET
// /api/v1/webhooks/:token/requests endpoint to be reachable from tests —
// that route is session-gated in the testhelpers wiring, which would
// force us to mint a JWT just to read back the obvious storage state.
func storedRequests(t *testing.T, rdb *redis.Client, token string) []map[string]any {
	t.Helper()
	raws, err := rdb.LRange(context.Background(), "wh:list:"+token, 0, -1).Result()
	require.NoError(t, err)
	out := make([]map[string]any, 0, len(raws))
	for _, raw := range raws {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &m))
		out = append(out, m)
	}
	return out
}

// firstStoredRequest is a small convenience over storedRequests for the
// "I just need the latest payload" case. Fails the test if the buffer is
// empty.
func firstStoredRequest(t *testing.T, rdb *redis.Client, token string) map[string]any {
	t.Helper()
	items := storedRequests(t, rdb, token)
	require.NotEmpty(t, items, "expected at least one stored webhook request for token %s", token)
	return items[0]
}

// TestWebhookReceiver_RedactsSensitiveHeaders verifies that auth / cookie /
// API key headers are stored as [REDACTED] (BugBash #119 / #S7). The key
// stays so an agent debugging "did my sender attach Authorization?" can
// see the answer, but the secret never reaches Redis or the GET endpoint.
func TestWebhookReceiver_RedactsSensitiveHeaders(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.1")

	recvReq := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token,
		strings.NewReader(`{"e":"order.created"}`))
	recvReq.Header.Set("Content-Type", "application/json")
	recvReq.Header.Set("Authorization", "Bearer s3cret-jwt-9f8a")
	recvReq.Header.Set("Cookie", "sess=abc; admin=true")
	recvReq.Header.Set("X-Api-Key", "sk_live_super_secret_42")
	recvReq.Header.Set("X-Auth-Token", "tok_dont_log_me")
	recvReq.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	recvReq.Header.Set("X-Custom-Header", "safe-value-keep-me")

	recvResp, err := app.Test(recvReq, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, recvResp.Body)
	recvResp.Body.Close()
	require.Equal(t, http.StatusOK, recvResp.StatusCode)

	stored := firstStoredRequest(t, rdb, prov.Token)
	headers, ok := stored["headers"].(map[string]any)
	require.True(t, ok, "stored payload must have headers map")

	// Assert every sensitive header value is REDACTED but the key
	// itself is present. Values arrive as []any because the receive
	// handler captures duplicates as a slice.
	for _, key := range []string{"Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "Proxy-Authorization"} {
		vals, present := headers[key].([]any)
		require.Truef(t, present, "expected header %q to be present (key kept, value redacted) — got %#v", key, headers[key])
		require.NotEmptyf(t, vals, "expected header %q to have at least one captured value", key)
		for _, v := range vals {
			assert.Equalf(t, "[REDACTED]", v, "header %q must be redacted; got %v", key, v)
		}
	}
	// Non-sensitive header keeps its real value.
	custom, ok := headers["X-Custom-Header"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, custom)
	assert.Equal(t, "safe-value-keep-me", custom[0])

	// And no raw secret ends up anywhere in the stored payload (defence in depth).
	raw, _ := json.Marshal(stored)
	rawStr := string(raw)
	for _, secret := range []string{"s3cret-jwt-9f8a", "sk_live_super_secret_42", "tok_dont_log_me", "sess=abc"} {
		assert.NotContainsf(t, rawStr, secret, "raw secret %q must not appear in stored payload", secret)
	}
}

// TestWebhookReceiver_PreservesQueryString verifies that everything after
// '?' in the receive URL ends up in the captured payload (BugBash #123 / #Q33).
// Senders often encode the shop / event id in the query string; dropping it
// silently is data loss.
func TestWebhookReceiver_PreservesQueryString(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.2")

	recvReq := httptest.NewRequest(http.MethodPost,
		"/webhook/receive/"+prov.Token+"?shop=42&event=order.created&utm_source=stripe",
		strings.NewReader(`{}`))
	recvResp, err := app.Test(recvReq, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, recvResp.Body)
	recvResp.Body.Close()
	require.Equal(t, http.StatusOK, recvResp.StatusCode)

	stored := firstStoredRequest(t, rdb, prov.Token)
	q, ok := stored["query"].(string)
	require.True(t, ok, "stored payload must include 'query' field")
	assert.Equal(t, "shop=42&event=order.created&utm_source=stripe", q)
}

// TestWebhookReceiver_AllMethods verifies GET / POST / PUT / DELETE all
// reach the handler (BugBash #Q29). Slack URL verification uses GET,
// Twilio occasionally uses other methods — a 405 here blocks production
// integration.
func TestWebhookReceiver_AllMethods(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.3")

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			var body io.Reader
			if method != http.MethodGet && method != http.MethodDelete {
				body = strings.NewReader(`{"m":"` + method + `"}`)
			}
			req := httptest.NewRequest(method, "/webhook/receive/"+prov.Token, body)
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"method %s must reach the handler (no 405)", method)
		})
	}

	// Verify the stored ring buffer contains all four methods.
	items := storedRequests(t, rdb, prov.Token)
	require.Len(t, items, 4)
	gotMethods := make(map[string]bool, 4)
	for _, r := range items {
		gotMethods[r["method"].(string)] = true
	}
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		assert.Truef(t, gotMethods[m], "method %q must appear in stored ring buffer", m)
	}
}

// withHMACSecret sets the HMAC secret on a webhook token by looking up its
// resource id in the test DB and writing the column directly via the model
// helper. Avoids needing a public PATCH endpoint just for the test.
func withHMACSecret(t *testing.T, db *sql.DB, token, secret string) {
	t.Helper()
	tokUUID, err := uuid.Parse(token)
	require.NoError(t, err)
	var id uuid.UUID
	require.NoError(t, db.QueryRow(`SELECT id FROM resources WHERE token = $1`, tokUUID).Scan(&id))
	require.NoError(t, models.SetWebhookHMACSecret(context.Background(), db, id, secret))
}

// signHMAC returns the GitHub-style sha256=<hex> signature header value
// for a given secret + body. Mirrors the verifyWebhookHMAC implementation
// in webhook.go; an integration sender would compute this exactly the same
// way.
func signHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// TestWebhookReceiver_HMACVerifyHappy verifies that a request carrying a
// correct X-Hub-Signature-256 header is accepted when hmac_secret is set
// (BugBash #122).
func TestWebhookReceiver_HMACVerifyHappy(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.4")
	withHMACSecret(t, db, prov.Token, "shhh-very-secret")

	body := []byte(`{"event":"signed"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", signHMAC("shhh-very-secret", body))

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"correctly-signed request must reach the handler")
}

// TestWebhookReceiver_HMACVerifyMismatch verifies that a signed request
// whose HMAC does not match the configured secret is rejected with 401.
// Covers both "wrong digest" and "missing header" cases.
func TestWebhookReceiver_HMACVerifyMismatch(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.5")
	withHMACSecret(t, db, prov.Token, "the-real-secret")

	body := []byte(`{"event":"forged"}`)

	t.Run("wrong digest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Hub-Signature-256", signHMAC("a-DIFFERENT-secret", body))
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("missing signature header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No X-Hub-Signature-256 header set.
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestWebhookReceiver_HMACUnsetAllowsAll verifies that webhooks WITHOUT an
// hmac_secret set continue to accept unsigned traffic (back-compat — every
// existing token must keep working without re-provisioning).
func TestWebhookReceiver_HMACUnsetAllowsAll(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.6")
	// Deliberately do NOT call withHMACSecret.

	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token,
		strings.NewReader(`{"unsigned":"ok"}`))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"webhook without hmac_secret must accept unsigned traffic")
}

// TestWebhookReceiver_RotationHeader verifies that when the ring buffer is
// already full and a new payload evicts the oldest, the response carries
// the X-Webhook-Rotated header (BugBash #Q34). Real webhook senders ignore
// extra response headers, but a human/agent watching the receiver can see
// rotation explicitly instead of silently losing payloads.
//
// Anonymous tier cap is 100 from plans.yaml; sending 101 payloads should
// trigger rotation on the 101st.
func TestWebhookReceiver_RotationHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("rotation test sends 101 requests; skipping in -short mode")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.7")

	// Fill to the anonymous cap (100). The 100th send is still inside cap
	// and must NOT carry the rotation header.
	const cap = 100
	for i := 0; i < cap; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token,
			strings.NewReader(fmt.Sprintf(`{"i":%d}`, i)))
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("X-Webhook-Rotated"),
			"send #%d (within cap) must not advertise rotation", i+1)
	}

	// 101st send pushes one off the tail; rotation header must fire.
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token,
		strings.NewReader(`{"i":100}`))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, prov.Token, resp.Header.Get("X-Webhook-Rotated"),
		"send #101 must set X-Webhook-Rotated to the token")
}

// TestWebhookReceiver_IdempotencyKey verifies that two POSTs with the same
// X-Idempotency-Key return identical request ids and only one entry is
// added to the ring buffer (BugBash #Q28).
func TestWebhookReceiver_IdempotencyKey(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.8")

	postWithKey := func(t *testing.T, key, body string) webhookReceiveResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token,
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Idempotency-Key", key)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var out webhookReceiveResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		return out
	}

	first := postWithKey(t, "idem-aaa-111", `{"order":1}`)
	second := postWithKey(t, "idem-aaa-111", `{"order":1}`)
	assert.Equal(t, first.ID, second.ID,
		"duplicate idempotency key must replay the original response id")

	// A different idempotency key must produce a fresh id.
	third := postWithKey(t, "idem-bbb-222", `{"order":2}`)
	assert.NotEqual(t, first.ID, third.ID,
		"different idempotency key must produce a new id")

	// Ring buffer should hold exactly 2 entries — the first and the third.
	items := storedRequests(t, rdb, prov.Token)
	assert.Len(t, items, 2,
		"idempotent replays must not double-write to the ring buffer")
}

// TestWebhookReceiver_PayloadTooLarge verifies that a body exceeding the
// explicit 1 MiB cap returns 413 instead of being silently truncated
// (BugBash #Q30: reconcile ingress vs Fiber vs docs).
func TestWebhookReceiver_PayloadTooLarge(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	prov := provisionWebhookForTest(t, app, "10.11.99.9")

	// 1 MiB + 1 byte — one over the cap.
	oversized := bytes.Repeat([]byte("x"), (1<<20)+1)
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+prov.Token,
		bytes.NewReader(oversized))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.False(t, body.OK)
	assert.Equal(t, "payload_too_large", body.Error)
}
