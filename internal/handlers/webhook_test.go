package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
