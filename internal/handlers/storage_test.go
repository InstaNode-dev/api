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

// storageNewResponse mirrors the JSON body returned by POST /storage/new.
type storageNewResponse struct {
	OK              bool   `json:"ok"`
	ID              string `json:"id"`
	Token           string `json:"token"`
	Name            string `json:"name"`
	ConnectionURL   string `json:"connection_url"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Prefix          string `json:"prefix"`
	Tier            string `json:"tier"`
	Limits          any    `json:"limits"`
	Note            string `json:"note"`
	ExpiresAt       string `json:"expires_at,omitempty"`
}

func skipIfMinIOUnavailable(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("MinIO not available in test environment — storage handler returns 503")
	}
}

// TestStorageNew_ServiceDisabled_Returns503 verifies that POST /storage/new returns 503
// when the storage service is not listed in EnabledServices.
func TestStorageNew_ServiceDisabled_Returns503(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Default app has EnabledServices="redis" — storage is not enabled.
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/storage/new", nil)
	req.Header.Set("X-Forwarded-For", "10.10.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestStorageNew_Returns201WithRequiredFields verifies the happy path for POST /storage/new.
// Requires a running MinIO instance; the test helper wires storage with a nil provider
// so provisions return 503 unless infra is present.
func TestStorageNew_Returns201WithRequiredFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/storage/new", nil)
	req.Header.Set("X-Forwarded-For", "10.10.0.2")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("MinIO not available in test environment — storage handler returns 503")
	}
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body storageNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.True(t, body.OK)
	assert.NotEmpty(t, body.ID, "response must include resource id")
	assert.NotEmpty(t, body.Token, "response must include token")
	assert.NotEmpty(t, body.ConnectionURL, "response must include connection_url")
	assert.NotEmpty(t, body.AccessKeyID, "response must include access_key_id")
	assert.NotEmpty(t, body.SecretAccessKey, "response must include secret_access_key")
	assert.NotEmpty(t, body.Prefix, "response must include prefix")
	assert.Equal(t, "anonymous", body.Tier, "unauthenticated request must get anonymous tier")
	assert.NotNil(t, body.Limits, "response must include limits")
	assert.NotEmpty(t, body.Note, "response must include note")
}

// TestStorageNew_ConnectionURLFormat verifies that connection_url contains the expected
// endpoint and prefix components.
func TestStorageNew_ConnectionURLFormat(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/storage/new", nil)
	req.Header.Set("X-Forwarded-For", "10.10.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	skipIfMinIOUnavailable(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body storageNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	// connection_url should start with https:// (S3-compatible endpoint)
	assert.True(t, strings.HasPrefix(body.ConnectionURL, "https://"),
		"connection_url must start with https://; got %q", body.ConnectionURL)

	// prefix must match the token suffix embedded in the URL
	assert.NotEmpty(t, body.Prefix, "prefix must not be empty")
	assert.True(t, strings.Contains(body.ConnectionURL, body.Prefix),
		"connection_url must contain the prefix %q; got %q", body.Prefix, body.ConnectionURL)
}

// TestStorageNew_NameFieldRoundTrip verifies that an optional name in the request body
// is stored and returned in the response.
func TestStorageNew_NameFieldRoundTrip(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	reqBody := strings.NewReader(`{"name":"user-assets"}`)
	req := httptest.NewRequest(http.MethodPost, "/storage/new", reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.10.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	skipIfMinIOUnavailable(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body storageNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, "user-assets", body.Name, "name must be echoed in response")

	var dbName string
	err = db.QueryRow(`SELECT COALESCE(name, '') FROM resources WHERE token = $1::uuid`, body.Token).Scan(&dbName)
	require.NoError(t, err)
	assert.Equal(t, "user-assets", dbName, "name must be persisted in DB")
}

// TestStorageNew_XInstantUpgradeHeaderPresent verifies the upgrade CTA header is set.
func TestStorageNew_XInstantUpgradeHeaderPresent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/storage/new", nil)
	req.Header.Set("X-Forwarded-For", "10.10.0.5")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	skipIfMinIOUnavailable(t, resp)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.NotEmpty(t, resp.Header.Get("X-Instant-Upgrade"),
		"POST /storage/new must include X-Instant-Upgrade header")
}

// TestStorageNew_StoresResourceInDB verifies that a storage resource row is written to DB.
func TestStorageNew_StoresResourceInDB(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/storage/new", nil)
	req.Header.Set("X-Forwarded-For", "10.10.0.6")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	skipIfMinIOUnavailable(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body storageNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	var resourceType, tier string
	err = db.QueryRow(
		`SELECT resource_type, tier FROM resources WHERE token = $1::uuid`, body.Token,
	).Scan(&resourceType, &tier)
	require.NoError(t, err)
	assert.Equal(t, "storage", resourceType, "resource_type must be 'storage'")
	assert.Equal(t, "anonymous", tier, "anonymous provision must have tier='anonymous'")
}

// TestStorageNew_AnonymousHasExpiresAt verifies that anonymous storage resources
// include an expires_at field (24h TTL).
func TestStorageNew_AnonymousHasExpiresAt(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/storage/new", nil)
	req.Header.Set("X-Forwarded-For", "10.10.0.7")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	skipIfMinIOUnavailable(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body storageNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.NotEmpty(t, body.ExpiresAt, "anonymous storage provision must include expires_at")
}
