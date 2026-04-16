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

// nosqlNewResponse mirrors the JSON body returned by POST /nosql/new.
type nosqlNewResponse struct {
	OK            bool   `json:"ok"`
	ID            string `json:"id"`
	Token         string `json:"token"`
	Name          string `json:"name"`
	ConnectionURL string `json:"connection_url"`
	Tier          string `json:"tier"`
	Limits        any    `json:"limits"`
	Note          string `json:"note"`
	Upgrade       string `json:"upgrade,omitempty"`
}

// postNoSQL issues a POST /nosql/new and returns the response.
// Caller must close the body.
func postNoSQL(t *testing.T, app interface{ Test(*http.Request, ...int) (*http.Response, error) }, ip string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/nosql/new", nil)
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// requireMongoReachable checks if a POST /nosql/new returns 201.
// Skips the test if MongoDB is not reachable (returns 503 from provision_failed).
func requireMongoReachable(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()
	if resp.StatusCode == http.StatusServiceUnavailable {
		var errBody map[string]any
		if jsonErr := json.Unmarshal(body, &errBody); jsonErr == nil {
			errCode, _ := errBody["error"].(string)
			if errCode != "service_disabled" {
				t.Skip("MongoDB not reachable in test env — provision_failed is correct behavior")
			}
		}
	}
}

// TestNoSQLNew_ServiceDisabled_Returns503 verifies that POST /nosql/new returns 503
// when the mongodb service is not listed in EnabledServices.
func TestNoSQLNew_ServiceDisabled_Returns503(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Default app has EnabledServices="redis" — mongodb is not enabled.
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/nosql/new", nil)
	req.Header.Set("X-Forwarded-For", "10.3.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "service_disabled", body["error"],
		"error code must be service_disabled when mongodb is not in EnabledServices")
}

// TestNoSQLNew_Returns201WithRequiredFields verifies the happy path of POST /nosql/new
// when the mongodb service is enabled. Skipped if MongoDB is not reachable.
func TestNoSQLNew_Returns201WithRequiredFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postNoSQL(t, app, "10.3.0.2")
	rawBody, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, readErr)

	requireMongoReachable(t, resp, rawBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"want 201, got %d: %s", resp.StatusCode, rawBody)

	var body nosqlNewResponse
	require.NoError(t, json.Unmarshal(rawBody, &body))

	assert.True(t, body.OK)
	assert.NotEmpty(t, body.ID, "response must include resource id")
	assert.NotEmpty(t, body.Token, "response must include token")
	assert.NotEmpty(t, body.ConnectionURL, "response must include connection_url")
	assert.True(t, strings.HasPrefix(body.ConnectionURL, "mongodb://"),
		"connection_url must start with mongodb://; got %q", body.ConnectionURL)
	assert.NotEmpty(t, body.Tier, "response must include tier")
	assert.NotNil(t, body.Limits, "response must include limits")
	assert.NotEmpty(t, body.Note, "response must include note")
}

// TestNoSQLNew_XInstantUpgradeHeaderPresent verifies the upgrade CTA header is set
// on a successful POST /nosql/new response. Skipped if MongoDB is not reachable.
func TestNoSQLNew_XInstantUpgradeHeaderPresent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postNoSQL(t, app, "10.3.0.4")
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	requireMongoReachable(t, resp, rawBody)

	assert.NotEmpty(t, resp.Header.Get("X-Instant-Upgrade"),
		"POST /nosql/new must include X-Instant-Upgrade header with upgrade CTA URL")
}

// TestNoSQLNew_StoresEncryptedURLInDB verifies that a mongodb resource row is written
// to the database with an AES-encrypted connection_url after a successful POST /nosql/new.
// Skipped if MongoDB is not reachable.
func TestNoSQLNew_StoresEncryptedURLInDB(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postNoSQL(t, app, "10.3.0.5")
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	requireMongoReachable(t, resp, rawBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result nosqlNewResponse
	require.NoError(t, json.Unmarshal(rawBody, &result))

	// Verify the resource row exists in the DB with an encrypted connection_url.
	var resourceType, encryptedURL string
	err := db.QueryRow(
		`SELECT resource_type, COALESCE(connection_url, '') FROM resources WHERE token = $1::uuid`,
		result.Token,
	).Scan(&resourceType, &encryptedURL)
	require.NoError(t, err)

	assert.Equal(t, "mongodb", resourceType, "resource_type must be 'mongodb'")
	assert.NotEmpty(t, encryptedURL, "connection_url must be stored in DB")
	// The stored value must be AES-encrypted, not the plaintext mongodb:// URL.
	assert.NotEqual(t, result.ConnectionURL, encryptedURL,
		"stored connection_url must be AES-encrypted, not plaintext")
	assert.False(t, strings.HasPrefix(encryptedURL, "mongodb://"),
		"stored connection_url must be AES-encrypted; got raw URL %q", encryptedURL)
}

// TestNoSQLNew_6thCallReturnsPreviousToken verifies that the 6th POST /nosql/new
// from the same IP returns an existing token (fail-open deduplication), not a new one.
// Skipped if MongoDB is not reachable.
func TestNoSQLNew_6thCallReturnsPreviousToken(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	ip := testhelpers.FingerprintToIP(fp)

	var seenTokens []string
	for i := 0; i < 5; i++ {
		resp := postNoSQL(t, app, ip)
		rawBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		requireMongoReachable(t, resp, rawBody)
		require.Equal(t, http.StatusCreated, resp.StatusCode,
			"call %d: want 201, got %d: %s", i+1, resp.StatusCode, rawBody)

		var result nosqlNewResponse
		require.NoError(t, json.Unmarshal(rawBody, &result))
		seenTokens = append(seenTokens, result.Token)
	}

	// 6th call — limit exceeded; must return an existing token, status 200.
	resp := postNoSQL(t, app, ip)
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	assert.NotEqual(t, http.StatusTooManyRequests, resp.StatusCode,
		"6th provision must not return 429 — should fail-open and return existing token")

	var result nosqlNewResponse
	require.NoError(t, json.Unmarshal(rawBody, &result))

	seenSet := make(map[string]bool, len(seenTokens))
	for _, tok := range seenTokens {
		seenSet[tok] = true
	}

	assert.True(t, seenSet[result.Token],
		"6th provision must return one of the existing tokens; got new token %q", result.Token)
}
