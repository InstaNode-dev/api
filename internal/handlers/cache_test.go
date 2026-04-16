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

// cacheNewResponse mirrors the JSON body returned by POST /cache/new.
type cacheNewResponse struct {
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

// TestCacheNew_ServiceDisabled_Returns503 verifies that POST /cache/new returns 503
// when the redis service is not listed in EnabledServices.
func TestCacheNew_ServiceDisabled_Returns503(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", "10.2.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestCacheNew_Returns201WithRequiredFields verifies the happy path of POST /cache/new
// when the redis service is enabled.
func TestCacheNew_Returns201WithRequiredFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", "10.2.0.2")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body cacheNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.True(t, body.OK)
	assert.NotEmpty(t, body.ID, "response must include resource id")
	assert.NotEmpty(t, body.Token, "response must include token")
	assert.NotEmpty(t, body.ConnectionURL, "response must include connection_url")
	assert.NotEmpty(t, body.Tier, "response must include tier")
	assert.NotNil(t, body.Limits, "response must include limits")
	assert.NotEmpty(t, body.Note, "response must include note")
}

// TestCacheNew_NameFieldRoundTrip verifies that a name sent in the request body
// is stored and returned in the response.
func TestCacheNew_NameFieldRoundTrip(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	body := strings.NewReader(`{"name":"users-db"}`)
	req := httptest.NewRequest(http.MethodPost, "/cache/new", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.2.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result cacheNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.Equal(t, "users-db", result.Name, "name must be echoed in response")
	assert.NotEmpty(t, result.ID, "id must be present in response")

	// Verify the name is persisted in the DB.
	var dbName string
	err = db.QueryRow(`SELECT COALESCE(name, '') FROM resources WHERE token = $1::uuid`, result.Token).Scan(&dbName)
	require.NoError(t, err)
	assert.Equal(t, "users-db", dbName, "name must be stored in the DB")
}

// TestCacheNew_XInstantUpgradeHeaderPresent verifies the upgrade CTA header is set
// on a successful POST /cache/new response.
func TestCacheNew_XInstantUpgradeHeaderPresent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", "10.2.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.NotEmpty(t, resp.Header.Get("X-Instant-Upgrade"),
		"POST /cache/new must include X-Instant-Upgrade header with upgrade CTA URL")
}

// TestCacheNew_StoresResourceInDB verifies that a redis resource row is written
// to the database after a successful POST /cache/new.
func TestCacheNew_StoresResourceInDB(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	token := testhelpers.MustProvisionCache(t, app, testhelpers.FingerprintToIP(fp))
	defer db.Exec(`DELETE FROM resources WHERE token = $1::uuid`, token)

	var resourceType string
	err := db.QueryRow(
		`SELECT resource_type FROM resources WHERE token = $1::uuid`, token,
	).Scan(&resourceType)
	require.NoError(t, err)
	assert.Equal(t, "redis", resourceType, "resource_type must be 'redis'")
}

// TestCacheNew_ConnectionURLStartsWithRedis verifies that connection_url is a real
// redis:// URL (not a stub placeholder like shared.instant.dev).
func TestCacheNew_ConnectionURLStartsWithRedis(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", "10.2.0.5")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result cacheNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.True(t, strings.HasPrefix(result.ConnectionURL, "redis://"),
		"connection_url must start with redis://; got %q", result.ConnectionURL)
	// Real provisioned URL must NOT be the old stub placeholder.
	assert.NotContains(t, result.ConnectionURL, "shared.instant.dev",
		"connection_url must not be a stub placeholder; got %q", result.ConnectionURL)
}

// TestCacheNew_ConnectionURLIsReal verifies that the provisioned connection_url is a
// real namespace URL from the local Redis provider, not the old stub placeholder.
func TestCacheNew_ConnectionURLIsReal(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", "10.2.0.6")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result cacheNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	// The real URL should point to "localhost" (test env) not the old stub host.
	assert.True(t, strings.HasPrefix(result.ConnectionURL, "redis://"),
		"connection_url must start with redis://")
	assert.NotContains(t, result.ConnectionURL, "shared.instant.dev",
		"connection_url must not be the old stub value")
}
