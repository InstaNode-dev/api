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

// dbNewResponse mirrors the JSON body returned by POST /db/new.
type dbNewResponse struct {
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

// TestDBNew_ServiceDisabled_Returns503 verifies that POST /db/new returns 503
// when the postgres service is not listed in EnabledServices.
func TestDBNew_ServiceDisabled_Returns503(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Default app has EnabledServices="redis" — postgres is not enabled.
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	req.Header.Set("X-Forwarded-For", "10.1.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestDBNew_Returns201WithRequiredFields verifies the happy path of POST /db/new
// when the postgres service is enabled.
func TestDBNew_Returns201WithRequiredFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	req.Header.Set("X-Forwarded-For", "10.1.0.2")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body dbNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.True(t, body.OK)
	assert.NotEmpty(t, body.ID, "response must include resource id")
	assert.NotEmpty(t, body.Token, "response must include token")
	assert.NotEmpty(t, body.ConnectionURL, "response must include connection_url")
	assert.NotEmpty(t, body.Tier, "response must include tier")
	assert.NotNil(t, body.Limits, "response must include limits")
	assert.NotEmpty(t, body.Note, "response must include note")
}

// TestDBNew_NameFieldRoundTrip verifies that a name sent in the request body
// is stored and returned in the response.
func TestDBNew_NameFieldRoundTrip(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	body := strings.NewReader(`{"name":"users-db"}`)
	req := httptest.NewRequest(http.MethodPost, "/db/new", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.1.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result dbNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.Equal(t, "users-db", result.Name, "name must be echoed in response")
	assert.NotEmpty(t, result.ID, "id must be present in response")

	// Verify the name is persisted in the DB.
	var dbName string
	err = db.QueryRow(`SELECT COALESCE(name, '') FROM resources WHERE token = $1::uuid`, result.Token).Scan(&dbName)
	require.NoError(t, err)
	assert.Equal(t, "users-db", dbName, "name must be stored in the DB")
}

// TestDBNew_XInstantUpgradeHeaderPresent verifies the upgrade CTA header is set
// on a successful POST /db/new response.
func TestDBNew_XInstantUpgradeHeaderPresent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	req.Header.Set("X-Forwarded-For", "10.1.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assert.NotEmpty(t, resp.Header.Get("X-Instant-Upgrade"),
		"POST /db/new must include X-Instant-Upgrade header with upgrade CTA URL")
}

// TestDBNew_StoresResourceInDB verifies that a postgres resource row is written
// to the database after a successful POST /db/new.
func TestDBNew_StoresResourceInDB(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	token := testhelpers.MustProvisionDB(t, app, testhelpers.FingerprintToIP(fp))
	defer db.Exec(`DELETE FROM resources WHERE token = $1::uuid`, token)

	var resourceType string
	err := db.QueryRow(
		`SELECT resource_type FROM resources WHERE token = $1::uuid`, token,
	).Scan(&resourceType)
	require.NoError(t, err)
	assert.Equal(t, "postgres", resourceType, "resource_type must be 'postgres'")
}

// TestDBNew_ConnectionURLContainsToken verifies that connection_url is a valid
// postgres:// string that embeds part of the provisioned token.
func TestDBNew_ConnectionURLContainsToken(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	req.Header.Set("X-Forwarded-For", "10.1.0.5")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result dbNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.True(t, strings.HasPrefix(result.ConnectionURL, "postgres://"),
		"connection_url must start with postgres://; got %q", result.ConnectionURL)
	// The stub URL embeds the first 8 chars of the token.
	tokenPrefix := result.Token
	if len(tokenPrefix) > 8 {
		tokenPrefix = tokenPrefix[:8]
	}
	assert.Contains(t, result.ConnectionURL, tokenPrefix,
		"connection_url must contain part of the token")
}
