package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/testhelpers"
)

// TestRotateCredentials_RequiresAuth_Returns401 verifies that an unauthenticated
// request to the rotation endpoint returns 401.
func TestRotateCredentials_RequiresAuth_Returns401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/00000000-0000-0000-0000-000000000001/rotate-credentials", nil)
	// No Authorization header.

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestRotateCredentials_InvalidUUID_Returns400 verifies that a non-UUID path param
// returns 400.
func TestRotateCredentials_InvalidUUID_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/not-a-uuid/rotate-credentials", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "invalid_id", body["error"])
}

// TestRotateCredentials_WrongTeam_Returns404 verifies that a team that does not
// own the resource gets 404 (not 403) — cross-team access must not leak
// existence of resources owned by other teams.
func TestRotateCredentials_WrongTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Team A owns the resource.
	teamAID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	// Team B tries to rotate it.
	teamBID := testhelpers.MustCreateTeamDB(t, db, "hobby")

	emailB := testhelpers.UniqueEmail(t)
	var userBID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamBID, emailB,
	).Scan(&userBID))
	jwtB := testhelpers.MustSignSessionJWT(t, userBID, teamBID, emailB)

	// Insert a postgres resource owned by team A with a plaintext connection_url.
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	encURL, err := crypto.Encrypt(aesKey, "postgres://user:pass@host:5432/db")
	require.NoError(t, err)

	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, connection_url)
		VALUES ($1::uuid, 'postgres', 'hobby', $2)
		RETURNING token::text
	`, teamAID, encURL).Scan(&resourceToken))

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+resourceToken+"/rotate-credentials", nil)
	req.Header.Set("Authorization", "Bearer "+jwtB)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "not_found", body["error"])
}

// TestRotateCredentials_ResourceHasNoURL_Returns400 verifies that rotating credentials
// on a resource with no connection_url returns 400 with error code "no_connection_url".
func TestRotateCredentials_ResourceHasNoURL_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	// Insert a redis resource with no connection_url.
	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier)
		VALUES ($1::uuid, 'redis', 'hobby')
		RETURNING token::text
	`, teamID).Scan(&resourceToken))

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+resourceToken+"/rotate-credentials", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "no_connection_url", body["error"])
}

// TestRotateCredentials_Success verifies the happy path:
//   - Resource has an encrypted connection_url
//   - Rotation returns 200 with a new plaintext connection_url
//   - The DB is updated (new encrypted value differs from old)
//   - The new plaintext URL parses correctly and differs from the original
func TestRotateCredentials_Success(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	originalPlainURL := "postgres://dbuser:originalpassword@host.example.com:5432/mydb"
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	origEncURL, err := crypto.Encrypt(aesKey, originalPlainURL)
	require.NoError(t, err)

	// Insert a postgres resource with encrypted connection_url.
	var resourceToken, resourceID string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, connection_url)
		VALUES ($1::uuid, 'postgres', 'hobby', $2)
		RETURNING token::text, id::text
	`, teamID, origEncURL).Scan(&resourceToken, &resourceID))

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+resourceToken+"/rotate-credentials", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])

	newPlainURL, ok := body["connection_url"].(string)
	require.True(t, ok, "connection_url must be a string in response")
	assert.NotEmpty(t, newPlainURL)
	assert.NotEqual(t, originalPlainURL, newPlainURL, "rotated URL must differ from original")

	// The scheme, host, path, and username must be preserved; only password changes.
	assert.Contains(t, newPlainURL, "postgres://", "scheme must be preserved")
	assert.Contains(t, newPlainURL, "host.example.com:5432/mydb", "host/path must be preserved")
	assert.Contains(t, newPlainURL, "dbuser:", "username must be preserved")
	assert.NotContains(t, newPlainURL, "originalpassword", "old password must not appear in rotated URL")

	// Verify the DB was updated: the stored encrypted value must differ from the original.
	var storedEncURL string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COALESCE(connection_url,'') FROM resources WHERE id = $1::uuid`, resourceID,
	).Scan(&storedEncURL))
	assert.NotEqual(t, origEncURL, storedEncURL, "stored encrypted URL must be updated")

	// Decrypt the new stored value and confirm it matches the returned plaintext.
	decrypted, err := crypto.Decrypt(aesKey, storedEncURL)
	require.NoError(t, err)
	assert.Equal(t, newPlainURL, decrypted, "stored encrypted URL must decrypt to the returned plaintext")
}
