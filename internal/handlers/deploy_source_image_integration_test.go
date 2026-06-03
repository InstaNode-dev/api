package handlers_test

// deploy_source_image_integration_test.go — end-to-end coverage for the P2
// source=image branch of POST /deploy/new (migration 064). Exercises the
// source switch (flag-off 501, invalid-source 400, flag-on invalid-ref 400,
// flag-on happy 202) so the handler-level source-routing lines are covered
// in CI (these tests run with a real DB; they skip locally without one).

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/testhelpers"
)

// buildImageDeployForm assembles a multipart body for a source=image deploy.
// Fields with an empty value are omitted (so callers can test a missing
// image_ref by passing "").
func buildImageDeployForm(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	for k, v := range fields {
		require.NoError(t, mw.WriteField(k, v))
	}
	require.NoError(t, mw.Close())
	return buf, mw.FormDataContentType()
}

func postDeploy(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, body *bytes.Buffer, contentType, jwt string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.42.0.7")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	return resp
}

// TestDeployNew_SourceImage_FlagOff_501 — source=image is rejected with 501
// while DEPLOY_SOURCE_IMAGE_ENABLED is off (the production default), and the
// tarball path is never touched.
func TestDeployNew_SourceImage_FlagOff_501(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "img@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy") // flag defaults OFF
	defer cleanApp()

	body, ct := buildImageDeployForm(t, map[string]string{
		"name":      "img-app",
		"source":    "image",
		"image_ref": "ghcr.io/owner/app:v1",
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "source=image must 501 while flag is off")
	var env struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.Equal(t, "source_image_disabled", env.Error)
}

// TestDeployNew_InvalidSource_400 — an unrecognised source (none of tarball,
// image, or git — e.g. "svn") is a clean 400. (Was "git" before P3 wired it.)
func TestDeployNew_InvalidSource_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "bad@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := buildImageDeployForm(t, map[string]string{
		"name":   "bad-source-app",
		"source": "svn", // not tarball/image/git → default → invalid_source
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var env struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.Equal(t, "invalid_source", env.Error)
}

// TestDeployNew_SourceImage_FlagOn_InvalidRef_400 — with the flag enabled, a
// bare image name (no registry host) is rejected by validateImageRef.
func TestDeployNew_SourceImage_FlagOn_InvalidRef_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badref@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy",
		func(c *config.Config) { c.DeploySourceImageEnabled = true })
	defer cleanApp()

	body, ct := buildImageDeployForm(t, map[string]string{
		"name":      "bad-ref-app",
		"source":    "image",
		"image_ref": "nginx", // bare name, no registry host → rejected
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var env struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.Equal(t, "invalid_image_ref", env.Error)
}

// TestDeployNew_SourceImage_EncryptFailure_503 — when AES_KEY is misconfigured,
// encrypting BYO registry creds fails and the handler returns 503 rather than
// persisting unencrypted secrets. AES parsing is request-time, so a bad key on
// the test config only trips this path (the app still builds).
func TestDeployNew_SourceImage_EncryptFailure_503(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "enc@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy",
		func(c *config.Config) {
			c.DeploySourceImageEnabled = true
			c.AESKey = "not-a-valid-hex-key" // crypto.ParseAESKey rejects → encrypt fails
		})
	defer cleanApp()

	body, ct := buildImageDeployForm(t, map[string]string{
		"name":           "enc-fail-app",
		"source":         "image",
		"image_ref":      "ghcr.io/owner/app:v1",
		"registry_creds": `{"auths":{}}`,
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var env struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.Equal(t, "encrypt_failed", env.Error)
}

// TestDeployNew_SourceImage_FlagOn_Accepted — the happy path: flag on, valid
// image_ref + BYO private-registry creds → 202, the response item echoes
// source=image + image_ref + registry_creds_set:true (never the creds), and
// the async runDeploy reaches the (noop) compute provider, which stamps the
// row healthy. Polling the row to healthy proves applyImageSourceOpts ran.
func TestDeployNew_SourceImage_FlagOn_Accepted(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ok@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy",
		func(c *config.Config) { c.DeploySourceImageEnabled = true })
	defer cleanApp()

	const ref = "ghcr.io/owner/app:v1"
	body, ct := buildImageDeployForm(t, map[string]string{
		"name":           "img-ok-app",
		"source":         "image",
		"image_ref":      ref,
		"registry_creds": `{"auths":{"ghcr.io":{"auth":"dG9rZW4="}}}`,
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	require.Equal(t, http.StatusAccepted, resp.StatusCode, "valid source=image deploy must 202")
	var env struct {
		OK   bool `json:"ok"`
		Item struct {
			ID               string `json:"id"`
			AppID            string `json:"app_id"`
			Source           string `json:"source"`
			ImageRef         string `json:"image_ref"`
			RegistryCredsSet bool   `json:"registry_creds_set"`
			RegistryCreds    string `json:"registry_creds"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.True(t, env.OK)
	assert.Equal(t, "image", env.Item.Source)
	assert.Equal(t, ref, env.Item.ImageRef)
	assert.True(t, env.Item.RegistryCredsSet, "registry_creds_set must be true when creds supplied")
	assert.Empty(t, env.Item.RegistryCreds, "registry creds must NEVER be echoed back")
	require.NotEmpty(t, env.Item.ID)

	// runDeploy is async — poll the row until the (noop) compute provider has
	// stamped it healthy with a provider id. This deterministically waits for
	// the applyImageSourceOpts → compute.Deploy path to execute.
	// Generous deadline: the async runDeploy goroutine does DB writes that can
	// be slow under `-race -p 1` with the full suite loaded (was 5s → flaked).
	deadline := time.Now().Add(30 * time.Second)
	var status, providerID string
	var imageRef sql.NullString
	for time.Now().Before(deadline) {
		row := db.QueryRow(
			`SELECT status, COALESCE(provider_id,''), image_ref FROM deployments WHERE id = $1`,
			env.Item.ID)
		require.NoError(t, row.Scan(&status, &providerID, &imageRef))
		if providerID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.Equal(t, "healthy", status, "noop provider should drive the row to healthy")
	assert.NotEmpty(t, providerID, "runDeploy must persist the provider id")
	assert.Equal(t, ref, imageRef.String, "image_ref must be persisted on the row")
}
