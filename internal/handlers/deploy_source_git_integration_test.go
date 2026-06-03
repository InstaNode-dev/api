package handlers_test

// deploy_source_git_integration_test.go — end-to-end coverage for the P3
// source=git branch of POST /deploy/new (migration 065): flag-off 501, flag-on
// invalid git_url 400, encrypt-failure 503, and the flag-on happy 202 (git_url/
// git_ref echoed, git_token never echoed, async runDeploy drives the row
// healthy via the noop provider). Reuses buildImageDeployForm/postDeploy from
// deploy_source_image_integration_test.go. DB-gated; skips locally without one.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/testhelpers"
)

func TestDeployNew_SourceGit_FlagOff_501(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "git@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy") // flag defaults OFF
	defer cleanApp()

	body, ct := buildImageDeployForm(t, map[string]string{
		"name":    "git-app",
		"source":  "git",
		"git_url": "https://github.com/owner/repo",
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "source=git must 501 while flag is off")
	var env struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.Equal(t, "source_git_disabled", env.Error)
}

func TestDeployNew_SourceGit_FlagOn_InvalidURL_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badurl@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy",
		func(c *config.Config) { c.DeploySourceGitEnabled = true })
	defer cleanApp()

	body, ct := buildImageDeployForm(t, map[string]string{
		"name":    "bad-git-app",
		"source":  "git",
		"git_url": "git@github.com:owner/repo.git", // ssh scheme → rejected
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var env struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.Equal(t, "invalid_git_url", env.Error)
}

// bad AES key → encrypting the private-repo token fails → 503.
func TestDeployNew_SourceGit_EncryptFailure_503(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "gitenc@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy",
		func(c *config.Config) {
			c.DeploySourceGitEnabled = true
			c.AESKey = "not-a-valid-hex-key"
		})
	defer cleanApp()

	body, ct := buildImageDeployForm(t, map[string]string{
		"name":      "git-enc-fail",
		"source":    "git",
		"git_url":   "https://github.com/owner/repo",
		"git_token": "ghp_secret",
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

// happy path: flag on, valid git_url + ref + private token → 202; the response
// echoes source=git + git_url + git_ref + git_token_set:true (never the token),
// and the async runDeploy drives the row healthy via the noop provider.
func TestDeployNew_SourceGit_FlagOn_Accepted(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "gitok@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy",
		func(c *config.Config) { c.DeploySourceGitEnabled = true })
	defer cleanApp()

	const gitURL = "https://github.com/owner/repo"
	body, ct := buildImageDeployForm(t, map[string]string{
		"name":      "git-ok-app",
		"source":    "git",
		"git_url":   gitURL,
		"git_ref":   "main",
		"git_token": "ghp_secrettoken",
	})
	resp := postDeploy(t, app, body, ct, jwt)
	defer resp.Body.Close()

	require.Equal(t, http.StatusAccepted, resp.StatusCode, "valid source=git deploy must 202")
	var env struct {
		OK   bool `json:"ok"`
		Item struct {
			ID          string `json:"id"`
			Source      string `json:"source"`
			GitURL      string `json:"git_url"`
			GitRef      string `json:"git_ref"`
			GitTokenSet bool   `json:"git_token_set"`
			GitToken    string `json:"git_token"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.True(t, env.OK)
	assert.Equal(t, "git", env.Item.Source)
	assert.Equal(t, gitURL, env.Item.GitURL)
	assert.Equal(t, "main", env.Item.GitRef)
	assert.True(t, env.Item.GitTokenSet, "git_token_set must be true when a token is supplied")
	assert.Empty(t, env.Item.GitToken, "git token must NEVER be echoed back")
	require.NotEmpty(t, env.Item.ID)

	// runDeploy is async — poll the row until the noop provider stamps it
	// healthy with a provider id (proves applyGitSourceOpts → compute.Deploy ran).
	deadline := time.Now().Add(5 * time.Second)
	var status, providerID string
	var gitURLCol sql.NullString
	for time.Now().Before(deadline) {
		row := db.QueryRow(`SELECT status, COALESCE(provider_id,''), git_url FROM deployments WHERE id = $1`, env.Item.ID)
		require.NoError(t, row.Scan(&status, &providerID, &gitURLCol))
		if providerID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.Equal(t, "healthy", status, "noop provider should drive the row to healthy")
	assert.NotEmpty(t, providerID, "runDeploy must persist the provider id")
	assert.Equal(t, gitURL, gitURLCol.String, "git_url must be persisted on the row")
}
