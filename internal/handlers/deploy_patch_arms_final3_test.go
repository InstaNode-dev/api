package handlers_test

// deploy_patch_arms_final3_test.go — FINAL serial pass #3. Closes the
// invalid_body arm of DeployHandler.Patch (deploy_private.go:204-207): a
// malformed JSON body on an existing deploy → 400 invalid_body.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestDeployPatchFinal3_InvalidBody(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "d0000000-0000-0000-0000-000000000009", teamID, "patch-badbody@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := createPublicDeploy(t, app, sessionJWT)

	// Malformed JSON body → BodyParser errors → invalid_body 400
	// (deploy_private.go:204-207).
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/deployments/"+appID, bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
