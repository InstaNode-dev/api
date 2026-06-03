package handlers_test

// deploy_tarball_cap_integration_test.go — end-to-end 10 MB cap on /deploy/new
// (2026-06-03). Posts an over-cap tarball and asserts 413 + tarball_too_large +
// the routed agent_action. Covers the New handler's enforceTarballCap call site.

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestDeployNew_OversizedTarball_413(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "big@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// Build a multipart body whose tarball part is just over the 10 MB cap.
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	require.NoError(t, mw.WriteField("name", "too-big-app"))
	fw, err := mw.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write(make([]byte, (10<<20)+1)) // 10 MiB + 1 byte
	require.NoError(t, err)
	require.NoError(t, mw.Close())

	req := httptest.NewRequest(http.MethodPost, "/deploy/new", buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.41.0.9")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "over-cap tarball must be 413")
	var env struct {
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	assert.Equal(t, "tarball_too_large", env.Error)
	assert.Contains(t, env.AgentAction, "prebuilt image", "413 must carry the slim/image agent_action")
}
