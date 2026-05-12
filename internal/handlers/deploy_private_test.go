package handlers_test

// deploy_private_test.go — POST /deploy/new private / allowed_ips fields.
//
// Track A of the private-deploys feature (migration 020). Seven cases, mirror
// the brief's spec:
//
//   1. Pro tier + private=true + 1 IP            → 202 (deployment created)
//   2. Hobby tier + private=true                 → 402 + agent_action
//   3. Pro tier + private=true + empty IPs       → 400 + agent_action
//   4. Pro tier + private=true + invalid IP      → 400 (bad literal surfaced)
//   5. Pro tier + private=true + 33 IPs          → 400 (cap enforced)
//   6. Pro tier + private=false (default)        → 202 (existing path)
//   7. GET /deploy/:id round-trip                → private + allowed_ips
//
// All tests run against the noop compute provider — k8s isn't involved.
// We assert handler-level behaviour: status codes, error keys, agent_action
// text, and the persisted shape via GET /deploy/:id.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// privateDeployBody is like multipartDeployBody but with named convenience
// for the private+allowed_ips fields. Stays a tiny helper so each test still
// reads top-to-bottom.
func privateDeployBody(t *testing.T, private string, allowedIPs string, extra map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball-bytes"))
	require.NoError(t, err)
	if private != "" {
		require.NoError(t, w.WriteField("private", private))
	}
	if allowedIPs != "" {
		require.NoError(t, w.WriteField("allowed_ips", allowedIPs))
	}
	for k, v := range extra {
		require.NoError(t, w.WriteField(k, v))
	}
	require.NoError(t, w.Close())
	return buf, w.FormDataContentType()
}

// TestDeployNew_Private_Pro_Accepts is case 1: Pro + private=true + 1 IP →
// 202. Asserts the persisted record carries private=true and the allowed_ips
// list round-trips. Uses GET /deploy/:id to read the row back (handler is
// the contract — bypassing it to read the DB directly hides surface bugs).
func TestDeployNew_Private_Pro_Accepts(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "10000000-0000-0000-0000-000000000001", teamID, "agent-priv-pro@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := privateDeployBody(t, "true", "1.2.3.4,10.0.0.0/8", nil)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.1")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"Pro + private=true + valid IPs must be 202; got %d, body: %s", resp.StatusCode, string(bodyBytes))

	var created struct {
		Item struct {
			AppID      string   `json:"app_id"`
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &created))
	assert.True(t, created.Item.Private, "private must be true on the response item")
	assert.Equal(t, []string{"1.2.3.4", "10.0.0.0/8"}, created.Item.AllowedIPs,
		"allowed_ips must be parsed into the slice in original order")

	// Round-trip via GET /deploy/:id — proves the row was persisted, not
	// just echoed back from the request.
	getReq := httptest.NewRequest(http.MethodGet, "/deploy/"+created.Item.AppID, nil)
	getReq.Header.Set("Authorization", "Bearer "+sessionJWT)
	getResp, err := app.Test(getReq, 5000)
	require.NoError(t, err)
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	var fetched struct {
		Item struct {
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&fetched))
	assert.True(t, fetched.Item.Private, "private must round-trip through GET")
	assert.Equal(t, []string{"1.2.3.4", "10.0.0.0/8"}, fetched.Item.AllowedIPs,
		"allowed_ips must round-trip through GET")
}

// TestDeployNew_Private_Hobby_Returns402 is case 2: hobby tier hitting
// private=true gets the 402 wall with the Pro-required agent_action.
// Critical: the message must point at the upgrade URL, not "contact support".
func TestDeployNew_Private_Hobby_Returns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "20000000-0000-0000-0000-000000000002", teamID, "agent-priv-hobby@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := privateDeployBody(t, "true", "1.2.3.4", nil)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.2")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"hobby + private=true must be 402")

	var errBody struct {
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
		UpgradeURL  string `json:"upgrade_url"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "private_deploy_requires_pro", errBody.Error,
		"error key must be private_deploy_requires_pro so agents can branch")
	assert.True(t, strings.HasPrefix(errBody.AgentAction, "Tell the user"),
		"agent_action must satisfy the U3 contract; got: %q", errBody.AgentAction)
	assert.Contains(t, errBody.AgentAction, "https://instanode.dev/pricing",
		"agent_action must contain the upgrade URL verbatim")
	assert.Equal(t, "https://instanode.dev/pricing", errBody.UpgradeURL,
		"upgrade_url must be set so dashboards can render a CTA without parsing the agent_action sentence")
}

// TestDeployNew_Private_EmptyAllowedIPs_Returns400 is case 3: private=true
// with no allowed_ips is the silent-brick path we explicitly refuse.
func TestDeployNew_Private_EmptyAllowedIPs_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "30000000-0000-0000-0000-000000000003", teamID, "agent-priv-empty@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := privateDeployBody(t, "true", "", nil)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.3")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "private_deploy_requires_allowed_ips", errBody.Error)
	assert.Contains(t, errBody.AgentAction, "Tell the user")
	assert.Contains(t, errBody.AgentAction, "allowed_ips")
}

// TestDeployNew_Private_InvalidIP_Returns400 is case 4: a malformed entry
// must surface verbatim in the 400 message — the LLM agent reads it back
// to the human verbatim and fixes the literal in the next prompt.
func TestDeployNew_Private_InvalidIP_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "40000000-0000-0000-0000-000000000004", teamID, "agent-priv-invalid@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	const badEntry = "not.a.real.ip"
	body, ct := privateDeployBody(t, "true", "1.2.3.4,"+badEntry, nil)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.4")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "invalid_allowed_ip", errBody.Error)
	assert.Contains(t, errBody.Message, badEntry,
		"message must include the bad literal verbatim — the agent has to fix the exact thing the user passed; got %q", errBody.Message)
}

// TestDeployNew_Private_TooManyIPs_Returns400 is case 5: cap enforcement.
// 33 entries trips the maxAllowedIPs=32 ceiling. Larger lists belong in CF
// Access or a VPN, not an nginx annotation.
func TestDeployNew_Private_TooManyIPs_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "50000000-0000-0000-0000-000000000005", teamID, "agent-priv-flood@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// 33 distinct /32s.
	ips := make([]string, 0, 33)
	for i := 0; i < 33; i++ {
		ips = append(ips, fmt.Sprintf("10.99.%d.1", i))
	}
	body, ct := privateDeployBody(t, "true", strings.Join(ips, ","), nil)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.5")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "too_many_allowed_ips", errBody.Error,
		"error key must be too_many_allowed_ips so agents can disambiguate from invalid_allowed_ip")
	assert.Contains(t, errBody.Message, "33",
		"message must surface the actual entry count (33)")
	assert.Contains(t, errBody.Message, "32",
		"message must surface the cap (32) so the agent knows what to trim to")
}

// TestDeployNew_Public_Default is case 6: no `private` field at all (the
// existing public-deploy path) must continue to return 202 with the new
// fields zero-valued in the response. Guards against silent regression for
// every existing caller in the wild.
func TestDeployNew_Public_Default(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "60000000-0000-0000-0000-000000000006", teamID, "agent-pub-default@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// No private, no allowed_ips — the existing two-field path.
	body, ct := privateDeployBody(t, "", "", nil)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.6")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"public deploy (no private field) must still be 202; got %d, body: %s", resp.StatusCode, string(bodyBytes))

	var created struct {
		Item struct {
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &created))
	assert.False(t, created.Item.Private, "default deploy must have private=false")
	assert.Equal(t, []string{}, created.Item.AllowedIPs,
		"default deploy must emit empty allowed_ips (not null) so dashboards always see a list")
}

// TestDeployNew_Private_GetReturnsFields is case 7: the GET endpoint must
// surface the private + allowed_ips fields on read. (Same surface as case 1,
// but here the assertion lives in a dedicated test that won't silently pass
// if case 1 ever loses its GET round-trip.)
func TestDeployNew_Private_GetReturnsFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "70000000-0000-0000-0000-000000000007", teamID, "agent-priv-get@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := privateDeployBody(t, "true", "203.0.113.0/24", nil)
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.7")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var created struct {
		Item struct {
			AppID string `json:"app_id"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))

	// List endpoint round-trip too — covers GET /api/v1/deployments which
	// the dashboard reads.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/deployments", nil)
	listReq.Header.Set("Authorization", "Bearer "+sessionJWT)
	listResp, err := app.Test(listReq, 5000)
	require.NoError(t, err)
	defer listResp.Body.Close()
	require.Equal(t, http.StatusOK, listResp.StatusCode)

	var listed struct {
		Items []struct {
			AppID      string   `json:"app_id"`
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"items"`
	}
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listed))

	var found bool
	for _, it := range listed.Items {
		if it.AppID == created.Item.AppID {
			found = true
			assert.True(t, it.Private, "private deploy must surface private=true on list")
			assert.Equal(t, []string{"203.0.113.0/24"}, it.AllowedIPs,
				"private deploy must surface allowed_ips on list")
		}
	}
	assert.True(t, found, "the just-created deployment must appear in the team's list")
}
