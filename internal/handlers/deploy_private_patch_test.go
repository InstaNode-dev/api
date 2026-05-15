package handlers_test

// deploy_private_patch_test.go — PATCH /api/v1/deployments/:id for in-place
// access-control edits (private + allowed_ips).
//
// Seven cases, mirroring the brief's spec:
//
//   1. PATCH {private:true, allowed_ips:[...]} on existing Pro deploy → 200
//   2. PATCH replacing allowed_ips on existing private deploy → 200 (REPLACE)
//   3. PATCH {private:false} clears allow-list → 200
//   4. PATCH on hobby tier flipping private → 402 with agent_action
//   5. PATCH with invalid IP → 400 with the bad literal surfaced
//   6. PATCH on missing deploy → 404
//   7. PATCH cross-team → 404 (never confirm existence to a non-owner)
//
// All tests run against the noop compute provider — same as the POST suite.
// The handler-level contract (status codes, error keys, agent_action, JSON
// shape) is what's under test; the live Ingress patch is exercised by the
// k8s provider tests.

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

// createPrivateDeploy is a small test-only helper that posts a private
// deployment as a Pro team and returns the app_id. We piggy-back on the
// already-tested POST surface so the PATCH tests don't have to keep their
// own DB-insertion logic in sync with CreateDeploymentParams.
func createPrivateDeploy(t *testing.T, app httpTester, sessionJWT, initialIPs string) string {
	t.Helper()
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball-bytes"))
	require.NoError(t, err)
	require.NoError(t, w.WriteField("private", "true"))
	require.NoError(t, w.WriteField("allowed_ips", initialIPs))
	require.NoError(t, w.WriteField("name", "test deploy"))
	require.NoError(t, w.Close())

	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "precondition: POST /deploy/new must succeed before PATCH tests can run")

	var created struct {
		Item struct {
			AppID string `json:"app_id"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	require.NotEmpty(t, created.Item.AppID)
	return created.Item.AppID
}

// createPublicDeploy is the same as createPrivateDeploy but with no privacy
// fields — produces a baseline deploy we can flip private via PATCH.
func createPublicDeploy(t *testing.T, app httpTester, sessionJWT string) string {
	t.Helper()
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball-bytes"))
	require.NoError(t, err)
	require.NoError(t, w.WriteField("name", "test deploy"))
	require.NoError(t, w.Close())

	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.2")
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
	return created.Item.AppID
}

// httpTester is the minimal subset of *fiber.App we use here. Defined to keep
// the helper signatures readable without importing fiber.
type httpTester interface {
	Test(*http.Request, ...int) (*http.Response, error)
}

// jsonPatch builds an http.Request for PATCH /api/v1/deployments/:id with a
// JSON body. Centralised so each test case is two-line readable.
func jsonPatch(t *testing.T, appID, sessionJWT string, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/deployments/"+appID, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.99")
	return req
}

// TestDeployPatch_Pro_SetsPrivate is case 1: PATCH a public Pro deploy →
// private with a real IP list. The handler must flip the row and emit the
// new private + allowed_ips in the response, no rebuild required.
func TestDeployPatch_Pro_SetsPrivate(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-000000000001", teamID, "agent-patch-pro@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := createPublicDeploy(t, app, sessionJWT)

	req := jsonPatch(t, appID, sessionJWT, map[string]any{
		"private":     true,
		"allowed_ips": []string{"1.2.3.4", "10.0.0.0/8"},
	})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"PATCH flipping public→private with valid IPs must be 200; got %d, body: %s", resp.StatusCode, string(bodyBytes))

	var got struct {
		Item struct {
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &got))
	assert.True(t, got.Item.Private, "private must round-trip true on the response")
	assert.Equal(t, []string{"1.2.3.4", "10.0.0.0/8"}, got.Item.AllowedIPs,
		"allowed_ips must be the new list verbatim")

	// Confirm via GET that the row was actually persisted (not just echoed).
	getReq := httptest.NewRequest(http.MethodGet, "/deploy/"+appID, nil)
	getReq.Header.Set("Authorization", "Bearer "+sessionJWT)
	getResp, err := app.Test(getReq, 5000)
	require.NoError(t, err)
	defer getResp.Body.Close()
	var fetched struct {
		Item struct {
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&fetched))
	assert.True(t, fetched.Item.Private)
	assert.Equal(t, []string{"1.2.3.4", "10.0.0.0/8"}, fetched.Item.AllowedIPs)
}

// TestDeployPatch_ReplacesAllowedIPs is case 2: PATCH with only allowed_ips
// REPLACES the existing list (not appends). The brief explicitly picks
// REPLACE semantics — this test is the contract test that documents it.
func TestDeployPatch_ReplacesAllowedIPs(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-000000000002", teamID, "agent-patch-replace@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Existing private deploy with ["1.1.1.1","2.2.2.2"].
	appID := createPrivateDeploy(t, app, sessionJWT, "1.1.1.1,2.2.2.2")

	// PATCH with ONLY allowed_ips (no `private` field). private must stay
	// true; the list must REPLACE (not append).
	req := jsonPatch(t, appID, sessionJWT, map[string]any{
		"allowed_ips": []string{"9.9.9.9"},
	})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got struct {
		Item struct {
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.True(t, got.Item.Private, "omitting `private` must preserve the existing private=true")
	assert.Equal(t, []string{"9.9.9.9"}, got.Item.AllowedIPs,
		"allowed_ips PATCH must REPLACE the existing list — append semantics would leave 1.1.1.1 / 2.2.2.2 in there. The brief explicitly chose REPLACE.")
	assert.NotContains(t, got.Item.AllowedIPs, "1.1.1.1",
		"old IPs must be gone — append-style merging would be a silent allow-list growth bug.")
}

// TestDeployPatch_PrivateFalseClearsList is case 3: PATCH {private:false}
// drops the allow-list to empty regardless of allowed_ips in the same body.
// The invariant "public deploy has no whitelist annotation" is what's under
// test — a public deploy with a residual allow-list would be a UX trap.
func TestDeployPatch_PrivateFalseClearsList(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-000000000003", teamID, "agent-patch-public@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := createPrivateDeploy(t, app, sessionJWT, "1.1.1.1,2.2.2.2,3.3.3.3")

	req := jsonPatch(t, appID, sessionJWT, map[string]any{
		"private": false,
	})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got struct {
		Item struct {
			Private    bool     `json:"private"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"item"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.False(t, got.Item.Private, "private=false must persist")
	assert.Equal(t, []string{}, got.Item.AllowedIPs,
		"public deploy must have an empty allow-list — keeping the prior list would create a 'public but with residual rules' UX trap.")
}

// TestDeployPatch_Hobby_Returns402 is case 4: a hobby team trying to flip a
// deploy private hits the 402 wall with the same agent_action POST emits.
// Reuses AgentActionPrivateDeployRequiresPro — no separate constant for the
// PATCH path.
func TestDeployPatch_Hobby_Returns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-000000000004", teamID, "agent-patch-hobby@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Hobby can create a public deploy fine.
	appID := createPublicDeploy(t, app, sessionJWT)

	req := jsonPatch(t, appID, sessionJWT, map[string]any{
		"private":     true,
		"allowed_ips": []string{"1.2.3.4"},
	})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"hobby tier flipping private must be 402 — the contract is identical to POST /deploy/new")

	var errBody struct {
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
		UpgradeURL  string `json:"upgrade_url"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "private_deploy_requires_pro", errBody.Error,
		"error key must match POST so dashboards branch on a single code")
	assert.True(t, strings.HasPrefix(errBody.AgentAction, "Tell the user"),
		"agent_action must satisfy the U3 contract")
	assert.Contains(t, errBody.AgentAction, "https://instanode.dev/pricing",
		"agent_action must contain the full upgrade URL verbatim")
	assert.Equal(t, "https://instanode.dev/pricing", errBody.UpgradeURL,
		"upgrade_url must be set so the dashboard can render the CTA without parsing the sentence")
}

// TestDeployPatch_InvalidIP_Returns400 is case 5: an invalid CIDR/IP literal
// must surface verbatim in the 400 message — same behaviour as POST so the
// agent can feed the typo back to the human.
func TestDeployPatch_InvalidIP_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-000000000005", teamID, "agent-patch-bad-ip@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := createPublicDeploy(t, app, sessionJWT)

	const badEntry = "999.bad.literal/16"
	req := jsonPatch(t, appID, sessionJWT, map[string]any{
		"private":     true,
		"allowed_ips": []string{"1.2.3.4", badEntry},
	})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "invalid_allowed_ip", errBody.Error,
		"error key must be invalid_allowed_ip (matches POST) so agents branch identically across surfaces")
	assert.Contains(t, errBody.Message, badEntry,
		"message must include the bad literal verbatim — agent has to fix the exact thing the user typed; got %q", errBody.Message)
}

// TestDeployPatch_NotFound is case 6: PATCH on a missing deploy → 404.
func TestDeployPatch_NotFound(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-000000000006", teamID, "agent-patch-404@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := jsonPatch(t, "does-not-exist", sessionJWT, map[string]any{
		"private":     true,
		"allowed_ips": []string{"1.2.3.4"},
	})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"PATCH on a missing deploy must be 404 — must NOT leak 'forbidden' (would tell anonymous probers the id-space exists).")
}

// TestDeployPatch_CrossTeam_Returns404 is case 7: PATCHing a deploy owned by
// another team is 404, not 403. Returning 403 would confirm the deploy
// exists in another tenant — 404 keeps cross-team existence opaque and
// matches GET/DELETE/Logs/UpdateEnv/Redeploy on the same id-space.
func TestDeployPatch_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Team A owns the deploy.
	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionA := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-00000000000a", teamA, "agent-patch-owner@example.com")

	// Team B tries to PATCH it.
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionB := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-00000000000b", teamB, "agent-patch-attacker@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := createPublicDeploy(t, app, sessionA)

	req := jsonPatch(t, appID, sessionB, map[string]any{
		"private":     true,
		"allowed_ips": []string{"1.2.3.4"},
	})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team PATCH must be 404 — never confirm the deploy's existence to a non-owner.")
}

// TestDeployPatch_EmptyBody_Returns400 covers a paranoid edge: an empty {}
// body must return 400 with a clear key. Avoids silent no-ops that hide
// dashboard bugs (PrivacyPanel sending the wrong shape).
func TestDeployPatch_EmptyBody_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "a0000000-0000-0000-0000-00000000000e", teamID, "agent-patch-empty@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := createPublicDeploy(t, app, sessionJWT)

	req := jsonPatch(t, appID, sessionJWT, map[string]any{})
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "missing_fields", errBody.Error,
		"empty body must surface a distinct 'missing_fields' key (not 'invalid_body') so the dashboard can branch the message.")
}

// shut up unused-import lint when the fmt helper isn't otherwise needed —
// declared here so future cases referring to fmt.Sprintf don't break.
var _ = fmt.Sprintf
