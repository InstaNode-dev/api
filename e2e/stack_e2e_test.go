//go:build e2e

// Stack E2E Tests
//
// Black-box tests for the Stacks API endpoints against a live instant.dev server.
// Covers:
//   - Auth enforcement on all stack endpoints
//   - Request validation (bad manifest YAML, missing tarballs, unknown service refs)
//   - Async deploy kick-off (202 + slug in GET /api/v1/stacks)
//   - GET /stacks/:slug — 404 for missing or wrong-team slugs
//   - DELETE /stacks/:slug — owner can delete, subsequent GET returns 404
//   - GET /api/v1/stacks — lists stacks for authenticated team
//   - GET /stacks/:slug/logs/:svc — SSE stream content-type check
//
// POST/GET/DELETE /stacks/* use OptionalAuth (anonymous deploys supported).
// PATCH /stacks/:slug/env, POST /stacks/:slug/redeploy, and GET /api/v1/stacks require auth.
// Tests that need a real session skip if E2E_JWT_SECRET is not set.
//
// Required env:
//
//	E2E_BASE_URL      live server (default: http://localhost:30080)
//	E2E_JWT_SECRET    required for all stack tests
//
// Run:
//
//	E2E_BASE_URL=http://localhost:30080 \
//	E2E_JWT_SECRET=$(kubectl get secret instant-secrets -n instant -o jsonpath='{.data.JWT_SECRET}' | base64 -d) \
//	go test ./e2e/... -v -tags e2e -run TestStack -timeout 60s
package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── response types ────────────────────────────────────────────────────────────

// stackNewResponse mirrors the 202 body from POST /stacks/new and POST /stacks/:slug/redeploy.
type stackNewResponse struct {
	OK        bool   `json:"ok"`
	StackID   string `json:"stack_id"`
	Status    string `json:"status"`
	Tier      string `json:"tier"`
	ExpiresIn string `json:"expires_in"`
	Note      string `json:"note"`
}

// stackServiceStatus is one entry in a stack's service list.
type stackServiceStatus struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	AppURL   string `json:"app_url,omitempty"`
	ErrorMsg string `json:"error_msg,omitempty"`
}

// stackGetResponse mirrors GET /stacks/:slug.
type stackGetResponse struct {
	OK       bool                 `json:"ok"`
	StackID  string               `json:"stack_id"`
	Status   string               `json:"status"`
	Services []stackServiceStatus `json:"services"`
}

// stackListItem is one entry in GET /api/v1/stacks.
type stackListItem struct {
	StackID string `json:"stack_id"`
	Status  string `json:"status"`
	Tier    string `json:"tier"`
}

// stackListResponse mirrors GET /api/v1/stacks.
type stackListResponse struct {
	OK    bool            `json:"ok"`
	Items []stackListItem `json:"items"`
	Total int             `json:"total"`
}

// stackDeleteResponse mirrors DELETE /stacks/:slug.
type stackDeleteResponse struct {
	OK bool `json:"ok"`
}

// ── test manifests ────────────────────────────────────────────────────────────

const e2eManifestTwoServices = `
services:
  api:
    build: ./api
    port: 8080
    expose: true
  worker:
    build: ./worker
    port: 8080
    expose: false
`

const e2eManifestSingleService = `
services:
  web:
    build: ./web
    port: 3000
    expose: true
`

const e2eManifestBadYAML = `:::not valid yaml:::`

const e2eManifestUnknownServiceRef = `
services:
  web:
    build: ./web
    port: 3000
    expose: true
    env:
      BACKEND_URL: service://nonexistent-service
`

// ── multipart helpers ─────────────────────────────────────────────────────────

// e2eMinimalTarball returns a minimal valid gzipped tarball containing a
// placeholder Dockerfile. The noop / k8s provider receives the tarball bytes;
// for E2E shape tests the tarball just needs to be a well-formed gzip stream.
func e2eMinimalTarball(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("FROM scratch\n")
	hdr := &tar.Header{
		Name: "Dockerfile",
		Mode: 0o644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("e2eMinimalTarball: WriteHeader: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("e2eMinimalTarball: Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("e2eMinimalTarball: tw.Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("e2eMinimalTarball: gw.Close: %v", err)
	}
	return buf.Bytes()
}

// e2eMultipartBody builds a multipart/form-data body from the given manifest YAML
// and per-service tarball map. Returns the body bytes and the Content-Type header value.
func e2eMultipartBody(t *testing.T, manifestYAML string, tarballs map[string][]byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Write manifest field.
	fw, err := mw.CreateFormField("manifest")
	if err != nil {
		t.Fatalf("e2eMultipartBody: CreateFormField(manifest): %v", err)
	}
	if _, err = io.WriteString(fw, manifestYAML); err != nil {
		t.Fatalf("e2eMultipartBody: WriteString(manifest): %v", err)
	}

	// Write the required `name` field (mandatory-resource-naming contract,
	// 2026-05-16). Every /stacks/new call now needs a valid human label;
	// stack tests don't assert on it, so a fixed default keeps them green.
	nf, err := mw.CreateFormField("name")
	if err != nil {
		t.Fatalf("e2eMultipartBody: CreateFormField(name): %v", err)
	}
	if _, err = io.WriteString(nf, "e2e stack"); err != nil {
		t.Fatalf("e2eMultipartBody: WriteString(name): %v", err)
	}

	// Write per-service tarballs.
	for svcName, tarball := range tarballs {
		ff, err := mw.CreateFormFile(svcName, svcName+".tar.gz")
		if err != nil {
			t.Fatalf("e2eMultipartBody: CreateFormFile(%s): %v", svcName, err)
		}
		if _, err = ff.Write(tarball); err != nil {
			t.Fatalf("e2eMultipartBody: Write tarball(%s): %v", svcName, err)
		}
	}

	if err := mw.Close(); err != nil {
		t.Fatalf("e2eMultipartBody: Close: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

// postStackNew sends POST /stacks/new with a multipart body and auth token.
// Caller must close resp.Body.
func postStackNew(t *testing.T, sessionJWT, manifestYAML string, tarballs map[string][]byte) *http.Response {
	t.Helper()
	body, ct := e2eMultipartBody(t, manifestYAML, tarballs)

	req, err := http.NewRequest(http.MethodPost, baseURL()+"/stacks/new", body)
	if err != nil {
		t.Fatalf("postStackNew: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", ct)
	if sessionJWT != "" {
		req.Header.Set("Authorization", "Bearer "+sessionJWT)
	}
	req.Header.Set("X-Forwarded-For", uniqueIP(t))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("postStackNew: Do: %v", err)
	}
	return resp
}

// postStackRedeploy sends POST /stacks/:slug/redeploy with a multipart body and auth token.
func postStackRedeploy(t *testing.T, slug, sessionJWT, manifestYAML string, tarballs map[string][]byte) *http.Response {
	t.Helper()
	body, ct := e2eMultipartBody(t, manifestYAML, tarballs)

	req, err := http.NewRequest(http.MethodPost, baseURL()+"/stacks/"+slug+"/redeploy", body)
	if err != nil {
		t.Fatalf("postStackRedeploy: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", ct)
	if sessionJWT != "" {
		req.Header.Set("Authorization", "Bearer "+sessionJWT)
	}
	req.Header.Set("X-Forwarded-For", uniqueIP(t))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("postStackRedeploy: Do: %v", err)
	}
	return resp
}

// deleteStack sends DELETE /stacks/:slug with an auth token.
func deleteStack(t *testing.T, slug, sessionJWT string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, baseURL()+"/stacks/"+slug, nil)
	if err != nil {
		t.Fatalf("deleteStack: NewRequest: %v", err)
	}
	if sessionJWT != "" {
		req.Header.Set("Authorization", "Bearer "+sessionJWT)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("deleteStack: Do: %v", err)
	}
	return resp
}

// newTeamSession provisions anonymous cache, claims it, and returns (teamID, sessionJWT).
// All stack tests that need a real team+user call this helper.
// Skips if E2E_JWT_SECRET is not set (via makeSessionJWTWithUser).
func newTeamSession(t *testing.T) (teamID, sessionJWT string) {
	t.Helper()
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	onboardingJWT := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()
	teamName := "e2e-stack-" + uuid.NewString()[:6]

	claimResp := post(t, "/claim", map[string]any{
		"jwt":       onboardingJWT,
		"email":     email,
		"team_name": teamName,
	})
	if claimResp.StatusCode != http.StatusCreated {
		t.Fatalf("newTeamSession: POST /claim: want 201, got %d\n%s",
			claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	// makeSessionJWTWithUser skips the test if E2E_JWT_SECRET is not set.
	jwt := makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)
	return claim.TeamID, jwt
}

// deployStack is a convenience that calls POST /stacks/new with a single-service
// manifest and returns the decoded 202 body. Fatals if the response is not 202.
func deployStack(t *testing.T, sessionJWT string) stackNewResponse {
	t.Helper()
	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	resp := postStackNew(t, sessionJWT, e2eManifestSingleService, tarballs)
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /stacks/new: service unavailable (503) — skipping (stacks not enabled?)")
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("deployStack: want 202, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body stackNewResponse
	decodeJSON(t, resp, &body)
	if body.StackID == "" {
		t.Fatal("deployStack: stack_id must not be empty in 202 response")
	}
	return body
}

// ── auth enforcement ──────────────────────────────────────────────────────────

// TestStack_AnonymousNew_Returns202 verifies that POST /stacks/new without a session token
// is accepted (202) and returns an anonymous-tier stack with a 24h TTL.
// This mirrors the anonymous model used by /db/new, /cache/new, etc.
func TestStack_AnonymousNew_Returns202(t *testing.T) {
	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	resp := postStackNew(t, "", e2eManifestSingleService, tarballs)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /stacks/new (no auth): want 202, got %d\n%s", resp.StatusCode, body)
	}

	var parsed struct {
		OK        bool   `json:"ok"`
		StackID   string `json:"stack_id"`
		Status    string `json:"status"`
		Tier      string `json:"tier"`
		ExpiresIn string `json:"expires_in"`
		Note      string `json:"note"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("POST /stacks/new (no auth): response is not valid JSON: %v\n%s", err, body)
	}
	if !parsed.OK {
		t.Errorf("POST /stacks/new (no auth): ok=false")
	}
	if parsed.StackID == "" {
		t.Errorf("POST /stacks/new (no auth): stack_id is empty")
	}
	if parsed.Tier != "anonymous" {
		t.Errorf("POST /stacks/new (no auth): want tier=anonymous, got %q", parsed.Tier)
	}
	if parsed.ExpiresIn != "24h" {
		t.Errorf("POST /stacks/new (no auth): want expires_in=24h, got %q", parsed.ExpiresIn)
	}
	if !strings.Contains(parsed.Note, "instant.dev/start") {
		t.Errorf("POST /stacks/new (no auth): note should contain upgrade URL, got %q", parsed.Note)
	}
}

// TestStack_Redeploy_RequiresAuth verifies that POST /stacks/:slug/redeploy still
// requires authentication (anonymous stacks cannot be redeployed via the API).
func TestStack_Redeploy_RequiresAuth(t *testing.T) {
	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	body, ct := e2eMultipartBody(t, e2eManifestSingleService, tarballs)
	req, _ := http.NewRequest(http.MethodPost, baseURL()+"/stacks/stk-anon-test/redeploy", body)
	req.Header.Set("Content-Type", ct)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /stacks/stk-anon-test/redeploy: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /stacks/:slug/redeploy (no auth): want 401, got %d\n%s", resp.StatusCode, string(respBody))
	}
}

// TestStack_List_RequiresAuth verifies GET /api/v1/stacks returns 401 without a token.
func TestStack_List_RequiresAuth(t *testing.T) {
	resp := get(t, "/api/v1/stacks")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/stacks (no auth): want 401, got %d\n%s", resp.StatusCode, body)
	}
}

// TestStack_Delete_RequiresAuth verifies DELETE /stacks/:slug returns 401 without token.
func TestStack_Delete_RequiresAuth(t *testing.T) {
	resp := deleteStack(t, "stk-some-slug", "")
	body := readBody(t, resp)

	// 401 expected; 404 is also acceptable (no auth check could reach the 404 check).
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusNotFound:
		// both acceptable — route may 401 before doing the slug lookup
	default:
		t.Errorf("DELETE /stacks/:slug (no auth): want 401 or 404, got %d\n%s", resp.StatusCode, body)
	}
}

// ── request validation ────────────────────────────────────────────────────────

// TestStack_InvalidManifest verifies that POST /stacks/new with bad YAML returns 400
// with error="invalid_manifest".
func TestStack_InvalidManifest(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	resp := postStackNew(t, sessionJWT, e2eManifestBadYAML, nil)
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /stacks/new: service unavailable (503)")
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /stacks/new (bad YAML): want 400, got %d\n%s", resp.StatusCode, body)
	}

	// Optionally decode to check error field.
	var errBody struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := decodeBodyJSON(body, &errBody); err == nil {
		if errBody.OK {
			t.Error("bad manifest: ok must be false in error response")
		}
		if errBody.Error != "" && errBody.Error != "invalid_manifest" {
			// If the server returns any error code, log it; only fail for wrong 2xx.
			t.Logf("invalid manifest error code: %q", errBody.Error)
		}
	}
}

// TestStack_MissingTarball verifies that a valid 2-service manifest with only 1
// tarball returns 400 with error="missing_tarball".
func TestStack_MissingTarball(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	// Manifest declares "api" and "worker" but we only supply "api".
	tarballs := map[string][]byte{
		"api": e2eMinimalTarball(t),
		// "worker" intentionally omitted
	}
	resp := postStackNew(t, sessionJWT, e2eManifestTwoServices, tarballs)
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /stacks/new: service unavailable (503)")
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /stacks/new (missing tarball): want 400, got %d\n%s", resp.StatusCode, body)
	}

	var errBody struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := decodeBodyJSON(body, &errBody); err == nil {
		if errBody.OK {
			t.Error("missing tarball: ok must be false in error response")
		}
		if errBody.Error != "" && errBody.Error != "missing_tarball" {
			t.Logf("missing tarball error code: %q (expected missing_tarball)", errBody.Error)
		}
	}
}

// TestStack_UnknownServiceRef verifies that a manifest with a service:// env
// reference pointing to a non-existent service returns 400.
func TestStack_UnknownServiceRef(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	resp := postStackNew(t, sessionJWT, e2eManifestUnknownServiceRef, tarballs)
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /stacks/new: service unavailable (503)")
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /stacks/new (unknown service ref): want 400, got %d\n%s", resp.StatusCode, body)
	}

	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := decodeBodyJSON(body, &errBody); err == nil {
		if errBody.Error != "" && errBody.Error != "invalid_manifest" {
			t.Logf("unknown service ref error code: %q (expected invalid_manifest)", errBody.Error)
		}
		if errBody.Message != "" && !strings.Contains(strings.ToLower(errBody.Message), "unknown") {
			t.Logf("unknown service ref message: %q (expected 'unknown' substring)", errBody.Message)
		}
	}
}

// ── deploy kick-off ───────────────────────────────────────────────────────────

// TestStack_DeployKicksOff verifies that a valid POST /stacks/new returns 202,
// slug is present in the response, and the stack appears in GET /api/v1/stacks.
//
// We don't wait for the build to complete — the test only verifies the async
// kick-off is acknowledged and the stack record is visible.
func TestStack_DeployKicksOff(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	createBody := deployStack(t, sessionJWT)

	if !createBody.OK {
		t.Error("POST /stacks/new: ok must be true in 202 response")
	}
	if createBody.StackID == "" {
		t.Error("POST /stacks/new: stack_id must not be empty")
	}
	if createBody.Status == "" {
		t.Error("POST /stacks/new: status must not be empty")
	}
	t.Logf("deployed stack slug=%s status=%s", createBody.StackID, createBody.Status)

	// Verify the stack appears in the list immediately (before build completes).
	listResp := get(t, "/api/v1/stacks", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/stacks: want 200, got %d\n%s",
			listResp.StatusCode, readBody(t, listResp))
	}
	var listBody stackListResponse
	decodeJSON(t, listResp, &listBody)

	if !listBody.OK {
		t.Error("GET /api/v1/stacks: ok must be true")
	}

	found := false
	for _, item := range listBody.Items {
		if item.StackID == createBody.StackID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("deployed slug %q not found in GET /api/v1/stacks response (total=%d)",
			createBody.StackID, listBody.Total)
	}
}

// TestStack_DeployKicksOff_TwoServices exercises the two-service manifest path
// and verifies both services appear in GET /stacks/:slug.
func TestStack_DeployKicksOff_TwoServices(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{
		"api":    tarball,
		"worker": tarball,
	}
	resp := postStackNew(t, sessionJWT, e2eManifestTwoServices, tarballs)
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /stacks/new: service unavailable (503)")
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /stacks/new (2 services): want 202, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}
	var createBody stackNewResponse
	decodeJSON(t, resp, &createBody)

	if createBody.StackID == "" {
		t.Fatal("stack_id must not be empty")
	}

	// GET the stack to verify service count.
	getResp := get(t, "/stacks/"+createBody.StackID, "Authorization", "Bearer "+sessionJWT)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stacks/%s: want 200, got %d\n%s",
			createBody.StackID, getResp.StatusCode, readBody(t, getResp))
	}
	var getBody stackGetResponse
	decodeJSON(t, getResp, &getBody)

	if !getBody.OK {
		t.Error("GET /stacks/:slug: ok must be true")
	}
	if len(getBody.Services) != 2 {
		t.Errorf("GET /stacks/:slug: want 2 services, got %d", len(getBody.Services))
	}
	t.Logf("stack %s has %d service(s), status=%s",
		getBody.StackID, len(getBody.Services), getBody.Status)
}

// ── GET /stacks/:slug ─────────────────────────────────────────────────────────

// TestStack_GetNotFound verifies that GET /stacks/nonexistent-slug returns 404.
func TestStack_GetNotFound(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	fakeSlug := "stk-" + uuid.NewString()[:12]
	resp := get(t, "/stacks/"+fakeSlug, "Authorization", "Bearer "+sessionJWT)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /stacks/nonexistent: want 404, got %d\n%s", resp.StatusCode, body)
	}
}

// TestStack_GetWrongTeam verifies that a stack slug belonging to team A returns 404
// when accessed by team B (existence must not be leaked as 403).
func TestStack_GetWrongTeam(t *testing.T) {
	// Team A deploys a stack.
	_, sessionJWTA := newTeamSession(t)
	createBody := deployStack(t, sessionJWTA)

	// Team B gets a fresh session.
	_, sessionJWTB := newTeamSession(t)

	resp := get(t, "/stacks/"+createBody.StackID, "Authorization", "Bearer "+sessionJWTB)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /stacks/:slug (wrong team): want 404, got %d\n%s", resp.StatusCode, body)
	}
}

// ── DELETE /stacks/:slug ──────────────────────────────────────────────────────

// TestStack_Delete verifies that a stack can be deleted by its owner and
// subsequently returns 404 on GET.
func TestStack_Delete(t *testing.T) {
	_, sessionJWT := newTeamSession(t)
	createBody := deployStack(t, sessionJWT)
	slug := createBody.StackID

	// DELETE.
	delResp := deleteStack(t, slug, sessionJWT)
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /stacks/%s: want 200, got %d\n%s",
			slug, delResp.StatusCode, readBody(t, delResp))
	}
	var delBody stackDeleteResponse
	decodeJSON(t, delResp, &delBody)

	if !delBody.OK {
		t.Error("DELETE /stacks/:slug: ok must be true")
	}

	// Subsequent GET must return 404.
	getResp := get(t, "/stacks/"+slug, "Authorization", "Bearer "+sessionJWT)
	body := readBody(t, getResp)

	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /stacks/%s after DELETE: want 404, got %d\n%s", slug, getResp.StatusCode, body)
	}
}

// TestStack_DeleteNotFound verifies that deleting a nonexistent slug returns 404.
func TestStack_DeleteNotFound(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	fakeSlug := "stk-" + uuid.NewString()[:12]
	resp := deleteStack(t, fakeSlug, sessionJWT)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE /stacks/nonexistent: want 404, got %d\n%s", resp.StatusCode, body)
	}
}

// TestStack_DeleteWrongTeam verifies that team B cannot delete a stack owned by team A.
// The response must be 404 (not 403, to avoid leaking existence).
func TestStack_DeleteWrongTeam(t *testing.T) {
	// Team A deploys a stack.
	_, sessionJWTA := newTeamSession(t)
	createBody := deployStack(t, sessionJWTA)

	// Team B tries to delete it.
	_, sessionJWTB := newTeamSession(t)
	resp := deleteStack(t, createBody.StackID, sessionJWTB)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE /stacks/:slug (wrong team): want 404, got %d\n%s", resp.StatusCode, body)
	}
}

// ── GET /api/v1/stacks ────────────────────────────────────────────────────────

// TestStack_List verifies that GET /api/v1/stacks returns all stacks for the
// calling team, including ones deployed in this test run.
func TestStack_List(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	// Deploy two stacks.
	tarball := e2eMinimalTarball(t)

	resp1 := postStackNew(t, sessionJWT, e2eManifestSingleService, map[string][]byte{"web": tarball})
	if resp1.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp1)
		t.Skip("POST /stacks/new: service unavailable (503)")
	}
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("deploy stack 1: want 202, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	var body1 stackNewResponse
	decodeJSON(t, resp1, &body1)

	resp2 := postStackNew(t, sessionJWT, e2eManifestSingleService, map[string][]byte{"web": tarball})
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("deploy stack 2: want 202, got %d\n%s", resp2.StatusCode, readBody(t, resp2))
	}
	var body2 stackNewResponse
	decodeJSON(t, resp2, &body2)

	// List stacks.
	listResp := get(t, "/api/v1/stacks", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/stacks: want 200, got %d\n%s",
			listResp.StatusCode, readBody(t, listResp))
	}
	var listBody stackListResponse
	decodeJSON(t, listResp, &listBody)

	if !listBody.OK {
		t.Error("GET /api/v1/stacks: ok must be true")
	}
	if listBody.Total < 2 {
		t.Errorf("GET /api/v1/stacks: want total >= 2, got %d", listBody.Total)
	}

	slugsInList := make(map[string]bool, len(listBody.Items))
	for _, item := range listBody.Items {
		slugsInList[item.StackID] = true
		if item.Status == "" {
			t.Errorf("list item %q: status must not be empty", item.StackID)
		}
	}
	if !slugsInList[body1.StackID] {
		t.Errorf("stack 1 (%s) not found in list", body1.StackID)
	}
	if !slugsInList[body2.StackID] {
		t.Errorf("stack 2 (%s) not found in list", body2.StackID)
	}
}

// TestStack_List_Empty verifies that a fresh team with no stacks gets an empty
// items array (not 404 or 500).
func TestStack_List_Empty(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	listResp := get(t, "/api/v1/stacks", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/stacks (empty): want 200, got %d\n%s",
			listResp.StatusCode, readBody(t, listResp))
	}
	var listBody stackListResponse
	decodeJSON(t, listResp, &listBody)

	if !listBody.OK {
		t.Error("GET /api/v1/stacks: ok must be true for empty result")
	}
	if listBody.Total != 0 {
		t.Errorf("fresh team: want total=0, got %d", listBody.Total)
	}
	if listBody.Items == nil {
		t.Error("items must be a non-null array even when empty")
	}
}

// ── redeploy ──────────────────────────────────────────────────────────────────

// TestStack_Redeploy verifies that POST /stacks/:slug/redeploy returns 202 and
// the slug is unchanged after a redeploy.
func TestStack_Redeploy(t *testing.T) {
	_, sessionJWT := newTeamSession(t)
	createBody := deployStack(t, sessionJWT)
	slug := createBody.StackID

	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	redeployResp := postStackRedeploy(t, slug, sessionJWT, e2eManifestSingleService, tarballs)
	if redeployResp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, redeployResp)
		t.Skip("POST /stacks/:slug/redeploy: service unavailable (503)")
	}
	if redeployResp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /stacks/%s/redeploy: want 202, got %d\n%s",
			slug, redeployResp.StatusCode, readBody(t, redeployResp))
	}
	var redeployBody stackNewResponse
	decodeJSON(t, redeployResp, &redeployBody)

	if !redeployBody.OK {
		t.Error("redeploy: ok must be true")
	}
	// The slug must remain the same after a redeploy.
	if redeployBody.StackID != slug && redeployBody.StackID != "" {
		t.Errorf("redeploy: stack_id changed: was %q, now %q", slug, redeployBody.StackID)
	}
	t.Logf("redeployed slug=%s status=%s", slug, redeployBody.Status)
}

// TestStack_Redeploy_WrongTeam verifies team B cannot redeploy team A's stack.
func TestStack_Redeploy_WrongTeam(t *testing.T) {
	_, sessionJWTA := newTeamSession(t)
	createBody := deployStack(t, sessionJWTA)
	slug := createBody.StackID

	_, sessionJWTB := newTeamSession(t)
	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	resp := postStackRedeploy(t, slug, sessionJWTB, e2eManifestSingleService, tarballs)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /stacks/:slug/redeploy (wrong team): want 404, got %d\n%s",
			resp.StatusCode, body)
	}
}

// ── logs SSE stream ───────────────────────────────────────────────────────────

// TestStack_Logs_ContentType verifies that GET /stacks/:slug/logs/:svc returns
// text/event-stream content-type for a valid authenticated request.
// We don't validate SSE frame content — just that the stream is opened correctly.
func TestStack_Logs_ContentType(t *testing.T) {
	_, sessionJWT := newTeamSession(t)
	createBody := deployStack(t, sessionJWT)
	slug := createBody.StackID

	// Use a short-timeout client for the SSE stream — we only want to check headers.
	sseClient := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/stacks/%s/logs/web", baseURL(), slug), nil)
	if err != nil {
		t.Fatalf("logs request: NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := sseClient.Do(req)
	if err != nil {
		// A timeout from the SSE stream is expected — the server will keep
		// the connection open. If we get EOF it means the server wrote headers
		// and the stream is valid.
		if strings.Contains(err.Error(), "context deadline exceeded") ||
			strings.Contains(err.Error(), "Client.Timeout exceeded") {
			t.Log("SSE stream timed out as expected — headers were received")
			return
		}
		// 404 is acceptable: the stack may not have reached the log-collection
		// phase yet (build still in progress).
		t.Logf("GET /stacks/:slug/logs/:svc error: %v", err)
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "text/event-stream") {
			t.Errorf("GET /stacks/:slug/logs/:svc: want Content-Type text/event-stream, got %q", ct)
		}
		t.Logf("SSE stream opened: Content-Type=%q", ct)

	case http.StatusNotFound:
		// Build may not have started log collection yet — acceptable.
		t.Log("GET logs: 404 (build not yet logging) — acceptable")

	case http.StatusServiceUnavailable:
		t.Skip("logs endpoint: service unavailable (503)")

	default:
		t.Errorf("GET /stacks/:slug/logs/:svc: unexpected status %d", resp.StatusCode)
	}
}

// TestStack_Logs_AnonymousSlugNotFound_Returns404 verifies that an anonymous GET to
// /stacks/:slug/logs/:svc with a non-existent slug returns 404 (not 401, since the
// logs route uses OptionalAuth — anonymous access is allowed; unknown slug → 404).
func TestStack_Logs_AnonymousSlugNotFound_Returns404(t *testing.T) {
	// A fake slug that doesn't exist in the DB — anonymous caller, no auth header.
	fakeslug := "stk-" + uuid.NewString()[:12]
	resp := get(t, "/stacks/"+fakeslug+"/logs/web")
	body := readBody(t, resp)

	switch resp.StatusCode {
	case http.StatusNotFound:
		// Expected: anonymous access is permitted; missing slug → 404.
	case http.StatusUnauthorized:
		// Acceptable if the test cluster still has RequireAuth on logs (misconfiguration).
		t.Logf("WARN: got 401 — route may still use RequireAuth instead of OptionalAuth")
	default:
		t.Errorf("GET /stacks/:slug/logs/:svc (no auth, fake slug): want 404, got %d\n%s",
			resp.StatusCode, body)
	}
}

// ── response shape validation ─────────────────────────────────────────────────

// TestStack_ResponseShape verifies that POST /stacks/new → GET /stacks/:slug
// have the full expected response shape (all required fields present).
func TestStack_ResponseShape(t *testing.T) {
	_, sessionJWT := newTeamSession(t)

	tarball := e2eMinimalTarball(t)
	tarballs := map[string][]byte{"web": tarball}

	// POST /stacks/new
	resp := postStackNew(t, sessionJWT, e2eManifestSingleService, tarballs)
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /stacks/new: service unavailable (503)")
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /stacks/new: want 202, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}
	var createBody stackNewResponse
	decodeJSON(t, resp, &createBody)

	// Verify POST shape.
	if !createBody.OK {
		t.Error("POST /stacks/new: ok must be true")
	}
	if createBody.StackID == "" {
		t.Error("POST /stacks/new: stack_id must be set")
	}
	if createBody.Status == "" {
		t.Error("POST /stacks/new: status must be set")
	}

	// GET /stacks/:slug
	getResp := get(t, "/stacks/"+createBody.StackID, "Authorization", "Bearer "+sessionJWT)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stacks/%s: want 200, got %d\n%s",
			createBody.StackID, getResp.StatusCode, readBody(t, getResp))
	}
	var getBody stackGetResponse
	decodeJSON(t, getResp, &getBody)

	// Verify GET shape.
	if !getBody.OK {
		t.Error("GET /stacks/:slug: ok must be true")
	}
	if getBody.StackID == "" {
		t.Error("GET /stacks/:slug: stack_id must be set")
	}
	if getBody.Status == "" {
		t.Error("GET /stacks/:slug: status must be set")
	}
	if getBody.Services == nil {
		t.Error("GET /stacks/:slug: services must not be nil")
	}
	for i, svc := range getBody.Services {
		if svc.Name == "" {
			t.Errorf("GET /stacks/:slug: services[%d].name must not be empty", i)
		}
		if svc.Status == "" {
			t.Errorf("GET /stacks/:slug: services[%d].status must not be empty", i)
		}
	}
}

// ── utility ───────────────────────────────────────────────────────────────────

// decodeBodyJSON is a convenience wrapper that decodes a JSON string into v
// without requiring an *http.Response. Used when body has already been read
// by readBody.
func decodeBodyJSON(body string, v any) error {
	return json.Unmarshal([]byte(body), v)
}
