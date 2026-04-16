//go:build e2e

package e2e

// deploy_e2e_test.go — E2E tests for POST /deploy/new (Phase 6).
//
// These tests require a running server. When the deploy service is disabled or
// k8s is unavailable (the normal case in local dev), tests that require an actual
// deployment succeed by detecting the 503 and skipping the remainder.
//
// Run with:
//
//	E2E_BASE_URL=http://localhost:30080 \
//	E2E_JWT_SECRET=<jwt-secret> \
//	go test ./e2e/... -v -tags e2e -run TestE2E_Deploy -timeout 60s

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// deployNewResponse mirrors the JSON body of POST /deploy/new.
type deployNewResponse struct {
	OK      bool   `json:"ok"`
	Token   string `json:"token"`
	URL     string `json:"url"`
	Status  string `json:"status"`
	Image   string `json:"image"`
	Tier    string `json:"tier"`
	ID      string `json:"id,omitempty"`
	Note    string `json:"note,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// TestE2E_Deploy_RequiresAuth verifies that POST /deploy/new returns 401
// when no Authorization header is supplied.
func TestE2E_Deploy_RequiresAuth(t *testing.T) {
	resp := post(t, "/deploy/new", map[string]any{
		"image": "nginx:latest",
		"port":  80,
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}

	var body deployNewResponse
	decodeJSON(t, resp, &body)
	if body.OK {
		t.Errorf("expected ok=false, got true")
	}
	if body.Error != "unauthorized" {
		t.Errorf("expected error=unauthorized, got %q", body.Error)
	}
}

// TestE2E_Deploy_ServiceDisabled_Or_ValidShape verifies the endpoint behaviour
// when called with a valid JWT:
//   - 503 (service disabled or k8s unavailable) → logs and passes; expected in local dev.
//   - 201 → verifies the response has the correct shape.
//   - 400 → acceptable when the synthetic team UUID has no DB row.
//   - anything else → test FAILS.
func TestE2E_Deploy_ServiceDisabled_Or_ValidShape(t *testing.T) {
	// makeSessionJWT skips the test when E2E_JWT_SECRET is not set.
	teamID := uuid.NewString()
	sessionJWT := makeSessionJWT(t, teamID, "deploy-e2e@instant.dev")

	resp := post(t, "/deploy/new",
		map[string]any{
			"image": "nginx:latest",
			"port":  80,
			"name":  "e2e-test",
		},
		"Authorization", "Bearer "+sessionJWT,
	)

	switch resp.StatusCode {
	case http.StatusServiceUnavailable:
		// Expected when running outside k8s or deploy service is disabled.
		var body deployNewResponse
		decodeJSON(t, resp, &body)
		t.Logf("deploy service disabled/unavailable (expected in local dev): error=%s message=%s",
			body.Error, body.Message)
		// Not a failure.

	case http.StatusCreated:
		// Deploy succeeded — verify response shape.
		var body deployNewResponse
		decodeJSON(t, resp, &body)
		if !body.OK {
			t.Errorf("expected ok=true, got false; message=%q", body.Message)
		}
		if body.Token == "" {
			t.Error("expected non-empty token")
		}
		if len(body.Token) != 8 {
			t.Errorf("expected 8-char token, got %q (len %d)", body.Token, len(body.Token))
		}
		if body.URL == "" {
			t.Error("expected non-empty url")
		}
		if body.Status != "healthy" && body.Status != "running" {
			t.Errorf("expected status healthy or running, got %q", body.Status)
		}
		if body.Image == "" {
			t.Error("expected non-empty image")
		}
		t.Logf("deploy succeeded: token=%s url=%s status=%s", body.Token, body.URL, body.Status)

	case http.StatusBadRequest:
		// Synthetic team UUID has no DB row — expected.
		var body deployNewResponse
		decodeJSON(t, resp, &body)
		t.Logf("deploy returned 400 (expected with synthetic team UUID): error=%s message=%s",
			body.Error, body.Message)

	default:
		body := readBody(t, resp)
		t.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}
}
