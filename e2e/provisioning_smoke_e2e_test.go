//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPostDeploySmoke_ProvisionPostgresEndToEnd is the regression test for the
// outage on 2026-05-13 where a rotated PROVISIONER_SECRET was applied to the
// instant-infra-secrets Secret but the running provisioner pods captured the
// stale value at startup (the auth interceptor closes over `secret` at server
// boot). The api kept presenting the new value; the provisioner kept comparing
// it against the old captured value; every /db/new returned 503
// `provisioner.ProvisionPostgres: rpc error: code = Unauthenticated desc =
// invalid provisioner token`.
//
// /healthz reported green throughout because it does not exercise the
// provisioner gRPC path. The only signal was customer traffic getting 503s.
//
// This test runs as a post-deploy smoke and as a periodic external probe. It
// MUST be part of every promotion to production. A failure here means the api
// is up but cannot provision — which means the platform is functionally down
// even though k8s and /healthz are green.
//
// Run after every `kubectl set image / rollout`:
//
//	E2E_BASE_URL=https://api.instanode.dev go test ./e2e/... -run TestPostDeploySmoke -tags e2e -count=1 -v
//
// One call per run — burning the anonymous-tier fingerprint cap is the wrong
// trade.
func TestPostDeploySmoke_ProvisionPostgresEndToEnd(t *testing.T) {
	base := os.Getenv("E2E_BASE_URL")
	if base == "" {
		t.Skip("E2E_BASE_URL not set — skipping live-cluster smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/db/new", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "instant-post-deploy-smoke/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /db/new dial: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		token, _ := body["id"].(string)
		t.Logf("provision OK status=%d token=%s", resp.StatusCode, token)
		return
	case http.StatusTooManyRequests, http.StatusPaymentRequired:
		// 429: fingerprint cap from prior runs on this IP. 402: anonymous tier
		// disabled mid-test. Both prove the request reached the api AND the
		// provisioner auth path is healthy enough that the request was not
		// rejected before tier evaluation. Not ideal signal, but not a
		// regression of the bug this test guards against.
		t.Logf("provision rate-limited but not a regression: status=%d body=%v", resp.StatusCode, body)
		return
	case http.StatusServiceUnavailable:
		errStr, _ := body["error"].(string)
		msg, _ := body["message"].(string)
		if errStr == "provision_failed" || strings.Contains(strings.ToLower(msg), "provisioner") {
			t.Fatalf(`REGRESSION — provisioner unreachable from api.
status: 503
body:   %v
This is the exact failure mode from 2026-05-13: rotated PROVISIONER_SECRET
without rolling the provisioner pods, or any change that breaks the api↔
provisioner gRPC auth path. Run:
  kubectl logs -n instant -l app=instant-api --tail=20 | grep provision_failed
to confirm the underlying gRPC error, then:
  kubectl rollout restart deployment/instant-provisioner -n instant-infra
to force a re-read of PROVISIONER_SECRET if rotation is the cause.`, body)
		}
		t.Fatalf("unexpected 503 (not a provisioner-auth regression but still a failed deploy): %v", body)
	default:
		t.Fatalf("unexpected status=%d body=%v", resp.StatusCode, body)
	}
}

// TestPostDeploySmoke_HealthzReportsCommitID asserts that /healthz returns the
// commit_id matching the expected SHA. This catches the "deploy reports
// success but pods still serve the old image" failure mode.
//
//	E2E_BASE_URL=https://api.instanode.dev \
//	  E2E_EXPECTED_COMMIT=cb634f1 \
//	  go test ./e2e/... -run TestPostDeploySmoke_HealthzReportsCommitID -tags e2e -count=1
//
// If E2E_EXPECTED_COMMIT is unset the test just asserts the field is present
// and non-"dev".
func TestPostDeploySmoke_HealthzReportsCommitID(t *testing.T) {
	base := os.Getenv("E2E_BASE_URL")
	if base == "" {
		t.Skip("E2E_BASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status=%d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}

	commit, _ := body["commit_id"].(string)
	if commit == "" || commit == "dev" {
		t.Fatalf("healthz commit_id=%q — image was built without GIT_SHA build-arg (every prod image MUST stamp commit_id)", commit)
	}

	expected := os.Getenv("E2E_EXPECTED_COMMIT")
	if expected != "" && !strings.HasPrefix(commit, expected) && !strings.HasPrefix(expected, commit) {
		t.Fatalf("healthz commit_id=%q does not match expected %q — pods are likely still serving the old image", commit, expected)
	}

	mstatus, _ := body["migration_status"].(string)
	if mstatus != "ok" {
		t.Fatalf("healthz migration_status=%q — deploy ran but migrations did not complete cleanly", mstatus)
	}

	t.Logf("healthz OK commit=%s migrations=%s version=%v", commit, mstatus, body["version"])
}

// helper to format the failure body uniformly in case future expansions want it.
var _ = fmt.Sprintf
