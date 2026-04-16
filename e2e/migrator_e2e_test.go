//go:build e2e

// Persona C — The Migrator
//
// Tests the migrator HTTP API directly. The migrator runs in instant-infra
// and is not exposed as a NodePort by default — expose it for testing:
//
//	kubectl port-forward -n instant-infra svc/instant-migrator 8090:8090 &
//	export E2E_MIGRATOR_URL=http://localhost:8090
//	export E2E_MIGRATOR_SECRET=$(kubectl get secret instant-infra-secrets \
//	  -n instant-infra -o jsonpath='{.data.MIGRATOR_SECRET}' | base64 -d)
//	go test ./e2e/... -tags e2e -run TestE2E_Migrator
//
// For Temporal-specific tests (C8-C10), also set:
//
//	export E2E_TEMPORAL_HOST=localhost:30777
//
// All tests skip if E2E_MIGRATOR_URL is not set.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	temporalclient "go.temporal.io/sdk/client"
)

// migratorHTTPClient is a plain http.Client for the migrator service.
var migratorHTTPClient = &http.Client{Timeout: 15 * time.Second}

// migratorURL returns the migrator base URL or skips.
func migratorURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("E2E_MIGRATOR_URL")
	if u == "" {
		t.Skip("E2E_MIGRATOR_URL not set — skipping migrator E2E.\n" +
			"  kubectl port-forward -n instant-infra svc/instant-migrator 8090:8090 &\n" +
			"  E2E_MIGRATOR_URL=http://localhost:8090 go test ./e2e/... -tags e2e -run TestE2E_Migrator")
	}
	return strings.TrimRight(u, "/")
}

// migratorSecret returns E2E_MIGRATOR_SECRET or skips.
func migratorSecret(t *testing.T) string {
	t.Helper()
	s := os.Getenv("E2E_MIGRATOR_SECRET")
	if s == "" {
		t.Skip("E2E_MIGRATOR_SECRET not set.\n" +
			"  kubectl get secret instant-infra-secrets -n instant-infra " +
			"-o jsonpath='{.data.MIGRATOR_SECRET}' | base64 -d")
	}
	return s
}

func mPost(t *testing.T, base, path, secret string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("mPost NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Migrator-Secret", secret)
	}
	resp, err := migratorHTTPClient.Do(req)
	if err != nil {
		t.Fatalf("mPost %s: %v", path, err)
	}
	return resp
}

func mGet(t *testing.T, base, path, secret string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("mGet NewRequest: %v", err)
	}
	if secret != "" {
		req.Header.Set("X-Migrator-Secret", secret)
	}
	resp, err := migratorHTTPClient.Do(req)
	if err != nil {
		t.Fatalf("mGet %s: %v", path, err)
	}
	return resp
}

// fakeMigrationPayload returns a complete, syntactically valid migration request
// that will be accepted by the HTTP layer but fail inside the workflow
// (localhost:5432 does not exist inside the migrator pod). Use ONLY for HTTP-layer
// tests (C1–C7) that need to exercise request validation, not migration execution.
func fakeMigrationPayload() map[string]any {
	return map[string]any{
		"migration_id":  uuid.NewString(),
		"resource_id":   uuid.NewString(),
		"resource_type": "postgres",
		"token":         uuid.NewString(),
		"source_url":    "postgres://invalid:invalid@localhost:5432/nonexistent",
		"source_tier":   "hobby",
		"target_tier":   "pro",
		"request_id":    uuid.NewString(),
	}
}

// realRedisMigrationPayload provisions a fresh Redis cache via the API and returns
// a migration payload that will actually succeed inside the cluster.
// The migrator pod (instant-infra) can reach redis-provision.instant-data.svc.cluster.local
// directly — no NetworkPolicy blocks that path.
// For an empty Redis DB, CopyData copies 0 keys and completes immediately.
// The workflow then enters the rollback-window timer (10 min) and stays "running".
// This helper skips the test if the cache service is disabled (503).
func realRedisMigrationPayload(t *testing.T) map[string]any {
	t.Helper()
	ip := uniqueIP(t)
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	defer resp.Body.Close()
	if resp.StatusCode == 503 {
		t.Skip("POST /cache/new: service disabled (503) — skipping real migration test")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Skipf("POST /cache/new: unexpected status %d — skipping real migration test", resp.StatusCode)
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)
	if body.ConnectionURL == "" {
		t.Skip("POST /cache/new: empty connection_url — skipping real migration test")
	}
	return map[string]any{
		"migration_id":  uuid.NewString(),
		"resource_id":   body.ID,
		"resource_type": "redis",
		"token":         body.Token,
		"source_url":    body.ConnectionURL,
		"source_tier":   body.Tier,
		"target_tier":   "hobby",
		"request_id":    uuid.NewString(),
	}
}

// ── C1: Health check ─────────────────────────────────────────────────────────

func TestE2E_Migrator_Health_Returns200(t *testing.T) {
	base := migratorURL(t)
	resp := mGet(t, base, "/health", "")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /health: want 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["ok"] != true {
		t.Errorf("GET /health: want ok=true, got %v", body)
	}
}

// ── C2: Wrong secret → 401 ───────────────────────────────────────────────────

func TestE2E_Migrator_InvalidSecret_Returns401(t *testing.T) {
	base := migratorURL(t)
	resp := mPost(t, base, "/migrations", "definitely-wrong-secret", fakeMigrationPayload())
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("wrong secret: want 401, got %d", resp.StatusCode)
	}
}

// ── C3: Missing fields → 400 ─────────────────────────────────────────────────

func TestE2E_Migrator_MissingFields_Returns400(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)
	resp := mPost(t, base, "/migrations", secret, map[string]any{"migration_id": ""})
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("missing fields: want 400, got %d", resp.StatusCode)
	}
}

// ── C4: Invalid resource type → 400 ─────────────────────────────────────────

func TestE2E_Migrator_InvalidResourceType_Returns400(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)
	resp := mPost(t, base, "/migrations", secret, map[string]any{
		"migration_id":  uuid.NewString(),
		"resource_id":   uuid.NewString(),
		"resource_type": "mysql",
		"token":         uuid.NewString(),
		"source_url":    "mysql://usr:pass@host/db",
		"target_tier":   "pro",
		"request_id":    uuid.NewString(),
	})
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("invalid resource_type: want 400, got %d", resp.StatusCode)
	}
}

// ── C5: Valid request → 202 + workflow_id + pending ──────────────────────────

func TestE2E_Migrator_ValidRequest_Returns202WithWorkflowID(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)

	payload := fakeMigrationPayload()
	migrationID := payload["migration_id"].(string)

	resp := mPost(t, base, "/migrations", secret, payload)
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("valid migration: want 202, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	if wid, _ := body["workflow_id"].(string); wid == "" {
		t.Errorf("response must include non-empty workflow_id; got %v", body)
	}
	if body["migration_id"] != migrationID {
		t.Errorf("migration_id mismatch: want %q got %v", migrationID, body["migration_id"])
	}
	if body["status"] != "pending" {
		t.Errorf("initial status must be 'pending'; got %v", body["status"])
	}
}

// ── C6: Status check returns id and state ────────────────────────────────────

func TestE2E_Migrator_StatusCheck_ReturnsCurrentState(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)

	startResp := mPost(t, base, "/migrations", secret, fakeMigrationPayload())
	if startResp.StatusCode != 202 {
		t.Fatalf("POST /migrations: want 202, got %d", startResp.StatusCode)
	}
	var startBody map[string]any
	json.NewDecoder(startResp.Body).Decode(&startBody)
	workflowID, _ := startBody["workflow_id"].(string)

	statusResp := mGet(t, base, "/migrations/"+workflowID, secret)
	defer statusResp.Body.Close()
	if statusResp.StatusCode != 200 {
		t.Fatalf("GET /migrations/:id: want 200, got %d", statusResp.StatusCode)
	}
	var statusBody map[string]any
	json.NewDecoder(statusResp.Body).Decode(&statusBody)
	if statusBody["id"] == nil {
		t.Errorf("status response must include id; got %v", statusBody)
	}
	if statusBody["state"] == nil {
		t.Errorf("status response must include state; got %v", statusBody)
	}
}

// ── C7: Unknown workflow ID → 404 ────────────────────────────────────────────

func TestE2E_Migrator_UnknownWorkflowID_Returns404(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)
	resp := mGet(t, base, "/migrations/nonexistent-xyz-"+uuid.NewString(), secret)
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("unknown workflow ID: want 404, got %d", resp.StatusCode)
	}
}

// ── C8: Temporal engine — workflow_id has "migration-" prefix ────────────────

func TestE2E_Migrator_Temporal_WorkflowID_HasMigrationPrefix(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)
	if os.Getenv("E2E_TEMPORAL_HOST") == "" {
		t.Skip("E2E_TEMPORAL_HOST not set — skipping Temporal prefix test.")
	}

	resp := mPost(t, base, "/migrations", secret, fakeMigrationPayload())
	if resp.StatusCode != 202 {
		t.Fatalf("POST /migrations: want 202, got %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	wid, _ := body["workflow_id"].(string)
	if !strings.HasPrefix(wid, "migration-") {
		t.Errorf("Temporal: workflow_id must start with 'migration-', got %q", wid)
	}
}

// ── C9: Temporal workflow history accessible via SDK ─────────────────────────

func TestE2E_Migrator_Temporal_WorkflowHistory_Accessible(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)

	temporalHost := os.Getenv("E2E_TEMPORAL_HOST")
	if temporalHost == "" {
		t.Skip("E2E_TEMPORAL_HOST not set — skipping Temporal workflow history test.")
	}

	resp := mPost(t, base, "/migrations", secret, fakeMigrationPayload())
	if resp.StatusCode != 202 {
		t.Fatalf("POST /migrations: want 202, got %d", resp.StatusCode)
	}
	var startBody map[string]any
	json.NewDecoder(resp.Body).Decode(&startBody)
	workflowID, _ := startBody["workflow_id"].(string)

	tc, err := temporalclient.Dial(temporalclient.Options{
		HostPort:  temporalHost,
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("Temporal client dial %q: %v", temporalHost, err)
	}
	defer tc.Close()

	time.Sleep(500 * time.Millisecond)

	desc, err := tc.DescribeWorkflowExecution(context.Background(), workflowID, "")
	if err != nil {
		t.Fatalf("DescribeWorkflowExecution(%q): %v", workflowID, err)
	}
	if desc.WorkflowExecutionInfo == nil {
		t.Fatal("WorkflowExecutionInfo is nil")
	}
	t.Logf("Temporal workflow %q status: %s", workflowID, desc.WorkflowExecutionInfo.Status)
}

// ── C10: Pod restart — Temporal resumes workflow from checkpoint ──────────────
//
// This test uses a REAL provisioned Redis resource (via realRedisMigrationPayload).
// CopyData copies 0 keys (empty DB) and succeeds immediately. The workflow then
// enters the 10-minute rollback-window timer — a durable Temporal checkpoint.
// After the pod is restarted mid-timer, Temporal must resume the workflow.
// Expected final state: "running" (timer still ticking) or "complete" (timer expired).
// "failed" is a real test failure — it means migration execution broke.

func TestE2E_Migrator_Temporal_PodRestart_WorkflowResumes(t *testing.T) {
	base := migratorURL(t)
	secret := migratorSecret(t)
	if os.Getenv("E2E_TEMPORAL_HOST") == "" {
		t.Skip("E2E_TEMPORAL_HOST not set — skipping Temporal durability test.")
	}

	// Use a real Redis resource so the migration actually succeeds and the workflow
	// reaches the rollback-window timer checkpoint before we kill the pod.
	payload := realRedisMigrationPayload(t)

	resp := mPost(t, base, "/migrations", secret, payload)
	if resp.StatusCode != 202 {
		t.Fatalf("POST /migrations: want 202, got %d", resp.StatusCode)
	}
	var startBody map[string]any
	json.NewDecoder(resp.Body).Decode(&startBody)
	workflowID, _ := startBody["workflow_id"].(string)

	// Give the workflow time to complete CopyData + Verify + Cutover and reach the timer.
	t.Logf("workflow started: %s — waiting 5s for migration to complete before restart...", workflowID)
	time.Sleep(5 * time.Second)

	t.Log("restarting migrator pod...")
	out, err := exec.Command("kubectl", "rollout", "restart",
		"deployment/instant-migrator", "-n", "instant-infra").CombinedOutput()
	if err != nil {
		t.Skipf("kubectl rollout restart unavailable: %v — %s", err, out)
	}

	t.Log("waiting 20s for pod to come back...")
	time.Sleep(20 * time.Second)

	var finalState string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		statusResp := mGet(t, base, "/migrations/"+workflowID, secret)
		var statusBody map[string]any
		json.NewDecoder(statusResp.Body).Decode(&statusBody)
		statusResp.Body.Close()
		finalState, _ = statusBody["state"].(string)
		if finalState != "" && finalState != "pending" {
			break
		}
		time.Sleep(3 * time.Second)
	}

	t.Logf("workflow %q final state after pod restart: %s", workflowID, finalState)

	if finalState == "" || finalState == "pending" {
		t.Errorf("Temporal must resume after pod restart; state stuck at %q", finalState)
	}
	// "failed" means the migration itself broke — this is a real failure, not expected.
	// Accepted states: "running" (timer still active) or "complete" (timer expired).
	if finalState == "failed" {
		t.Errorf("migration workflow failed after pod restart — Temporal resumed but migration execution broke; check migrator logs")
	}
}
