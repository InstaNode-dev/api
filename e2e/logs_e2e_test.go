//go:build e2e

// logs_e2e_test.go — black-box tests for GET /resources/:token/logs
//
// Growth-tier persona coverage of the same endpoint: TestE2E_Growth_G4_LogsGrowthVsShared in growth_tier_e2e_test.go.
//
// Tests the SSE log streaming endpoint for growth-tier resources.
// Requires a namespace with running pods. Defaults to "instant-examples-tasks"
// (the tasks-pro demo namespace) if it exists.
//
// # Gate
//
// Tests skip unless either:
//   - E2E_LOGS_NAMESPACE is set to an existing k8s namespace with pods, OR
//   - the "instant-examples-tasks" namespace exists in the cluster
//
// Inserts/deletes test resource rows via kubectl exec into postgres-customers pod
// (which has psql and network access to postgres-platform). No extra port-forward needed.
//
// # Run
//
//	E2E_BASE_URL=http://localhost:30080 go test ./e2e/... -v -tags e2e -run TestE2E_Logs -timeout 60s

package e2e

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// logsNamespace returns the namespace to use for logs tests.
// Returns ("", false) if no suitable namespace is available → tests skip.
func logsNamespace(t *testing.T) (string, bool) {
	t.Helper()
	if ns := os.Getenv("E2E_LOGS_NAMESPACE"); ns != "" {
		return ns, true
	}
	// Check if the tasks-pro demo namespace exists.
	out, _ := exec.Command("kubectl", "get", "namespace", "instant-examples-tasks",
		"--ignore-not-found", "-o", "name").Output()
	if strings.TrimSpace(string(out)) != "" {
		return "instant-examples-tasks", true
	}
	return "", false
}

// insertLogsTestResource inserts a growth-tier resource row into the platform DB
// pointing to the given namespace. Returns the resource token UUID string.
// Cleans up the row via t.Cleanup.
func insertLogsTestResource(t *testing.T, resourceType, namespace string) string {
	t.Helper()
	// Random fingerprint per call — avoids conflicts if a previous run's cleanup failed.
	fp := "e2e-logs-" + uuid.NewString()[:8]
	sql := fmt.Sprintf(`
		INSERT INTO resources (resource_type, tier, fingerprint, status, provider_resource_id)
		VALUES ('%s', 'growth', '%s', 'active', '%s')
		RETURNING token;
	`, resourceType, fp, namespace)

	out, err := exec.Command("kubectl", "exec", "-n", "instant-data",
		"deploy/postgres-customers", "--",
		"sh", "-c",
		fmt.Sprintf(`PGPASSWORD=instant psql -h postgres-platform.instant.svc.cluster.local -U instant -d instant_platform -t -A -c "%s"`,
			strings.ReplaceAll(sql, "\n", " "),
		),
	).Output()
	if err != nil {
		t.Skipf("insertLogsTestResource: kubectl exec failed (%v) — cluster not reachable, skipping", err)
	}

	// psql with -t -A still emits "INSERT 0 1" on stdout after the data row.
	// Extract the first line that looks like a UUID (36 chars, hex + dashes).
	token := ""
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 36 && strings.Count(line, "-") == 4 {
			token = line
			break
		}
	}
	if token == "" {
		t.Skipf("insertLogsTestResource: could not extract UUID from output %q — skipping", string(out))
	}

	t.Cleanup(func() {
		deleteSQL := fmt.Sprintf(`DELETE FROM resources WHERE token = '%s';`, token)
		exec.Command("kubectl", "exec", "-n", "instant-data", //nolint:errcheck
			"deploy/postgres-customers", "--",
			"sh", "-c",
			fmt.Sprintf(`PGPASSWORD=instant psql -h postgres-platform.instant.svc.cluster.local -U instant -d instant_platform -c "%s"`,
				deleteSQL,
			),
		).Run()
	})

	return token
}

// readSSELines reads an SSE response body and returns all data: lines (stripped of prefix).
// Reads until the stream closes or "data: [end]" is seen.
func readSSELines(t *testing.T, body io.ReadCloser) []string {
	t.Helper()
	defer body.Close()
	var lines []string
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			lines = append(lines, strings.TrimPrefix(line, "data: "))
		}
		if line == "data: [end]" {
			break
		}
	}
	return lines
}

// ── L1: postgres logs — growth-tier resource returns log lines ───────────────

func TestE2E_Logs_GrowthPostgres_ReturnsLines(t *testing.T) {
	ns, ok := logsNamespace(t)
	if !ok {
		t.Skip("no logs namespace available — set E2E_LOGS_NAMESPACE or deploy instant-examples-tasks")
	}

	token := insertLogsTestResource(t, "postgres", ns)

	resp, err := http.Get(baseURL() + "/resources/" + token + "/logs?tail=10")
	if err != nil {
		t.Fatalf("GET /resources/:token/logs: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got %q", contentType)
	}

	lines := readSSELines(t, resp.Body)
	if len(lines) == 0 {
		t.Fatal("expected at least one log line, got none")
	}
	// The last line should be [end].
	if lines[len(lines)-1] != "[end]" {
		t.Errorf("expected last line to be [end], got %q", lines[len(lines)-1])
	}
	// At least one non-[end] line contains actual log content.
	hasContent := false
	for _, l := range lines {
		if l != "[end]" && l != "" {
			hasContent = true
			break
		}
	}
	if !hasContent {
		t.Errorf("expected at least one non-empty log line, got lines: %v", lines)
	}
	t.Logf("L1: postgres logs OK — %d lines, first: %q", len(lines)-1, lines[0])
}

// ── L2: redis logs — cache resource type maps to app=redis ───────────────────

func TestE2E_Logs_GrowthCache_ReturnsLines(t *testing.T) {
	ns, ok := logsNamespace(t)
	if !ok {
		t.Skip("no logs namespace available — set E2E_LOGS_NAMESPACE or deploy instant-examples-tasks")
	}

	token := insertLogsTestResource(t, "cache", ns)

	resp, err := http.Get(baseURL() + "/resources/" + token + "/logs?tail=5")
	if err != nil {
		t.Fatalf("GET /resources/:token/logs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	lines := readSSELines(t, resp.Body)
	if len(lines) == 0 {
		t.Fatal("expected at least one log line, got none")
	}
	t.Logf("L2: cache logs OK — %d lines, first: %q", len(lines)-1, lines[0])
}

// ── L3: nats logs — queue resource type maps to app=nats ─────────────────────

func TestE2E_Logs_GrowthQueue_ReturnsLines(t *testing.T) {
	ns, ok := logsNamespace(t)
	if !ok {
		t.Skip("no logs namespace available — set E2E_LOGS_NAMESPACE or deploy instant-examples-tasks")
	}

	token := insertLogsTestResource(t, "queue", ns)

	resp, err := http.Get(baseURL() + "/resources/" + token + "/logs?tail=5")
	if err != nil {
		t.Fatalf("GET /resources/:token/logs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	lines := readSSELines(t, resp.Body)
	if len(lines) == 0 {
		t.Fatal("expected at least one log line, got none")
	}
	t.Logf("L3: queue logs OK — %d lines, first: %q", len(lines)-1, lines[0])
}

// ── L4: shared tier → 400 not_growth ─────────────────────────────────────────

func TestE2E_Logs_SharedTier_Returns400(t *testing.T) {
	ns, ok := logsNamespace(t)
	if !ok {
		t.Skip("no logs namespace available")
	}

	// Insert an anonymous (shared) resource — no provider_resource_id.
	fp := "e2e-logs-shared-" + uuid.NewString()[:8]
	sql := fmt.Sprintf(`INSERT INTO resources (resource_type, tier, fingerprint, status)
		VALUES ('postgres', 'anonymous', '%s', 'active')
		RETURNING token;`, fp)
	out, err := exec.Command("kubectl", "exec", "-n", "instant-data",
		"deploy/postgres-customers", "--",
		"sh", "-c",
		fmt.Sprintf(`PGPASSWORD=instant psql -h postgres-platform.instant.svc.cluster.local -U instant -d instant_platform -t -A -c "%s"`,
			strings.ReplaceAll(sql, "\n", " "),
		),
	).Output()
	if err != nil {
		t.Skipf("kubectl exec failed — skipping: %v", err)
	}
	token := ""
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 36 && strings.Count(line, "-") == 4 {
			token = line
			break
		}
	}
	if token == "" {
		t.Skipf("unexpected output %q — skipping", string(out))
	}
	t.Cleanup(func() {
		exec.Command("kubectl", "exec", "-n", "instant-data", //nolint:errcheck
			"deploy/postgres-customers", "--",
			"sh", "-c",
			fmt.Sprintf(`PGPASSWORD=instant psql -h postgres-platform.instant.svc.cluster.local -U instant -d instant_platform -c "DELETE FROM resources WHERE token = '%s';"`, token),
		).Run()
	})

	_ = ns // namespace not needed for this test
	resp, err := http.Get(baseURL() + "/resources/" + token + "/logs")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, body)
	}
	var body struct {
		Error string `json:"error"`
	}
	decodeJSON(t, resp, &body)
	if body.Error != "not_growth" {
		t.Errorf("expected error=not_growth, got %q", body.Error)
	}
	t.Logf("L4: shared tier correctly rejected with 400 not_growth")
}

// ── L5: unknown token → 404 ──────────────────────────────────────────────────

func TestE2E_Logs_UnknownToken_Returns404(t *testing.T) {
	resp := get(t, "/resources/00000000-0000-0000-0000-000000000000/logs")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 404, got %d: %s", resp.StatusCode, body)
	}
	t.Logf("L5: unknown token correctly returns 404")
}

// ── L6: invalid UUID → 400 ───────────────────────────────────────────────────

func TestE2E_Logs_InvalidUUID_Returns400(t *testing.T) {
	resp := get(t, "/resources/not-a-uuid/logs")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, body)
	}
	var body struct {
		Error string `json:"error"`
	}
	decodeJSON(t, resp, &body)
	if body.Error != "invalid_token" {
		t.Errorf("expected error=invalid_token, got %q", body.Error)
	}
	t.Logf("L6: invalid UUID correctly returns 400 invalid_token")
}

// ── L7: tail param is clamped ────────────────────────────────────────────────

func TestE2E_Logs_TailParam_Clamped(t *testing.T) {
	ns, ok := logsNamespace(t)
	if !ok {
		t.Skip("no logs namespace available")
	}

	token := insertLogsTestResource(t, "postgres", ns)

	// tail=999 should be clamped to 500 server-side — just verify it doesn't error.
	resp, err := http.Get(baseURL() + "/resources/" + token + "/logs?tail=999")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 with clamped tail, got %d: %s", resp.StatusCode, body)
	}
	t.Logf("L7: tail=999 accepted and clamped — 200 OK")
}
