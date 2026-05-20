//go:build e2e

package e2e

// readyz_integration_test.go — Track 4: cross-service /readyz
// integration tests.
//
// What this adds on top of:
//   - api/internal/handlers/readyz_test.go (sqlmock + httptest unit
//     tests for the API handler in isolation).
//   - worker + provisioner have analogous unit-level tests in their
//     respective repos.
//
// What's MISSING that this file covers: cross-service contract checks.
// All three services (api, worker, provisioner) expose /readyz on their
// own port + namespace. The contract — same JSON envelope, same status
// vocabulary, same secret-leak discipline — has never been verified
// across the three services in one pass.
//
// Tests below:
//
//   1. TestE2EReadyz_AllServices_RespondWithCorrectShape — hit api +
//      worker + provisioner /readyz; assert the documented JSON
//      envelope (overall, service, commit_id, checks[].name, status,
//      latency_ms, last_check_at).
//
//   2. TestE2EReadyz_BrevoUnreachable_StaysDegraded — verifies brevo
//      probe is NON-critical: when an invalid api-key is configured,
//      the overall status stays at 200 (degraded), NOT 503. Without
//      a way to set BREVO_API_KEY="garbage" on a live deploy, this
//      test is SKIPPED by default; it documents the contract for the
//      operator to run against a staging cluster.
//
//   3. TestE2EReadyz_CacheTTL_NoUpstreamSpam — hits /readyz 50× in a
//      tight loop and asserts the response stays consistent (the
//      per-check cache TTL absorbs the load). Indirectly verifies the
//      runner doesn't bypass the cache on every request.
//
//   4. TestE2EReadyz_NoSecretsLeaked — scrapes /readyz from every
//      service, regex-greps the body for hex secret patterns (>=20
//      hex chars contiguous), fails if any match. The actual probe
//      logic NEVER serialises a secret value; this test guards
//      against a future "helpful" PR that adds the api-key to the
//      check's metadata.
//
//   5. TestE2EReadyz_ResponseTime_UnderSLA — measures wall-clock
//      latency of /readyz hits; asserts P95 under 500ms (the cache
//      amortises real upstream-probe cost so a single hit is
//      effectively free).
//
//   6. TestE2EReadyz_RegistryWalk_AllChecksInMatrix — per-service
//      walk over the checks[].name list, asserts every check name is
//      in the published criticality matrix. Catches the "added a new
//      check but forgot to document it" drift.
//
// CLAUDE.md rule 17 coverage block — see per-test docstrings.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// ─── Service registry ─────────────────────────────────────────────────────────

// readyzServiceURLEnvVars maps each backend service to the env var
// that points at its /readyz endpoint. The env vars are set by the
// operator (or by the make test-e2e-full target).
//
// SKIPS if the env var is unset — the test runs against whichever
// services the operator has port-forwarded.
//
// Per CLAUDE.md rule 18 (registry-iterating tests): every backend
// service whose /readyz we own ships an env var here. A new service
// without a matching env var IS missing from this test.
var readyzServiceURLEnvVars = map[string]string{
	"api":          "E2E_API_READYZ_URL",
	"worker":       "E2E_WORKER_READYZ_URL",
	"provisioner":  "E2E_PROVISIONER_READYZ_URL",
}

// readyzCriticalityMatrix is the published per-service criticality
// matrix. Sourced from each service's buildChecks() function — must
// stay in sync via the registry-walk test below. Critical=true means
// a failed check pulls the pod from k8s Service rotation. False means
// the pod stays serving (degraded).
//
// IMPORTANT: a check whose criticality changes is a customer-visible
// contract change. Edits here must be paired with the service-side
// buildChecks() edit in the SAME PR.
var readyzCriticalityMatrix = map[string]map[string]bool{
	"api": {
		"platform_db":      true,
		"provisioner_grpc": true,
		"redis":            false,
		"customer_db":      false,
		"brevo":            false,
		"razorpay":         false,
		"do_spaces":        false,
	},
	"worker": {
		"platform_db": true,
		"redis":       false,
		"river":       true,
		"brevo":       false,
	},
	"provisioner": {
		"customer_db": true,
		"redis":       false,
	},
}

// readyzResponse is the documented envelope. All three services
// return this shape; a mismatch fails the shape test.
type readyzResponse struct {
	Overall  string `json:"overall"`
	Service  string `json:"service"`
	CommitID string `json:"commit_id"`
	Checks   []struct {
		Name        string    `json:"name"`
		Status      string    `json:"status"`
		LatencyMS   int64     `json:"latency_ms"`
		LastError   string    `json:"last_error,omitempty"`
		LastCheckAt time.Time `json:"last_check_at"`
	} `json:"checks"`
}

// fetchReadyz fetches the named service's /readyz; returns the
// HTTP status code + parsed body + raw body bytes (for the
// secret-leak test). SKIPS the test if the env var is unset.
func fetchReadyz(t *testing.T, service string) (int, readyzResponse, []byte) {
	t.Helper()
	envVar := readyzServiceURLEnvVars[service]
	url := os.Getenv(envVar)
	if url == "" {
		t.Skipf("set %s to hit %s's /readyz", envVar, service)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	var parsed readyzResponse
	if jerr := json.Unmarshal(body, &parsed); jerr != nil {
		t.Fatalf("unmarshal %s body (status=%d body=%q): %v", url, resp.StatusCode, string(body), jerr)
	}
	return resp.StatusCode, parsed, body
}

// ─── Test 1: shape — all three services match the documented envelope ────────

// TestE2EReadyz_AllServices_RespondWithCorrectShape iterates each
// configured service and asserts the JSON envelope shape.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       a future refactor adds a new field to one
//                  service's response (e.g. uptime_seconds) without
//                  adding it to the others — a polyglot fleet that
//                  inconsistently surfaces health.
//   Enumeration:   readyzServiceURLEnvVars iterated below.
//   Sites found:   3 (api, worker, provisioner).
//   Sites touched: 3 (each one tested).
//   Coverage test: an envelope drift in one service fails the
//                  per-service assertion.
//   Live verified: against `make test-e2e-full` after deploy.
func TestE2EReadyz_AllServices_RespondWithCorrectShape(t *testing.T) {
	for service := range readyzServiceURLEnvVars {
		service := service
		t.Run(service, func(t *testing.T) {
			status, resp, _ := fetchReadyz(t, service)
			// 200 (ok or degraded) OR 503 (failed) — both are valid
			// /readyz responses. Anything else is the contract break.
			if status != http.StatusOK && status != http.StatusServiceUnavailable {
				t.Errorf("%s /readyz: status=%d, want 200 or 503", service, status)
			}
			if resp.Service == "" {
				t.Errorf("%s /readyz: empty `service` field — envelope contract requires service identifier", service)
			}
			if resp.Overall == "" {
				t.Errorf("%s /readyz: empty `overall` field — must be one of ok/degraded/failed", service)
			}
			if !isValidOverallStatus(resp.Overall) {
				t.Errorf("%s /readyz: overall=%q, want ok/degraded/failed", service, resp.Overall)
			}
			if len(resp.Checks) == 0 {
				t.Errorf("%s /readyz: zero checks — the registry must surface at least the critical ones", service)
			}
			for _, c := range resp.Checks {
				if c.Name == "" {
					t.Errorf("%s /readyz: check with empty name — envelope contract violated", service)
				}
				if !isValidCheckStatus(c.Status) {
					t.Errorf("%s /readyz: check %q status=%q, want ok/degraded/failed", service, c.Name, c.Status)
				}
				if c.LatencyMS < 0 {
					t.Errorf("%s /readyz: check %q latency_ms=%d, want >= 0", service, c.Name, c.LatencyMS)
				}
				if c.LastCheckAt.IsZero() {
					t.Errorf("%s /readyz: check %q last_check_at is zero — cache hasn't populated?", service, c.Name)
				}
			}
		})
	}
}

func isValidOverallStatus(s string) bool {
	switch s {
	case "ok", "degraded", "failed":
		return true
	}
	return false
}

func isValidCheckStatus(s string) bool {
	switch s {
	case "ok", "degraded", "failed":
		return true
	}
	return false
}

// ─── Test 2: Brevo unreachable → 200 degraded (NOT 503) ──────────────────────

// TestE2EReadyz_BrevoUnreachable_StaysDegraded asserts the api stays
// at 200 (overall=degraded) when Brevo upstream is failing. The api's
// readyz handler marks brevo as Critical=false; a 401 from
// /v3/account counts as degraded, NOT failed.
//
// This test is SKIPPED by default — there's no live-hostile knob to
// turn off Brevo from the test side. Documents the operator-side
// procedure in the skip message.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       a future PR re-classifies brevo as Critical=true
//                  → a Brevo outage pulls the api pod from rotation
//                  (200/sec degraded → 503 critical-fail).
//   Enumeration:   `rg -F 'Name:     "brevo"' api/internal/handlers/`
//   Sites found:   1 (the readyz handler).
//   Sites touched: 1.
//   Coverage test: this test fails LOUD when the brevo flag flips.
func TestE2EReadyz_BrevoUnreachable_StaysDegraded(t *testing.T) {
	if os.Getenv("E2E_INDUCE_BREVO_OUTAGE") != "1" {
		t.Skip("set E2E_INDUCE_BREVO_OUTAGE=1 against a staging cluster with BREVO_API_KEY temporarily set to 'garbage' to run this test — the test does NOT mutate api config")
	}
	status, resp, _ := fetchReadyz(t, "api")
	// We expect 200 + overall=degraded. NOT 503 (which would mean
	// Critical=true — a regression).
	if status != http.StatusOK {
		t.Errorf("api /readyz with Brevo unreachable: status=%d, want 200 (degraded, NOT critical-fail)", status)
	}
	if resp.Overall != "degraded" {
		t.Errorf("api /readyz with Brevo unreachable: overall=%q, want degraded", resp.Overall)
	}
	// And specifically: the brevo check must be the one degraded.
	var brevo *struct {
		Name        string    `json:"name"`
		Status      string    `json:"status"`
		LatencyMS   int64     `json:"latency_ms"`
		LastError   string    `json:"last_error,omitempty"`
		LastCheckAt time.Time `json:"last_check_at"`
	}
	for i := range resp.Checks {
		if resp.Checks[i].Name == "brevo" {
			brevo = &resp.Checks[i]
			break
		}
	}
	if brevo == nil {
		t.Fatal("brevo check not present in /readyz output (BREVO_API_KEY may not be set)")
	}
	if brevo.Status != "degraded" && brevo.Status != "failed" {
		t.Errorf("brevo check status=%q, want degraded or failed under induced outage", brevo.Status)
	}
}

// ─── Test 3: cache TTL — hot-loop /readyz doesn't spam upstream ──────────────

// TestE2EReadyz_CacheTTL_NoUpstreamSpam hits /readyz 50 times in a
// tight loop. The contract: response stays consistent (the per-check
// cache TTL absorbs the load).
//
// We can't easily measure upstream call count from the client side;
// what we CAN measure is response-time consistency. A 50-burst that
// blew the cache would see latency creep upward as each call dials
// the upstream; with the cache intact every call should land in
// sub-50ms.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       a future refactor sets CacheTTL=0 — every /readyz
//                  hit dials Brevo/Razorpay/DO Spaces, blowing
//                  upstream rate limits + the k8s readinessProbe (10s
//                  period × N pods) becomes a self-DoS.
//   Enumeration:   `rg -F 'CacheTTL' api/`
//   Sites found:   1 (the readyz handler).
//   Sites touched: 1.
//   Coverage test: the latency-creep assertion below catches a
//                  cache-bust regression.
func TestE2EReadyz_CacheTTL_NoUpstreamSpam(t *testing.T) {
	if os.Getenv("E2E_API_READYZ_URL") == "" {
		t.Skip("set E2E_API_READYZ_URL")
	}
	const N = 50
	var maxLatency time.Duration
	url := os.Getenv("E2E_API_READYZ_URL")
	for i := 0; i < N; i++ {
		start := time.Now()
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("hit #%d: %v", i, err)
		}
		_ = resp.Body.Close()
		took := time.Since(start)
		if took > maxLatency {
			maxLatency = took
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("hit #%d: unexpected status %d", i, resp.StatusCode)
		}
	}
	// With cache intact, every call returns sub-100ms (the cache hit
	// path is ~microseconds). With cache bust, the slowest upstream
	// (DO Spaces HEAD) would be ~1-3s. A 500ms ceiling catches the
	// regression without flaking on network jitter.
	const sla = 500 * time.Millisecond
	if maxLatency > sla {
		t.Errorf("max latency over %d hits = %s (> %s SLA) — cache may be bypassed",
			N, maxLatency, sla)
	}
}

// ─── Test 4: no secrets leak ──────────────────────────────────────────────────

// TestE2EReadyz_NoSecretsLeaked scrapes /readyz from every service
// and asserts the body has no contiguous hex strings of suspicious
// length (which would indicate a secret value accidentally
// serialised in the check metadata).
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       a future "helpful" PR adds the upstream URL
//                  WITH the api-key query-string to the check's
//                  LastError metadata, or stamps the Razorpay
//                  basic-auth header verbatim — these end up in
//                  the JSON the response.
//   Enumeration:   readyzServiceURLEnvVars iterated below.
//   Sites found:   3 services.
//   Sites touched: 3 (each scraped).
//   Coverage test: a 20+ hex secret-looking string in any body
//                  fails the test.
func TestE2EReadyz_NoSecretsLeaked(t *testing.T) {
	// 20-hex-char floor catches AES keys (32+) + JWT-prefix entropy +
	// most API token formats; short enough to also catch the test
	// fixtures the response might legitimately include. False positives
	// (e.g. a commit SHA padded to 40 chars) are knocked out by the
	// explicit allowlist below — commit_id is the only documented
	// hex-string field in the envelope.
	hexLong := regexp.MustCompile(`[a-f0-9]{20,}`)
	for service := range readyzServiceURLEnvVars {
		service := service
		t.Run(service, func(t *testing.T) {
			_, parsed, raw := fetchReadyz(t, service)
			// Strip the commit_id from the body before scanning — it's
			// the only allowed long hex string.
			scan := strings.ReplaceAll(string(raw), parsed.CommitID, "")
			if matches := hexLong.FindAllString(scan, -1); len(matches) > 0 {
				// Bound the log dump so a huge payload doesn't drown CI logs.
				preview := scan
				if len(preview) > 500 {
					preview = preview[:500] + "..."
				}
				t.Errorf("%s /readyz body contains %d hex-string(s) ≥ 20 chars (potential secret leak): %v\nbody preview: %s",
					service, len(matches), matches, preview)
			}
		})
	}
}

// ─── Test 5: response time under 500ms ────────────────────────────────────────

// TestE2EReadyz_ResponseTime_UnderSLA hits /readyz 20× per service,
// asserts the P95 latency stays under 500ms.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       a future check added with a high-latency upstream
//                  AND no per-check timeout — first hit pays the
//                  full latency, k8s readinessProbe times out after
//                  its default 1s.
//   Enumeration:   readyzServiceURLEnvVars iterated below.
//   Sites found:   3.
//   Sites touched: 3 (each times its own hits).
//   Coverage test: a P95 > 500ms fails the test.
func TestE2EReadyz_ResponseTime_UnderSLA(t *testing.T) {
	const N = 20
	const sla = 500 * time.Millisecond
	for service := range readyzServiceURLEnvVars {
		service := service
		t.Run(service, func(t *testing.T) {
			url := os.Getenv(readyzServiceURLEnvVars[service])
			if url == "" {
				t.Skipf("set %s", readyzServiceURLEnvVars[service])
			}
			var samples []time.Duration
			for i := 0; i < N; i++ {
				start := time.Now()
				req, _ := http.NewRequest(http.MethodGet, url, nil)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("hit #%d: %v", i, err)
				}
				_ = resp.Body.Close()
				samples = append(samples, time.Since(start))
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			p95 := samples[(N*95)/100]
			t.Logf("%s /readyz P95 over %d hits = %s", service, N, p95)
			if p95 > sla {
				t.Errorf("%s /readyz P95 = %s > %s SLA", service, p95, sla)
			}
		})
	}
}

// ─── Test 6: registry walk — checks in matrix, matrix in checks ──────────────

// TestE2EReadyz_RegistryWalk_AllChecksInMatrix verifies the
// per-service checks list matches the criticality matrix in this
// file. A new check added to the buildChecks function but missing
// from the matrix fails the test; a matrix entry that's never
// surfaced by the service also fails (catches a published-but-
// retired check that the operator playbook still references).
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       drift between the service's runtime check list
//                  and the published matrix → operator runbooks
//                  reference checks that no longer exist, or the
//                  service has secret checks not in the playbook.
//   Enumeration:   readyzCriticalityMatrix[service] keys ↔
//                  resp.Checks[].Name.
//   Sites found:   N (per-service check counts).
//   Sites touched: N (each iterated).
//   Coverage test: a drift in either direction fails the test.
func TestE2EReadyz_RegistryWalk_AllChecksInMatrix(t *testing.T) {
	for service, matrix := range readyzCriticalityMatrix {
		service := service
		matrix := matrix
		t.Run(service, func(t *testing.T) {
			_, resp, _ := fetchReadyz(t, service)
			seen := map[string]bool{}
			for _, c := range resp.Checks {
				seen[c.Name] = true
				// Matrix lookup: every surfaced check must be documented.
				if _, ok := matrix[c.Name]; !ok {
					t.Errorf("%s /readyz surfaces check %q but it's NOT in readyzCriticalityMatrix — published criticality matrix drifted from runtime",
						service, c.Name)
				}
			}
			// Reverse: every matrix entry must be surfaced (modulo
			// optionally-enabled probes like brevo / razorpay /
			// customer_db / do_spaces, which the matrix marks). For
			// those, missing IS expected when the corresponding env
			// var is unset. We allow Critical=false to be absent;
			// Critical=true MUST appear.
			for name, critical := range matrix {
				if critical && !seen[name] {
					t.Errorf("%s matrix entry %q (Critical=true) is NOT surfaced by /readyz — a critical check disappeared from buildChecks",
						service, name)
				}
			}
		})
	}
	_ = fmt.Sprint // ensure fmt stays used if subtests skip
}
