//go:build e2e

// Package e2e contains black-box end-to-end tests that run against a live instant.dev
// server. Tests hit real HTTP endpoints — no in-process Fiber, no mock DB.
//
// Run against local k8s:
//
//	E2E_BASE_URL=http://localhost:32108 go test ./e2e/... -v -tags e2e
//
// Run against Docker Compose:
//
//	E2E_BASE_URL=http://localhost:8080 go test ./e2e/... -v -tags e2e
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestMain runs before any test in the e2e package.
// It flushes per-fingerprint provision-limit counters (prov:*) from Redis
// before the suite executes, preventing cross-binary-run collision flakiness.
// This is safe for dev k8s clusters. It is best-effort: if kubectl is unavailable
// or the flush fails, tests still run (they may be flaky if the cluster is saturated).
func TestMain(m *testing.M) {
	if os.Getenv("E2E_BASE_URL") != "" {
		// Delete all prov:* keys. Scan + del is needed because Redis KEYS
		// is O(N) and blocks, but in dev clusters this is fine.
		exec.Command("kubectl", "exec", "-n", "instant", "deploy/redis", "--",
			"sh", "-c",
			"redis-cli --scan --pattern 'prov:*' | tr '\\n' '\\0' | xargs -0 -r redis-cli del 2>/dev/null || true",
		).Run() //nolint:errcheck — best-effort
	}
	os.Exit(m.Run())
}

// e2eTestToken returns the shared secret used to override the production
// fingerprint middleware's source-IP selection (see middleware/fingerprint.go).
// When E2E_TEST_TOKEN is set on both the cluster (env) and the test runner,
// the test runner's X-Forwarded-For is honored as the leftmost entry,
// restoring per-test fingerprint isolation against the live cluster.
func e2eTestToken() string {
	return os.Getenv("E2E_TEST_TOKEN")
}

// ipSeq is an atomic counter incremented per uniqueSubnet/uniqueIP call.
// It guarantees distinct /24 subnets within a single binary run.
var ipSeq atomic.Int64

// runSeed is a per-binary-invocation random offset applied to ipSeq so that
// consecutive test runs on the same day land on different /24 subnets.
// The Redis provision counter persists for 25h; without a per-run offset,
// run 2 would reuse the same IPs as run 1 and immediately hit the limit.
var (
	runSeedOnce sync.Once
	runSeed     int64
)

func subnets() int64 { return 254 * 254 } // 64,516 available /24 subnets

func runSeedValue() int64 {
	runSeedOnce.Do(func() {
		id := uuid.New()
		// Map 2 random bytes to [0, 64516) as a stable per-run offset.
		runSeed = int64(id[0])*254 + int64(id[1])
	})
	return runSeed
}

// baseURL returns the server root, defaulting to the local k8s NodePort.
func baseURL() string {
	if u := os.Getenv("E2E_BASE_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:32108"
}

// client is a shared HTTP client with a generous timeout.
// DisableKeepAlives is set to avoid an intermittent FastHTTP/Fiber behaviour where
// header parsing on keep-alive connections can lose headers (e.g., Authorization)
// across requests. E2E tests don't benefit from connection pooling, and fresh
// connections per request guarantee reliable header delivery.
//
// Timeout is 300s because pro/team-tier provisioning may create an isolated k8s pod,
// Razorpay webhook + tier elevation + follow-on provisions can run long under cluster load.
var client = &http.Client{
	Timeout:   300 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

// noRedirectClient is like client but does not follow HTTP redirects.
// Use it when testing endpoints that are expected to return 3xx responses.
var noRedirectClient = &http.Client{
	Timeout:   300 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// getNoRedirect issues a GET without following redirects and returns the response.
// Caller must close Body.
func getNoRedirect(t *testing.T, path string, headers ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL()+path, nil)
	if err != nil {
		t.Fatalf("getNoRedirect: NewRequest: %v", err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if tok := e2eTestToken(); tok != "" && req.Header.Get("X-E2E-Test-Token") == "" {
		req.Header.Set("X-E2E-Test-Token", tok)
		// Mirror X-Forwarded-For onto X-E2E-Source-IP because ingress-nginx
		// overwrites XFF by default. The bypass middleware reads X-E2E-Source-IP
		// when the trust token is valid, so the test's chosen IP survives.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" && req.Header.Get("X-E2E-Source-IP") == "" {
			req.Header.Set("X-E2E-Source-IP", xff)
		}
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("getNoRedirect %s: %v", path, err)
	}
	return resp
}

// get issues a GET and returns the response. Caller must close Body.
func get(t *testing.T, path string, headers ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL()+path, nil)
	if err != nil {
		t.Fatalf("get: NewRequest: %v", err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if tok := e2eTestToken(); tok != "" && req.Header.Get("X-E2E-Test-Token") == "" {
		req.Header.Set("X-E2E-Test-Token", tok)
		// Mirror X-Forwarded-For onto X-E2E-Source-IP because ingress-nginx
		// overwrites XFF by default. The bypass middleware reads X-E2E-Source-IP
		// when the trust token is valid, so the test's chosen IP survives.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" && req.Header.Get("X-E2E-Source-IP") == "" {
			req.Header.Set("X-E2E-Source-IP", xff)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	return resp
}

// post issues a POST with JSON body. Caller must close Body.
func post(t *testing.T, path string, body any, headers ...string) *http.Response {
	t.Helper()
	return postCtx(t, context.Background(), path, body, headers...)
}

// postCtx is like post but honors ctx for deadline / cancellation (e.g. per-request timeout).
func postCtx(t *testing.T, ctx context.Context, path string, body any, headers ...string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("postCtx: marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL()+path, r)
	if err != nil {
		t.Fatalf("postCtx: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if tok := e2eTestToken(); tok != "" && req.Header.Get("X-E2E-Test-Token") == "" {
		req.Header.Set("X-E2E-Test-Token", tok)
		// Mirror X-Forwarded-For onto X-E2E-Source-IP because ingress-nginx
		// overwrites XFF by default. The bypass middleware reads X-E2E-Source-IP
		// when the trust token is valid, so the test's chosen IP survives.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" && req.Header.Get("X-E2E-Source-IP") == "" {
			req.Header.Set("X-E2E-Source-IP", xff)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("postCtx %s: request timed out after context deadline: %v", path, err)
		}
		t.Fatalf("postCtx %s: %v", path, err)
	}
	return resp
}

// decodeJSON decodes resp.Body into v and closes the body.
func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("decodeJSON: read: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decodeJSON: unmarshal (%s): %v", string(b), err)
	}
}

// readBody drains and closes the body, returning the string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// uniqueSubnetIP holds a unique /24 subnet assigned to a single test or test group.
// All IPs in the same subnetIP share a fingerprint (same /24); IPs in different
// subnetIPs are guaranteed to be in distinct /24 subnets within a test run.
type subnetIP struct{ x, y int64 }

// IP returns an address in this /24 with the given last octet (1–254).
func (s subnetIP) IP(lastOctet int) string {
	return fmt.Sprintf("10.%d.%d.%d", s.x, s.y, lastOctet)
}

// uniqueSubnet allocates a fresh /24 subnet guaranteed to be distinct from
// every other call within this binary run AND (with overwhelming probability)
// distinct from calls in previous runs on the same day.
//
// Within a run: sequential counter guarantees no collision.
// Across runs: a per-run random seed offsets into the 64,516-subnet space,
// making same-day re-use of the same /24 extremely unlikely (~0.0015%).
func uniqueSubnet(_ *testing.T) subnetIP {
	n := (runSeedValue() + ipSeq.Add(1)) % subnets()
	if n <= 0 {
		n += subnets()
	}
	return subnetIP{x: n/254 + 1, y: n%254 + 1}
}

// uniqueIP returns an IP in a unique /24 subnet per call.
// Fingerprinting masks IPv4 to /24, so tests that share a /24 share a fingerprint
// and compete for the same provisioning cap.
// Uses an atomic counter rather than random UUIDs to guarantee no birthday collisions
// between tests running in the same binary invocation.
func uniqueIP(t *testing.T) string {
	t.Helper()
	return uniqueSubnet(t).IP(1)
}

// uniqueEmail returns a test-only email address that won't collide across runs.
func uniqueEmail() string {
	return "e2e+" + uuid.NewString()[:8] + "@instant.dev"
}

// provisionAnonymous provisions a cache resource anonymously via POST /cache/new.
// Used as the canonical "get an anonymous resource with an upgrade JWT" helper
// across all E2E test personas that just need a valid onboarding JWT to test
// the claim/upgrade funnel.
func provisionAnonymous(t *testing.T, ip string) provisionNewResponse {
	t.Helper()
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		t.Skip("POST /cache/new: service not enabled (503) — skipping")
	}
	if resp.StatusCode != 201 {
		t.Fatalf("provisionAnonymous: POST /cache/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)
	if body.Token == "" {
		t.Fatalf("provisionAnonymous: got empty token")
	}
	return body
}

// extractJWTFromNote pulls the JWT query-param value out of the upgrade URL
// embedded in the note field, e.g.:
//
//	"Shared infra. Persists 24h. Sign up: https://instant.dev/start?t=eyJ..."
func extractJWTFromNote(t *testing.T, note string) string {
	t.Helper()
	const marker = "?t="
	idx := strings.Index(note, marker)
	if idx == -1 {
		t.Fatalf("extractJWTFromNote: no %q found in note: %q", marker, note)
	}
	raw := note[idx+len(marker):]
	// JWT ends at first space or end of string
	if sp := strings.IndexAny(raw, " \t\n"); sp != -1 {
		raw = raw[:sp]
	}
	if raw == "" {
		t.Fatal("extractJWTFromNote: extracted empty JWT")
	}
	return raw
}

// startResourceInfo is one entry in the resources list returned by GET /start.
type startResourceInfo struct {
	Token  string `json:"token"`
	Status string `json:"status"`
	Tier   string `json:"tier"`
}

// startLandingResponse mirrors GET /start response.
type startLandingResponse struct {
	OK            bool                `json:"ok"`
	Fingerprint   string              `json:"fingerprint"`
	Country       string              `json:"country"`
	CloudVendor   string              `json:"cloud_vendor"`
	Resources     []startResourceInfo `json:"resources"`
	ResourceTypes []string            `json:"resource_types"`
	SuggestedPlan string              `json:"suggested_plan"`
	JTI           string              `json:"jti"`
}

// claimResponse mirrors POST /claim response.
type claimResponse struct {
	OK      bool   `json:"ok"`
	TeamID  string `json:"team_id"`
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// errorResponse is the standard error envelope.
type errorResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// localURL rewrites k8s-internal service hostnames to localhost port-forwards.
//
// When running E2E tests from outside the cluster, connection URLs returned by
// the API contain k8s-internal DNS names that are not resolvable from the host.
// Set these env vars to redirect connections via kubectl port-forward:
//
//	E2E_PG_HOST    e.g. "localhost:5435"  → replaces postgres-customers.*:5432
//	E2E_REDIS_HOST e.g. "localhost:6380"  → replaces redis-provision.*:6379
//	E2E_MONGO_HOST e.g. "localhost:27018" → replaces mongodb.*:27017
//
// Example setup:
//
//	kubectl port-forward -n instant-data svc/postgres-customers 5435:5432 &
//	kubectl port-forward -n instant-data svc/redis-provision 6380:6379 &
//	kubectl port-forward -n instant-data svc/mongodb 27018:27017 &
//	E2E_PG_HOST=localhost:5435 E2E_REDIS_HOST=localhost:6380 E2E_MONGO_HOST=localhost:27018 \
//	  go test ./e2e/... -tags e2e
func localURL(connectionURL string) string {
	result := connectionURL
	if h := os.Getenv("E2E_PG_HOST"); h != "" {
		for _, svc := range []string{
			"postgres-customers.instant-data.svc.cluster.local:5432",
			"postgres-customers.instant.svc.cluster.local:5432",
		} {
			result = strings.ReplaceAll(result, svc, h)
		}
	}
	if h := os.Getenv("E2E_REDIS_HOST"); h != "" {
		for _, svc := range []string{
			"redis-provision.instant-data.svc.cluster.local:6379",
			"redis.instant.svc.cluster.local:6379",
		} {
			result = strings.ReplaceAll(result, svc, h)
		}
	}
	if h := os.Getenv("E2E_MONGO_HOST"); h != "" {
		for _, svc := range []string{
			"mongodb.instant-data.svc.cluster.local:27017",
			"mongodb.instant.svc.cluster.local:27017",
		} {
			result = strings.ReplaceAll(result, svc, h)
		}
	}
	return result
}

// mongoDBName extracts the database name from a mongodb:// connection URL.
// The database is the path component after the last "/" and before any "?".
// e.g. "mongodb://usr:pass@host/db_pool_abc?authSource=admin" → "db_pool_abc"
func mongoDBName(connectionURL string) string {
	u := connectionURL
	// Strip query string.
	if i := strings.Index(u, "?"); i >= 0 {
		u = u[:i]
	}
	// Take everything after the last "/".
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return ""
}
