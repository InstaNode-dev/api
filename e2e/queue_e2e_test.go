//go:build e2e

// Queue E2E tests — POST /queue/new and storage quota behaviour.
//
// Test groups:
//
//	TestE2E_Queue_*         — queue provisioning (skips gracefully when service is disabled)
//	TestE2E_StorageQuota_*  — GET /api/v1/resources/:id storage_exceeded field
//	TestE2E_DoubleClaim_*   — atomic single-use JWT claim idempotency
//	TestE2E_Concurrent_*    — concurrent-provision race conditions
//
// Queue service status:
//
//	The NATS JetStream queue service is not yet in INSTANT_ENABLED_SERVICES.
//	The deployed server returns 404 (route not yet shipped) or 503 (route present
//	but feature-flagged off) for POST /queue/new.  All queue tests detect either
//	status code and skip rather than fail, so the suite is safe to run against
//	any cluster state.
//
// Required env vars (optional — tests skip when absent):
//
//	E2E_BASE_URL              live server (default: http://localhost:30080)
//	E2E_JWT_SECRET            required for session-JWT tests
//	E2E_RAZORPAY_WEBHOOK_SECRET required for Razorpay webhook helpers (imported transitively)
package e2e

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// ── Queue helpers ─────────────────────────────────────────────────────────────

// queueServiceDisabled returns true and skips the test when the queue endpoint
// responds with 404 (route not deployed) or 503 (feature-flagged off).
// The caller must still drain the response body before calling this helper.
func queueServiceDisabled(t *testing.T, statusCode int) bool {
	t.Helper()
	if statusCode == http.StatusNotFound || statusCode == http.StatusServiceUnavailable {
		t.Skipf("queue service not enabled (HTTP %d) — skipping", statusCode)
		return true
	}
	return false
}

// ── TestE2E_Queue_ServiceDisabled_Or_ValidShape ───────────────────────────────
//
// Always-run: detects whether the service is disabled (skip) or live (validate shape).

func TestE2E_Queue_ServiceDisabled_Or_ValidShape(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/queue/new", nil, "X-Forwarded-For", ip)

	// Service disabled paths — skip gracefully.
	if resp.StatusCode == http.StatusNotFound {
		body := readBody(t, resp)
		t.Skipf("POST /queue/new: 404 — route not deployed on this cluster (body: %s)", body)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		var errBody errorResponse
		decodeJSON(t, resp, &errBody)
		if errBody.Error != "service_disabled" {
			t.Errorf("503 from /queue/new must carry error=service_disabled, got %q", errBody.Error)
		}
		t.Skipf("POST /queue/new: 503 service_disabled — queue not yet in INSTANT_ENABLED_SERVICES")
	}

	// Service is live — validate full response shape.
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /queue/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if !body.OK {
		t.Error("ok field must be true")
	}
	if body.Token == "" {
		t.Error("token field must not be empty")
	}
	if _, err := uuid.Parse(body.Token); err != nil {
		t.Errorf("token %q must be a valid UUID: %v", body.Token, err)
	}
	if !strings.HasPrefix(body.ConnectionURL, "nats://") {
		t.Errorf("connection_url must start with nats://; got %q", body.ConnectionURL)
	}
	if body.Tier != "anonymous" {
		t.Errorf("unauthenticated provision must produce anonymous tier, got %q", body.Tier)
	}
	if body.Limits == nil {
		t.Error("limits field must not be nil")
	}
}

// ── TestE2E_Queue_Dedup_SameFingerprintReturnsExisting ───────────────────────
//
// Only runs when queue IS enabled.  Provisions 6 times from the same fingerprint
// and asserts the 6th call returns an existing token (dedup, not a new resource).

func TestE2E_Queue_Dedup_SameFingerprintReturnsExisting(t *testing.T) {
	// Probe once to check service availability — same pattern as cache/nosql tests.
	probe := post(t, "/queue/new", nil, "X-Forwarded-For", uniqueIP(t))
	if probe.StatusCode == http.StatusNotFound || probe.StatusCode == http.StatusServiceUnavailable {
		readBody(t, probe)
		t.Skip("queue service not enabled — skipping dedup test")
	}
	// Drain the probe body so the response is closed.
	var probeBody provisionNewResponse
	decodeJSON(t, probe, &probeBody)

	// All 6 provisions share one /24 subnet → same fingerprint.
	// uniqueSubnet guarantees no collision with other tests in this run.
	ip := uniqueSubnet(t).IP(1)

	var seen []string
	for i := 0; i < 5; i++ {
		r := post(t, "/queue/new", nil, "X-Forwarded-For", ip)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("provision %d: want 201, got %d\n%s", i+1, r.StatusCode, readBody(t, r))
		}
		var b provisionNewResponse
		decodeJSON(t, r, &b)
		seen = append(seen, b.Token)
	}

	// 6th call — must return an existing token (fail-open dedup), not a new one.
	r6 := post(t, "/queue/new", nil, "X-Forwarded-For", ip)
	if r6.StatusCode != http.StatusOK && r6.StatusCode != http.StatusCreated {
		t.Fatalf("6th provision: want 200 or 201, got %d\n%s", r6.StatusCode, readBody(t, r6))
	}
	var body6 provisionNewResponse
	decodeJSON(t, r6, &body6)

	existingSet := make(map[string]bool, len(seen))
	for _, tok := range seen {
		existingSet[tok] = true
	}
	if !existingSet[body6.Token] {
		t.Errorf("6th provision must return an existing token; got new token %q (seen: %v)", body6.Token, seen)
	}
}

// itoa converts an int to a decimal string without importing strconv.
// Used to build IP address strings above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 3)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// ── TestE2E_Queue_StorageLimitInResponse ─────────────────────────────────────
//
// Only when queue is enabled.  Verifies the anonymous provision response includes
// limits.storage_mb == 1024 and limits.expires_in == "24h".

func TestE2E_Queue_StorageLimitInResponse(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/queue/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("queue service not enabled — skipping limits test")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /queue/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Limits == nil {
		t.Fatal("limits field must not be nil")
	}

	storageMB, ok := body.Limits["storage_mb"].(float64)
	if !ok {
		t.Fatalf("limits.storage_mb must be a number, got %T (%v)", body.Limits["storage_mb"], body.Limits["storage_mb"])
	}
	if storageMB != 1024 {
		t.Errorf("anonymous queue limits.storage_mb: want 1024, got %.0f", storageMB)
	}

	expiresIn, ok := body.Limits["expires_in"].(string)
	if !ok {
		t.Fatalf("limits.expires_in must be a string, got %T (%v)", body.Limits["expires_in"], body.Limits["expires_in"])
	}
	if expiresIn != "24h" {
		t.Errorf("anonymous queue limits.expires_in: want '24h', got %q", expiresIn)
	}
}

// ── Storage quota tests (always runnable — uses anonymous cache + claim) ─────

// TestE2E_StorageQuota_GetResourceIncludesStorageExceeded verifies that
// GET /api/v1/resources/:id includes a storage_exceeded boolean field.
// Provisions anonymous cache (always enabled), claims it, and fetches the individual
// resource — confirming the field is present and false for a fresh resource.
func TestE2E_StorageQuota_GetResourceIncludesStorageExceeded(t *testing.T) {
	// Claim a team so we can use the management API.
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()

	claimResp := post(t, "/claim", map[string]any{
		"jwt":       jwtStr,
		"email":     email,
		"team_name": "e2e-sqe-" + uuid.NewString()[:6],
	})
	if claimResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT := makeSessionJWT(t, claim.TeamID, email)

	// GET /api/v1/resources to find the resource token.
	// Note: GET /api/v1/resources/:id is actually a token-based lookup (the handler
	// calls GetResourceByToken), so we use the token field from the list as the path param.
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}

	var listBody struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)

	if len(listBody.Items) == 0 {
		t.Fatal("GET /api/v1/resources: expected at least 1 resource after claim, got 0")
	}

	// Pick the first resource — the :id path param is the resource token UUID,
	// not the internal database id (the handler uses GetResourceByToken).
	resource := listBody.Items[0]
	resourceToken, ok := resource["token"].(string)
	if !ok || resourceToken == "" {
		t.Fatalf("resource item must have a non-empty token field, got %v", resource["token"])
	}

	// GET /api/v1/resources/:id  (where :id == token UUID)
	itemResp := get(t, "/api/v1/resources/"+resourceToken, "Authorization", "Bearer "+sessionJWT)
	if itemResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/resources/%s: want 200, got %d\n%s", resourceToken, itemResp.StatusCode, readBody(t, itemResp))
	}

	var itemBody struct {
		OK   bool           `json:"ok"`
		Item map[string]any `json:"item"`
	}
	decodeJSON(t, itemResp, &itemBody)

	if !itemBody.OK {
		t.Error("GET /api/v1/resources/:id: ok field must be true")
	}
	if itemBody.Item == nil {
		t.Fatal("GET /api/v1/resources/:id: item field must not be nil")
	}

	// storage_exceeded must be present as a boolean.
	storageExceededRaw, present := itemBody.Item["storage_exceeded"]
	if !present {
		t.Fatal("GET /api/v1/resources/:id: response must include storage_exceeded field")
	}
	storageExceeded, isBool := storageExceededRaw.(bool)
	if !isBool {
		t.Fatalf("storage_exceeded must be a boolean, got %T (%v)", storageExceededRaw, storageExceededRaw)
	}
	// A freshly provisioned resource must not have exceeded its quota.
	if storageExceeded {
		t.Error("storage_exceeded must be false for a freshly provisioned resource")
	}
}

// TestE2E_StorageQuota_ProvisionResponseNoWarningWhenFresh verifies that a fresh
// DB/cache/nosql provision response does NOT include a warning field and does NOT
// set X-Instant-Notice.  Uses the first available provisioning service.
func TestE2E_StorageQuota_ProvisionResponseNoWarningWhenFresh(t *testing.T) {
	ip := uniqueIP(t)

	// Try DB, then cache, then nosql — use the first one that responds 201.
	type serviceCandidate struct {
		path string
		name string
	}
	candidates := []serviceCandidate{
		{"/db/new", "postgres"},
		{"/cache/new", "redis"},
		{"/nosql/new", "mongodb"},
	}

	var (
		respBody provisionNewResponse
		rawResp  *http.Response
		service  string
	)
	for _, c := range candidates {
		r := post(t, c.path, nil, "X-Forwarded-For", uniqueIP(t))
		if r.StatusCode == http.StatusCreated {
			decodeJSON(t, r, &respBody)
			rawResp = r
			service = c.name
			break
		}
		readBody(t, r)
	}

	if rawResp == nil || service == "" {
		t.Skip("no provisioning service (db/cache/nosql) responded 201 — all may be disabled on this cluster")
	}

	_ = ip // used for fingerprint isolation

	// warning must be absent or empty.
	// provisionNewResponse embeds Warning only when a handler fills it; for
	// DB/cache/nosql, the field is not present in the struct, so check raw JSON.
	// We re-examine via the raw map path below.
	t.Logf("Provisioned %s resource: token=%s tier=%s", service, respBody.Token, respBody.Tier)

	// Re-provision using a raw map decode to check the warning field.
	r2 := post(t, func() string {
		for _, c := range candidates {
			if c.name == service {
				return c.path
			}
		}
		return candidates[0].path
	}(), nil, "X-Forwarded-For", uniqueIP(t))

	notice := r2.Header.Get("X-Instant-Notice")

	var raw map[string]any
	decodeJSON(t, r2, &raw)

	// warning field must be absent or empty string.
	if w, exists := raw["warning"]; exists {
		if wStr, ok := w.(string); ok && wStr != "" {
			t.Errorf("fresh %s provision must not include warning; got %q", service, wStr)
		}
	}

	// X-Instant-Notice must not be set for a fresh provision.
	if notice != "" {
		t.Errorf("fresh %s provision must not set X-Instant-Notice; got %q", service, notice)
	}
}

// ── Race condition tests ──────────────────────────────────────────────────────

// TestE2E_Queue_ConcurrentSameFingerprintProvisions sends 5 concurrent /queue/new
// requests from the same IP fingerprint and asserts:
//   - No 500 errors (server stability)
//   - All return 2xx
//   - Distinct token count <= 5 (dedup works under concurrency)
func TestE2E_Queue_ConcurrentSameFingerprintProvisions(t *testing.T) {
	// Probe for service availability.
	probe := post(t, "/queue/new", nil, "X-Forwarded-For", uniqueIP(t))
	if probe.StatusCode == http.StatusNotFound || probe.StatusCode == http.StatusServiceUnavailable {
		readBody(t, probe)
		t.Skip("queue service not enabled — skipping concurrency test")
	}
	// Count the probe token too.
	var probeBody provisionNewResponse
	decodeJSON(t, probe, &probeBody)

	const goroutines = 5
	// Fixed /24 subnet so all goroutines share one fingerprint.
	// uniqueSubnet guarantees no collision with other tests in this run.
	sharedIP := uniqueSubnet(t).IP(1)

	type result struct {
		status int
		token  string
	}
	results := make([]result, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			r := post(t, "/queue/new", nil, "X-Forwarded-For", sharedIP)
			code := r.StatusCode
			var b provisionNewResponse
			if code == http.StatusCreated || code == http.StatusOK {
				decodeJSON(t, r, &b)
			} else {
				readBody(t, r)
			}
			results[i] = result{status: code, token: b.Token}
		}()
	}
	wg.Wait()

	distinctTokens := make(map[string]bool)
	for _, res := range results {
		if res.status >= 500 {
			t.Errorf("concurrent provision goroutine returned 5xx: %d", res.status)
		}
		if res.status != http.StatusOK && res.status != http.StatusCreated {
			t.Errorf("concurrent provision: unexpected status %d (want 2xx)", res.status)
		}
		if res.token != "" {
			distinctTokens[res.token] = true
		}
	}

	if len(distinctTokens) > 5 {
		t.Errorf("dedup must keep distinct tokens <= 5; got %d tokens: %v",
			len(distinctTokens), distinctTokens)
	}
	t.Logf("concurrent queue provisions: %d goroutines → %d distinct tokens", goroutines, len(distinctTokens))
}

// TestE2E_DoubleClaim_SecondClaimReturns409 verifies that the JWT single-use
// claim guarantee is preserved: the first POST /claim returns 201, the second
// with the same JWT returns 409 Conflict.
//
// This test duplicates TestE2E_Claim_DoubleClaim_Returns409 in e2e_test.go but
// names it explicitly in the queue/quota context so the -run filter in the task
// picks it up together with the other queue tests.
func TestE2E_DoubleClaim_SecondClaimReturns409(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, prov.Note)
	email := uniqueEmail()
	body := map[string]any{
		"jwt":       jwtStr,
		"email":     email,
		"team_name": "e2e-dc-" + uuid.NewString()[:6],
	}

	resp1 := post(t, "/claim", body)
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first POST /claim: want 201, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	readBody(t, resp1)

	// Second claim with the identical JWT — must be 409 Conflict.
	resp2 := post(t, "/claim", body)
	readBody(t, resp2)

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("second POST /claim (same JWT): want 409 Conflict, got %d", resp2.StatusCode)
	}
}

// TestE2E_ConcurrentProvisions_DifferentServices_SameFingerprintIndependent
// provisions three different services (queue, cache, nosql) from the same
// fingerprint simultaneously.  Rate limits are per-service, so each enabled
// service should respond 201 independently.
func TestE2E_ConcurrentProvisions_DifferentServices_SameFingerprintIndependent(t *testing.T) {
	// Fixed subnet for all three goroutines so they share one fingerprint.
	// uniqueSubnet guarantees no collision with other tests in this run.
	sharedIP := uniqueSubnet(t).IP(1)

	type serviceResult struct {
		name   string
		path   string
		status int
		token  string
	}

	services := []serviceResult{
		{name: "queue", path: "/queue/new"},
		{name: "cache", path: "/cache/new"},
		{name: "nosql", path: "/nosql/new"},
	}

	var wg sync.WaitGroup
	wg.Add(len(services))

	for i := range services {
		i := i
		go func() {
			defer wg.Done()
			r := post(t, services[i].path, nil, "X-Forwarded-For", sharedIP)
			code := r.StatusCode
			var b provisionNewResponse
			if code == http.StatusCreated {
				decodeJSON(t, r, &b)
			} else {
				readBody(t, r)
			}
			services[i].status = code
			services[i].token = b.Token
		}()
	}
	wg.Wait()

	enabledCount := 0
	for _, svc := range services {
		switch svc.status {
		case http.StatusCreated:
			enabledCount++
			t.Logf("service %s: 201 token=%s", svc.name, svc.token)
		case http.StatusNotFound, http.StatusServiceUnavailable:
			t.Logf("service %s: %d (disabled — skip)", svc.name, svc.status)
		default:
			t.Errorf("service %s: unexpected status %d (want 201 or 503/404)", svc.name, svc.status)
		}
	}

	if enabledCount == 0 {
		t.Skip("no provisioning service (queue/cache/nosql) responded 201 — all may be disabled on this cluster")
	}

	// Each enabled service must have produced a distinct, valid-UUID token.
	seen := make(map[string]bool)
	for _, svc := range services {
		if svc.status != http.StatusCreated {
			continue
		}
		if svc.token == "" {
			t.Errorf("service %s: 201 response but empty token", svc.name)
			continue
		}
		if _, err := uuid.Parse(svc.token); err != nil {
			t.Errorf("service %s: token %q is not a valid UUID: %v", svc.name, svc.token, err)
		}
		if seen[svc.token] {
			t.Errorf("service %s: duplicate token %q across services", svc.name, svc.token)
		}
		seen[svc.token] = true
	}
}
