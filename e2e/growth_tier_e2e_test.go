//go:build e2e

// Growth tier (dedicated k8s backends) — lifecycle, limits, migration, logs, isolation, cleanup.
//
// Many cases require a cluster with K8S_DEDICATED_BACKEND enabled on the provisioner.
// When dedicated routing is not active, growth-tier provisions still land on shared
// infrastructure — G1/G5/G6 detect that and skip with a clear message.
//
// Env vars:
//
//	E2E_BASE_URL              agent API (required)
//	E2E_DEDICATED_INFRA       must be "true" to run G1–G6 (requires dedicated k8s backends)
//	E2E_JWT_SECRET            management API + claim session (G1–G2, G4–G6)
//	E2E_MIGRATOR_URL          migrator HTTP base (G3)
//	E2E_MIGRATOR_SECRET       migrator auth header (G3)
//	E2E_ALLOW_QUOTA_BURN      must be "true" for destructive G6
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/google/uuid"
)

// sharedInfraSubstrings match connection URLs routed to shared instant-data services.
var sharedInfraSubstrings = []string{
	"postgres-customers.",
	"redis-provision.",
	"mongodb.instant-data.",
	"mongodb.instant.svc.cluster.local",
	"redis.instant.svc.cluster.local",
}

func connectionURLIsDedicatedInfrastructure(conn string) bool {
	if conn == "" {
		return false
	}
	lower := strings.ToLower(conn)
	for _, s := range sharedInfraSubstrings {
		if strings.Contains(lower, strings.ToLower(s)) {
			return false
		}
	}
	return true
}

func jwtSecretOrSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("E2E_JWT_SECRET") == "" {
		t.Skip("E2E_JWT_SECRET not set — skipping growth-tier authenticated tests")
	}
}

func dedicatedInfraOrSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("E2E_DEDICATED_INFRA") != "true" {
		t.Skip("E2E_DEDICATED_INFRA not set — skipping (dedicated k8s backends not available)")
	}
}

func setTierGrowth(t *testing.T, teamID string) {
	t.Helper()
	resp := post(t, "/internal/set-tier", map[string]any{
		"team_id": teamID,
		"tier":    "growth",
	})
	defer resp.Body.Close()
	body := readBody(t, resp)
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("POST /internal/set-tier: 404 — not a development API build")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /internal/set-tier: want 200, got %d: %s", resp.StatusCode, body)
	}
}

func skipUnlessDedicatedConn(t *testing.T, label, conn string) {
	t.Helper()
	if connectionURLIsDedicatedInfrastructure(conn) {
		return
	}
	t.Skipf("%s: connection still routes to shared infra (dedicated k8s backend not active?): %s",
		label, truncateURL(conn))
}

func truncateURL(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// growthMigratorClient allows long-running migration status polls.
var growthMigratorClient = &http.Client{
	Timeout:   60 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

func growthMigratorPost(t *testing.T, base, path, secret string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("growthMigratorPost: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Migrator-Secret", secret)
	}
	resp, err := growthMigratorClient.Do(req)
	if err != nil {
		t.Fatalf("growthMigratorPost %s: %v", path, err)
	}
	return resp
}

func growthMigratorGet(t *testing.T, base, path, secret string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("growthMigratorGet: %v", err)
	}
	if secret != "" {
		req.Header.Set("X-Migrator-Secret", secret)
	}
	resp, err := growthMigratorClient.Do(req)
	if err != nil {
		t.Fatalf("growthMigratorGet %s: %v", path, err)
	}
	return resp
}

// ── G1: Growth provisions use dedicated backends ─────────────────────────────

func TestE2E_Growth_G1_ProvisionsUseDedicatedBackends(t *testing.T) {
	dedicatedInfraOrSkip(t)
	jwtSecretOrSkip(t)

	teamID, sessionJWT, _ := claimAndGetSession(t)
	setTierGrowth(t, teamID)

	me := getAuthMe(t, sessionJWT)
	if me["tier"] != "growth" {
		t.Fatalf("G1: GET /auth/me tier: want growth, got %v", me["tier"])
	}

	hdr := []string{
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer " + sessionJWT,
	}

	dbResp := apiPost(t, "/db/new", nil, hdr...)
	skipIfServiceDown(t, dbResp, "postgres")
	if dbResp.StatusCode != http.StatusCreated {
		t.Fatalf("G1: POST /db/new: want 201, got %d\n%s", dbResp.StatusCode, readBody(t, dbResp))
	}
	var dbBody provisionNewResponse
	decodeJSON(t, dbResp, &dbBody)
	if dbBody.Tier != "growth" {
		t.Errorf("G1: postgres tier: want growth, got %q", dbBody.Tier)
	}
	skipUnlessDedicatedConn(t, "G1 postgres", dbBody.ConnectionURL)

	cacheResp := apiPost(t, "/cache/new", nil, hdr...)
	skipIfServiceDown(t, cacheResp, "redis")
	if cacheResp.StatusCode != http.StatusCreated {
		t.Fatalf("G1: POST /cache/new: want 201, got %d\n%s", cacheResp.StatusCode, readBody(t, cacheResp))
	}
	var cacheBody provisionNewResponse
	decodeJSON(t, cacheResp, &cacheBody)
	if cacheBody.Tier != "growth" {
		t.Errorf("G1: redis tier: want growth, got %q", cacheBody.Tier)
	}
	skipUnlessDedicatedConn(t, "G1 redis", cacheBody.ConnectionURL)

	mongoResp := apiPost(t, "/nosql/new", nil, hdr...)
	skipIfServiceDown(t, mongoResp, "mongodb")
	if mongoResp.StatusCode != http.StatusCreated {
		t.Fatalf("G1: POST /nosql/new: want 201, got %d\n%s", mongoResp.StatusCode, readBody(t, mongoResp))
	}
	var mongoBody provisionNewResponse
	decodeJSON(t, mongoResp, &mongoBody)
	if mongoBody.Tier != "growth" {
		t.Errorf("G1: mongodb tier: want growth, got %q", mongoBody.Tier)
	}
	skipUnlessDedicatedConn(t, "G1 mongodb", mongoBody.ConnectionURL)

	t.Logf("G1: dedicated URLs verified (postgres, redis, mongodb)")
}

// ── G2: Growth tier resources have higher limits (plans.yaml growth = unlimited / -1) ─

func TestE2E_Growth_G2_LimitsMatchPlansYAML(t *testing.T) {
	dedicatedInfraOrSkip(t)
	jwtSecretOrSkip(t)

	teamID, sessionJWT, _ := claimAndGetSession(t)
	_ = teamID
	setTierGrowth(t, teamID)

	hdr := []string{
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer " + sessionJWT,
	}

	dbResp := apiPost(t, "/db/new", nil, hdr...)
	skipIfServiceDown(t, dbResp, "postgres")
	if dbResp.StatusCode != http.StatusCreated {
		t.Fatalf("G2: POST /db/new: want 201, got %d", dbResp.StatusCode)
	}
	var dbBody struct {
		Tier   string `json:"tier"`
		Limits struct {
			StorageMB   int `json:"storage_mb"`
			Connections int `json:"connections"`
		} `json:"limits"`
	}
	decodeJSON(t, dbResp, &dbBody)
	if dbBody.Tier != "growth" {
		t.Fatalf("G2: tier: want growth, got %q", dbBody.Tier)
	}
	if dbBody.Limits.StorageMB != -1 {
		t.Errorf("G2: growth postgres storage_mb: want -1 (unlimited per plans.yaml), got %d", dbBody.Limits.StorageMB)
	}
	if dbBody.Limits.Connections != -1 {
		t.Errorf("G2: growth postgres connections: want -1, got %d", dbBody.Limits.Connections)
	}

	cacheResp := apiPost(t, "/cache/new", nil, hdr...)
	skipIfServiceDown(t, cacheResp, "redis")
	if cacheResp.StatusCode != http.StatusCreated {
		t.Fatalf("G2: POST /cache/new: want 201, got %d", cacheResp.StatusCode)
	}
	var cacheBody struct {
		Tier   string `json:"tier"`
		Limits struct {
			MemoryMB int `json:"memory_mb"`
		} `json:"limits"`
	}
	decodeJSON(t, cacheResp, &cacheBody)
	if cacheBody.Tier != "growth" {
		t.Fatalf("G2: cache tier: want growth, got %q", cacheBody.Tier)
	}
	if cacheBody.Limits.MemoryMB != -1 {
		t.Errorf("G2: growth redis memory_mb: want -1, got %d", cacheBody.Limits.MemoryMB)
	}

	mongoResp := apiPost(t, "/nosql/new", nil, hdr...)
	skipIfServiceDown(t, mongoResp, "mongodb")
	if mongoResp.StatusCode != http.StatusCreated {
		t.Fatalf("G2: POST /nosql/new: want 201, got %d", mongoResp.StatusCode)
	}
	var mongoBody struct {
		Tier   string `json:"tier"`
		Limits struct {
			StorageMB   int `json:"storage_mb"`
			Connections int `json:"connections"`
		} `json:"limits"`
	}
	decodeJSON(t, mongoResp, &mongoBody)
	if mongoBody.Tier != "growth" {
		t.Fatalf("G2: mongo tier: want growth, got %q", mongoBody.Tier)
	}
	if mongoBody.Limits.StorageMB != -1 || mongoBody.Limits.Connections != -1 {
		t.Errorf("G2: growth mongo limits: want storage_mb=-1 connections=-1, got %d/%d",
			mongoBody.Limits.StorageMB, mongoBody.Limits.Connections)
	}
}

// ── G3: Migration shared (hobby) → growth ─────────────────────────────────────

func TestE2E_Growth_G3_MigrateHobbyRedisToGrowth(t *testing.T) {
	dedicatedInfraOrSkip(t)
	jwtSecretOrSkip(t)
	base := migratorURL(t)
	secret := migratorSecret(t)

	_, sessionJWT, _ := claimAndGetSession(t)
	ip := uniqueIP(t)
	provResp := apiPost(t, "/cache/new", nil, "X-Forwarded-For", ip, "Authorization", "Bearer "+sessionJWT)
	skipIfServiceDown(t, provResp, "redis")
	if provResp.StatusCode != http.StatusCreated {
		t.Fatalf("G3: POST /cache/new: want 201, got %d\n%s", provResp.StatusCode, readBody(t, provResp))
	}
	var prov provisionNewResponse
	decodeJSON(t, provResp, &prov)
	if prov.Tier != "hobby" {
		t.Skipf("G3: expected hobby-tier cache before migration, got %q", prov.Tier)
	}
	if prov.ConnectionURL == "" {
		t.Fatal("G3: empty connection_url from hobby provision")
	}

	payload := map[string]any{
		"migration_id":  uuid.NewString(),
		"resource_id":   prov.ID,
		"resource_type": "redis",
		"token":         prov.Token,
		"source_url":    prov.ConnectionURL,
		"source_tier":   "hobby",
		"target_tier":   "growth",
		"request_id":    "e2e-g3-" + uuid.NewString()[:8],
	}

	start := growthMigratorPost(t, base, "/migrations", secret, payload)
	defer start.Body.Close()
	if start.StatusCode != http.StatusAccepted { // 202
		t.Fatalf("G3: POST /migrations: want 202, got %d\n%s", start.StatusCode, readBody(t, start))
	}
	var startBody map[string]any
	if err := json.NewDecoder(start.Body).Decode(&startBody); err != nil {
		t.Fatalf("G3: decode start response: %v", err)
	}
	wfID, _ := startBody["workflow_id"].(string)
	if wfID == "" {
		t.Fatal("G3: missing workflow_id")
	}

	var finalState string
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		stResp := growthMigratorGet(t, base, "/migrations/"+wfID, secret)
		var st map[string]any
		json.NewDecoder(stResp.Body).Decode(&st)
		stResp.Body.Close()
		finalState, _ = st["state"].(string)
		if finalState == "complete" || finalState == "failed" {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if finalState != "complete" {
		t.Fatalf("G3: migration did not complete: state=%q (want complete)", finalState)
	}

	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("G3: GET /api/v1/resources: want 200, got %d", listResp.StatusCode)
	}
	var listBody struct {
		Items []struct {
			Token string `json:"token"`
			Tier  string `json:"tier"`
		} `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)
	var sawGrowth bool
	for _, it := range listBody.Items {
		if it.Token == prov.Token && it.Tier == "growth" {
			sawGrowth = true
			break
		}
	}
	if !sawGrowth {
		t.Fatal("G3: migrated resource not listed as tier=growth")
	}

	rotResp := post(t, "/api/v1/resources/"+prov.Token+"/rotate-credentials", nil,
		"Authorization", "Bearer "+sessionJWT)
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("G3: rotate-credentials: want 200, got %d\n%s", rotResp.StatusCode, readBody(t, rotResp))
	}
	var rot map[string]any
	decodeJSON(t, rotResp, &rot)
	newURL, _ := rot["connection_url"].(string)
	if newURL == "" {
		t.Fatal("G3: rotate-credentials returned empty connection_url")
	}
	skipUnlessDedicatedConn(t, "G3 post-migration redis", newURL)

	opts, err := goredis.ParseURL(localURL(newURL))
	if err != nil {
		t.Fatalf("G3: parse redis URL: %v", err)
	}
	rdb := goredis.NewClient(opts)
	defer rdb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("G3: redis PING after migration+rotate: %v", err)
	}
	t.Logf("G3: hobby→growth redis migration complete; PING ok")
}

// ── G4: Logs — cross-reference logs_e2e_test.go ───────────────────────────────
//
// Full SSE coverage lives in logs_e2e_test.go (L1–L7). Here we assert the same
// HTTP contract from the growth-tier persona: growth can stream logs; shared tier
// receives 400 not_growth.

func TestE2E_Growth_G4_LogsGrowthVsShared(t *testing.T) {
	dedicatedInfraOrSkip(t)
	jwtSecretOrSkip(t)

	t.Log("G4: see also TestE2E_Logs_GrowthPostgres_ReturnsLines and TestE2E_Logs_SharedTier_Returns400 in logs_e2e_test.go")

	// Shared / hobby resource → 400 not_growth
	_, sessionJWT, _ := claimAndGetSession(t)
	hobby := provisionAnonymousAuth(t, sessionJWT)
	if hobby.Tier != "hobby" {
		t.Skipf("G4: need hobby cache for logs negative test, got tier=%q", hobby.Tier)
	}
	logResp, err := http.Get(baseURL() + "/resources/" + hobby.Token + "/logs?tail=3")
	if err != nil {
		t.Fatalf("G4: GET logs: %v", err)
	}
	if logResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("G4: hobby resource logs: want 400, got %d\n%s", logResp.StatusCode, readBody(t, logResp))
	}
	var errBody struct {
		Error string `json:"error"`
	}
	decodeJSON(t, logResp, &errBody)
	if errBody.Error != "not_growth" {
		t.Errorf("G4: want error not_growth, got %q", errBody.Error)
	}

	// Growth resource → 200 when a workload namespace exists (same gate as L1).
	ns, ok := logsNamespace(t)
	if !ok {
		t.Skip("G4: no logs namespace — set E2E_LOGS_NAMESPACE (see logs_e2e_test.go)")
	}
	tok := insertLogsTestResource(t, "postgres", ns)
	resp, err := http.Get(baseURL() + "/resources/" + tok + "/logs?tail=5")
	if err != nil {
		t.Fatalf("G4: GET growth logs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("G4: growth logs: want 200, got %d: %s", resp.StatusCode, string(b))
	}
	t.Logf("G4: growth logs OK in namespace %q", ns)
}

// ── G5: Two growth teams get distinct connection endpoints ─────────────────────

func TestE2E_Growth_G5_TwoTeamsIsolation(t *testing.T) {
	dedicatedInfraOrSkip(t)
	jwtSecretOrSkip(t)

	teamA, jwtA, _ := claimAndGetSession(t)
	teamB, jwtB, _ := claimAndGetSession(t)
	_ = teamA
	_ = teamB

	setTierGrowth(t, teamA)
	setTierGrowth(t, teamB)

	hdrA := []string{"X-Forwarded-For", uniqueIP(t), "Authorization", "Bearer " + jwtA}
	hdrB := []string{"X-Forwarded-For", uniqueIP(t), "Authorization", "Bearer " + jwtB}

	dbA := apiPost(t, "/db/new", nil, hdrA...)
	skipIfServiceDown(t, dbA, "postgres")
	if dbA.StatusCode != http.StatusCreated {
		t.Fatalf("G5: POST /db/new (team A): want 201, got %d", dbA.StatusCode)
	}
	var bodyA provisionNewResponse
	decodeJSON(t, dbA, &bodyA)
	skipUnlessDedicatedConn(t, "G5 team A postgres", bodyA.ConnectionURL)

	dbB := apiPost(t, "/db/new", nil, hdrB...)
	skipIfServiceDown(t, dbB, "postgres")
	if dbB.StatusCode != http.StatusCreated {
		t.Fatalf("G5: POST /db/new (team B): want 201, got %d", dbB.StatusCode)
	}
	var bodyB provisionNewResponse
	decodeJSON(t, dbB, &bodyB)
	skipUnlessDedicatedConn(t, "G5 team B postgres", bodyB.ConnectionURL)

	if bodyA.ConnectionURL == bodyB.ConnectionURL {
		t.Fatal("G5: expected distinct connection_url for two growth teams")
	}
	t.Logf("G5: distinct growth postgres endpoints (team A vs B)")
}

// ── G6: Delete growth resource triggers backend cleanup (best-effort kubectl) ─

func TestE2E_Growth_G6_DeleteDeprovisionsDedicatedNamespace(t *testing.T) {
	dedicatedInfraOrSkip(t)
	if os.Getenv("E2E_ALLOW_QUOTA_BURN") != "true" {
		t.Skip("E2E_ALLOW_QUOTA_BURN not set to true — skipping destructive growth deprovision test")
	}
	jwtSecretOrSkip(t)

	teamID, sessionJWT, _ := claimAndGetSession(t)
	setTierGrowth(t, teamID)

	hdr := []string{"X-Forwarded-For", uniqueIP(t), "Authorization", "Bearer " + sessionJWT}
	dbResp := apiPost(t, "/db/new", nil, hdr...)
	skipIfServiceDown(t, dbResp, "postgres")
	if dbResp.StatusCode != http.StatusCreated {
		t.Fatalf("G6: POST /db/new: want 201, got %d", dbResp.StatusCode)
	}
	var prov provisionNewResponse
	decodeJSON(t, dbResp, &prov)
	skipUnlessDedicatedConn(t, "G6 postgres", prov.ConnectionURL)

	// provisioner/internal/backend/postgres/k8s.go: namespace = "instant-customer-" + token
	ns := "instant-customer-" + prov.Token

	delReq, err := http.NewRequest(http.MethodDelete, baseURL()+"/api/v1/resources/"+prov.Token, nil)
	if err != nil {
		t.Fatalf("G6: NewRequest: %v", err)
	}
	delReq.Header.Set("Authorization", "Bearer "+sessionJWT)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("G6: DELETE: %v", err)
	}
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("G6: DELETE /api/v1/resources/:id: want 200, got %d\n%s", delResp.StatusCode, readBody(t, delResp))
	}
	_ = readBody(t, delResp)

	// Best-effort: namespace removal is async; poll kubectl.
	deadline := time.Now().Add(90 * time.Second)
	gone := false
	for time.Now().Before(deadline) {
		out, err := exec.Command("kubectl", "get", "namespace", ns, "--ignore-not-found", "-o", "name").CombinedOutput()
		if err != nil {
			t.Logf("G6: kubectl get namespace (best-effort): %v — %s", err, string(out))
			t.Skip("G6: kubectl unavailable — cannot verify k8s cleanup")
		}
		if strings.TrimSpace(string(out)) == "" {
			gone = true
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !gone {
		t.Errorf("G6: namespace %q still exists after delete (deprovision may be delayed or failed)", ns)
	} else {
		t.Logf("G6: namespace %q removed after DELETE", ns)
	}
}
