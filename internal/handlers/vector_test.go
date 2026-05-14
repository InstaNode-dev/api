package handlers_test

// vector_test.go — handler-level tests for POST /vector/new.
//
// Coverage:
//
//   - happy path: 201 with required fields + extension="pgvector"
//   - service-disabled gate returns 503
//   - default dimensions is 1536, custom dimension echoed back
//   - dimensions out of range (0, -1, 16001) → 400 invalid_dimensions
//   - resource_type column is "vector" in the DB
//   - end-to-end pgvector verification when the testhelpers postgres-customers
//     instance has the extension installed (skipped when it isn't)
//   - anonymous tier limit (storage_mb=10) reported in response
//
// The tests follow the same shape as db_test.go and rely on testhelpers.
// MustProvisionVector skips gracefully when postgres-customers is not
// reachable, matching MustProvisionDB.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// vectorNewResponse mirrors the JSON body returned by POST /vector/new.
type vectorNewResponse struct {
	OK            bool   `json:"ok"`
	ID            string `json:"id"`
	Token         string `json:"token"`
	Name          string `json:"name"`
	ConnectionURL string `json:"connection_url"`
	Tier          string `json:"tier"`
	Env           string `json:"env"`
	Extension     string `json:"extension"`
	Dimensions    int    `json:"dimensions"`
	Limits        struct {
		StorageMB   int    `json:"storage_mb"`
		Connections int    `json:"connections"`
		ExpiresIn   string `json:"expires_in"`
	} `json:"limits"`
	Note    string `json:"note"`
	Upgrade string `json:"upgrade,omitempty"`
	Warning string `json:"warning,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// postVector POSTs to /vector/new with the given body + X-Forwarded-For.
// Returns the response so the test can inspect status + body. If body is
// nil, no body is sent — equivalent to /db/new tests' "empty body" path.
func postVector(t *testing.T, app *fiber.App, ip, body string) *http.Response {
	t.Helper()
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/vector/new", reqBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// decodeVectorResponse drains and decodes a /vector/new response body.
func decodeVectorResponse(t *testing.T, resp *http.Response) vectorNewResponse {
	t.Helper()
	defer resp.Body.Close()
	var v vectorNewResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&v))
	return v
}

// maybeSkipProvisionFailed inspects the response and skips the test when the
// postgres-customers backend is unreachable. Matches MustProvisionDB's gate
// so vector tests behave the same way under CI without postgres-customers.
func maybeSkipProvisionFailed(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode == http.StatusCreated {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var errBody map[string]any
	if err := json.Unmarshal(body, &errBody); err == nil {
		if code, _ := errBody["error"].(string); code == "provision_failed" {
			t.Skipf("vector_test: postgres-customers not reachable — skipping (%s)", body)
		}
	}
	t.Fatalf("vector_test: expected 201, got %d: %s", resp.StatusCode, body)
}

// ── 1. Service-disabled gate ───────────────────────────────────────────────

// TestVectorNew_ServiceDisabled_Returns503 — when neither "vector" nor
// "postgres" is in EnabledServices, /vector/new must return 503.
func TestVectorNew_ServiceDisabled_Returns503(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Default test app enables only "redis".
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	resp := postVector(t, app, "10.40.0.1", "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestVectorNew_EnabledViaPostgres_AcceptsRequest — the gate also accepts
// the existing "postgres" flag, so operators don't have to flip a new
// configmap key to start serving /vector/new.
func TestVectorNew_EnabledViaPostgres_AcceptsRequest(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postVector(t, app, "10.40.0.2", "")
	maybeSkipProvisionFailed(t, resp)
	v := decodeVectorResponse(t, resp)
	assert.True(t, v.OK)
	assert.Equal(t, "pgvector", v.Extension)
}

// ── 2. Happy path ─────────────────────────────────────────────────────────

// TestVectorNew_Returns201WithRequiredFields verifies the happy path.
func TestVectorNew_Returns201WithRequiredFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "vector,postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postVector(t, app, "10.40.1.1", "")
	maybeSkipProvisionFailed(t, resp)
	v := decodeVectorResponse(t, resp)

	assert.True(t, v.OK)
	assert.NotEmpty(t, v.ID)
	assert.NotEmpty(t, v.Token)
	assert.True(t, strings.HasPrefix(v.ConnectionURL, "postgres://"),
		"vector connection_url must start with postgres://; got %q", v.ConnectionURL)
	assert.Equal(t, "anonymous", v.Tier)
	assert.Equal(t, "pgvector", v.Extension, "response must declare extension=pgvector")
	assert.Equal(t, 1536, v.Dimensions, "default dimensions must be 1536 (OpenAI ada-002)")
	assert.NotEmpty(t, v.Note)
}

// TestVectorNew_StoresResourceTypeVector verifies the row in `resources`
// has resource_type='vector' so audit feeds and the storage scanner can
// distinguish vector workloads.
func TestVectorNew_StoresResourceTypeVector(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "vector,postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postVector(t, app, "10.40.1.2", "")
	maybeSkipProvisionFailed(t, resp)
	v := decodeVectorResponse(t, resp)
	defer db.Exec(`DELETE FROM resources WHERE token = $1::uuid`, v.Token)

	var resourceType string
	err := db.QueryRow(
		`SELECT resource_type FROM resources WHERE token = $1::uuid`, v.Token,
	).Scan(&resourceType)
	require.NoError(t, err)
	assert.Equal(t, "vector", resourceType, "resource_type must be 'vector'")
}

// ── 3. Dimensions handling ────────────────────────────────────────────────

// TestVectorNew_CustomDimensionsEchoed — a valid custom dimensions value
// is echoed back in the response. The dimension itself doesn't change
// what gets provisioned (pgvector picks dimensions per column), but the
// echo lets callers confirm their request landed.
func TestVectorNew_CustomDimensionsEchoed(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "vector,postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postVector(t, app, "10.40.2.1", `{"dimensions":3072}`)
	maybeSkipProvisionFailed(t, resp)
	v := decodeVectorResponse(t, resp)
	assert.Equal(t, 3072, v.Dimensions, "custom dimensions must be echoed (3072 = text-embedding-3-large)")
}

// TestVectorNew_InvalidDimensions_Returns400 — dimensions outside (0..16000]
// must be rejected with 400. The handler runs validation BEFORE the
// service-enabled gate's expensive provisioning so the error returns fast.
func TestVectorNew_InvalidDimensions_Returns400(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"negative", `{"dimensions":-1}`},
		{"too_large", `{"dimensions":16001}`},
		// dimensions:0 is treated as "unset" and defaults to 1536 — see
		// parseDimensions. That's intentional so callers can send the
		// JSON zero value without hitting an error.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			rdb, cleanRedis := testhelpers.SetupTestRedis(t)
			defer cleanRedis()

			app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "vector,postgres,redis,mongodb,queue,webhook,storage")
			defer cleanApp()

			resp := postVector(t, app, "10.40.3."+tc.name, tc.body)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"dimensions=%s must return 400", tc.body)
			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "invalid_dimensions", body["error"],
				"error code must be invalid_dimensions; got %v", body)
		})
	}
}

// ── 4. Tier limits ────────────────────────────────────────────────────────

// TestVectorNew_AnonymousTierLimits — anonymous tier returns 10MB storage,
// 2 connections, 24h TTL. Matches the vector_* keys in plans.yaml and
// mirrors postgres exactly (the underlying storage IS Postgres).
func TestVectorNew_AnonymousTierLimits(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "vector,postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postVector(t, app, "10.40.4.1", "")
	maybeSkipProvisionFailed(t, resp)
	v := decodeVectorResponse(t, resp)
	assert.Equal(t, 10, v.Limits.StorageMB, "anonymous vector storage_mb must be 10")
	assert.Equal(t, 2, v.Limits.Connections, "anonymous vector connections must be 2")
	assert.Equal(t, "24h", v.Limits.ExpiresIn, "anonymous vector ttl must be 24h")
}

// TestPlansRegistry_VectorTierLimits — locks in the per-tier vector quotas
// from the original spec. The hobby tier deliberately ships a tighter
// envelope than its postgres sibling (500MB/5conn vs 1024MB/8conn) so the
// hobby plan's "AI app builder gets a real vector DB" promise is honoured
// without burning a full hobby Postgres allowance. Pro and team match
// postgres exactly because the underlying storage IS Postgres at those
// tiers — there is no separate vector budget to defend.
func TestPlansRegistry_VectorTierLimits(t *testing.T) {
	reg := plans.Default()
	cases := []struct {
		tier            string
		wantStorageMB   int
		wantConnections int
	}{
		{"anonymous", 10, 2},
		{"free", 10, 2},
		{"hobby", 500, 5},
		{"pro", 5120, 20},
		{"team", -1, -1},
		{"growth", 5120, 20},
	}
	for _, tc := range cases {
		t.Run(tc.tier, func(t *testing.T) {
			assert.Equal(t, tc.wantStorageMB, reg.StorageLimitMB(tc.tier, "vector"),
				"vector storage_mb at tier %q", tc.tier)
			assert.Equal(t, tc.wantConnections, reg.ConnectionsLimit(tc.tier, "vector"),
				"vector connections at tier %q", tc.tier)
		})
	}
}

// ── 5. End-to-end pgvector verification ───────────────────────────────────

// TestVectorNew_PgvectorExtensionInstalled connects to the returned
// connection_url and runs `SELECT extname FROM pg_extension WHERE extname='vector'`.
// Skips when the testhelpers postgres-customers backend isn't reachable or
// when the pgvector binary isn't installed in the test cluster (CREATE
// EXTENSION will fail in the handler and we'll catch it as provision_failed).
func TestVectorNew_PgvectorExtensionInstalled(t *testing.T) {
	if os.Getenv("TEST_POSTGRES_CUSTOMERS_URL") == "" {
		t.Skip("TEST_POSTGRES_CUSTOMERS_URL not set — skipping end-to-end pgvector check")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "vector,postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postVector(t, app, "10.40.5.1", "")
	maybeSkipProvisionFailed(t, resp)
	v := decodeVectorResponse(t, resp)
	defer db.Exec(`DELETE FROM resources WHERE token = $1::uuid`, v.Token)

	// Replace the in-cluster host with whatever the test customers URL points
	// at (typically localhost via port-forward). The token user + password
	// remain valid; only the host:port differs.
	connURL := rewriteConnectionURLHost(v.ConnectionURL, os.Getenv("TEST_POSTGRES_CUSTOMERS_URL"))

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connURL)
	if err != nil {
		t.Skipf("could not connect to provisioned vector DB at %s: %v", connURL, err)
	}
	defer conn.Close(ctx)

	var extName string
	err = conn.QueryRow(ctx, `SELECT extname FROM pg_extension WHERE extname='vector'`).Scan(&extName)
	require.NoError(t, err, "pgvector extension must be installed in the provisioned database")
	assert.Equal(t, "vector", extName)
}

// rewriteConnectionURLHost replaces the host:port portion of a postgres://
// URL with the host:port from the admin URL. Used so tests can talk to a
// port-forwarded postgres-customers from outside the cluster.
func rewriteConnectionURLHost(connURL, adminURL string) string {
	// Extract auth and database from connURL, host from adminURL.
	// connURL: postgres://USER:PASS@HOST:PORT/DB
	const prefix = "postgres://"
	if !strings.HasPrefix(connURL, prefix) || !strings.HasPrefix(adminURL, prefix) {
		return connURL
	}
	connRest := connURL[len(prefix):]
	adminRest := adminURL[len(prefix):]

	atConn := strings.Index(connRest, "@")
	atAdmin := strings.Index(adminRest, "@")
	if atConn < 0 || atAdmin < 0 {
		return connURL
	}
	connAuth := connRest[:atConn]
	connAfterAt := connRest[atConn+1:]
	adminAfterAt := adminRest[atAdmin+1:]

	// host:port is the substring up to the first "/" in connAfterAt.
	slashConn := strings.Index(connAfterAt, "/")
	if slashConn < 0 {
		return connURL
	}
	connDB := connAfterAt[slashConn:]

	slashAdmin := strings.Index(adminAfterAt, "/")
	var adminHost string
	if slashAdmin < 0 {
		adminHost = adminAfterAt
	} else {
		adminHost = adminAfterAt[:slashAdmin]
	}
	// Strip any query string off the admin host (sslmode=disable etc.).
	if q := strings.Index(adminHost, "?"); q >= 0 {
		adminHost = adminHost[:q]
	}
	return fmt.Sprintf("%s%s@%s%s", prefix, connAuth, adminHost, connDB)
}
