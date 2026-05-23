package handlers_test

// storage_exceeded_seam2_test.go — seam2 coverage pass for the StorageExceeded
// warning arms of the provisioning handlers.
//
// The `if <…>StorageExceeded { resp["warning"]=…; c.Set("X-Instant-Notice", …) }`
// arms in db.go (anon 341 / auth 469), cache.go (anon 299 / auth 426), and
// nosql.go (anon 292 / auth 423) are only reachable when a freshly-provisioned
// resource ALREADY exceeds its tier's storage cap — a state that cannot be
// seeded before the row exists. The checkStorageQuota seam (seams.go) lets a
// test force exceeded=true at exactly that gate, driving each warning arm.
//
// These tests reuse the real local-backend fixture (setupBackendFixture in
// coverage_resource_backend_test.go); they skip cleanly when the customer
// backend is unreachable (503), exactly like the existing full-backend tests.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
)

// forceStorageExceeded installs a checkStorageQuota seam that always reports the
// resource as over its cap, and returns a restore func.
func forceStorageExceeded(t *testing.T) func() {
	t.Helper()
	return handlers.SetCheckStorageQuotaForTest(
		func(_ context.Context, _ *sql.DB, _ uuid.UUID, limitMB int) (int64, bool, error) {
			return int64(limitMB)*1024*1024 + 1, true, nil
		},
	)
}

// assertWarningArm asserts the response surfaced the storage-limit warning that
// the StorageExceeded arm sets (both the JSON field and the notice header).
func assertWarningArm(t *testing.T, resp *http.Response) {
	t.Helper()
	assert.Equal(t, "storage_limit_reached", resp.Header.Get("X-Instant-Notice"),
		"StorageExceeded arm must stamp the X-Instant-Notice header")
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	warning, _ := body["warning"].(string)
	assert.Contains(t, warning, "Storage limit reached",
		"StorageExceeded arm must surface the warning field")
}

// ── Authenticated paths: newDBAuthenticated / newCacheAuthenticated / newNoSQLAuthenticated ──

func TestSeam2_DBNew_AuthenticatedStorageExceeded(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	f := setupBackendFixture(t, "pro")
	resp := f.post(t, "/db/new", `{"name":"pg-exceeded"}`, "10.70.0.1", true)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("postgres backend not reachable in test env (503)")
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assertWarningArm(t, resp)
}

func TestSeam2_CacheNew_AuthenticatedStorageExceeded(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	f := setupBackendFixture(t, "pro")
	resp := f.post(t, "/cache/new", `{"name":"redis-exceeded"}`, "10.71.0.1", true)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("redis backend not reachable in test env (503)")
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assertWarningArm(t, resp)
}

func TestSeam2_NoSQLNew_AuthenticatedStorageExceeded(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	f := setupBackendFixture(t, "pro")
	resp := f.post(t, "/nosql/new", `{"name":"mongo-exceeded"}`, "10.72.0.1", true)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("mongo backend not reachable in test env (503)")
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assertWarningArm(t, resp)
}

// ── Anonymous paths: NewDB / NewCache / NewNoSQL ──

func TestSeam2_DBNew_AnonymousStorageExceeded(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	f := setupBackendFixture(t, "pro")
	resp := f.post(t, "/db/new", `{"name":"pg-anon-exceeded"}`, "10.73.0.1", false)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("postgres backend not reachable in test env (503)")
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assertWarningArm(t, resp)
}

func TestSeam2_CacheNew_AnonymousStorageExceeded(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	f := setupBackendFixture(t, "pro")
	resp := f.post(t, "/cache/new", `{"name":"redis-anon-exceeded"}`, "10.74.0.1", false)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("redis backend not reachable in test env (503)")
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assertWarningArm(t, resp)
}

func TestSeam2_NoSQLNew_AnonymousStorageExceeded(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	f := setupBackendFixture(t, "pro")
	resp := f.post(t, "/nosql/new", `{"name":"mongo-anon-exceeded"}`, "10.75.0.1", false)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("mongo backend not reachable in test env (503)")
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assertWarningArm(t, resp)
}
