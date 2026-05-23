package handlers_test

// twin_storage_exceeded_twinlogs_test.go — covers the `if res.StorageExceeded`
// warning arm of the three twin renderers:
//
//	db.go:574    DBHandler.ProvisionForTwin
//	cache.go:502 CacheHandler.ProvisionForTwin
//	nosql.go:507 NoSQLHandler.ProvisionForTwin
//
// That arm sets resp["warning"] + the X-Instant-Notice header, and is reachable
// only when ProvisionForTwinCore returns StorageExceeded=true — a state that
// requires a freshly-twinned resource to already exceed its tier's storage cap.
// The checkStorageQuota seam (seams.go, driven by forceStorageExceeded in
// storage_exceeded_seam2_test.go) forces exceeded=true at exactly the Core gate,
// so the renderer takes the warning arm and surfaces it on the 201 response.
//
// Backend is the bufconn-backed fakeProvisioner from
// coverage_provisioner_grpc_test.go (setupGRPCProvFixture), so the twin pipeline
// reaches a real 201 (not a 503) under CI's postgres-only matrix — unlike the
// live-backend seam2 anon/auth tests which skip when the customer backend is
// unreachable.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// postTwinDevRaw POSTs a single twin to the development env (which bypasses the
// approval gate) and returns the raw response plus the decoded warning field, so
// a test can assert both the X-Instant-Notice header and the warning JSON the
// StorageExceeded arm sets.
func postTwinDevRaw(t *testing.T, fx grpcProvFixture, sourceToken, jwt string) (*http.Response, string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"env": "development"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+sourceToken+"/provision-twin", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	_ = json.Unmarshal(raw, &parsed)
	warning, _ := parsed["warning"].(string)
	return resp, warning
}

// assertTwinWarningArm asserts the twin renderer surfaced the storage-limit
// warning that the StorageExceeded arm sets (both the JSON field and the notice
// header).
func assertTwinWarningArm(t *testing.T, resp *http.Response, warning string) {
	t.Helper()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "storage_limit_reached", resp.Header.Get("X-Instant-Notice"),
		"StorageExceeded twin arm must stamp the X-Instant-Notice header")
	assert.Contains(t, warning, "Storage limit reached",
		"StorageExceeded twin arm must surface the warning field")
}

func TestTwin_DB_StorageExceeded_WarningArm(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")

	resp, warning := postTwinDevRaw(t, fx, srcToken, jwt)
	defer resp.Body.Close()
	assertTwinWarningArm(t, resp, warning)
}

func TestTwin_Cache_StorageExceeded_WarningArm(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "redis", "pro", "production")

	resp, warning := postTwinDevRaw(t, fx, srcToken, jwt)
	defer resp.Body.Close()
	assertTwinWarningArm(t, resp, warning)
}

func TestTwin_NoSQL_StorageExceeded_WarningArm(t *testing.T) {
	restore := forceStorageExceeded(t)
	defer restore()

	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "mongodb", "pro", "production")

	resp, warning := postTwinDevRaw(t, fx, srcToken, jwt)
	defer resp.Body.Close()
	assertTwinWarningArm(t, resp, warning)
}
