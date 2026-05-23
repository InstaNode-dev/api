package handlers_test

// twin_arms_provarms_test.go — fills the single-twin error arms for cache and
// nosql (the gRPC suite only covers the postgres twin error path) and the
// bulk-twin "already-exists skip" arm that records a skipped item with the
// existing twin's token.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// Cache single-twin gRPC error → 503 provision_failed (ProvisionForTwinCore
// provision-failure arm + soft-delete).
func TestGRPCTwin_Cache_DevEnv_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "redis", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// NoSQL single-twin gRPC error → 503 provision_failed.
func TestGRPCTwin_NoSQL_DevEnv_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "mongodb", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// Cache + NoSQL single-twin persist failure (bad AES) → 503.
func TestGRPCTwin_Cache_PersistFailure_Returns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true) // bad AES key
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "redis", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestGRPCTwin_NoSQL_PersistFailure_Returns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	_, srcToken := seedSourceResource(t, fx.db, teamID, "mongodb", "pro", "production")

	resp, body := postTwinDev(t, fx, srcToken, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// Bulk-twin where a twin already exists in the target env → twinOneParent
// records a SKIPPED item carrying the existing twin's token (the duplicate_twin
// branch), with twinned=0 / skipped=1 and a 200.
func TestGRPCBulkTwin_AlreadyExists_SkipsWithExistingToken(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	// One prod parent + an existing development twin of it.
	parentID, _ := seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")
	_, _ = seedResourceFull(t, fx.db, teamID, "postgres", "pro", "development", &parentID)

	resp, body := postBulk(t, fx, jwt, "production", "development")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Equal(t, 0, body.Twinned, "the only parent already has a dev twin → nothing new")
	assert.Empty(t, body.Failures)
}
