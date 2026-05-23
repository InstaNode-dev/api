package handlers_test

// storage_arms_bvwave_test.go — covers the authenticated-path arms of
// storage.go (newStorageAuthenticated) that storage_hermetic_coverage_test.go
// leaves open:
//
//   - storage_limit_reached (402): a team whose summed storage_bytes already
//     meets/exceeds its tier cap.
//   - team_lookup_failed (503): a JWT carrying a well-formed but non-existent
//     team UUID.
//   - invalid_team (400): a JWT whose team claim is not a UUID.
//
// Reuses storageHermeticApp / shStoragePost from storage_hermetic_coverage_test.go.

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func TestStorageHermetic_Authenticated_QuotaExceeded_402_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storageHermeticApp(t, db, rdb)

	// Hobby tier has a finite storage cap. Seed a prior storage resource whose
	// storage_bytes already exceeds the cap so the quota gate fires.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	limitMB := plans.Default().StorageLimitMB("hobby", "storage")
	require.Positive(t, limitMB, "hobby storage limit must be finite for this test")
	overBytes := int64(limitMB)*1024*1024 + 1

	// Insert an active storage resource for the team with storage_bytes over cap.
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env, status, storage_bytes)
		VALUES ($1::uuid, 'storage', 'hobby', 'production', 'active', $2)
	`, teamID, overBytes)
	require.NoError(t, err)

	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "q@example.com")
	resp := shStoragePost(t, app, "/storage/new", "10.60.0.1", jwt, `{"name":"more-assets"}`)
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	resp.Body.Close()
}

func TestStorageHermetic_Authenticated_TeamLookupFailed_503_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storageHermeticApp(t, db, rdb)

	// A well-formed team UUID that does not exist → GetTeamByID errors → 503.
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), uuid.NewString(), "ghost@example.com")
	resp := shStoragePost(t, app, "/storage/new", "10.60.0.2", jwt, `{"name":"assets"}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
}

func TestStorageHermetic_Authenticated_InvalidTeam_400_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storageHermeticApp(t, db, rdb)

	// A JWT whose team claim is not a UUID → parseTeamID fails → 400 invalid_team.
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid-team", "x@example.com")
	resp := shStoragePost(t, app, "/storage/new", "10.60.0.3", jwt, `{"name":"assets"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}
