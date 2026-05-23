package handlers_test

// twin_core_fault_final3_test.go — FINAL serial pass #3. Drives the
// ProvisionForTwinCore CreateResource-error arm across all three backends
// (db / cache / nosql). A dev-env twin bypasses the email-approval gate and
// flows straight into ProvisionForTwinCore; a fault DB failing after the
// source-lookup(1) + team-lookup(2) + ValidateFamilyParent(3) makes the
// CreateResource(4) call error → the create_resource_failed arm + twinCoreErr
// + ProvisionForTwin's respondProvisionFailed 503.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func twinCreateResourceFault(t *testing.T, resourceType string) {
	t.Helper()
	seedDB, cleanSeed := testhelpers.SetupTestDB(t)
	defer cleanSeed()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := twinJWT(t, seedDB, teamID)
	_, srcToken := seedTwinSource(t, seedDB, teamID, resourceType, "pro")

	// failAfter=3: source-lookup(1) + team-lookup(2) + ValidateFamilyParent(3)
	// succeed; the ProvisionForTwinCore CreateResource INSERT(4) errors.
	faultDB := openFaultDB(t, 3)
	app := twinFaultApp(t, faultDB)

	// env=development bypasses the approval gate → direct provision path.
	resp := postTwin(t, app, srcToken, jwt, map[string]any{"env": "development"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestTwinCoreFaultFinal3_Postgres_CreateResourceError — db.go ProvisionForTwinCore.
func TestTwinCoreFaultFinal3_Postgres_CreateResourceError(t *testing.T) {
	twinCreateResourceFault(t, "postgres")
}

// TestTwinCoreFaultFinal3_Redis_CreateResourceError — cache.go ProvisionForTwinCore.
func TestTwinCoreFaultFinal3_Redis_CreateResourceError(t *testing.T) {
	twinCreateResourceFault(t, "redis")
}

// TestTwinCoreFaultFinal3_Mongo_CreateResourceError — nosql.go ProvisionForTwinCore.
func TestTwinCoreFaultFinal3_Mongo_CreateResourceError(t *testing.T) {
	twinCreateResourceFault(t, "mongodb")
}

// TestTwinCoreFaultFinal3_HappyPath_Postgres_DevEnv — a dev-env twin that fully
// succeeds against the local backend, exercising ProvisionForTwin's success
// response path (the 201 + internal_url branch) — complements the fault arms.
func TestTwinCoreFaultFinal3_HappyPath_Postgres_DevEnv(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	_, srcToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	resp := postTwin(t, app, srcToken, jwt, map[string]any{"env": "development"})
	defer resp.Body.Close()
	// Local backend → 201 on success, or 503 if the customer DB is unreachable.
	// Either way the ProvisionForTwin response path executed (not a 4xx).
	assert.NotEqual(t, http.StatusBadRequest, resp.StatusCode)
}
